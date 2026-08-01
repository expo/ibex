#!/usr/bin/env node
// Derive the LLP 0045 network Lane B mechanism matrix from a generated
// CapSec conformance recipe catalog.
//
// Every summary in the output is derived from the emitted per-cell rows in
// this same run, and the script asserts the invariants that a hand-rolled
// analysis got wrong (self-inconsistent totals, an unnamed mechanism bucket).
// It fails loudly rather than emitting a summary that cannot be recomputed.
//
// @ref LLP 0045#1-measured-problem-shape — the artifact this produces is the
// plan's measured basis; prose figures must be recomputed from it, never
// transcribed from an exploratory run.
//
// Usage:
//   bun packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs \
//     --target aarch64-apple-darwin --output /tmp/catalog.json
//   node scripts/llp0045-mechanism-matrix.mjs /tmp/catalog.json > matrix.json

import { readFileSync } from "node:fs";

const LANE_REASONS = {
  B: "no-static-enforcement-terminal",
  C: "native-public-source-invocation-unavailable",
  D: "builtin-export-resolves-to-bootstrap-internal",
};

// Every raw `ambiguousCallees` value maps to exactly one mechanism. An
// unrecognized shape is a hard error: silently bucketing it as "other" is how
// a 13-cell mechanism went unnamed in the first analysis.
function mechanismOf(raw) {
  if (raw.startsWith("cross-source-export-projection")) return "projection";
  if (
    raw.startsWith("dynamic-call-receiver") ||
    raw.startsWith("dynamic-call-target") ||
    raw === "computed-call"
  ) {
    return "dynamic-dispatch";
  }
  if (raw.startsWith("unresolved-call:")) {
    return raw.slice("unresolved-call:".length).includes(".")
      ? "qualified-member-miss"
      : "unresolved-ident";
  }
  // A bare (unprefixed) name is the walker's DUPLICATE-DEFINITION marker:
  // `routeForCallable` pushes the plain name when `definitions.length > 1`
  // (capsec-surface-inventory.mjs:4494-4498 for unqualified names, :4538
  // inside `directAmbiguities` for qualified ones). It is not a "shape"
  // bucket — it means the source declares the callee more than once.
  //
  // The inventory also emits `dynamic-callable-alternative:`, `shadowed:`,
  // `computed-terminal:`, `dynamic-terminal-receiver:`, `dynamic-constructor:`
  // and `unresolved-required-export:`. None appear in this data set, and all
  // would throw below rather than be absorbed — which is what makes the
  // taxonomy exhaustive *for this catalog* rather than merely total.
  if (/^[A-Za-z_$][\w$]*(\.[\w$]+)*$/u.test(raw)) return "duplicate-definition";
  throw new Error(`unrecognized ambiguity shape: ${JSON.stringify(raw)}`);
}

function modulePrefixOf(edgeId) {
  // NOTE: a positional slice of the edge id, so this is a module.export
  // PREFIX, not a module: ws.js's exports appear as `ws.server`,
  // `ws.websocket`, …, and `node.dns` rows are `node.dns.promises` exports.
  // Labelled `modulePrefix` in the output for that reason.
  const segments = edgeId.split(".");
  return segments[1] === "builtin"
    ? segments.slice(3, 5).join(".")
    : segments[1];
}

const catalogPath = process.argv[2];
if (!catalogPath) throw new Error("usage: llp0045-mechanism-matrix.mjs <catalog.json>");
const catalog = JSON.parse(readFileSync(catalogPath, "utf8"));

const laneCells = { B: new Set(), C: new Set(), D: new Set() };
const cells = new Map(); // edgeId -> {module, mechanisms:Set, raw:Set, rows:Set}

for (const recipe of catalog.recipes) {
  if (!recipe.actionIds.some((action) => action.startsWith("network"))) continue;
  for (const [lane, reason] of Object.entries(LANE_REASONS)) {
    if (recipe.residualReasons.includes(reason)) {
      for (const edgeId of recipe.edgeIds) laneCells[lane].add(edgeId);
    }
  }
  if (!recipe.residualReasons.includes(LANE_REASONS.B)) continue;
  for (const edgeId of recipe.edgeIds) {
    let cell = cells.get(edgeId);
    if (!cell) {
      cell = {
        modulePrefix: modulePrefixOf(edgeId),
        mechanisms: new Set(),
        raw: new Set(),
        rows: new Set(),
      };
      cells.set(edgeId, cell);
    }
    cell.rows.add(recipe.fixtureId);
    for (const raw of recipe.route.ambiguousCallees ?? []) {
      cell.raw.add(raw);
      cell.mechanisms.add(mechanismOf(raw));
    }
  }
}

const cellRows = [...cells]
  .map(([edgeId, cell]) => ({
    edgeId,
    modulePrefix: cell.modulePrefix,
    bucket: cell.mechanisms.size
      ? [...cell.mechanisms].sort().join("+")
      : "empty-no-mechanism",
    mechanisms: [...cell.mechanisms].sort(),
    rawAmbiguousCallees: [...cell.raw].sort(),
    rowCount: cell.rows.size,
    fixtureIds: [...cell.rows].sort(),
  }))
  .sort((left, right) => left.edgeId.localeCompare(right.edgeId));

// --- summaries, all derived from cellRows in this run ---
const tally = (pairs) => {
  const out = {};
  for (const key of pairs) out[key] = (out[key] ?? 0) + 1;
  return Object.fromEntries(Object.entries(out).sort((a, b) => b[1] - a[1]));
};
const bucketCells = tally(cellRows.map((row) => row.bucket));
const pureCells = tally(
  cellRows.map((row) =>
    row.mechanisms.length === 1
      ? row.mechanisms[0]
      : row.mechanisms.length === 0
        ? "zero-mechanism"
        : null,
  ).filter(Boolean),
);
const cellsTouching = tally(cellRows.flatMap((row) => row.mechanisms));
const perModulePrefix = {};
for (const row of cellRows) {
  perModulePrefix[row.modulePrefix] ??= { cells: 0, buckets: {} };
  perModulePrefix[row.modulePrefix].cells += 1;
  perModulePrefix[row.modulePrefix].buckets[row.bucket] =
    (perModulePrefix[row.modulePrefix].buckets[row.bucket] ?? 0) + 1;
}
const rawByMechanism = {};
for (const row of cellRows) {
  for (const raw of row.rawAmbiguousCallees) {
    const mechanism = mechanismOf(raw);
    rawByMechanism[mechanism] ??= {};
    rawByMechanism[mechanism][raw] = (rawByMechanism[mechanism][raw] ?? 0) + 1;
  }
}

// --- invariants ---
// The first check is the only genuinely falsifiable one: it re-derives the
// Lane B cell set by an INDEPENDENT second pass over the catalog rather than
// from the structures built above, so a bug in the main loop's filtering or
// edge attribution shows up as a mismatch. (The tallies below are derived
// from cellRows, so they mostly restate its construction; they are kept as
// cheap regression guards, not as proof.)
const independentLaneB = new Set();
for (const recipe of catalog.recipes) {
  if (!recipe.residualReasons.includes(LANE_REASONS.B)) continue;
  if (!recipe.actionIds.some((action) => action.startsWith("network"))) continue;
  for (const edgeId of recipe.edgeIds) independentLaneB.add(edgeId);
}
const problems = [];
if (
  independentLaneB.size !== cellRows.length ||
  cellRows.some((row) => !independentLaneB.has(row.edgeId))
) {
  problems.push(
    `independent Lane B pass (${independentLaneB.size}) disagrees with emitted rows (${cellRows.length})`,
  );
}
const bucketSum = Object.values(bucketCells).reduce((a, b) => a + b, 0);
if (bucketSum !== laneCells.B.size) {
  problems.push(`bucket cells ${bucketSum} != Lane B cells ${laneCells.B.size}`);
}
if (cellRows.length !== laneCells.B.size) {
  problems.push(`emitted rows ${cellRows.length} != Lane B cells ${laneCells.B.size}`);
}
for (const [mechanism, count] of Object.entries(cellsTouching)) {
  const recomputed = cellRows.filter((row) => row.mechanisms.includes(mechanism)).length;
  if (recomputed !== count) {
    problems.push(`touching ${mechanism}: ${count} != recomputed ${recomputed}`);
  }
}
if (problems.length) throw new Error(`invariant failure:\n  ${problems.join("\n  ")}`);

process.stdout.write(
  `${JSON.stringify(
    {
      measurement: "llp-0045-network-laneB-mechanism-matrix",
      generator: "scripts/llp0045-mechanism-matrix.mjs",
      catalogDigest: catalog.recipeCatalogDigest,
      target: catalog.target,
      laneCellCounts: Object.fromEntries(
        Object.entries(laneCells).map(([lane, set]) => [lane, set.size]),
      ),
      unionBCD: new Set([...laneCells.B, ...laneCells.C, ...laneCells.D]).size,
      laneBCells: laneCells.B.size,
      bucketCells,
      pureCells,
      cellsTouchingMechanism: cellsTouching,
      perModulePrefix,
      rawAmbiguityByMechanism: rawByMechanism,
      cells: cellRows,
    },
    null,
    1,
  )}\n`,
);
