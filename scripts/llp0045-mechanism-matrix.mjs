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
  // Bare callee names the walker emitted without a prefix: unqualified
  // callback/virtual-member misses (e.g. `oncreate`, `IncomingMessage._read`).
  if (/^[A-Za-z_$][\w$]*(\.[\w$]+)*$/u.test(raw)) return "bare-callee-miss";
  throw new Error(`unrecognized ambiguity shape: ${JSON.stringify(raw)}`);
}

function moduleOf(edgeId) {
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
        module: moduleOf(edgeId),
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
    module: cell.module,
    bucket: cell.mechanisms.size
      ? [...cell.mechanisms].sort().join("+")
      : "empty-no-mechanism",
    mechanisms: [...cell.mechanisms].sort(),
    rawAmbiguousCallees: [...cell.raw].sort(),
    rowCount: cell.rows.size,
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
  cellRows.filter((row) => row.mechanisms.length === 1).map((row) => row.mechanisms[0]),
);
const cellsTouching = tally(cellRows.flatMap((row) => row.mechanisms));
const perModule = {};
for (const row of cellRows) {
  perModule[row.module] ??= { cells: 0, buckets: {} };
  perModule[row.module].cells += 1;
  perModule[row.module].buckets[row.bucket] =
    (perModule[row.module].buckets[row.bucket] ?? 0) + 1;
}
const rawByMechanism = {};
for (const row of cellRows) {
  for (const raw of row.rawAmbiguousCallees) {
    const mechanism = mechanismOf(raw);
    rawByMechanism[mechanism] ??= {};
    rawByMechanism[mechanism][raw] = (rawByMechanism[mechanism][raw] ?? 0) + 1;
  }
}

// --- invariants: fail loudly rather than emit an unauditable summary ---
const problems = [];
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
      perModule,
      rawAmbiguityByMechanism: rawByMechanism,
      cells: cellRows,
    },
    null,
    1,
  )}\n`,
);
