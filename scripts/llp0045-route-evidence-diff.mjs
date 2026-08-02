#!/usr/bin/env node
// LLP 0045 §3 acceptance gate: the paired route-evidence allow-list check.
//
// A falling residual count is not evidence. This tool decides whether a
// candidate catalog differs from a baseline catalog ONLY in ways that were
// individually declared in advance, with a source span and a resolution proof
// for each. It is symmetric: an unexplained REMOVAL fails exactly as an
// unexplained ADDITION does, across every route-evidence field.
//
// @ref LLP 0045#3-acceptance-criteria-what-the-count-fell-is-not — the gate is paired allow-lists, not
// "additive-only": step 2's resolutions legitimately retire ambiguity entries,
// and step 1's extraction rewrites route strings on cells whose terminals and
// ambiguities are unchanged, so a one-directional or one-field rule would fail
// the very work it exists to gate.
//
// Usage:
//   node scripts/llp0045-route-evidence-diff.mjs \
//     --baseline <catalog.json> --candidate <catalog.json> \
//     [--allow-list <allow-list.json>] [--json <out.json>] [--scope network]
//
// Allow-list entries carry `edgeId` (one cell) or `edgeIdPrefix` (a family),
// plus `field`, `direction`, `value`, `sourceSpan`, and `proof` — the last two
// are mandatory and non-empty, because an entry without them declares a change
// without evidence, which is the thing the gate exists to prevent. The
// consequential `residualReasons` removal that clears a lane is gated too: one
// prefix entry normally covers a whole family's worth, but it must still be
// written down, since a residual reason that vanishes with no matching route
// change is exactly §3's "bug that suppresses ambiguity" case.
//
// Exit status is 0 only when every observed change is covered by a used
// allow-list entry and no entry is stale. `--allow-list` may be omitted to
// survey a diff before writing one; the run then always reports FAIL if there
// is any change, and prints a skeleton allow-list you must fill in by hand.
// The skeleton deliberately leaves `sourceSpan` and `proof` empty: this tool
// cannot supply the evidence, only check that it was supplied.

import { readFileSync, writeFileSync } from "node:fs";

// ---------------------------------------------------------------- arguments

function parseArgs(argv) {
  const args = { scope: "network" };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const take = () => {
      const value = argv[index + 1];
      if (value === undefined) throw new Error(`${flag} requires a value`);
      index += 1;
      return value;
    };
    if (flag === "--baseline") args.baseline = take();
    else if (flag === "--candidate") args.candidate = take();
    else if (flag === "--allow-list") args.allowList = take();
    else if (flag === "--json") args.json = take();
    else if (flag === "--scope") args.scope = take();
    else throw new Error(`unrecognized argument: ${flag}`);
  }
  if (!args.baseline || !args.candidate) {
    throw new Error(
      "usage: llp0045-route-evidence-diff.mjs --baseline <catalog.json> --candidate <catalog.json> [--allow-list <f>] [--json <f>] [--scope network|all]",
    );
  }
  if (args.scope !== "network" && args.scope !== "all") {
    throw new Error(`--scope must be "network" or "all", got ${args.scope}`);
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const read = (path) => JSON.parse(readFileSync(path, "utf8"));

// ------------------------------------------------------------------- model
//
// The unit of comparison is one recipe (fixtureId is unique per catalog and is
// asserted so below). Route evidence fields are enumerated from the DATA, not
// from a hard-coded list, so a schema extension — e.g. step 0's representation
// for the conditional alias shape, which §2 requires `enforcementRouteEvidence`
// to gain — is gated on arrival instead of being silently ignored.

const GATED_TOP_LEVEL = ["residualReasons"];

function indexRecipes(catalog, label) {
  if (!Array.isArray(catalog.recipes)) {
    throw new Error(`${label}: catalog has no recipes array`);
  }
  const byFixture = new Map();
  for (const recipe of catalog.recipes) {
    if (byFixture.has(recipe.fixtureId)) {
      throw new Error(`${label}: duplicate fixtureId ${recipe.fixtureId}`);
    }
    byFixture.set(recipe.fixtureId, recipe);
  }
  return byFixture;
}

const inScope = (recipe) =>
  args.scope === "all" ||
  (recipe.actionIds ?? []).some((action) => action.startsWith("network"));

// A recipe's cell(s). A recipe may carry several edgeIds; a change is reported
// against each, because the allow-list is written in terms of cells.
const cellsOf = (recipe) =>
  (recipe.edgeIds ?? []).length ? recipe.edgeIds : ["<no-edge-id>"];

function routeFieldsOf(recipe) {
  const route = recipe.route ?? {};
  const fields = new Map();
  for (const [key, value] of Object.entries(route)) {
    // Only list-shaped route evidence is diffable entry-by-entry. A scalar or
    // object-shaped field is compared whole, as a single JSON-encoded entry,
    // so it can never slip through unexamined.
    fields.set(
      `route.${key}`,
      Array.isArray(value) ? value.map(String) : [JSON.stringify(value)],
    );
  }
  for (const key of GATED_TOP_LEVEL) {
    const value = recipe[key];
    if (value === undefined) continue;
    fields.set(
      key,
      Array.isArray(value) ? value.map(String) : [JSON.stringify(value)],
    );
  }
  return fields;
}

// ------------------------------------------------------------------ diffing

const baselineCatalog = read(args.baseline);
const candidateCatalog = read(args.candidate);
const baseline = indexRecipes(baselineCatalog, "baseline");
const candidate = indexRecipes(candidateCatalog, "candidate");

/** @type {Array<{kind:string,cell:string,fixtureId:string,field:string,direction:string,value:string}>} */
const changes = [];
const pushChange = (change) => changes.push(change);

const allFixtures = new Set([...baseline.keys(), ...candidate.keys()]);
for (const fixtureId of allFixtures) {
  const before = baseline.get(fixtureId);
  const after = candidate.get(fixtureId);

  if (before && !after) {
    if (!inScope(before)) continue;
    for (const cell of cellsOf(before)) {
      pushChange({
        kind: "recipe",
        cell,
        fixtureId,
        field: "<recipe>",
        direction: "removed",
        value: fixtureId,
      });
    }
    continue;
  }
  if (!before && after) {
    if (!inScope(after)) continue;
    for (const cell of cellsOf(after)) {
      pushChange({
        kind: "recipe",
        cell,
        fixtureId,
        field: "<recipe>",
        direction: "added",
        value: fixtureId,
      });
    }
    continue;
  }
  if (!inScope(before) && !inScope(after)) continue;

  const beforeFields = routeFieldsOf(before);
  const afterFields = routeFieldsOf(after);
  const fieldNames = new Set([...beforeFields.keys(), ...afterFields.keys()]);
  const cells = cellsOf(after);

  // An edgeId set change is itself a route-provenance change.
  const beforeEdges = JSON.stringify([...cellsOf(before)].sort());
  const afterEdges = JSON.stringify([...cells].sort());
  if (beforeEdges !== afterEdges) {
    for (const cell of new Set([...cellsOf(before), ...cells])) {
      pushChange({
        kind: "edgeIds",
        cell,
        fixtureId,
        field: "edgeIds",
        direction: "changed",
        value: `${beforeEdges} -> ${afterEdges}`,
      });
    }
  }

  for (const field of fieldNames) {
    const beforeEntries = beforeFields.get(field) ?? [];
    const afterEntries = afterFields.get(field) ?? [];
    // Multiset comparison: a duplicated entry appearing or vanishing is a
    // change, even when the set of distinct values is unchanged.
    const counts = new Map();
    for (const entry of beforeEntries) {
      counts.set(entry, (counts.get(entry) ?? 0) - 1);
    }
    for (const entry of afterEntries) {
      counts.set(entry, (counts.get(entry) ?? 0) + 1);
    }
    for (const [value, delta] of counts) {
      if (delta === 0) continue;
      const direction = delta > 0 ? "added" : "removed";
      for (let repeat = 0; repeat < Math.abs(delta); repeat += 1) {
        for (const cell of cells) {
          pushChange({
            kind: "route",
            cell,
            fixtureId,
            field,
            direction,
            value,
          });
        }
      }
    }
  }
}

// -------------------------------------------------------------- allow-list

function loadAllowList(path) {
  if (!path) return { entries: [], present: false };
  const parsed = read(path);
  if (!Array.isArray(parsed.entries)) {
    throw new Error("allow-list must have an `entries` array");
  }
  parsed.entries.forEach((entry, index) => {
    for (const required of ["field", "direction", "value", "sourceSpan", "proof"]) {
      if (typeof entry[required] !== "string" || entry[required].trim() === "") {
        throw new Error(
          `allow-list entry ${index}: \`${required}\` is required and must be a non-empty string`,
        );
      }
    }
    if (!entry.edgeId && !entry.edgeIdPrefix) {
      throw new Error(
        `allow-list entry ${index}: one of \`edgeId\` or \`edgeIdPrefix\` is required`,
      );
    }
    if (entry.direction !== "added" && entry.direction !== "removed" && entry.direction !== "changed") {
      throw new Error(
        `allow-list entry ${index}: direction must be added|removed|changed`,
      );
    }
  });
  return { ...parsed, present: true };
}

const allowList = loadAllowList(args.allowList);
const entryUses = allowList.entries.map(() => 0);

function matches(entry, change) {
  if (entry.field !== change.field) return false;
  if (entry.direction !== change.direction) return false;
  if (entry.value !== change.value) return false;
  if (entry.edgeId !== undefined) return entry.edgeId === change.cell;
  return change.cell.startsWith(entry.edgeIdPrefix);
}

const unexplained = [];
for (const change of changes) {
  const index = allowList.entries.findIndex((entry) => matches(entry, change));
  if (index === -1) unexplained.push(change);
  else entryUses[index] += 1;
}
const staleEntries = allowList.entries
  .map((entry, index) => ({ entry, uses: entryUses[index] }))
  .filter(({ uses }) => uses === 0)
  .map(({ entry }) => entry);

// ------------------------------------------------------- derived reporting
//
// These are reported for the reviewer, NOT gated: they are consequences of the
// gated route-evidence changes. Reporting a residual count here does not make
// it evidence — §3's point is precisely that it is not.

function laneTally(catalog) {
  const lanes = {
    B: new Set(),
    C: new Set(),
    D: new Set(),
  };
  const reasons = {
    B: "no-static-enforcement-terminal",
    C: "native-public-source-invocation-unavailable",
    D: "builtin-export-resolves-to-bootstrap-internal",
  };
  for (const recipe of catalog.recipes) {
    if (!inScope(recipe)) continue;
    for (const [lane, reason] of Object.entries(reasons)) {
      if ((recipe.residualReasons ?? []).includes(reason)) {
        for (const edgeId of cellsOf(recipe)) lanes[lane].add(edgeId);
      }
    }
  }
  return Object.fromEntries(
    Object.entries(lanes).map(([lane, set]) => [lane, set.size]),
  );
}

// Movement anywhere OUTSIDE the gated scope is a collateral-damage check: a
// change that clears network cells while quietly perturbing another family is
// not the change that was reviewed.
function residualReasonTotals(catalog) {
  const totals = {};
  for (const recipe of catalog.recipes) {
    for (const reason of recipe.residualReasons ?? []) {
      totals[reason] = (totals[reason] ?? 0) + 1;
    }
  }
  return totals;
}

const beforeTotals = residualReasonTotals(baselineCatalog);
const afterTotals = residualReasonTotals(candidateCatalog);
const residualDelta = {};
for (const reason of new Set([
  ...Object.keys(beforeTotals),
  ...Object.keys(afterTotals),
])) {
  const delta = (afterTotals[reason] ?? 0) - (beforeTotals[reason] ?? 0);
  if (delta !== 0) residualDelta[reason] = delta;
}

// With no allow-list supplied every change lands in `unexplained`, so a survey
// run passes only when the diff is genuinely empty — which is itself the check
// wanted for "prove this refactor changed no route evidence at all".
const passed = unexplained.length === 0 && staleEntries.length === 0;

const report = {
  measurement: "llp-0045-route-evidence-paired-allow-list",
  gate: "LLP 0045 §3",
  tool: "scripts/llp0045-route-evidence-diff.mjs",
  scope: args.scope,
  baseline: {
    path: args.baseline,
    digest: baselineCatalog.recipeCatalogDigest,
    recipes: baselineCatalog.recipes.length,
  },
  candidate: {
    path: args.candidate,
    digest: candidateCatalog.recipeCatalogDigest,
    recipes: candidateCatalog.recipes.length,
  },
  allowList: args.allowList ?? null,
  result: passed ? "PASS" : "FAIL",
  changeCount: changes.length,
  explainedCount: changes.length - unexplained.length,
  unexplainedCount: unexplained.length,
  staleEntryCount: staleEntries.length,
  changesByFieldAndDirection: changes.reduce((acc, change) => {
    const key = `${change.field} ${change.direction}`;
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {}),
  unexplained,
  staleEntries,
  derived: {
    note: "Reported for review, NOT gated. A falling count is not evidence (§3).",
    laneCellsBefore: laneTally(baselineCatalog),
    laneCellsAfter: laneTally(candidateCatalog),
    residualReasonDeltaWholeCatalog: residualDelta,
  },
};

if (args.json) writeFileSync(args.json, `${JSON.stringify(report, null, 1)}\n`);

// ------------------------------------------------------------------ output

const summarize = (list, limit = 40) =>
  list
    .slice(0, limit)
    .map(
      (change) =>
        `    ${change.direction.padEnd(7)} ${change.field.padEnd(24)} ${change.cell}\n      ${change.value}`,
    )
    .join("\n") + (list.length > limit ? `\n    … ${list.length - limit} more` : "");

process.stderr.write(
  [
    `LLP 0045 §3 route-evidence gate — ${report.result}`,
    `  scope: ${args.scope}`,
    `  baseline ${report.baseline.digest} (${report.baseline.recipes} recipes)`,
    `  candidate ${report.candidate.digest} (${report.candidate.recipes} recipes)`,
    `  changes: ${report.changeCount} (${report.explainedCount} allow-listed, ${report.unexplainedCount} unexplained)`,
    `  stale allow-list entries: ${report.staleEntryCount}`,
    `  lane cells before: ${JSON.stringify(report.derived.laneCellsBefore)}`,
    `  lane cells after:  ${JSON.stringify(report.derived.laneCellsAfter)}`,
    `  whole-catalog residual delta: ${JSON.stringify(report.derived.residualReasonDeltaWholeCatalog)}`,
    ...(unexplained.length
      ? ["", "  UNEXPLAINED CHANGES (each must be allow-listed with a source span and proof):", summarize(unexplained)]
      : []),
    ...(staleEntries.length
      ? [
          "",
          "  STALE ALLOW-LIST ENTRIES (declared but never observed — the change they",
          "  describe did not happen, so the allow-list no longer describes the work):",
          staleEntries
            .slice(0, 40)
            .map(
              (entry) =>
                `    ${entry.direction.padEnd(7)} ${entry.field.padEnd(24)} ${entry.edgeId ?? `${entry.edgeIdPrefix}*`}\n      ${entry.value}`,
            )
            .join("\n"),
        ]
      : []),
    ...(!allowList.present && changes.length
      ? [
          "",
          "  No --allow-list supplied: this is a SURVEY run and always FAILs when the",
          "  diff is non-empty. Skeleton for the observed changes (fill in sourceSpan",
          "  and proof by hand — this tool cannot supply the evidence, only check it):",
          JSON.stringify(
            {
              measurement: "llp-0045-route-evidence-allow-list",
              step: "<name the step>",
              baselineDigest: baselineCatalog.recipeCatalogDigest,
              candidateDigest: candidateCatalog.recipeCatalogDigest,
              entries: [
                ...new Map(
                  changes.map((change) => [
                    `${change.cell}|${change.field}|${change.direction}|${change.value}`,
                    {
                      edgeId: change.cell,
                      field: change.field,
                      direction: change.direction,
                      value: change.value,
                      sourceSpan: "",
                      proof: "",
                    },
                  ]),
                ).values(),
              ].slice(0, 200),
            },
            null,
            1,
          ),
        ]
      : []),
    "",
  ].join("\n"),
);

if (!args.json) process.stdout.write(`${JSON.stringify(report, null, 1)}\n`);
process.exit(passed ? 0 : 1);
