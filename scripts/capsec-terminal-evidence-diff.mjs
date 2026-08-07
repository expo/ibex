#!/usr/bin/env node
// LLP 0049 §3 rule 7: the standing per-edgeId terminal-set diff.
//
// A falling Lane B count is not a soundness metric — confident
// misattributions live outside Lane B. This tool is the `8cf677e7`
// verification method as a named instrument: for every edgeId (cell) it
// unions the terminal identifiers across all of the cell's recipes' route
// evidence in a baseline and a candidate catalog, and decides whether the
// candidate's per-cell terminal sets differ ONLY in ways individually
// declared in advance with a source span and proof. It is symmetric: a
// terminal that vanishes fails exactly as one that appears does, and a cell
// that appears or disappears is itself a delta.
//
// It differs from scripts/llp0045-route-evidence-diff.mjs (rule 3's gate) on
// purpose: that tool diffs per-recipe route evidence, so a terminal moving
// between two recipes of the same cell is two changes there; here the unit is
// the cell's unioned terminal set, so intra-cell moves are invisible and only
// genuine gains/losses of attribution surface. Every batch runs both.
//
// @ref LLP 0049#3-construction-rules — rule 7: per-edgeId unioned terminal
// sets, additions and removals both explained; whole catalog, all families,
// no scope flag by design.
//
// Usage:
//   node scripts/capsec-terminal-evidence-diff.mjs \
//     --baseline <catalog.json> --candidate <catalog.json> \
//     [--allow-list <allow-list.json>] [--json <out.json>]
//
// Allow-list entries reuse the rule 3 gate's schema: `edgeId` (one cell) or
// `edgeIdPrefix` (a family), plus `field`, `direction`, `value`,
// `sourceSpan`, and `proof` — the last two mandatory and non-empty, because
// an entry without them declares a change without evidence. A stale entry
// (declared but never observed) fails: the allow-list no longer describes
// the work. `--allow-list` may be omitted to survey; the run then FAILs on
// any delta and prints a skeleton with `sourceSpan` and `proof` left empty —
// this tool cannot supply the evidence, only check that it was supplied.

import { readFileSync, writeFileSync } from "node:fs";

// ---------------------------------------------------------------- arguments

function parseArgs(argv) {
  const args = {};
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
    else throw new Error(`unrecognized argument: ${flag}`);
  }
  if (!args.baseline || !args.candidate) {
    throw new Error(
      "usage: capsec-terminal-evidence-diff.mjs --baseline <catalog.json> --candidate <catalog.json> [--allow-list <f>] [--json <f>]",
    );
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const read = (path) => JSON.parse(readFileSync(path, "utf8"));

// ------------------------------------------------------------------- model
//
// The unit of comparison is one cell (edgeId); its terminal set is the union
// over every recipe carrying that edgeId. Terminal-bearing fields are
// enumerated from the DATA, not from a hard-coded list, so a schema
// extension is gated on arrival instead of silently ignored:
//   - `terminalObservedKey` — the recipe-level terminal;
//   - each `route.<key>` array of strings — observed keys, ambiguity
//     markers, and any future string-list evidence, kept per-field so a
//     surfaceObservedKey gained never masks an identical terminal lost;
//   - each `route.<key>` array-of-objects — the object's own
//     `terminalObservedKey` when present (the alternatives shape), else the
//     whole object JSON-encoded so an unknown shape cannot slip through;
//   - a scalar/object-valued `route.<key>` — JSON-encoded whole.

function terminalFieldsOf(recipe) {
  const fields = new Map();
  const add = (field, value) => {
    if (!fields.has(field)) fields.set(field, new Set());
    fields.get(field).add(value);
  };
  if (recipe.terminalObservedKey !== undefined) {
    add("terminalObservedKey", String(recipe.terminalObservedKey));
  }
  for (const [key, value] of Object.entries(recipe.route ?? {})) {
    const field = `route.${key}`;
    if (!Array.isArray(value)) {
      add(field, JSON.stringify(value));
      continue;
    }
    for (const entry of value) {
      if (entry !== null && typeof entry === "object" && !Array.isArray(entry)) {
        if (typeof entry.terminalObservedKey === "string") {
          add(`${field}.terminalObservedKey`, entry.terminalObservedKey);
        } else {
          add(field, JSON.stringify(entry));
        }
      } else {
        add(field, String(entry));
      }
    }
  }
  return fields;
}

// cell -> field -> Set of terminal identifiers, unioned across recipes.
function indexCells(catalog, label) {
  if (!Array.isArray(catalog.recipes)) {
    throw new Error(`${label}: catalog has no recipes array`);
  }
  const cells = new Map();
  for (const recipe of catalog.recipes) {
    for (const cell of recipe.edgeIds ?? []) {
      if (!cells.has(cell)) cells.set(cell, new Map());
      const byField = cells.get(cell);
      for (const [field, values] of terminalFieldsOf(recipe)) {
        if (!byField.has(field)) byField.set(field, new Set());
        for (const value of values) byField.get(field).add(value);
      }
    }
  }
  return cells;
}

// ------------------------------------------------------------------ diffing

const baselineCatalog = read(args.baseline);
const candidateCatalog = read(args.candidate);
const baseline = indexCells(baselineCatalog, "baseline");
const candidate = indexCells(candidateCatalog, "candidate");

/** @type {Array<{kind:string,cell:string,field:string,direction:string,value:string}>} */
const deltas = [];

const allCells = new Set([...baseline.keys(), ...candidate.keys()]);
for (const cell of allCells) {
  const before = baseline.get(cell);
  const after = candidate.get(cell);

  // A cell appearing or disappearing is one delta, mirroring the rule 3
  // gate's `<recipe>` rows: its members are not itemized, because the entry
  // that explains a new cell explains its whole initial terminal set.
  if (before && !after) {
    deltas.push({ kind: "cell", cell, field: "<cell>", direction: "removed", value: cell });
    continue;
  }
  if (!before && after) {
    deltas.push({ kind: "cell", cell, field: "<cell>", direction: "added", value: cell });
    continue;
  }

  const fieldNames = new Set([...before.keys(), ...after.keys()]);
  for (const field of fieldNames) {
    const beforeSet = before.get(field) ?? new Set();
    const afterSet = after.get(field) ?? new Set();
    for (const value of afterSet) {
      if (!beforeSet.has(value)) {
        deltas.push({ kind: "terminal", cell, field, direction: "added", value });
      }
    }
    for (const value of beforeSet) {
      if (!afterSet.has(value)) {
        deltas.push({ kind: "terminal", cell, field, direction: "removed", value });
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
    if (entry.direction !== "added" && entry.direction !== "removed") {
      throw new Error(
        `allow-list entry ${index}: direction must be added|removed`,
      );
    }
  });
  return { ...parsed, present: true };
}

const allowList = loadAllowList(args.allowList);
const entryUses = allowList.entries.map(() => 0);

function matches(entry, delta) {
  if (entry.field !== delta.field) return false;
  if (entry.direction !== delta.direction) return false;
  if (entry.value !== delta.value) return false;
  if (entry.edgeId !== undefined) return entry.edgeId === delta.cell;
  return delta.cell.startsWith(entry.edgeIdPrefix);
}

const unexplained = [];
for (const delta of deltas) {
  const index = allowList.entries.findIndex((entry) => matches(entry, delta));
  if (index === -1) unexplained.push(delta);
  else entryUses[index] += 1;
}
const staleEntries = allowList.entries
  .map((entry, index) => ({ entry, uses: entryUses[index] }))
  .filter(({ uses }) => uses === 0)
  .map(({ entry }) => entry);

// With no allow-list supplied every delta lands in `unexplained`, so a survey
// run passes only when the terminal sets are genuinely identical.
const passed = unexplained.length === 0 && staleEntries.length === 0;

const changedCells = new Set(deltas.map((delta) => delta.cell));

const report = {
  measurement: "capsec-terminal-evidence-diff",
  gate: "LLP 0049 §3 rule 7",
  tool: "scripts/capsec-terminal-evidence-diff.mjs",
  baseline: {
    path: args.baseline,
    digest: baselineCatalog.recipeCatalogDigest,
    cells: baseline.size,
  },
  candidate: {
    path: args.candidate,
    digest: candidateCatalog.recipeCatalogDigest,
    cells: candidate.size,
  },
  allowList: args.allowList ?? null,
  result: passed ? "PASS" : "FAIL",
  deltaCount: deltas.length,
  changedCellCount: changedCells.size,
  explainedCount: deltas.length - unexplained.length,
  unexplainedCount: unexplained.length,
  staleEntryCount: staleEntries.length,
  deltasByFieldAndDirection: deltas.reduce((acc, delta) => {
    const key = `${delta.field} ${delta.direction}`;
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {}),
  unexplained,
  staleEntries,
};

if (args.json) writeFileSync(args.json, `${JSON.stringify(report, null, 1)}\n`);

// ------------------------------------------------------------------ output

const summarize = (list, limit = 40) =>
  list
    .slice(0, limit)
    .map(
      (delta) =>
        `    ${delta.direction.padEnd(7)} ${delta.field.padEnd(24)} ${delta.cell}\n      ${delta.value}`,
    )
    .join("\n") + (list.length > limit ? `\n    … ${list.length - limit} more` : "");

process.stderr.write(
  [
    `LLP 0049 §3 rule 7 terminal-evidence gate — ${report.result}`,
    `  baseline ${report.baseline.digest} (${report.baseline.cells} cells)`,
    `  candidate ${report.candidate.digest} (${report.candidate.cells} cells)`,
    `  deltas: ${report.deltaCount} on ${report.changedCellCount} cells (${report.explainedCount} allow-listed, ${report.unexplainedCount} unexplained)`,
    `  stale allow-list entries: ${report.staleEntryCount}`,
    ...(unexplained.length
      ? ["", "  UNEXPLAINED TERMINAL DELTAS (each must be allow-listed with a source span and proof):", summarize(unexplained)]
      : []),
    ...(staleEntries.length
      ? [
          "",
          "  STALE ALLOW-LIST ENTRIES (declared but never observed — the delta they",
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
    ...(!allowList.present && deltas.length
      ? [
          "",
          "  No --allow-list supplied: this is a SURVEY run and always FAILs when the",
          "  terminal diff is non-empty. Skeleton for the observed deltas (fill in",
          "  sourceSpan and proof by hand — this tool cannot supply the evidence,",
          "  only check it):",
          JSON.stringify(
            {
              measurement: "capsec-terminal-evidence-allow-list",
              step: "<name the batch>",
              baselineDigest: baselineCatalog.recipeCatalogDigest,
              candidateDigest: candidateCatalog.recipeCatalogDigest,
              entries: [
                ...new Map(
                  deltas.map((delta) => [
                    `${delta.cell}|${delta.field}|${delta.direction}|${delta.value}`,
                    {
                      edgeId: delta.cell,
                      field: delta.field,
                      direction: delta.direction,
                      value: delta.value,
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
