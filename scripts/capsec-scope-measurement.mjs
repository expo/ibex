#!/usr/bin/env node
// LLP 0049 §3 rule 5: the canonical scope-measurement instrument.
//
// Denominators are re-derived at every phase boundary; planning against a
// stale number is the error that produced LLP 0045. This tool derives, from
// one recipe catalog and one capability-family set, the figures every phase
// gate quotes: cells, clean vs poisoned cells, authorable rows, surfaces,
// and template classes — plus per-family breakdowns — and emits the
// `ibex/llp-evidence/scope-measurement/1` schema for retention under
// `llp/evidence/`. `--assert` turns any headline figure into an exit gate.
//
// The definitions are LLP 0044 §9's measurement, replicated exactly (this
// tool reproduces the 2026-08-05 figures recorded in
// issues/20260728-capsec-public-surface-evidence-backlog.md on the catalogs
// they were measured from):
//   - a CELL is one edgeId; its family memberships come from its rows'
//     actionId families (the prefix before `:` — the coverage model's
//     family vocabulary);
//   - a row is IN SCOPE when its action families are non-empty and entirely
//     within the selected family set (a row that also touches an unselected
//     family is not authorable under this scope and does not pull its cell
//     in on its own);
//   - a cell is IN SCOPE when at least one of its rows, of any status, is
//     in scope;
//   - a cell is POISONED when any of its unresolved rows — in-scope or not —
//     carries a Lane B/C/D residual reason (rows authoring cannot clear);
//   - AUTHORABLE ROWS are the unresolved in-scope rows on clean cells;
//   - SURFACES are the clean cells carrying at least one authorable row;
//   - TEMPLATE CLASSES are (surface-kind × exact row action set) groups over
//     the authorable rows; they bound template count, not labor.
//
// @ref LLP 0049#3-construction-rules — rule 5: the named scope-measurement
// deliverable; §4.1 fixes it as `scripts/capsec-scope-measurement.mjs`
// emitting `ibex/llp-evidence/scope-measurement/1` with an `--assert` mode.
//
// Usage:
//   node scripts/capsec-scope-measurement.mjs \
//     --catalog <catalog.json> --families fs,env,process \
//     [--output <out.json>] [--assert clean-unresolved=0] [--assert cells=610]

import { readFileSync, writeFileSync } from "node:fs";

// ---------------------------------------------------------------- arguments

const ASSERTABLE = [
  "cells",
  "clean-cells",
  "poisoned-cells",
  "clean-unresolved",
  "surfaces",
  "template-classes",
];

function parseArgs(argv) {
  const args = { asserts: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const take = () => {
      const value = argv[index + 1];
      if (value === undefined) throw new Error(`${flag} requires a value`);
      index += 1;
      return value;
    };
    if (flag === "--catalog") args.catalog = take();
    else if (flag === "--families") args.families = take();
    else if (flag === "--output") args.output = take();
    else if (flag === "--assert") args.asserts.push(take());
    else throw new Error(`unrecognized argument: ${flag}`);
  }
  if (!args.catalog || !args.families) {
    throw new Error(
      "usage: capsec-scope-measurement.mjs --catalog <catalog.json> --families <comma-list> [--output <f>] [--assert <figure>=<count>]",
    );
  }
  args.familyList = [...new Set(args.families.split(",").map((name) => name.trim()))]
    .filter((name) => name !== "")
    .sort();
  if (args.familyList.length === 0) {
    throw new Error("--families must name at least one capability family");
  }
  args.assertions = args.asserts.map((raw) => {
    const match = raw.match(/^([a-z-]+)=(\d+)$/u);
    if (!match || !ASSERTABLE.includes(match[1])) {
      throw new Error(
        `--assert must be <figure>=<count> with figure one of ${ASSERTABLE.join("|")}, got ${raw}`,
      );
    }
    return { figure: match[1], expected: Number(match[2]) };
  });
  return args;
}

const args = parseArgs(process.argv.slice(2));
const catalog = JSON.parse(readFileSync(args.catalog, "utf8"));
if (!Array.isArray(catalog.recipes)) {
  throw new Error("catalog has no recipes array");
}

// -------------------------------------------------------------- measurement

// Lane B/C/D: the residual reasons authoring cannot clear (LLP 0044 §9).
const LANE_REASONS = {
  B: "no-static-enforcement-terminal",
  C: "native-public-source-invocation-unavailable",
  D: "builtin-export-resolves-to-bootstrap-internal",
};

const selected = new Set(args.familyList);
const familyOf = (actionId) => actionId.split(":")[0];
const familiesOf = (recipe) =>
  new Set((recipe.actionIds ?? []).map((actionId) => familyOf(actionId)));
const rowInScope = (recipe) => {
  const families = familiesOf(recipe);
  return families.size > 0 && [...families].every((family) => selected.has(family));
};
// Surface kind: the leading `surface.<group>.<kind>` triple of an edgeId
// (e.g. surface.builtin.export, surface.native.op, surface.host.abi).
const kindOf = (edgeId) => edgeId.split(".").slice(0, 3).join(".");

const cellRows = new Map();
for (const recipe of catalog.recipes) {
  for (const cell of recipe.edgeIds ?? []) {
    if (!cellRows.has(cell)) cellRows.set(cell, []);
    cellRows.get(cell).push(recipe);
  }
}

const cells = new Set(
  [...cellRows.keys()].filter((cell) => cellRows.get(cell).some(rowInScope)),
);

const poisonedLanes = new Map(); // cell -> Set of lane letters
for (const cell of cells) {
  for (const recipe of cellRows.get(cell)) {
    if (recipe.status !== "unresolved") continue;
    for (const [lane, reason] of Object.entries(LANE_REASONS)) {
      if ((recipe.residualReasons ?? []).includes(reason)) {
        if (!poisonedLanes.has(cell)) poisonedLanes.set(cell, new Set());
        poisonedLanes.get(cell).add(lane);
      }
    }
  }
}
const poisoned = new Set(poisonedLanes.keys());
const clean = new Set([...cells].filter((cell) => !poisoned.has(cell)));

// Authorable rows are counted once per fixtureId even when a row carries
// several edgeIds; surfaces and template classes are per (cell, row) pair.
const authorableRows = new Set();
const surfaces = new Set();
const templateClasses = new Map(); // key -> {surfaceKind, actionIds, surfaces:Set, rows:Set}
for (const cell of clean) {
  for (const recipe of cellRows.get(cell)) {
    if (recipe.status !== "unresolved" || !rowInScope(recipe)) continue;
    authorableRows.add(recipe.fixtureId);
    surfaces.add(cell);
    const actionIds = [...(recipe.actionIds ?? [])].sort();
    const key = `${kindOf(cell)}|${actionIds.join(",")}`;
    if (!templateClasses.has(key)) {
      templateClasses.set(key, {
        surfaceKind: kindOf(cell),
        actionIds,
        surfaces: new Set(),
        rows: new Set(),
      });
    }
    templateClasses.get(key).surfaces.add(cell);
    templateClasses.get(key).rows.add(recipe.fixtureId);
  }
}

function familyBreakdown(family) {
  const touches = (recipe) => rowInScope(recipe) && familiesOf(recipe).has(family);
  const familyCells = new Set(
    [...cells].filter((cell) => cellRows.get(cell).some(touches)),
  );
  const familyClean = new Set([...familyCells].filter((cell) => !poisoned.has(cell)));
  const rows = new Set();
  const familySurfaces = new Set();
  const classes = new Set();
  for (const cell of familyClean) {
    for (const recipe of cellRows.get(cell)) {
      if (recipe.status !== "unresolved" || !touches(recipe)) continue;
      rows.add(recipe.fixtureId);
      familySurfaces.add(cell);
      classes.add(`${kindOf(cell)}|${[...(recipe.actionIds ?? [])].sort().join(",")}`);
    }
  }
  return {
    cells: familyCells.size,
    cleanCells: familyClean.size,
    poisonedCells: familyCells.size - familyClean.size,
    authorableRows: rows.size,
    surfaces: familySurfaces.size,
    templateClasses: classes.size,
  };
}

const laneCells = Object.fromEntries(
  Object.keys(LANE_REASONS).map((lane) => [
    lane,
    [...poisonedLanes.values()].filter((lanes) => lanes.has(lane)).length,
  ]),
);

const figures = {
  cells: cells.size,
  cleanCells: clean.size,
  poisonedCells: poisoned.size,
  authorableRows: authorableRows.size,
  surfaces: surfaces.size,
  templateClasses: templateClasses.size,
};
const figureByAssertName = {
  cells: figures.cells,
  "clean-cells": figures.cleanCells,
  "poisoned-cells": figures.poisonedCells,
  "clean-unresolved": figures.authorableRows,
  surfaces: figures.surfaces,
  "template-classes": figures.templateClasses,
};

const assertions = args.assertions.map(({ figure, expected }) => ({
  figure,
  expected,
  actual: figureByAssertName[figure],
  pass: figureByAssertName[figure] === expected,
}));
const passed = assertions.every((assertion) => assertion.pass);

// ------------------------------------------------------------------ report

const report = {
  schema: "ibex/llp-evidence/scope-measurement/1",
  measurement: "capsec-scope-measurement",
  gate: "LLP 0049 §3 rule 5",
  tool: "scripts/capsec-scope-measurement.mjs",
  catalog: {
    path: args.catalog,
    digest: catalog.recipeCatalogDigest,
    target: catalog.target ?? null,
    requiredFixtures: catalog.summary?.requiredFixtures ?? catalog.recipes.length,
  },
  families: args.familyList,
  definitions: {
    source: "LLP 0044 §9 (day-one scope measurement), replicated exactly",
    cell: "one edgeId",
    rowInScope:
      "actionId families (prefix before ':') non-empty and all within the selected family set",
    cellInScope: "at least one row of any status is in scope",
    poisonedCell:
      "any unresolved row of the cell carries a Lane B/C/D residual reason",
    laneReasons: LANE_REASONS,
    authorableRows: "unresolved in-scope rows on clean cells, counted by fixtureId",
    surfaces: "clean cells carrying at least one authorable row",
    templateClass: "(surface-kind × exact row action set) over authorable rows",
  },
  ...figures,
  poisonedCellsByLane: laneCells,
  perFamily: Object.fromEntries(
    args.familyList.map((family) => [family, familyBreakdown(family)]),
  ),
  templateClassBreakdown: [...templateClasses.values()]
    .map((templateClass) => ({
      surfaceKind: templateClass.surfaceKind,
      actionIds: templateClass.actionIds,
      surfaces: templateClass.surfaces.size,
      rows: templateClass.rows.size,
    }))
    .sort(
      (a, b) =>
        b.rows - a.rows ||
        a.surfaceKind.localeCompare(b.surfaceKind) ||
        a.actionIds.join(",").localeCompare(b.actionIds.join(",")),
    ),
  assertions,
  result: passed ? "PASS" : "FAIL",
};

if (args.output) writeFileSync(args.output, `${JSON.stringify(report, null, 1)}\n`);

process.stderr.write(
  [
    `LLP 0049 §3 rule 5 scope measurement — ${report.result}`,
    `  catalog ${report.catalog.digest} (${report.catalog.requiredFixtures} rows)`,
    `  families: ${args.familyList.join(", ")}`,
    `  cells: ${figures.cells} (${figures.cleanCells} clean, ${figures.poisonedCells} poisoned; lanes ${JSON.stringify(laneCells)})`,
    `  authorable rows: ${figures.authorableRows} across ${figures.surfaces} surfaces in ${figures.templateClasses} template classes`,
    ...args.familyList.map(
      (family) =>
        `    ${family}: ${JSON.stringify(report.perFamily[family])}`,
    ),
    ...(assertions.length
      ? assertions.map(
          (assertion) =>
            `  assert ${assertion.figure}=${assertion.expected}: ${assertion.pass ? "PASS" : `FAIL (actual ${assertion.actual})`}`,
        )
      : []),
    "",
  ].join("\n"),
);

if (!args.output) process.stdout.write(`${JSON.stringify(report, null, 1)}\n`);
process.exit(passed ? 0 : 1);
