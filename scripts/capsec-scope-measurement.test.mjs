// Checks for the LLP 0049 §3 rule 5 scope-measurement instrument.
//
// The figures this tool emits are the denominators every phase gate quotes;
// a definition that drifts from LLP 0044 §9's measurement silently re-cuts
// the campaign. So these tests pin the definitions, not just the arithmetic:
// row-level family membership (a mixed-family row pulls no cell in), cell
// poisoning by each Lane B/C/D reason separately, template-class grouping by
// (surface-kind × exact row action set), and the --assert exit-gate mode.
//
// @ref LLP 0049#3-construction-rules — rule 5: denominators re-derived at
// every phase boundary by this tool; validated against the 2026-08-05
// figures in issues/20260728-capsec-public-surface-evidence-backlog.md.

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

const TOOL = fileURLToPath(new URL("./capsec-scope-measurement.mjs", import.meta.url));
const workDir = mkdtempSync(join(tmpdir(), "capsec-scope-measurement-"));

let sequence = 0;
function writeJson(value) {
  sequence += 1;
  const path = join(workDir, `fixture-${sequence}.json`);
  writeFileSync(path, JSON.stringify(value));
  return path;
}

function catalog(recipes) {
  return {
    recipeCatalogDigest: "sha256-test",
    target: "test-target",
    summary: { requiredFixtures: recipes.length },
    recipes,
  };
}

function recipe(overrides = {}) {
  return {
    fixtureId: "fixture.a",
    edgeIds: ["surface.builtin.export.node.fs.readfile.aaaaaaa"],
    actionIds: ["fs:read"],
    status: "unresolved",
    residualReasons: ["public-surface-invocation-not-authored"],
    ...overrides,
  };
}

function runTool({ catalog: catalogPath, families, asserts = [] }) {
  const argv = ["--catalog", catalogPath, "--families", families];
  for (const assertion of asserts) argv.push("--assert", assertion);
  const result = spawnSync(process.execPath, [TOOL, ...argv], { encoding: "utf8" });
  return {
    status: result.status,
    stderr: result.stderr,
    report: result.stdout.trim() ? JSON.parse(result.stdout) : null,
  };
}

test("family selection is row-level subset: fs rows count, network and mixed-family rows do not", () => {
  const path = writeJson(
    catalog([
      recipe(),
      recipe({
        fixtureId: "fixture.net",
        edgeIds: ["surface.builtin.export.node.net.connect.bbbbbbb"],
        actionIds: ["network:connect"],
      }),
      // A cell whose only rows mix a selected family with an unselected one
      // is NOT in scope: none of its rows is authorable under this scope.
      recipe({
        fixtureId: "fixture.mixed",
        edgeIds: ["surface.builtin.export.node.fs.watchpipe.ccccccc"],
        actionIds: ["fs:watch", "network:connect"],
      }),
    ]),
  );
  const run = runTool({ catalog: path, families: "fs,env,process" });
  assert.equal(run.status, 0);
  assert.equal(run.report.schema, "ibex/llp-evidence/scope-measurement/1");
  assert.equal(run.report.cells, 1);
  assert.equal(run.report.cleanCells, 1);
  assert.equal(run.report.authorableRows, 1);
  assert.equal(run.report.surfaces, 1);
  assert.deepEqual(run.report.families, ["env", "fs", "process"]);
});

test("a mixed-family row on an otherwise in-scope cell is excluded from authorable rows but still poisons", () => {
  const path = writeJson(
    catalog([
      recipe(),
      // Same cell: an out-of-scope row carrying a lane reason still poisons
      // the cell — poisoning looks at every unresolved row, not just the
      // in-scope ones.
      recipe({
        fixtureId: "fixture.a.lane",
        actionIds: ["fs:read", "network:connect"],
        residualReasons: ["no-static-enforcement-terminal"],
      }),
    ]),
  );
  const run = runTool({ catalog: path, families: "fs,env,process" });
  assert.equal(run.report.cells, 1);
  assert.equal(run.report.poisonedCells, 1);
  assert.equal(run.report.cleanCells, 0);
  assert.equal(run.report.authorableRows, 0);
});

for (const [lane, reason] of [
  ["B", "no-static-enforcement-terminal"],
  ["C", "native-public-source-invocation-unavailable"],
  ["D", "builtin-export-resolves-to-bootstrap-internal"],
]) {
  test(`a Lane ${lane} residual reason (${reason}) poisons its cell`, () => {
    const path = writeJson(
      catalog([
        recipe(),
        recipe({
          fixtureId: "fixture.poisoned",
          edgeIds: ["surface.builtin.export.node.fs.opendir.dddddgd"],
          residualReasons: [reason],
        }),
      ]),
    );
    const run = runTool({ catalog: path, families: "fs" });
    assert.equal(run.report.cells, 2);
    assert.equal(run.report.cleanCells, 1);
    assert.equal(run.report.poisonedCells, 1);
    assert.equal(run.report.poisonedCellsByLane[lane], 1);
    // The poisoned cell's rows are not authorable.
    assert.equal(run.report.authorableRows, 1);
  });
}

test("a lane reason on a RESOLVED row does not poison — only unresolved rows count", () => {
  const path = writeJson(
    catalog([
      recipe(),
      recipe({
        fixtureId: "fixture.resolved",
        status: "fully-executable",
        residualReasons: ["no-static-enforcement-terminal"],
      }),
    ]),
  );
  const run = runTool({ catalog: path, families: "fs" });
  assert.equal(run.report.poisonedCells, 0);
  assert.equal(run.report.cleanCells, 1);
});

test("template classes group by (surface-kind × exact row action set)", () => {
  const path = writeJson(
    catalog([
      recipe(),
      // Same kind, same action set, different surface: same class.
      recipe({
        fixtureId: "fixture.b",
        edgeIds: ["surface.builtin.export.node.fs.readlink.bbbbbbb"],
      }),
      // Same kind, different exact action set: new class.
      recipe({
        fixtureId: "fixture.c",
        edgeIds: ["surface.builtin.export.node.fs.writefile.ccccccc"],
        actionIds: ["fs:read", "fs:write"],
      }),
      // Different kind, same action set: new class.
      recipe({
        fixtureId: "fixture.d",
        edgeIds: ["surface.native.op.exact.readfile.ddddddd"],
      }),
    ]),
  );
  const run = runTool({ catalog: path, families: "fs" });
  assert.equal(run.report.templateClasses, 3);
  assert.equal(run.report.surfaces, 4);
  const classes = run.report.templateClassBreakdown;
  assert.deepEqual(
    classes.map((templateClass) => [templateClass.surfaceKind, templateClass.actionIds.join("+"), templateClass.surfaces]),
    [
      ["surface.builtin.export", "fs:read", 2],
      ["surface.builtin.export", "fs:read+fs:write", 1],
      ["surface.native.op", "fs:read", 1],
    ],
  );
});

test("a row with several edgeIds counts once in authorable rows but per-cell in surfaces", () => {
  const path = writeJson(
    catalog([
      recipe({
        edgeIds: [
          "surface.builtin.export.node.fs.readfile.aaaaaaa",
          "surface.builtin.export.node.fs.readfilesync.bbbbbbb",
        ],
      }),
    ]),
  );
  const run = runTool({ catalog: path, families: "fs" });
  assert.equal(run.report.cells, 2);
  assert.equal(run.report.authorableRows, 1);
  assert.equal(run.report.surfaces, 2);
});

test("per-family breakdown attributes cells and rows to each family they touch", () => {
  const path = writeJson(
    catalog([
      recipe(),
      recipe({
        fixtureId: "fixture.env",
        edgeIds: ["surface.native.op.exact.setenv.eeeeeee"],
        actionIds: ["env:write"],
      }),
      recipe({
        fixtureId: "fixture.both",
        edgeIds: ["surface.builtin.export.node.process.chdir.fffffff"],
        actionIds: ["env:read", "fs:list"],
      }),
    ]),
  );
  const run = runTool({ catalog: path, families: "fs,env" });
  assert.equal(run.report.cells, 3);
  assert.equal(run.report.perFamily.fs.cells, 2);
  assert.equal(run.report.perFamily.env.cells, 2);
  assert.equal(run.report.perFamily.fs.authorableRows, 2);
  assert.equal(run.report.perFamily.env.authorableRows, 2);
});

test("--assert clean-unresolved=0 passes only when no authorable rows remain", () => {
  const done = writeJson(
    catalog([recipe({ status: "fully-executable", residualReasons: [] })]),
  );
  const passing = runTool({
    catalog: done,
    families: "fs,env,process",
    asserts: ["clean-unresolved=0"],
  });
  assert.equal(passing.status, 0);
  assert.equal(passing.report.result, "PASS");
  assert.equal(passing.report.assertions[0].pass, true);

  const open = writeJson(catalog([recipe()]));
  const failing = runTool({
    catalog: open,
    families: "fs,env,process",
    asserts: ["clean-unresolved=0"],
  });
  assert.equal(failing.status, 1);
  assert.equal(failing.report.result, "FAIL");
  assert.deepEqual(failing.report.assertions[0], {
    figure: "clean-unresolved",
    expected: 0,
    actual: 1,
    pass: false,
  });
});

test("--assert accepts every headline figure and rejects unknown ones", () => {
  const path = writeJson(catalog([recipe()]));
  const run = runTool({
    catalog: path,
    families: "fs",
    asserts: [
      "cells=1",
      "clean-cells=1",
      "poisoned-cells=0",
      "clean-unresolved=1",
      "surfaces=1",
      "template-classes=1",
    ],
  });
  assert.equal(run.status, 0);
  assert.equal(run.report.assertions.length, 6);

  const bad = runTool({ catalog: path, families: "fs", asserts: ["rows=1"] });
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /--assert must be/u);
});
