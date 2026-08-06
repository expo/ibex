// Checks for the LLP 0049 §3 rule 7 terminal-evidence gate.
//
// The instrument exists because a falling Lane B count can be produced by a
// confident misattribution: a terminal quietly gained or lost on a cell whose
// residual labels never move. Every test here is written against silent
// passes — the gate must FAIL on any per-cell terminal-set delta nobody
// declared, in both directions, and must NOT fail on the one thing it is
// deliberately blind to: a terminal moving between two recipes of the same
// cell, which leaves the cell's unioned set unchanged.
//
// @ref LLP 0049#3-construction-rules — rule 7: the `8cf677e7` method as a
// standing tool; symmetric, whole-catalog, per-edgeId unions.

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

const TOOL = fileURLToPath(new URL("./capsec-terminal-evidence-diff.mjs", import.meta.url));
const workDir = mkdtempSync(join(tmpdir(), "capsec-terminal-gate-"));

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
    recipes,
  };
}

function recipe(overrides = {}) {
  return {
    fixtureId: "fixture.a",
    edgeIds: ["surface.builtin.export.node.fs.readfile.aaaaaaa"],
    actionIds: ["fs:read"],
    terminalObservedKey: "builtin:export:node_fs:readFile",
    residualReasons: [],
    route: {
      surfaceObservedKeys: ["builtin:export:node_fs:readFile"],
      alternatives: [
        {
          terminalObservedKey: "native-op:__exactReadFile",
          proofPaths: ["export:readFile -> __exactReadFile"],
        },
      ],
      ambiguousCallees: [],
    },
    ...overrides,
  };
}

function runGate({ baseline, candidate, allowList }) {
  const argv = ["--baseline", baseline, "--candidate", candidate];
  if (allowList) argv.push("--allow-list", allowList);
  const result = spawnSync(process.execPath, [TOOL, ...argv], { encoding: "utf8" });
  return {
    status: result.status,
    stderr: result.stderr,
    report: result.stdout.trim() ? JSON.parse(result.stdout) : null,
  };
}

test("identical catalogs pass with no allow-list", () => {
  const path = writeJson(catalog([recipe()]));
  const run = runGate({ baseline: path, candidate: path });
  assert.equal(run.status, 0);
  assert.equal(run.report.result, "PASS");
  assert.equal(run.report.deltaCount, 0);
});

test("an undeclared terminal ADDITION on a cell fails", () => {
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(
    catalog([
      recipe({
        route: {
          ...recipe().route,
          alternatives: [
            ...recipe().route.alternatives,
            { terminalObservedKey: "native-op:__exactInjected", proofPaths: ["x"] },
          ],
        },
      }),
    ]),
  );
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplainedCount, 1);
  assert.equal(run.report.unexplained[0].direction, "added");
  assert.equal(run.report.unexplained[0].field, "route.alternatives.terminalObservedKey");
  assert.equal(run.report.unexplained[0].value, "native-op:__exactInjected");
});

test("an undeclared terminal REMOVAL fails symmetrically", () => {
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(
    catalog([recipe({ route: { ...recipe().route, alternatives: [] } })]),
  );
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplainedCount, 1);
  assert.equal(run.report.unexplained[0].direction, "removed");
  assert.equal(run.report.unexplained[0].value, "native-op:__exactReadFile");
});

test("a terminal moving between recipes of the SAME cell is no delta — the union is the unit", () => {
  const before = writeJson(
    catalog([
      recipe(),
      recipe({
        fixtureId: "fixture.b",
        route: { ...recipe().route, alternatives: [] },
      }),
    ]),
  );
  const after = writeJson(
    catalog([
      recipe({ route: { ...recipe().route, alternatives: [] } }),
      recipe({ fixtureId: "fixture.b" }),
    ]),
  );
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 0);
  assert.equal(run.report.deltaCount, 0);
});

test("a declared delta with a source span and proof passes", () => {
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(
    catalog([recipe({ route: { ...recipe().route, alternatives: [] } })]),
  );
  const allowList = writeJson({
    entries: [
      {
        edgeId: "surface.builtin.export.node.fs.readfile.aaaaaaa",
        field: "route.alternatives.terminalObservedKey",
        direction: "removed",
        value: "native-op:__exactReadFile",
        sourceSpan: "src/builtins/fs.js:10-20",
        proof: "misattributed callback argument; real terminal retained on readFileSync",
      },
    ],
  });
  const run = runGate({ baseline: before, candidate: after, allowList });
  assert.equal(run.status, 0);
  assert.equal(run.report.result, "PASS");
  assert.equal(run.report.explainedCount, 1);
});

test("an allow-list entry that never matched is STALE and fails", () => {
  const path = writeJson(catalog([recipe()]));
  const allowList = writeJson({
    entries: [
      {
        edgeId: "surface.builtin.export.node.fs.readfile.aaaaaaa",
        field: "route.alternatives.terminalObservedKey",
        direction: "removed",
        value: "a delta that never happened",
        sourceSpan: "x:1",
        proof: "y",
      },
    ],
  });
  const run = runGate({ baseline: path, candidate: path, allowList });
  assert.equal(run.status, 1);
  assert.equal(run.report.staleEntryCount, 1);
});

test("an allow-list entry may not omit its proof", () => {
  const path = writeJson(catalog([recipe()]));
  const allowList = writeJson({
    entries: [
      {
        edgeId: "e",
        field: "terminalObservedKey",
        direction: "removed",
        value: "v",
        sourceSpan: "s",
      },
    ],
  });
  const run = runGate({ baseline: path, candidate: path, allowList });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /`proof` is required/u);
});

test("an edgeId APPEARING is a delta and fails undeclared", () => {
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(
    catalog([
      recipe(),
      recipe({
        fixtureId: "fixture.b",
        edgeIds: ["surface.builtin.export.node.fs.writefile.bbbbbbb"],
      }),
    ]),
  );
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplained[0].field, "<cell>");
  assert.equal(run.report.unexplained[0].direction, "added");
  assert.equal(
    run.report.unexplained[0].cell,
    "surface.builtin.export.node.fs.writefile.bbbbbbb",
  );
});

test("an edgeId DISAPPEARING is a delta, fails undeclared, and passes declared", () => {
  const before = writeJson(
    catalog([
      recipe(),
      recipe({
        fixtureId: "fixture.b",
        edgeIds: ["surface.builtin.export.node.fs.writefile.bbbbbbb"],
      }),
    ]),
  );
  const after = writeJson(catalog([recipe()]));
  const undeclared = runGate({ baseline: before, candidate: after });
  assert.equal(undeclared.status, 1);
  assert.equal(undeclared.report.unexplained[0].field, "<cell>");
  assert.equal(undeclared.report.unexplained[0].direction, "removed");

  const allowList = writeJson({
    entries: [
      {
        edgeId: "surface.builtin.export.node.fs.writefile.bbbbbbb",
        field: "<cell>",
        direction: "removed",
        value: "surface.builtin.export.node.fs.writefile.bbbbbbb",
        sourceSpan: "packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs:100",
        proof: "exact alias of node.fs.writeFileSync de-duplicated per LLP 0049 §4.1",
      },
    ],
  });
  const declared = runGate({ baseline: before, candidate: after, allowList });
  assert.equal(declared.status, 0);
});

test("an entry covering one cell does not license the same delta on another cell", () => {
  const other = {
    fixtureId: "fixture.b",
    edgeIds: ["surface.builtin.export.node.fs.writefile.bbbbbbb"],
  };
  const before = writeJson(catalog([recipe(), recipe(other)]));
  const after = writeJson(
    catalog([
      recipe({ route: { ...recipe().route, alternatives: [] } }),
      recipe({ ...other, route: { ...recipe().route, alternatives: [] } }),
    ]),
  );
  const allowList = writeJson({
    entries: [
      {
        edgeId: "surface.builtin.export.node.fs.readfile.aaaaaaa",
        field: "route.alternatives.terminalObservedKey",
        direction: "removed",
        value: "native-op:__exactReadFile",
        sourceSpan: "src/builtins/fs.js:10-20",
        proof: "attribution fix",
      },
    ],
  });
  const run = runGate({ baseline: before, candidate: after, allowList });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplainedCount, 1);
  assert.match(run.report.unexplained[0].cell, /writefile/u);
});

test("edgeIdPrefix licenses a family without licensing the rest of the catalog", () => {
  const other = {
    fixtureId: "fixture.b",
    edgeIds: ["surface.builtin.export.node.http.request.ccccccc"],
  };
  const before = writeJson(catalog([recipe(), recipe(other)]));
  const after = writeJson(
    catalog([
      recipe({ route: { ...recipe().route, alternatives: [] } }),
      recipe({ ...other, route: { ...recipe().route, alternatives: [] } }),
    ]),
  );
  const allowList = writeJson({
    entries: [
      {
        edgeIdPrefix: "surface.builtin.export.node.fs.",
        field: "route.alternatives.terminalObservedKey",
        direction: "removed",
        value: "native-op:__exactReadFile",
        sourceSpan: "src/builtins/fs.js:10-20",
        proof: "attribution fix",
      },
    ],
  });
  const run = runGate({ baseline: before, candidate: after, allowList });
  assert.equal(run.status, 1, "the http cell is outside the licensed prefix");
  assert.equal(run.report.unexplainedCount, 1);
  assert.match(run.report.unexplained[0].cell, /node\.http/u);
});

test("a NEW route-evidence field is gated on arrival, not ignored", () => {
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(
    catalog([
      recipe({
        route: { ...recipe().route, conditionalTerminals: ["__exactHook:net"] },
      }),
    ]),
  );
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplained[0].field, "route.conditionalTerminals");
});

test("the whole-catalog default covers non-network families — there is no scope flag", () => {
  const envRecipe = recipe({
    fixtureId: "fixture.env",
    edgeIds: ["surface.native.op.exact.setenv.ddddddd"],
    actionIds: ["env:write"],
    terminalObservedKey: "native-op:__exactSetEnv",
    route: {
      surfaceObservedKeys: ["native-op:__exactSetEnv"],
      alternatives: [],
      ambiguousCallees: [],
    },
  });
  const before = writeJson(catalog([recipe(), envRecipe]));
  const after = writeJson(
    catalog([
      recipe(),
      {
        ...envRecipe,
        terminalObservedKey: "native-op:__exactSetEnvRenamed",
      },
    ]),
  );
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 1);
  const fields = run.report.unexplained.map((delta) => delta.field);
  assert.ok(fields.includes("terminalObservedKey"));
  const cells = run.report.unexplained.map((delta) => delta.cell);
  assert.ok(cells.every((cell) => cell === "surface.native.op.exact.setenv.ddddddd"));
});
