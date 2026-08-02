// Checks for the LLP 0045 §3 route-evidence gate.
//
// The gate's whole value is that it FAILS on a change nobody declared. A gate
// that silently passes is worse than no gate, because it launders an
// unreviewed route-provenance change as a reviewed one — so every test here is
// written against that failure mode, not against the happy path.
//
// @ref LLP 0045#3-acceptance-criteria-what-the-count-fell-is-not — the pairing must be symmetric across
// fields and directions; the "additive-only" rule these tests replaced forbade
// step 2's own resolutions, which legitimately retire ambiguity entries.

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

const TOOL = fileURLToPath(new URL("./llp0045-route-evidence-diff.mjs", import.meta.url));
const workDir = mkdtempSync(join(tmpdir(), "llp0045-gate-"));

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
    edgeIds: ["surface.builtin.export.node.dns.promises.resolve4.aaaaaaa"],
    actionIds: ["network:resolve"],
    residualReasons: ["no-static-enforcement-terminal"],
    route: {
      surfaceObservedKeys: ["builtin:export:node_dns:promises.resolve4"],
      alternatives: [],
      ambiguousCallees: ["cross-source-export-projection:node_dns"],
    },
    ...overrides,
  };
}

function runGate({ baseline, candidate, allowList, scope }) {
  const argv = ["--baseline", baseline, "--candidate", candidate];
  if (allowList) argv.push("--allow-list", allowList);
  if (scope) argv.push("--scope", scope);
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
  assert.equal(run.report.changeCount, 0);
});

test("an undeclared ambiguity REMOVAL fails — the direction 'additive-only' would have missed", () => {
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(
    catalog([recipe({ route: { ...recipe().route, ambiguousCallees: [] } })]),
  );
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplainedCount, 1);
  assert.equal(run.report.unexplained[0].direction, "removed");
  assert.equal(run.report.unexplained[0].field, "route.ambiguousCallees");
});

test("an undeclared terminal ADDITION fails", () => {
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(
    catalog([
      recipe({
        route: {
          ...recipe().route,
          surfaceObservedKeys: ["builtin:export:node_dns:promises.resolve4", "injected"],
        },
      }),
    ]),
  );
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplained[0].value, "injected");
});

test("a declared change with a source span and proof passes", () => {
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(
    catalog([recipe({ route: { ...recipe().route, ambiguousCallees: [] } })]),
  );
  const allowList = writeJson({
    entries: [
      {
        edgeId: "surface.builtin.export.node.dns.promises.resolve4.aaaaaaa",
        field: "route.ambiguousCallees",
        direction: "removed",
        value: "cross-source-export-projection:node_dns",
        sourceSpan: "src/builtins/dns-promises.js:1-10",
        proof: "authenticated projection join to node_dns",
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
        edgeId: "surface.builtin.export.node.dns.promises.resolve4.aaaaaaa",
        field: "route.ambiguousCallees",
        direction: "removed",
        value: "a change that never happened",
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
        field: "route.ambiguousCallees",
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

test("an entry covering one cell does not license the same change on another cell", () => {
  const other = { fixtureId: "fixture.b", edgeIds: ["surface.builtin.export.node.dns.promises.resolve6.bbbbbbb"] };
  const before = writeJson(catalog([recipe(), recipe(other)]));
  const after = writeJson(
    catalog([
      recipe({ route: { ...recipe().route, ambiguousCallees: [] } }),
      recipe({ ...other, route: { ...recipe().route, ambiguousCallees: [] } }),
    ]),
  );
  const allowList = writeJson({
    entries: [
      {
        edgeId: "surface.builtin.export.node.dns.promises.resolve4.aaaaaaa",
        field: "route.ambiguousCallees",
        direction: "removed",
        value: "cross-source-export-projection:node_dns",
        sourceSpan: "src/builtins/dns-promises.js:1-10",
        proof: "join",
      },
    ],
  });
  const run = runGate({ baseline: before, candidate: after, allowList });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplainedCount, 1);
  assert.match(run.report.unexplained[0].cell, /resolve6/u);
});

test("edgeIdPrefix licenses a family without licensing the rest of the catalog", () => {
  const other = {
    fixtureId: "fixture.b",
    edgeIds: ["surface.builtin.export.node.http.request.bbbbbbb"],
  };
  const before = writeJson(catalog([recipe(), recipe(other)]));
  const after = writeJson(
    catalog([
      recipe({ route: { ...recipe().route, ambiguousCallees: [] } }),
      recipe({ ...other, route: { ...recipe().route, ambiguousCallees: [] } }),
    ]),
  );
  const allowList = writeJson({
    entries: [
      {
        edgeIdPrefix: "surface.builtin.export.node.dns.",
        field: "route.ambiguousCallees",
        direction: "removed",
        value: "cross-source-export-projection:node_dns",
        sourceSpan: "src/builtins/dns-promises.js:1-10",
        proof: "join",
      },
    ],
  });
  const run = runGate({ baseline: before, candidate: after, allowList });
  assert.equal(run.status, 1, "the http cell is outside the licensed prefix");
  assert.equal(run.report.unexplainedCount, 1);
  assert.match(run.report.unexplained[0].cell, /node\.http/u);
});

test("a residual reason that vanishes without a route change still fails", () => {
  // This is the §3 failure mode by name: "a bug that suppresses ambiguity or
  // records a merely-possible terminal also makes the count fall."
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(catalog([recipe({ residualReasons: [] })]));
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplained[0].field, "residualReasons");
  assert.equal(run.report.derived.laneCellsAfter.B, 0);
  assert.equal(run.report.derived.laneCellsBefore.B, 1);
});

test("a whole recipe appearing or vanishing is a change", () => {
  const before = writeJson(catalog([recipe(), recipe({ fixtureId: "fixture.b" })]));
  const after = writeJson(catalog([recipe()]));
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplained[0].field, "<recipe>");
  assert.equal(run.report.unexplained[0].direction, "removed");
});

test("a NEW route-evidence field is gated on arrival, not ignored", () => {
  // Step 0 requires `enforcementRouteEvidence` to gain a representation for the
  // conditional alias shape. A gate hard-coded to today's three fields would
  // wave that through.
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

test("a duplicated entry appearing is a change even though the value set is unchanged", () => {
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(
    catalog([
      recipe({
        route: {
          ...recipe().route,
          ambiguousCallees: [
            "cross-source-export-projection:node_dns",
            "cross-source-export-projection:node_dns",
          ],
        },
      }),
    ]),
  );
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 1);
  assert.equal(run.report.unexplainedCount, 1);
  assert.equal(run.report.unexplained[0].direction, "added");
});

test("non-network movement is invisible at --scope network and caught at --scope all", () => {
  const fsRecipe = recipe({
    fixtureId: "fixture.fs",
    edgeIds: ["surface.builtin.export.node.fs.readfile.ccccccc"],
    actionIds: ["fs:read"],
  });
  const before = writeJson(catalog([recipe(), fsRecipe]));
  const after = writeJson(
    catalog([
      recipe(),
      { ...fsRecipe, route: { ...fsRecipe.route, ambiguousCallees: [] } },
    ]),
  );
  assert.equal(runGate({ baseline: before, candidate: after }).status, 0);
  const wide = runGate({ baseline: before, candidate: after, scope: "all" });
  assert.equal(wide.status, 1);
  assert.match(wide.report.unexplained[0].cell, /node\.fs/u);
});

test("the whole-catalog residual delta reports collateral movement even at --scope network", () => {
  const fsRecipe = recipe({
    fixtureId: "fixture.fs",
    edgeIds: ["surface.builtin.export.node.fs.readfile.ccccccc"],
    actionIds: ["fs:read"],
  });
  const before = writeJson(catalog([recipe(), fsRecipe]));
  const after = writeJson(catalog([recipe(), { ...fsRecipe, residualReasons: [] }]));
  const run = runGate({ baseline: before, candidate: after });
  assert.equal(run.status, 0, "out of gated scope");
  assert.equal(
    run.report.derived.residualReasonDeltaWholeCatalog["no-static-enforcement-terminal"],
    -1,
    "but the reviewer is still told it moved",
  );
});
