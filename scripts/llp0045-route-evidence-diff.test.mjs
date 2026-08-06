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
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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

// --------------------------------------------------------------------------
// Strict mode (LLP 0049 §3 rule 3 — advance declaration). The candidate
// catalog may carry `declaredAllowListDigest`, embedded by the generator's
// `--declared-allow-list` flag BEFORE candidate generation. Precedence rules
// under test, mirroring the tool's comments:
//   * strict mode is opt-in via that embedded field, never inferred;
//   * in strict mode --allow-list is REQUIRED and must hash to the digest;
//   * a present `proofKind` is validated in every mode;
//   * proofKind is REQUIRED for `MASKED, NOT NEW` proofs only in strict mode,
//     so the archived pre-proofKind worked example keeps passing as-is.

const fileDigest = (path) =>
  `sha256-${createHash("sha256").update(readFileSync(path)).digest("base64url")}`;

const REMOVAL_ENTRY = {
  edgeId: "surface.builtin.export.node.dns.promises.resolve4.aaaaaaa",
  field: "route.ambiguousCallees",
  direction: "removed",
  value: "cross-source-export-projection:node_dns",
  sourceSpan: "src/builtins/dns-promises.js:1-10",
  proof: "authenticated projection join to node_dns",
};

// A baseline/candidate pair whose only change is REMOVAL_ENTRY's removal; the
// candidate carries the declared digest of `allowListPath`.
function strictScenario(allowListPath) {
  const before = writeJson(catalog([recipe()]));
  const candidateValue = catalog([
    recipe({ route: { ...recipe().route, ambiguousCallees: [] } }),
  ]);
  candidateValue.declaredAllowListDigest = fileDigest(allowListPath);
  const after = writeJson(candidateValue);
  return { before, after };
}

test("strict mode: the declared-and-matching allow-list passes", () => {
  const allowList = writeJson({ entries: [REMOVAL_ENTRY] });
  const { before, after } = strictScenario(allowList);
  const run = runGate({ baseline: before, candidate: after, allowList });
  assert.equal(run.status, 0);
  assert.equal(run.report.result, "PASS");
  assert.equal(run.report.strictMode, true);
  assert.equal(run.report.declaredAllowListDigest, fileDigest(allowList));
});

test("strict mode: a mismatched allow-list fails even if its content is otherwise valid", () => {
  const declared = writeJson({ entries: [REMOVAL_ENTRY] });
  const { before, after } = strictScenario(declared);
  // Same entries, different bytes (a re-authored file): must be rejected.
  const reauthored = writeJson({ note: "re-authored", entries: [REMOVAL_ENTRY] });
  const run = runGate({ baseline: before, candidate: after, allowList: reauthored });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /allow-list was not the one declared before generation/u);
});

test("strict mode: omitting --allow-list fails — a declared candidate cannot be surveyed into a pass", () => {
  const allowList = writeJson({ entries: [REMOVAL_ENTRY] });
  const { before, after } = strictScenario(allowList);
  const run = runGate({ baseline: before, candidate: after });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /strict mode.*--allow-list is required/u);
});

test("strict mode: an allow-list authored AFTER the diff cannot pass — the point of the mechanism", () => {
  // The declared list misses the change (it declares nothing). The diff runs,
  // the author sees the unexplained change, and writes a new allow-list that
  // covers it perfectly. In strict mode that post-diff list must still fail:
  // it is not the file whose digest was embedded before generation. The only
  // sanctioned path is fixing the declared list and REGENERATING.
  const declared = writeJson({ entries: [] });
  const { before, after } = strictScenario(declared);
  const postDiff = writeJson({ entries: [REMOVAL_ENTRY] });
  const run = runGate({ baseline: before, candidate: after, allowList: postDiff });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /allow-list was not the one declared before generation/u);
  // And the declared (matching) list does not pass either — the change it
  // failed to declare stays unexplained. Neither file passes: the gate forces
  // a regeneration against a corrected declaration.
  const honest = runGate({ baseline: before, candidate: after, allowList: declared });
  assert.equal(honest.status, 1);
  assert.equal(honest.report.unexplainedCount, 1);
});

test("an undeclared candidate is unchanged by strict mode: MASKED, NOT NEW without proofKind still passes", () => {
  const before = writeJson(catalog([recipe()]));
  const after = writeJson(
    catalog([
      recipe({
        route: { ...recipe().route, ambiguousCallees: [...recipe().route.ambiguousCallees, "unresolved-call:callback"] },
      }),
    ]),
  );
  const allowList = writeJson({
    entries: [
      {
        edgeId: "surface.builtin.export.node.dns.promises.resolve4.aaaaaaa",
        field: "route.ambiguousCallees",
        direction: "added",
        value: "unresolved-call:callback",
        sourceSpan: "src/builtins/dns.js:10 (the masking site)",
        proof: "MASKED, NOT NEW. The walker previously early-returned.",
      },
    ],
  });
  const run = runGate({ baseline: before, candidate: after, allowList });
  assert.equal(run.status, 0, "non-strict candidates keep pre-proofKind behavior");
});

test("strict mode: a MASKED, NOT NEW proof without proofKind fails", () => {
  const allowList = writeJson({
    entries: [
      {
        ...REMOVAL_ENTRY,
        direction: "added",
        proof: "MASKED, NOT NEW. Unmasked by the removal next door.",
      },
    ],
  });
  const { before, after } = strictScenario(allowList);
  const run = runGate({ baseline: before, candidate: after, allowList });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /carries no proofKind/u);
});

test("strict mode: a masked-not-new entry with proofKind, added direction, and a masking-site span passes", () => {
  const allowList = writeJson({
    entries: [
      REMOVAL_ENTRY,
      {
        edgeId: "surface.builtin.export.node.dns.promises.resolve4.aaaaaaa",
        field: "route.ambiguousCallees",
        direction: "added",
        value: "unresolved-call:callback",
        proofKind: "masked-not-new",
        sourceSpan: "src/builtins/dns-promises.js:7 (masking early-return removed at :1-10)",
        proof: "MASKED, NOT NEW. The projection join made the walker descend past the former early-return.",
      },
    ],
  });
  const before = writeJson(catalog([recipe()]));
  const candidateValue = catalog([
    recipe({
      route: {
        ...recipe().route,
        ambiguousCallees: ["unresolved-call:callback"],
      },
    }),
  ]);
  candidateValue.declaredAllowListDigest = fileDigest(allowList);
  const after = writeJson(candidateValue);
  const run = runGate({ baseline: before, candidate: after, allowList });
  assert.equal(run.status, 0);
  assert.equal(run.report.result, "PASS");
  assert.equal(run.report.explainedCount, 2);
});

test("proofKind on a non-added direction fails in ANY mode", () => {
  const path = writeJson(catalog([recipe()]));
  const allowList = writeJson({
    entries: [
      {
        ...REMOVAL_ENTRY,
        proofKind: "masked-not-new",
        proof: "MASKED, NOT NEW. But this entry is a removal.",
      },
    ],
  });
  const run = runGate({ baseline: path, candidate: path, allowList });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /valid only on direction "added"/u);
});

test("an unrecognized proofKind fails in ANY mode", () => {
  const path = writeJson(catalog([recipe()]));
  const allowList = writeJson({
    entries: [
      { ...REMOVAL_ENTRY, direction: "added", proofKind: "totally-new" },
    ],
  });
  const run = runGate({ baseline: path, candidate: path, allowList });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /unrecognized proofKind/u);
});

test("proofKind masked-not-new whose proof lacks the literal token fails in ANY mode", () => {
  const path = writeJson(catalog([recipe()]));
  const allowList = writeJson({
    entries: [
      {
        ...REMOVAL_ENTRY,
        direction: "added",
        proofKind: "masked-not-new",
        proof: "the walker descended further (vocabulary token missing)",
      },
    ],
  });
  const run = runGate({ baseline: path, candidate: path, allowList });
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /requires the proof text to carry the literal token/u);
});

test("the archived worked example passes EXACTLY as-is against an undeclared candidate", () => {
  // llp/evidence/0045-allow-list-duplicate-definition-hygiene.json predates
  // proofKind and carries three literal MASKED, NOT NEW proofs. Its continued
  // validity is a stated constraint of the strict-mode precedence rules:
  // proofKind is required only when the candidate declares an allow-list
  // digest. Reconstruct a minimal baseline/candidate pair realizing exactly
  // the file's declared changes and run the gate with the file, unmodified.
  const examplePath = fileURLToPath(
    new URL(
      "../llp/evidence/0045-allow-list-duplicate-definition-hygiene.json",
      import.meta.url,
    ),
  );
  const example = JSON.parse(readFileSync(examplePath, "utf8"));
  const recipes = example.entries.map((entry, index) => {
    const cell = entry.edgeId ?? `${entry.edgeIdPrefix}.0abcdef`;
    const base = {
      fixtureId: `fixture.${index}`,
      edgeIds: [cell],
      actionIds: ["network:connect"],
      residualReasons: ["no-static-enforcement-terminal"],
      route: { surfaceObservedKeys: ["k"], ambiguousCallees: [] },
    };
    const withValue = (target) => {
      const copy = structuredClone(base);
      if (entry.field === "route.ambiguousCallees") {
        copy.route.ambiguousCallees = [entry.value];
      } else if (entry.field === "residualReasons") {
        copy.residualReasons = [...copy.residualReasons, entry.value];
      } else {
        throw new Error(`unhandled field in worked example: ${entry.field}`);
      }
      return copy;
    };
    return entry.direction === "removed"
      ? { baseline: withValue(), candidate: base }
      : { baseline: base, candidate: withValue() };
  });
  const before = writeJson(catalog(recipes.map(({ baseline }) => baseline)));
  const after = writeJson(catalog(recipes.map(({ candidate }) => candidate)));
  const run = runGate({
    baseline: before,
    candidate: after,
    allowList: examplePath,
    scope: "all",
  });
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.report.result, "PASS");
  assert.equal(run.report.strictMode, false);
  assert.equal(run.report.explainedCount, example.entries.length);
  assert.equal(run.report.staleEntryCount, 0);
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
