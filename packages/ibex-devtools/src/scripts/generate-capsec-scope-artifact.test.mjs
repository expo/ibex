import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../../../../scripts/portable-engine-contract.mjs";
import {
  SCOPE_OUTPUT_FILES,
  writeOrCheckScopeArtifacts,
} from "./generate-capsec-scope-artifact.mjs";

function artifacts() {
  return {
    scope: { scopeSchema: "ibex/capsec-scope/1", scopeDigest: "fixture" },
    expansionDiff: {
      scopeExpansionDiffSchema: "ibex/capsec-scope-expansion-diff/1",
      scopeExpansionDiffDigest: "fixture",
    },
    cellMapping: {
      scopeCellMappingSchema: "ibex/capsec-scope-cell-mapping/1",
      scopeCellMappingDigest: "fixture",
    },
  };
}

test("write/check emits exactly three canonical, untracked output members", () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-scope-output-"));
  const expected = artifacts();
  const written = writeOrCheckScopeArtifacts({
    artifacts: expected,
    outputDir,
    mode: "write",
  });
  assert.deepEqual(
    written.map(({ path: outputPath }) => path.basename(outputPath)).sort(),
    Object.values(SCOPE_OUTPUT_FILES).sort(),
  );
  for (const [key, filename] of Object.entries(SCOPE_OUTPUT_FILES)) {
    assert.equal(
      fs.readFileSync(path.join(outputDir, filename), "utf8"),
      canonicalJson(expected[key]),
    );
  }
  assert.doesNotThrow(() =>
    writeOrCheckScopeArtifacts({
      artifacts: expected,
      outputDir,
      mode: "check",
    }),
  );

  fs.appendFileSync(path.join(outputDir, SCOPE_OUTPUT_FILES.scope), "\n");
  assert.throws(
    () =>
      writeOrCheckScopeArtifacts({
        artifacts: expected,
        outputDir,
        mode: "check",
      }),
    /generated scope artifact drift/u,
  );
});
