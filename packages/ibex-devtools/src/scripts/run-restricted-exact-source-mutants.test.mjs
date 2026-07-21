import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "bun:test";

import { repoRoot } from "./capsec-contract.mjs";
import {
  restrictedExactSourceMutants,
  validateRestrictedSourceMutantExecutions,
} from "./run-restricted-exact-source-mutants.mjs";
import { taggedDigest } from "./restricted-exact-target-report.mjs";

const testName = "host::embedder_artifacts::tests::restricted_exact_source_mutant_detection_fixture";

function executionFor(mutant) {
  const source = fs.readFileSync(path.join(repoRoot, mutant.sourcePath), "utf8");
  expect(source.split(mutant.before)).toHaveLength(2);
  const mutated = source.replace(mutant.before, mutant.after);
  const diff = Buffer.from(`diff --git a/${mutant.sourcePath} b/${mutant.sourcePath}\n`);
  const output = Buffer.from(mutant.expectedFailureMarker);
  return {
    mutantId: mutant.id,
    sourcePath: mutant.sourcePath,
    beforeBase64: Buffer.from(mutant.before).toString("base64"),
    afterBase64: Buffer.from(mutant.after).toString("base64"),
    originalSourceRawContentDigest: taggedDigest(Buffer.from(source)),
    mutatedSourceRawContentDigest: taggedDigest(Buffer.from(mutated)),
    diffBase64: diff.toString("base64"),
    diffRawContentDigest: taggedDigest(diff),
    buildCommand: [
      "cargo", "test", "-p", "ibex-runtime", "--lib", "--release",
      "--features", "capsec-conformance-observer", "--no-run", "--message-format=json",
    ],
    executeCommand: [
      "<compiled-rust-test-binary>", testName, "--exact", "--nocapture", "--test-threads=1",
    ],
    testBinaryDigest: `sha256-${"A".repeat(43)}`,
    buildExitCode: 0,
    testExitCode: 101,
    expectedFailureMarker: mutant.expectedFailureMarker,
    outputBase64: output.toString("base64"),
    outputRawContentDigest: taggedDigest(output),
    resultMarker: `ibex-restricted-source-mutant:detected:${mutant.id}`,
  };
}

describe("LLP 0033 executable source mutants", () => {
  test("pins five exact, non-ambiguous production source changes", () => {
    expect(restrictedExactSourceMutants.map((mutant) => mutant.id)).toEqual([
      "select-full-installer",
      "install-module-loader",
      "install-forbidden-global",
      "retain-callback-after-global-deletion",
      "lazy-global-after-poll",
    ]);
    expect(() => validateRestrictedSourceMutantExecutions(
      restrictedExactSourceMutants.map(executionFor),
    )).not.toThrow();
  });

  test("rejects mutation substitution and a missing exact failure boundary", () => {
    const substituted = restrictedExactSourceMutants.map(executionFor);
    substituted[0].mutantId = "install-module-loader";
    expect(() => validateRestrictedSourceMutantExecutions(substituted)).toThrow(
      "select-full-installer evidence drift",
    );

    const escaped = restrictedExactSourceMutants.map(executionFor);
    const output = Buffer.from("test result: ok");
    escaped[4].outputBase64 = output.toString("base64");
    escaped[4].outputRawContentDigest = taggedDigest(output);
    escaped[4].testExitCode = 0;
    expect(() => validateRestrictedSourceMutantExecutions(escaped)).toThrow(
      "lazy-global-after-poll evidence drift",
    );
  });
});
