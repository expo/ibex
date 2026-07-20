import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "bun:test";

import { capsecRoot } from "./capsec-contract.mjs";
import { buildRestrictedTargetReportFromReachableEvidence } from "./generate-restricted-exact-target-report.mjs";
import { ingestRestrictedReachableEvidence } from "./restricted-exact-reachable-evidence.mjs";

const evidencePath = path.join(
  capsecRoot,
  "conformance/evidence/restricted-exact/reachable-aarch64-apple-darwin-74666468.json",
);

function rawArtifact() {
  return fs.readFileSync(evidencePath);
}

function mutate(edit) {
  const artifact = JSON.parse(rawArtifact());
  edit(artifact);
  return Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`, "utf8");
}

describe("LLP 0033 restricted reachable evidence", () => {
  test("ingests all 126 exact native observations", () => {
    const result = ingestRestrictedReachableEvidence(rawArtifact());
    expect(result.executions).toHaveLength(126);
    expect(new Set(result.executions.map((row) => row.fixtureId)).size).toBe(126);
    expect(result.bindings.target.triple).toBe("aarch64-apple-darwin");
    expect(result.bindings.engine.kind).toBe("hermes");
    expect(result.rawContentDigest).toMatch(/^sha256-/);
  });

  test("credits 126 reachable rows without advertising target conformance", () => {
    const report = buildRestrictedTargetReportFromReachableEvidence(evidencePath);
    expect(report.status).toBe("incomplete");
    expect(report.summary.conformant).toBe(126);
    expect(report.summary.incomplete).toBe(7174);
    expect(report.summary.passedObservations).toBe(126);
    expect(report.summary.failedObservations).toBe(0);
    expect(report.summary.missingObservations).toBe(14326);
    expect(report.executions).toHaveLength(126);
  });

  test("rejects source, authority, engine, observation, and proof drift", () => {
    expect(() => ingestRestrictedReachableEvidence(mutate((artifact) => {
      artifact.sourceTreeDigest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }))).toThrow("source tree digest mismatch");

    expect(() => ingestRestrictedReachableEvidence(mutate((artifact) => {
      artifact.authorityDigests.coverageRawContentDigest =
        "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }))).toThrow("coverageRawContentDigest");

    expect(() => ingestRestrictedReachableEvidence(mutate((artifact) => {
      artifact.engine.binaryDigest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }))).toThrow("differs from provenance");

    expect(() => ingestRestrictedReachableEvidence(mutate((artifact) => {
      artifact.observations.pop();
    }))).toThrow("do not equal the projection");

    expect(() => ingestRestrictedReachableEvidence(mutate((artifact) => {
      artifact.observations.find((row) => "callbacksDelivered" in row.proof)
        .proof.callbacksDelivered = 0;
    }))).toThrow("callbacksDelivered mismatch");
  });
});
