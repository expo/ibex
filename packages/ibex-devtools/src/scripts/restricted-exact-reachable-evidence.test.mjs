import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "bun:test";

import { capsecRoot } from "./capsec-contract.mjs";
import { buildRestrictedTargetReportFromEvidence } from "./generate-restricted-exact-target-report.mjs";
import { ingestRestrictedControlEvidence } from "./restricted-exact-control-evidence.mjs";
import { ingestRestrictedReachableEvidence } from "./restricted-exact-reachable-evidence.mjs";

const evidencePath = path.join(
  capsecRoot,
  "conformance/evidence/restricted-exact/reachable-aarch64-apple-darwin-1a033000.json",
);
const controlEvidencePath = path.join(
  capsecRoot,
  "conformance/evidence/restricted-exact/control-aarch64-apple-darwin-1a033000.json",
);

function rawArtifact() {
  return fs.readFileSync(evidencePath);
}

function mutate(edit) {
  const artifact = JSON.parse(rawArtifact());
  edit(artifact);
  return Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`, "utf8");
}

function mutateControl(edit) {
  const artifact = JSON.parse(fs.readFileSync(controlEvidencePath));
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
    const report = buildRestrictedTargetReportFromEvidence(evidencePath, controlEvidencePath);
    expect(report.status).toBe("incomplete");
    expect(report.summary.conformant).toBe(148);
    expect(report.summary.incomplete).toBe(7152);
    expect(report.summary.passedObservations).toBe(148);
    expect(report.summary.failedObservations).toBe(0);
    expect(report.summary.missingObservations).toBe(14304);
    expect(report.executions).toHaveLength(148);
  });

  test("ingests all 22 exact control-plane lifecycle observations", () => {
    const result = ingestRestrictedControlEvidence(fs.readFileSync(controlEvidencePath));
    expect(result.executions).toHaveLength(22);
    expect(new Set(result.executions.map((row) => row.fixtureId)).size).toBe(22);
    expect(result.bindings.sourceRevision).toBe(
      "1a033000c5c84e01caa12342c9309c1f901d785f",
    );
  });

  test("rejects missing, identity-drifted, and proofless control observations", () => {
    expect(() => ingestRestrictedControlEvidence(mutateControl((artifact) => {
      artifact.observations.pop();
    }))).toThrow("do not equal the projection");

    expect(() => ingestRestrictedControlEvidence(mutateControl((artifact) => {
      artifact.observations[0].observedIdentity = "host-abi:wrong";
    }))).toThrow("identity/outcome drift");

    expect(() => ingestRestrictedControlEvidence(mutateControl((artifact) => {
      artifact.observations[0].proof.refusal = "";
    }))).toThrow("lacks lifecycle proof");
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
