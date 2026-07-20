import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "bun:test";

import { capsecRoot } from "./capsec-contract.mjs";
import { buildRestrictedTargetReportFromEvidence } from "./generate-restricted-exact-target-report.mjs";
import { ingestRestrictedAbsenceEvidence } from "./restricted-exact-absence-evidence.mjs";
import { ingestRestrictedControlEvidence } from "./restricted-exact-control-evidence.mjs";
import { ingestRestrictedReachableEvidence } from "./restricted-exact-reachable-evidence.mjs";

const evidencePath = path.join(
  capsecRoot,
  "conformance/evidence/restricted-exact/reachable-aarch64-apple-darwin-98e334d3.json",
);
const controlEvidencePath = path.join(
  capsecRoot,
  "conformance/evidence/restricted-exact/control-aarch64-apple-darwin-98e334d3.json",
);
const absenceEvidencePath = path.join(
  capsecRoot,
  "conformance/evidence/restricted-exact/absence-aarch64-apple-darwin-98e334d3.json",
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

function mutateAbsence(edit) {
  const artifact = JSON.parse(fs.readFileSync(absenceEvidencePath));
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

  test("credits all edge rows without bypassing global conformance", () => {
    const report = buildRestrictedTargetReportFromEvidence(
      evidencePath,
      controlEvidencePath,
      absenceEvidencePath,
    );
    expect(report.status).toBe("incomplete");
    expect(report.summary.conformant).toBe(7300);
    expect(report.summary.incomplete).toBe(0);
    expect(report.summary.passedObservations).toBe(14452);
    expect(report.summary.failedObservations).toBe(0);
    expect(report.summary.missingObservations).toBe(0);
    expect(report.executions).toHaveLength(14452);
  }, 30_000);

  test("ingests all 22 exact control-plane lifecycle observations", () => {
    const result = ingestRestrictedControlEvidence(fs.readFileSync(controlEvidencePath));
    expect(result.executions).toHaveLength(22);
    expect(new Set(result.executions.map((row) => row.fixtureId)).size).toBe(22);
    expect(result.bindings.sourceRevision).toBe(
      "98e334d3c8d097d884856356943da17942908338",
    );
  });

  test("ingests both exact absence obligations for all 7,152 edges", () => {
    const result = ingestRestrictedAbsenceEvidence(fs.readFileSync(absenceEvidencePath));
    expect(result.executions).toHaveLength(14304);
    expect(new Set(result.executions.map((row) => row.fixtureId)).size).toBe(14304);
    expect(result.artifact.barrierAttestation.descriptorProbedEdges).toBe(2460);
  });

  test("rejects root-authority and per-edge absence proof drift", () => {
    expect(() => ingestRestrictedAbsenceEvidence(mutateAbsence((artifact) => {
      artifact.barrierAttestation.rootGlobalManifestRawContentDigest =
        "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }))).toThrow("root-global authority");

    expect(() => ingestRestrictedAbsenceEvidence(mutateAbsence((artifact) => {
      const observation = artifact.observations.find(
        (row) => row.kind === "live-reachability" && row.proof.descriptorPrefixes.length > 0,
      );
      observation.proof.descriptorPrefixes[0].path = "wrong.path";
    }))).toThrow("live-reachability proof drift");
  }, 30_000);

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
