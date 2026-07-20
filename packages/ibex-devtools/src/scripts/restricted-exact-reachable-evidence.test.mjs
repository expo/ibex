import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "bun:test";

import { capsecRoot } from "./capsec-contract.mjs";
import { buildRestrictedTargetReportAfterFailedReview } from "./generate-restricted-exact-target-report.mjs";
import { ingestRestrictedAbsenceEvidence } from "./restricted-exact-absence-evidence.mjs";
import { ingestRestrictedControlEvidence } from "./restricted-exact-control-evidence.mjs";
import { ingestRestrictedGlobalCorporaEvidence } from "./restricted-exact-global-corpora-evidence.mjs";
import { ingestRestrictedReachableEvidence } from "./restricted-exact-reachable-evidence.mjs";

const evidencePath = path.join(
  capsecRoot,
  "conformance/evidence/restricted-exact/reachable-aarch64-apple-darwin-04a08eeb.json",
);
const controlEvidencePath = path.join(
  capsecRoot,
  "conformance/evidence/restricted-exact/control-aarch64-apple-darwin-04a08eeb.json",
);
const absenceEvidencePath = path.join(
  capsecRoot,
  "conformance/evidence/restricted-exact/absence-aarch64-apple-darwin-04a08eeb.json",
);
const corpusEvidencePath = path.join(
  capsecRoot,
  "conformance/evidence/restricted-exact/global-corpora-aarch64-apple-darwin-04a08eeb.json",
);
const failedReviewPath = path.join(
  capsecRoot,
  "conformance/reviews/restricted-exact-aarch64-apple-darwin-041fbd55.json",
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

  test("invalidates overclaimed absence and corpus rows after the failed review", () => {
    const report = buildRestrictedTargetReportAfterFailedReview(
      evidencePath,
      controlEvidencePath,
      absenceEvidencePath,
      corpusEvidencePath,
      failedReviewPath,
    );
    expect(report.status).toBe("incomplete");
    expect(report.summary.conformant).toBe(148);
    expect(report.summary.incomplete).toBe(7152);
    expect(report.summary.passedObservations).toBe(148);
    expect(report.summary.failedObservations).toBe(0);
    expect(report.summary.missingObservations).toBe(14304);
    expect(report.executions).toHaveLength(148);
    expect(report.globalCorpora.every((row) => row.status === "missing")).toBe(true);
    expect(report.independentReview.status).toBe("failed");
    expect(report.independentReview.unresolvedCritical).toBe(1);
    expect(report.independentReview.unresolvedHigh).toBe(1);
  }, 30_000);

  test("ingests all 22 exact control-plane lifecycle observations", () => {
    const result = ingestRestrictedControlEvidence(fs.readFileSync(controlEvidencePath));
    expect(result.executions).toHaveLength(22);
    expect(new Set(result.executions.map((row) => row.fixtureId)).size).toBe(22);
    expect(result.bindings.sourceRevision).toBe(
      "04a08eebc15fb76102f9be59ecf394a80e731a28",
    );
  });

  test("rejects the reviewed synthesized absence artifact", () => {
    expect(() => ingestRestrictedAbsenceEvidence(
      fs.readFileSync(absenceEvidencePath),
    )).toThrow("lacks an executed edge-specific probe");
  });

  test("rejects the reviewed teardown corpus after its plan gains the missing race fixture", () => {
    expect(() => ingestRestrictedGlobalCorporaEvidence(
      fs.readFileSync(corpusEvidencePath),
      fs.readFileSync(evidencePath),
    )).toThrow("global corpus teardown execution set drift");
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
    }))).toThrow(/live-reachability proof drift|lacks an executed edge-specific probe/u);
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
