import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "bun:test";

import { capsecRoot } from "./capsec-contract.mjs";
import { ingestRestrictedAbsenceEvidence } from "./restricted-exact-absence-evidence.mjs";
import { ingestRestrictedControlEvidence } from "./restricted-exact-control-evidence.mjs";
import { ingestRestrictedGlobalCorporaEvidence } from "./restricted-exact-global-corpora-evidence.mjs";
import { ingestRestrictedReachableEvidence } from "./restricted-exact-reachable-evidence.mjs";

const evidenceRoot = path.join(capsecRoot, "conformance/evidence/restricted-exact");
const evidencePath = path.join(evidenceRoot, "reachable-aarch64-apple-darwin-04a08eeb.json");
const controlEvidencePath = path.join(evidenceRoot, "control-aarch64-apple-darwin-04a08eeb.json");
const absenceEvidencePath = path.join(evidenceRoot, "absence-aarch64-apple-darwin-04a08eeb.json");
const corpusEvidencePath = path.join(evidenceRoot, "global-corpora-aarch64-apple-darwin-04a08eeb.json");
const currentAbsenceEvidencePath = path.join(
  evidenceRoot,
  "absence-aarch64-apple-darwin-59382127.json",
);
const currentAbsenceArtifact = JSON.parse(
  fs.readFileSync(currentAbsenceEvidencePath, "utf8"),
);

function currentArtifact() {
  return structuredClone(currentAbsenceArtifact);
}

describe("LLP 0033 restricted evidence invalidation", () => {
  test("invalidates every evidence family predating the per-edge probe plan", () => {
    expect(() => ingestRestrictedReachableEvidence(
      fs.readFileSync(evidencePath),
    )).toThrow("restricted authority changed after evidence");
    expect(() => ingestRestrictedControlEvidence(
      fs.readFileSync(controlEvidencePath),
    )).toThrow("restricted authority changed after evidence");
    expect(() => ingestRestrictedAbsenceEvidence(
      fs.readFileSync(absenceEvidencePath),
    )).toThrow("restricted authority changed after evidence");
    expect(() => ingestRestrictedGlobalCorporaEvidence(
      fs.readFileSync(corpusEvidencePath),
      fs.readFileSync(evidencePath),
    )).toThrow("restricted authority changed after evidence");
  });
});

describe("LLP 0033 per-edge absence evidence", () => {
  test("rejects a missing planned source-install result", () => {
    const artifact = currentArtifact();
    const observation = artifact.observations.find(
      (row) => row.kind === "source-install" && row.proof.probeResults.length > 0,
    );
    observation.proof.probeResults.pop();
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(artifact)}\n`),
    )).toThrow("wrong receipt count");
  }, 30_000);

  test("rejects a live-route result whose outcome was widened", () => {
    const artifact = currentArtifact();
    const observation = artifact.observations.find(
      (row) => row.kind === "live-reachability" && row.proof.probeResults.length > 0,
    );
    observation.proof.probeResults[0].outcome = "reachable";
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(artifact)}\n`),
    )).toThrow("live-reachability proof drift");
  }, 30_000);

  test("rejects fabricated runtime generations and failure boundaries", () => {
    const generation = currentArtifact();
    const source = generation.observations.find((row) => row.kind === "source-install");
    source.proof.probeResults[0].routeReceipt.runtimeGeneration += 1;
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(generation)}\n`),
    )).toThrow(/receipt drift|crossed runtime generations/u);

    const boundary = currentArtifact();
    const boundarySource = boundary.observations.find((row) => row.kind === "source-install");
    boundarySource.proof.probeResults[0].routeReceipt.failedSegment =
      boundarySource.proof.probeResults[0].routeReceipt.lastReachedSegment;
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(boundary)}\n`),
    )).toThrow("absence route receipt drift");
  }, 30_000);

  test("rejects target-insensitive, missing, and source/live-reused receipts", () => {
    const target = currentArtifact();
    const live = target.observations.find((row) => row.kind === "live-reachability");
    live.proof.probeResults[0].routeReceipts[0].probeTarget = "builtin:substituted";
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(target)}\n`),
    )).toThrow("absence route receipt drift");

    const missing = currentArtifact();
    const missingLive = missing.observations.find((row) => row.kind === "live-reachability");
    missingLive.proof.probeResults[0].routeReceipts = [];
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(missing)}\n`),
    )).toThrow("lacks complete routes");

    const reused = currentArtifact();
    const reusedSource = reused.observations.find((row) => row.kind === "source-install");
    const reusedLive = reused.observations.find((row) => row.kind === "live-reachability");
    reusedLive.proof.probeResults[0].routeReceipts[0] =
      reusedSource.proof.probeResults[0].routeReceipt;
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(reused)}\n`),
    )).toThrow("absence route receipt drift");
  }, 30_000);
});
