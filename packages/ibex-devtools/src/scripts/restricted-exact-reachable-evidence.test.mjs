import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { describe, expect, test } from "bun:test";

import { capsecRoot } from "./capsec-contract.mjs";
import {
  ingestRestrictedAbsenceEvidence,
  validateRestrictedActualBoundaryObservation,
} from "./restricted-exact-absence-evidence.mjs";
import { ingestRestrictedControlEvidence } from "./restricted-exact-control-evidence.mjs";
import { ingestRestrictedGlobalCorporaEvidence } from "./restricted-exact-global-corpora-evidence.mjs";
import {
  ingestRestrictedReachableEvidence,
  validateEngine,
} from "./restricted-exact-reachable-evidence.mjs";

const evidenceRoot = path.join(capsecRoot, "conformance/evidence/restricted-exact");
const evidencePath = path.join(evidenceRoot, "reachable-aarch64-apple-darwin-04a08eeb.json");
const controlEvidencePath = path.join(evidenceRoot, "control-aarch64-apple-darwin-04a08eeb.json");
const absenceEvidencePath = path.join(evidenceRoot, "absence-aarch64-apple-darwin-04a08eeb.json");
const corpusEvidencePath = path.join(evidenceRoot, "global-corpora-aarch64-apple-darwin-04a08eeb.json");
const currentAbsenceEvidencePath = path.join(
  evidenceRoot,
  "absence-aarch64-apple-darwin-9e3de2a0.json",
);
const currentAbsenceArtifact = JSON.parse(
  fs.readFileSync(currentAbsenceEvidencePath, "utf8"),
);
const historicalAuthorityPaths = {
  definition: "capsec/registry/restricted-exact-profile-definition.json",
  projection: "capsec/generated/restricted-exact-profile-projection.json",
  coverage: "capsec/registry/coverage-edges.json",
  implementationManifest: "capsec/generated/implementation-manifest.json",
  fixturePlan: "capsec/registry/restricted-exact-fixture-plan.json",
  reportSchema: "capsec/schema/restricted-profile-target-report.schema.json",
  rootManifest: "capsec/generated/root-global-disposition-manifest.json",
  absenceProbePlan: "capsec/generated/restricted-exact-absence-probe-plan.json",
  absenceRouteGraph: "capsec/generated/restricted-exact-absence-route-graph.json",
};

function historicalAuthorities(revision) {
  const rawAuthorities = Object.fromEntries(Object.entries(historicalAuthorityPaths).map(
    ([name, relativePath]) => [name, execFileSync(
      "git",
      ["show", `${revision}:${relativePath}`],
      { cwd: path.resolve(capsecRoot, ".."), maxBuffer: 64 * 1024 * 1024 },
    )],
  ));
  return {
    projection: JSON.parse(rawAuthorities.projection),
    coverage: JSON.parse(rawAuthorities.coverage),
    implementationManifest: JSON.parse(rawAuthorities.implementationManifest),
    fixturePlan: JSON.parse(rawAuthorities.fixturePlan),
    rawAuthorities,
  };
}

const currentHistoricalAuthorities = historicalAuthorities(
  currentAbsenceArtifact.sourceRevision,
);

function currentArtifact() {
  return structuredClone(currentAbsenceArtifact);
}

describe("LLP 0033 restricted evidence invalidation", () => {
  test("binds the engine architecture to either preregistered target", () => {
    const apple = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
    expect(() => validateEngine(apple)).not.toThrow();

    const linux = structuredClone(apple);
    linux.target.triple = "x86_64-unknown-linux-gnu";
    linux.engine.targetArchitecture = "x86_64";
    expect(() => validateEngine(linux)).not.toThrow();

    linux.engine.targetArchitecture = "aarch64";
    expect(() => validateEngine(linux)).toThrow(
      "reachable evidence engine architecture differs from its target",
    );
  });

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
  }, 30_000);
});

describe("LLP 0033 per-edge absence evidence", () => {
  test("requires and validates live boundary observations", () => {
    const observation = {
      routeKind: "descriptor-prefix",
      exactTarget: "__compartments",
      boundary: {
        kind: "root-descriptor",
        receipts: [{
          requestedPath: "__compartments",
          mode: "absent",
          boundaryKind: "missing-descriptor",
          lastResolvedSegmentIndex: null,
          lastResolvedSegment: null,
          firstBlockedSegmentIndex: 0,
          firstBlockedSegment: "__compartments",
        }],
      },
    };
    expect(() => validateRestrictedActualBoundaryObservation(
      observation,
      "descriptor-prefix",
      "__compartments",
    )).not.toThrow();
    expect(() => validateRestrictedActualBoundaryObservation(
      undefined,
      "descriptor-prefix",
      "__compartments",
    )).toThrow();

    const tampered = structuredClone(observation);
    tampered.boundary.receipts[0].requestedPath = "Exact";
    expect(() => validateRestrictedActualBoundaryObservation(
      tampered,
      "descriptor-prefix",
      "__compartments",
    )).toThrow("boundary receipt roster drift");
  });

  test("rejects a missing planned source-install result", () => {
    const artifact = currentArtifact();
    const observation = artifact.observations.find(
      (row) => row.kind === "source-install" && row.proof.probeResults.length > 0,
    );
    observation.proof.probeResults.pop();
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(artifact)}\n`),
      currentHistoricalAuthorities,
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
      currentHistoricalAuthorities,
    )).toThrow("live-reachability proof drift");
  }, 30_000);

  test("rejects fabricated runtime generations and failure boundaries", () => {
    const generation = currentArtifact();
    const source = generation.observations.find((row) => row.kind === "source-install");
    source.proof.probeResults[0].routeReceipt.runtimeGeneration += 1;
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(generation)}\n`),
      currentHistoricalAuthorities,
    )).toThrow(/receipt drift|crossed runtime generations/u);

    const boundary = currentArtifact();
    const boundarySource = boundary.observations.find((row) => row.kind === "source-install");
    boundarySource.proof.probeResults[0].routeReceipt.blockedEdge.to =
      "terminal.forged-bypass";
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(boundary)}\n`),
      currentHistoricalAuthorities,
    )).toThrow("absence route receipt drift");
  }, 30_000);

  test("rejects target-insensitive, missing, and source/live-reused receipts", () => {
    const target = currentArtifact();
    const live = target.observations.find((row) => row.kind === "live-reachability");
    live.proof.probeResults[0].routeReceipts[0].probeTarget = "builtin:substituted";
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(target)}\n`),
      currentHistoricalAuthorities,
    )).toThrow("absence route receipt drift");

    const missing = currentArtifact();
    const missingLive = missing.observations.find((row) => row.kind === "live-reachability");
    missingLive.proof.probeResults[0].routeReceipts = [];
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(missing)}\n`),
      currentHistoricalAuthorities,
    )).toThrow("lacks complete routes");

    const reused = currentArtifact();
    const reusedSource = reused.observations.find((row) => row.kind === "source-install");
    const reusedLive = reused.observations.find((row) => row.kind === "live-reachability");
    reusedLive.proof.probeResults[0].routeReceipts[0] =
      reusedSource.proof.probeResults[0].routeReceipt;
    expect(() => ingestRestrictedAbsenceEvidence(
      Buffer.from(`${JSON.stringify(reused)}\n`),
      currentHistoricalAuthorities,
    )).toThrow("absence route receipt drift");
  }, 120_000);
});
