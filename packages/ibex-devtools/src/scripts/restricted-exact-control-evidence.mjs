/** Validate LLP 0033 per-edge trusted-control-plane evidence. */

import fs from "node:fs";

import { canonicalJson, parseJsonStrict } from "./capsec-contract.mjs";
import {
  assertExactKeys,
  assertSortedUnique,
  validateEngine,
  validateRevisionAndAuthorities,
} from "./restricted-exact-reachable-evidence.mjs";
import {
  loadRestrictedReportAuthorities,
  taggedDigest,
} from "./restricted-exact-target-report.mjs";

const EVIDENCE_SCHEMA = "ibex/restricted-profile-control-evidence/1";
const PROFILE = "ibex/exact-embedder-contract/1";
const RESULT_MARKER = "ibex-restricted-control-evidence:passed";

export function ingestRestrictedControlEvidence(rawBytes, authorities = undefined) {
  const reportAuthorities = authorities ?? loadRestrictedReportAuthorities();
  const artifact = parseJsonStrict(rawBytes, "restricted control evidence");
  assertExactKeys(
    artifact,
    [
      "evidenceSchema",
      "profile",
      "runId",
      "sourceRevision",
      "sourceTreeDigest",
      "target",
      "engine",
      "hermesProfileProvenance",
      "authorityDigests",
      "command",
      "exitCode",
      "resultMarker",
      "observations",
    ],
    "restricted control evidence",
  );
  if (
    artifact.evidenceSchema !== EVIDENCE_SCHEMA
    || artifact.profile !== PROFILE
    || artifact.exitCode !== 0
    || artifact.resultMarker !== RESULT_MARKER
  ) {
    throw new Error("restricted control evidence envelope is not a passing v1 artifact");
  }
  if (!Array.isArray(artifact.command) || artifact.command.length === 0) {
    throw new Error("restricted control evidence command is missing");
  }
  const candidate = reportAuthorities.projection.candidateTargets.find(
    (target) => canonicalJson(target) === canonicalJson(artifact.target),
  );
  if (!candidate) throw new Error("control evidence names a non-candidate target");
  validateRevisionAndAuthorities(artifact, reportAuthorities);
  const patchIdentity = validateEngine(artifact);

  const controlIds = reportAuthorities.projection.rows
    .filter((row) => row[1] === "trusted-control-plane")
    .map((row) => row[0]);
  const observationIds = artifact.observations.map((row) => row.edgeId);
  assertSortedUnique(observationIds, "control evidence observations");
  if (canonicalJson(observationIds) !== canonicalJson(controlIds)) {
    throw new Error("control evidence observations do not equal the projection");
  }
  const coverageById = new Map(
    reportAuthorities.coverage.edges.map((edge) => [edge.id, edge]),
  );
  for (const observation of artifact.observations) {
    assertExactKeys(
      observation,
      ["edgeId", "kind", "outcome", "observedIdentity", "proof"],
      `control observation ${observation.edgeId}`,
    );
    const edge = coverageById.get(observation.edgeId);
    if (
      observation.kind !== "control-plane-negative"
      || observation.outcome !== "passed"
      || observation.observedIdentity !== `${edge.surface.kind}:${edge.surface.name}`
    ) {
      throw new Error(`control observation identity/outcome drift for ${observation.edgeId}`);
    }
    assertExactKeys(
      observation.proof,
      ["observer", "accepted", "refusal"],
      `control proof ${observation.edgeId}`,
    );
    if (
      observation.proof.observer !== "native-abi-lifecycle"
      || typeof observation.proof.accepted !== "string"
      || observation.proof.accepted.length === 0
      || typeof observation.proof.refusal !== "string"
      || observation.proof.refusal.length === 0
    ) {
      throw new Error(`control observation lacks lifecycle proof for ${observation.edgeId}`);
    }
  }

  const artifactDigest = taggedDigest(Buffer.from(canonicalJson(artifact), "utf8"));
  return {
    artifact,
    rawContentDigest: taggedDigest(rawBytes),
    artifactDigest,
    bindings: {
      sourceRevision: artifact.sourceRevision,
      sourceTreeDigest: artifact.sourceTreeDigest,
      target: artifact.target,
      engine: {
        artifactPath: artifact.engine.engineArtifactPath,
        kind: artifact.engine.kind,
        binaryDigest: artifact.engine.binaryDigest,
        patchIdentity,
        targetArchitecture: artifact.engine.targetArchitecture,
        structuralFeatures: artifact.engine.structuralFeatures,
      },
      ...artifact.authorityDigests,
    },
    executions: artifact.observations.map((observation) => ({
      executionId: `${artifact.runId}.${observation.edgeId}`,
      fixtureId: `restricted.control-plane-negative.${observation.edgeId}`,
      outcome: "passed",
      command: artifact.command,
      exitCode: artifact.exitCode,
      resultMarker: artifact.resultMarker,
      artifactDigest,
      engineBinaryDigest: artifact.engine.binaryDigest,
      observations: [{
        edgeId: observation.edgeId,
        kind: observation.kind,
        outcome: observation.outcome,
        observedIdentity: observation.observedIdentity,
      }],
    })),
  };
}

export function readRestrictedControlEvidence(filePath, authorities = undefined) {
  return ingestRestrictedControlEvidence(fs.readFileSync(filePath), authorities);
}
