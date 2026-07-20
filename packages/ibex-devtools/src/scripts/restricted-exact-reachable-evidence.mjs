/**
 * Validate and ingest native reachable-edge evidence for the LLP 0033
 * restricted Exact profile.
 *
 * The native observer intentionally emits one raw artifact for the complete
 * engine run. This module rejects identity drift in that artifact and expands
 * it into the report format's one-execution/one-observation rows. A successful
 * process exit is therefore never treated as evidence for an unobserved edge.
 *
 * @ref LLP 0033#8-generated-authority-and-conformance — exact-target evidence
 * is source-, authority-, engine-, target-, and per-edge-bound.
 */

import fs from "node:fs";
import { execFileSync } from "node:child_process";

import {
  canonicalJson,
  parseJsonStrict,
  repoRoot,
} from "./capsec-contract.mjs";
import {
  loadRestrictedReportAuthorities,
  taggedDigest,
} from "./restricted-exact-target-report.mjs";

const EVIDENCE_SCHEMA = "ibex/restricted-profile-reachable-evidence/1";
const PROFILE = "ibex/exact-embedder-contract/1";
const RESULT_MARKER = "ibex-restricted-reachable-evidence:passed";

const authorityPaths = Object.freeze({
  definitionRawContentDigest:
    "capsec/registry/restricted-exact-profile-definition.json",
  projectionRawContentDigest:
    "capsec/generated/restricted-exact-profile-projection.json",
  coverageRawContentDigest: "capsec/registry/coverage-edges.json",
  implementationManifestRawContentDigest:
    "capsec/generated/implementation-manifest.json",
  fixturePlanRawContentDigest:
    "capsec/registry/restricted-exact-fixture-plan.json",
  reportSchemaRawContentDigest:
    "capsec/schema/restricted-profile-target-report.schema.json",
});

export function assertExactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error(`${label} keys differ: ${actual.join(", ")}`);
  }
}

export function assertSortedUnique(values, label) {
  const sorted = [...values].sort();
  if (new Set(values).size !== values.length) {
    throw new Error(`${label} contains duplicates`);
  }
  if (canonicalJson(values) !== canonicalJson(sorted)) {
    throw new Error(`${label} must be sorted`);
  }
}

function git(...args) {
  return execFileSync("git", args, { cwd: repoRoot, maxBuffer: 64 * 1024 * 1024 });
}

function hexDigestToTagged(value, label) {
  const match = /^sha256-([0-9a-f]{64})$/u.exec(value);
  if (!match) throw new Error(`${label} is not a hexadecimal SHA-256 digest`);
  return `sha256-${Buffer.from(match[1], "hex").toString("base64url")}`;
}

export function validateRevisionAndAuthorities(artifact, authorities) {
  if (!/^[0-9a-f]{40}$/u.test(artifact.sourceRevision)) {
    throw new Error("reachable evidence source revision is invalid");
  }
  let sourceTree;
  try {
    sourceTree = git("rev-parse", `${artifact.sourceRevision}^{tree}`);
  } catch {
    throw new Error("reachable evidence source revision is unavailable");
  }
  if (taggedDigest(sourceTree) !== artifact.sourceTreeDigest) {
    throw new Error("reachable evidence source tree digest mismatch");
  }

  const currentBytes = {
    definitionRawContentDigest: authorities.rawAuthorities.definition,
    projectionRawContentDigest: authorities.rawAuthorities.projection,
    coverageRawContentDigest: authorities.rawAuthorities.coverage,
    implementationManifestRawContentDigest:
      authorities.rawAuthorities.implementationManifest,
    fixturePlanRawContentDigest: authorities.rawAuthorities.fixturePlan,
    reportSchemaRawContentDigest: authorities.rawAuthorities.reportSchema,
  };
  assertExactKeys(
    artifact.authorityDigests,
    Object.keys(authorityPaths),
    "reachable evidence authority digests",
  );
  for (const [field, relativePath] of Object.entries(authorityPaths)) {
    let revisionBytes;
    try {
      revisionBytes = git("show", `${artifact.sourceRevision}:${relativePath}`);
    } catch {
      throw new Error(`reachable evidence revision omits ${relativePath}`);
    }
    const digest = taggedDigest(revisionBytes);
    if (artifact.authorityDigests[field] !== digest) {
      throw new Error(`reachable evidence ${field} does not bind revision bytes`);
    }
    if (!revisionBytes.equals(currentBytes[field])) {
      throw new Error(`restricted authority changed after evidence: ${relativePath}`);
    }
  }
}

export function validateEngine(artifact) {
  assertExactKeys(
    artifact.engine,
    [
      "engineArtifactPath",
      "kind",
      "binaryDigest",
      "object",
      "targetArchitecture",
      "structuralFeatures",
    ],
    "reachable evidence engine",
  );
  if (artifact.engine.kind !== "hermes") {
    throw new Error("reachable evidence was not produced by Hermes");
  }
  if (
    canonicalJson(artifact.engine.structuralFeatures)
      !== canonicalJson(artifact.target.features)
  ) {
    throw new Error("reachable evidence target and engine features differ");
  }
  if (artifact.engine.targetArchitecture !== "aarch64") {
    throw new Error("reachable evidence engine architecture is not aarch64");
  }

  const provenance = artifact.hermesProfileProvenance;
  assertExactKeys(provenance, ["path", "rawContentDigest", "receipt"], "Hermes provenance");
  const receipt = provenance.receipt;
  if (
    receipt.schema !== "ibex/hermes-profile-provenance-receipt/2"
    || receipt.profileId !== "source-patched"
    || receipt.origin?.kind !== "source-patched-cache"
  ) {
    throw new Error("reachable evidence has an unreviewed Hermes provenance profile");
  }
  const identity = receipt.origin.reviewedProfileIdentity;
  if (
    !/^[0-9a-f]{40}$/u.test(identity?.sourceCommit)
    || typeof identity?.patchStackDigest !== "string"
    || typeof receipt.origin.cacheKey !== "string"
    || !receipt.origin.cacheKey.includes(identity.sourceCommit.slice(0, 12))
  ) {
    throw new Error("reachable evidence Hermes patch identity is incomplete");
  }
  const receiptBinaryDigest = hexDigestToTagged(
    receipt.artifact?.binaryDigest,
    "Hermes provenance binary digest",
  );
  if (receiptBinaryDigest !== artifact.engine.binaryDigest) {
    throw new Error("reachable evidence engine digest differs from provenance");
  }
  return `${identity.sourceCommit}@${identity.patchStackDigest}`;
}

function validateObservations(artifact, authorities) {
  const reachableIds = authorities.projection.rows
    .filter((row) => row[1] === "reachable")
    .map((row) => row[0]);
  const observationIds = artifact.observations.map((row) => row.edgeId);
  assertSortedUnique(observationIds, "reachable evidence observations");
  if (canonicalJson(observationIds) !== canonicalJson(reachableIds)) {
    throw new Error("reachable evidence observations do not equal the projection");
  }
  const coverageById = new Map(
    authorities.coverage.edges.map((edge) => [edge.id, edge]),
  );
  for (const observation of artifact.observations) {
    assertExactKeys(
      observation,
      ["edgeId", "kind", "outcome", "observedIdentity", "proof"],
      `reachable observation ${observation.edgeId}`,
    );
    const edge = coverageById.get(observation.edgeId);
    const expectedIdentity = `${edge.surface.kind}:${edge.surface.name}`;
    if (
      observation.kind !== "live-invocation"
      || observation.outcome !== "passed"
      || observation.observedIdentity !== expectedIdentity
    ) {
      throw new Error(`reachable observation identity/outcome drift for ${observation.edgeId}`);
    }
    if (!observation.proof || typeof observation.proof !== "object") {
      throw new Error(`reachable observation omits proof for ${observation.edgeId}`);
    }
    if (
      "status" in observation.proof
      && !["invoked-returned", "invoked-threw", "observed-noncallable"]
        .includes(observation.proof.status)
    ) {
      throw new Error(`reachable observation was not invoked for ${observation.edgeId}`);
    }
    if (
      observation.proof.status === "observed-noncallable"
      && (!observation.proof.valueType || observation.proof.valueType === "function")
    ) {
      throw new Error(`reachable non-callable proof is invalid for ${observation.edgeId}`);
    }
    if ("callbacksDelivered" in observation.proof) {
      for (const field of ["targetsConsumed", "callbacksQueued", "callbacksDelivered"]) {
        if (observation.proof[field] !== 1) {
          throw new Error(`reachable callback proof ${field} mismatch for ${observation.edgeId}`);
        }
      }
    }
    if (
      "observedCount" in observation.proof
      && (!Number.isSafeInteger(observation.proof.observedCount)
        || observation.proof.observedCount < 1)
    ) {
      throw new Error(`reachable callback observation count mismatch for ${observation.edgeId}`);
    }
  }
  const startup = artifact.observations.filter((row) => "bit" in row.proof);
  if (
    startup.length !== 9
    || canonicalJson(startup.map((row) => row.proof.bit).sort((a, b) => a - b))
      !== canonicalJson([0, 1, 2, 3, 4, 5, 6, 7, 8])
    || startup.some((row) => row.proof.trace !== 511)
  ) {
    throw new Error("reachable startup trace does not prove all nine edges");
  }
}

export function ingestRestrictedReachableEvidence(rawBytes, authorities = undefined) {
  const reportAuthorities = authorities ?? loadRestrictedReportAuthorities();
  const artifact = parseJsonStrict(rawBytes, "restricted reachable evidence");
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
    "restricted reachable evidence",
  );
  if (
    artifact.evidenceSchema !== EVIDENCE_SCHEMA
    || artifact.profile !== PROFILE
    || artifact.exitCode !== 0
    || artifact.resultMarker !== RESULT_MARKER
  ) {
    throw new Error("restricted reachable evidence envelope is not a passing v1 artifact");
  }
  if (!Array.isArray(artifact.command) || artifact.command.length === 0) {
    throw new Error("restricted reachable evidence command is missing");
  }
  const candidate = reportAuthorities.projection.candidateTargets.find(
    (target) => canonicalJson(target) === canonicalJson(artifact.target),
  );
  if (!candidate) throw new Error("reachable evidence names a non-candidate target");
  validateRevisionAndAuthorities(artifact, reportAuthorities);
  const patchIdentity = validateEngine(artifact);
  validateObservations(artifact, reportAuthorities);

  const artifactDigest = taggedDigest(Buffer.from(canonicalJson(artifact), "utf8"));
  const executions = artifact.observations.map((observation) => ({
    executionId: `${artifact.runId}.${observation.edgeId}`,
    fixtureId: `restricted.live-invocation.${observation.edgeId}`,
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
  }));
  assertSortedUnique(executions.map((row) => row.executionId), "reachable executions");

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
    executions,
  };
}

export function readRestrictedReachableEvidence(filePath, authorities = undefined) {
  return ingestRestrictedReachableEvidence(fs.readFileSync(filePath), authorities);
}
