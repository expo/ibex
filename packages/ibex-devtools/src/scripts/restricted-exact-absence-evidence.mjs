/** Validate LLP 0033 source-install and exact-engine absence evidence. */

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { canonicalJson, parseJsonStrict, repoRoot } from "./capsec-contract.mjs";
import {
  assertExactKeys,
  assertSortedUnique,
  validateEngine,
  validateRevisionAndAuthorities,
} from "./restricted-exact-reachable-evidence.mjs";
import {
  loadRestrictedReportAuthorities,
  taggedDigest,
  validateRestrictedFixturePlan,
} from "./restricted-exact-target-report.mjs";

const EVIDENCE_SCHEMA = "ibex/restricted-profile-absence-evidence/1";
const PROFILE = "ibex/exact-embedder-contract/1";
const RESULT_MARKER = "ibex-restricted-absence-evidence:passed";
const rootManifestRelativePath =
  "capsec/generated/root-global-disposition-manifest.json";

const expectedForbiddenRoots = [
  "Atomics",
  "Bun",
  "Deno",
  "Exact",
  "Ibex",
  "SharedArrayBuffer",
  "WebAssembly",
  "WebSocket",
  "XMLHttpRequest",
  "__compartments",
  "__exactCapabilityCheck",
  "__exactGetEnv",
  "__exactResolveModule",
  "__exactTimerRef",
  "__exactTimerUnref",
  "__hostCall",
  "__hostCallAsync",
  "fetch",
  "process",
  "require",
];

function barrierFor(kind) {
  switch (kind) {
    case "builtin":
    case "loader":
    case "cli": return "no-general-loader-or-cli-root";
    case "host-abi": return "no-javascript-native-abi-bridge";
    case "startup": return "not-selected-by-restricted-bootstrap";
    case "callback": return "no-installed-producer-or-retained-callback";
    case "native-op": return "descriptor-path-or-ambient-installer-absent";
    default: throw new Error(`unexpected absent surface kind ${kind}`);
  }
}

function revisionBytes(revision, relativePath) {
  try {
    return execFileSync("git", ["show", `${revision}:${relativePath}`], {
      cwd: repoRoot,
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch {
    throw new Error(`absence evidence revision omits ${relativePath}`);
  }
}

function expectedDescriptorPrefixes(rootManifest, absentIds) {
  const result = new Map();
  for (const row of rootManifest.rows) {
    if (!absentIds.has(row.registryEdgeId) || row.property.root.kind !== "string") continue;
    const segments = [row.property.root.value];
    let unresolvedSegment = null;
    for (const segment of row.property.path) {
      if (segment.kind !== "string") {
        unresolvedSegment = { kind: segment.kind, value: segment.value };
        break;
      }
      segments.push(segment.value);
    }
    const rows = result.get(row.registryEdgeId) ?? [];
    rows.push({ path: segments.join("."), unresolvedSegment });
    result.set(row.registryEdgeId, rows);
  }
  return result;
}

export function ingestRestrictedAbsenceEvidence(rawBytes, authorities = undefined) {
  const reportAuthorities = authorities ?? loadRestrictedReportAuthorities();
  const artifact = parseJsonStrict(rawBytes, "restricted absence evidence");
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
      "barrierAttestation",
      "barrierAttestationDigest",
      "command",
      "exitCode",
      "resultMarker",
      "observations",
    ],
    "restricted absence evidence",
  );
  if (
    artifact.evidenceSchema !== EVIDENCE_SCHEMA
    || artifact.profile !== PROFILE
    || artifact.exitCode !== 0
    || artifact.resultMarker !== RESULT_MARKER
  ) {
    throw new Error("restricted absence evidence envelope is not a passing v1 artifact");
  }
  if (!Array.isArray(artifact.command) || artifact.command.length === 0) {
    throw new Error("restricted absence evidence command is missing");
  }
  if (!reportAuthorities.projection.candidateTargets.some(
    (target) => canonicalJson(target) === canonicalJson(artifact.target),
  )) {
    throw new Error("absence evidence names a non-candidate target");
  }
  validateRevisionAndAuthorities(artifact, reportAuthorities);
  const patchIdentity = validateEngine(artifact);

  const barrier = artifact.barrierAttestation;
  assertExactKeys(
    barrier,
    [
      "observer",
      "rootGlobalManifestRawContentDigest",
      "forbiddenRoots",
      "restrictedStartupTrace",
      "completionObserver",
      "descriptorProbedEdges",
    ],
    "absence barrier attestation",
  );
  if (
    barrier.observer !== "exact-engine-closed-world-barriers"
    || barrier.restrictedStartupTrace !== 511
    || canonicalJson(barrier.completionObserver)
      !== canonicalJson({
        targetsConsumed: 0,
        callbacksQueued: 0,
        callbacksDelivered: 0,
      })
  ) {
    throw new Error("absence barrier attestation did not close startup/callback routes");
  }
  const rootManifestBytes = fs.readFileSync(path.join(repoRoot, rootManifestRelativePath));
  const historicalRootManifestBytes = revisionBytes(
    artifact.sourceRevision,
    rootManifestRelativePath,
  );
  if (
    !historicalRootManifestBytes.equals(rootManifestBytes)
    || taggedDigest(rootManifestBytes) !== barrier.rootGlobalManifestRawContentDigest
  ) {
    throw new Error("absence barrier does not bind the root-global authority");
  }
  if (
    taggedDigest(Buffer.from(canonicalJson(barrier), "utf8"))
      !== artifact.barrierAttestationDigest
  ) {
    throw new Error("absence barrier attestation digest mismatch");
  }
  assertSortedUnique(
    barrier.forbiddenRoots.map((row) => row.path),
    "absence forbidden roots",
  );
  if (
    canonicalJson(barrier.forbiddenRoots)
      !== canonicalJson(expectedForbiddenRoots.map((pathName) => ({
        path: pathName,
        absent: true,
      })))
  ) {
    throw new Error("absence forbidden-root observations are incomplete");
  }

  const absentIds = reportAuthorities.projection.rows
    .filter((row) => row[1] === "structurally-absent")
    .map((row) => row[0]);
  const absentSet = new Set(absentIds);
  const probePlan = validateRestrictedFixturePlan(reportAuthorities.fixturePlan);
  const plannedByEdge = new Map(probePlan.edges.map((row) => [row.edgeId, row]));
  if (
    canonicalJson(probePlan.edges.map((row) => row.edgeId))
      !== canonicalJson(absentIds)
  ) {
    throw new Error("absence evidence probe plan does not equal the projection obligations");
  }
  const probePlanRawContentDigest = reportAuthorities.fixturePlan
    .absenceProbePlan.rawContentDigest;
  const rootManifest = parseJsonStrict(rootManifestBytes, rootManifestRelativePath);
  const descriptorPrefixes = expectedDescriptorPrefixes(rootManifest, absentSet);
  if (barrier.descriptorProbedEdges !== descriptorPrefixes.size) {
    throw new Error("absence descriptor-probe count differs from root authority");
  }
  const coverageById = new Map(
    reportAuthorities.coverage.edges.map((edge) => [edge.id, edge]),
  );
  const observationKeys = artifact.observations.map(
    (row) => `${row.edgeId}\0${row.kind}`,
  );
  assertSortedUnique(observationKeys, "absence evidence observations");
  const expectedKeys = absentIds.flatMap((edgeId) => [
    `${edgeId}\0live-reachability`,
    `${edgeId}\0source-install`,
  ]);
  if (canonicalJson(observationKeys) !== canonicalJson(expectedKeys)) {
    throw new Error("absence evidence observations do not equal the projection obligations");
  }
  for (const observation of artifact.observations) {
    assertExactKeys(
      observation,
      ["edgeId", "kind", "outcome", "observedIdentity", "proof"],
      `absence observation ${observation.edgeId}`,
    );
    const edge = coverageById.get(observation.edgeId);
    const surfaceKind = edge.surface.kind;
    if (
      observation.outcome !== "passed"
      || observation.observedIdentity !== `${surfaceKind}:${edge.surface.name}`
      || !["source-install", "live-reachability"].includes(observation.kind)
    ) {
      throw new Error(`absence observation identity/outcome drift for ${observation.edgeId}`);
    }
    if (
      observation.proof.surfaceKind !== surfaceKind
      || observation.proof.barrier !== barrierFor(surfaceKind)
      || observation.proof.barrierAttestationDigest !== artifact.barrierAttestationDigest
    ) {
      throw new Error(`absence observation barrier drift for ${observation.edgeId}`);
    }
    if (observation.kind === "source-install") {
      assertExactKeys(
        observation.proof,
        [
          "observer",
          "surfaceKind",
          "barrier",
          "barrierAttestationDigest",
          "probePlanRawContentDigest",
          "probeResults",
        ],
        `source-install proof ${observation.edgeId}`,
      );
      if (
        observation.proof.observer !== "executed-edge-source-install-closure"
        || observation.proof.probePlanRawContentDigest !== probePlanRawContentDigest
      ) {
        throw new Error(`source-install proof drift for ${observation.edgeId}`);
      }
      const expectedResults = plannedByEdge.get(observation.edgeId).sourceInstall.map((probe) => ({
        probeId: probe.probeId,
        branchId: probe.branchId,
        enforcementBranchId: probe.enforcementBranchId,
        outcome: "not-selected-or-retained",
      }));
      if (
        canonicalJson(observation.proof.probeResults) !== canonicalJson(expectedResults)
        || observation.proof.probeResults.length === 0
      ) {
        throw new Error(`source-install proof ${observation.edgeId} was not executed per probe`);
      }
    } else {
      assertExactKeys(
        observation.proof,
        [
          "observer",
          "surfaceKind",
          "barrier",
          "barrierAttestationDigest",
          "probePlanRawContentDigest",
          "probeResults",
        ],
        `live-reachability proof ${observation.edgeId}`,
      );
      if (
        observation.proof.observer !== "executed-exact-engine-edge-routes"
        || observation.proof.probePlanRawContentDigest !== probePlanRawContentDigest
      ) {
        throw new Error(`live-reachability proof drift for ${observation.edgeId}`);
      }
      const expectedResults = plannedByEdge.get(observation.edgeId).liveReachability.map((probe) => ({
        probeId: probe.probeId,
        routeKind: probe.routeKind,
        target: probe.target,
        outcome: "unreachable",
      }));
      if (
        canonicalJson(observation.proof.probeResults) !== canonicalJson(expectedResults)
        || observation.proof.probeResults.length === 0
      ) {
        throw new Error(`live-reachability proof ${observation.edgeId} was not executed per probe`);
      }
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
      executionId: `${artifact.runId}.${observation.kind}.${observation.edgeId}`,
      fixtureId: `restricted.${observation.kind}.${observation.edgeId}`,
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

export function readRestrictedAbsenceEvidence(filePath, authorities = undefined) {
  return ingestRestrictedAbsenceEvidence(fs.readFileSync(filePath), authorities);
}
