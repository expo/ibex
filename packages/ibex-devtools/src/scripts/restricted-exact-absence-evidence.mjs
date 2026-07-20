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
import { validateRestrictedExactAbsenceRouteGraph } from "./generate-restricted-exact-absence-route-graph.mjs";

const EVIDENCE_SCHEMA = "ibex/restricted-profile-absence-evidence/1";
const PROFILE = "ibex/exact-embedder-contract/1";
const RESULT_MARKER = "ibex-restricted-absence-evidence:passed";
const rootManifestRelativePath =
  "capsec/generated/root-global-disposition-manifest.json";
const routeGraphRelativePath =
  "capsec/generated/restricted-exact-absence-route-graph.json";
const revisionByteCache = new Map();
const validatedRouteGraphInputs = new Set();

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
  const cacheKey = `${revision}\0${relativePath}`;
  const cached = revisionByteCache.get(cacheKey);
  if (cached !== undefined) return cached;
  try {
    const treeEntry = execFileSync(
      "git",
      ["ls-tree", revision, "--", relativePath],
      { cwd: repoRoot, encoding: "utf8", maxBuffer: 1024 * 1024 },
    );
    if (!/^100(?:644|755) blob [0-9a-f]{40}\t/u.test(treeEntry)) {
      throw new Error("not a regular Git blob");
    }
    const bytes = execFileSync("git", ["show", `${revision}:${relativePath}`], {
      cwd: repoRoot,
      maxBuffer: 64 * 1024 * 1024,
    });
    revisionByteCache.set(cacheKey, bytes);
    return bytes;
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

function validateLogicalPathReceipt(receipt, expectedMode, label) {
  assertExactKeys(
    receipt,
    [
      "requestedPath", "mode", "boundaryKind", "lastResolvedSegmentIndex",
      "lastResolvedSegment", "firstBlockedSegmentIndex", "firstBlockedSegment",
    ],
    label,
  );
  const segments = typeof receipt.requestedPath === "string"
    ? receipt.requestedPath.split(".")
    : null;
  if (
    !Array.isArray(segments)
    || segments.length === 0
    || segments.some((segment) => segment.length === 0)
    || receipt.mode !== expectedMode
    || !["missing-descriptor", "undefined-terminal-value"].includes(receipt.boundaryKind)
    || !Number.isSafeInteger(receipt.firstBlockedSegmentIndex)
    || receipt.firstBlockedSegmentIndex < 0
    || receipt.firstBlockedSegmentIndex >= segments.length
    || receipt.firstBlockedSegment !== segments[receipt.firstBlockedSegmentIndex]
  ) {
    throw new Error(`${label} identity or blocked segment drift`);
  }
  if (receipt.lastResolvedSegmentIndex === null) {
    if (receipt.lastResolvedSegment !== null || receipt.firstBlockedSegmentIndex !== 0) {
      throw new Error(`${label} root-boundary receipt drift`);
    }
  } else if (
    !Number.isSafeInteger(receipt.lastResolvedSegmentIndex)
    || receipt.lastResolvedSegmentIndex < 0
    || receipt.lastResolvedSegmentIndex >= receipt.firstBlockedSegmentIndex
    || receipt.lastResolvedSegment !== segments[receipt.lastResolvedSegmentIndex]
  ) {
    throw new Error(`${label} resolved segment drift`);
  }
}

export function validateRestrictedActualBoundaryObservation(
  observation,
  routeKind,
  probeTarget,
  label = "restricted actual boundary observation",
) {
  assertExactKeys(observation, ["routeKind", "exactTarget", "boundary"], label);
  if (observation.routeKind !== routeKind || observation.exactTarget !== probeTarget) {
    throw new Error(`${label} route identity drift`);
  }
  const boundary = observation.boundary;
  if (!boundary || typeof boundary !== "object" || Array.isArray(boundary)) {
    throw new Error(`${label} boundary is not an object`);
  }
  const receiptBoundary = (kind, expectedPaths, extraKeys = []) => {
    assertExactKeys(boundary, ["kind", "receipts", ...extraKeys], `${label} boundary`);
    if (boundary.kind !== kind || !Array.isArray(boundary.receipts) || boundary.receipts.length === 0) {
      throw new Error(`${label} boundary kind or receipt roster drift`);
    }
    if (canonicalJson(boundary.receipts.map((receipt) => receipt.requestedPath))
      !== canonicalJson(expectedPaths)) {
      throw new Error(`${label} boundary receipt roster drift`);
    }
    return boundary.receipts;
  };
  let receipts = [];
  let expectedMode = "absent";
  switch (routeKind) {
    case "descriptor-prefix":
      receipts = receiptBoundary("root-descriptor", [probeTarget]);
      break;
    case "restricted-module-resolution":
    case "restricted-loader-entry":
      receipts = receiptBoundary("module-loader-roots", [
        "require",
        "__exactResolveModule",
        "__exactResolveManifestBuiltinInternal",
        "__exactRegisterPackage",
      ]);
      break;
    case "restricted-cli-entry":
      receipts = receiptBoundary("cli-ingress-roots", ["process", "Bun", "Deno", "Ibex", "require"]);
      break;
    case "restricted-js-native-abi":
      receipts = receiptBoundary(
        "javascript-native-abi-roots",
        ["__hostCall", "__hostCallAsync", "process", "require", "Bun"],
      );
      break;
    case "restricted-callback-route":
      receipts = receiptBoundary(
        "callback-producer-roots-and-slots",
        ["__hostCall", "__hostCallAsync", "fetch", "WebSocket", "process"],
        ["completionSlots"],
      );
      assertExactKeys(
        boundary.completionSlots,
        ["targetsConsumed", "callbacksQueued", "callbacksDelivered"],
        `${label} completion slots`,
      );
      if (Object.values(boundary.completionSlots).some((value) => value !== 0)) {
        throw new Error(`${label} retained callback authority`);
      }
      break;
    case "restricted-startup-route":
      assertExactKeys(boundary, ["kind", "restrictedTrace", "selected"], `${label} boundary`);
      if (boundary.kind !== "startup-selection" || boundary.restrictedTrace !== 0x1ff || boundary.selected !== false) {
        throw new Error(`${label} startup selection drift`);
      }
      return;
    case "restricted-native-installer-route": {
      const logical = probeTarget.replace(/^native-op:/, "").replace(/^global:/, "");
      if (logical === "[[dynamic-table:native-global-name]]") {
        receipts = receiptBoundary(
          "dynamic-native-installer-roots",
          ["__hostCall", "__hostCallAsync", "__exactResolveModule", "process"],
          ["restrictedTrace"],
        );
        if (boundary.restrictedTrace !== 0x1ff) {
          throw new Error(`${label} dynamic installer trace drift`);
        }
      } else {
        receipts = receiptBoundary("native-logical-path", [logical]);
        expectedMode = "unreachable";
      }
      break;
    }
    default:
      throw new Error(`${label} unknown route kind ${routeKind}`);
  }
  for (let index = 0; index < receipts.length; index += 1) {
    validateLogicalPathReceipt(receipts[index], expectedMode, `${label} receipt ${index}`);
  }
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
      "actualCutsetObservations",
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
  const expectedCutsetIds = [
    "restricted-exact.profile-selected",
    "restricted-exact.full-installer-skipped",
    "restricted-exact.bootstrap-posture-sealed",
    "restricted-exact.bundle-posture-sealed",
    "restricted-exact.temporal-poll-posture-sealed",
  ];
  if (
    !Array.isArray(barrier.actualCutsetObservations)
    || canonicalJson(barrier.actualCutsetObservations.map((row) => row.observationId))
      !== canonicalJson(expectedCutsetIds)
    || barrier.actualCutsetObservations.some((row, index) => (
      !Number.isSafeInteger(row.runtimeGeneration)
      || row.runtimeGeneration <= 0
      || !Number.isSafeInteger(row.sequence)
      || row.sequence <= 0
      || (index > 0
        && row.sequence <= barrier.actualCutsetObservations[index - 1].sequence)
      || row.runtimeGeneration
        !== barrier.actualCutsetObservations[0].runtimeGeneration
    ))
  ) {
    throw new Error("absence barrier lacks ordered actual cut-set observations");
  }
  const cutsetRuntimeGeneration =
    barrier.actualCutsetObservations[0].runtimeGeneration;
  const rootManifestBytes = reportAuthorities.rawAuthorities.rootManifest
    ?? fs.readFileSync(path.join(repoRoot, rootManifestRelativePath));
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
  const probePlan = validateRestrictedFixturePlan(
    reportAuthorities.fixturePlan,
    reportAuthorities.rawAuthorities,
  );
  const plannedByEdge = new Map(probePlan.edges.map((row) => [row.edgeId, row]));
  if (
    canonicalJson(probePlan.edges.map((row) => row.edgeId))
      !== canonicalJson(absentIds)
  ) {
    throw new Error("absence evidence probe plan does not equal the projection obligations");
  }
  const probePlanRawContentDigest = reportAuthorities.fixturePlan
    .absenceProbePlan.rawContentDigest;
  const routeGraphBytes = reportAuthorities.rawAuthorities.absenceRouteGraph
    ?? fs.readFileSync(path.join(repoRoot, routeGraphRelativePath));
  const historicalRouteGraphBytes = revisionBytes(
    artifact.sourceRevision,
    routeGraphRelativePath,
  );
  const routeGraphRawContentDigest = reportAuthorities.fixturePlan
    .absenceRouteGraph.rawContentDigest;
  if (
    !historicalRouteGraphBytes.equals(routeGraphBytes)
    || taggedDigest(routeGraphBytes) !== routeGraphRawContentDigest
  ) {
    throw new Error("absence evidence does not bind the historical route graph");
  }
  const routeGraph = parseJsonStrict(routeGraphBytes, routeGraphRelativePath);
  const validatedRouteGraphKey = [
    artifact.sourceRevision,
    routeGraphRawContentDigest,
    artifact.authorityDigests.implementationManifestRawContentDigest,
  ].join("\0");
  if (!validatedRouteGraphInputs.has(validatedRouteGraphKey)) {
    validateRestrictedExactAbsenceRouteGraph(routeGraph, {
      probePlan,
      implementationManifest: reportAuthorities.implementationManifest,
      readSourceFile: (relativePath) => revisionBytes(
        artifact.sourceRevision,
        relativePath,
      ),
      sourceFilesAreAuthenticatedGitBlobs: true,
    });
    validatedRouteGraphInputs.add(validatedRouteGraphKey);
  }
  const routeBySourceProbe = new Map(
    routeGraph.routes.map((route) => [route.sourceProbeId, route]),
  );
  const routesByLiveProbe = new Map();
  for (const route of routeGraph.routes) {
    for (const probeId of route.liveProbeIds) {
      const routes = routesByLiveProbe.get(probeId) ?? [];
      routes.push(route);
      routesByLiveProbe.set(probeId, routes);
    }
  }
  let observedRuntimeGeneration = cutsetRuntimeGeneration;
  const cutsetObservationById = new Map(
    barrier.actualCutsetObservations.map((row) => [row.observationId, row]),
  );
  const expectsActualBoundaryObservation = revisionBytes(
    artifact.sourceRevision,
    "src/host/embedder_artifacts.rs",
  ).includes(Buffer.from('"actualBoundaryObservation"', "utf8"));
  const validateRouteReceipt = (
    receipt,
    route,
    probeId,
    probeTarget,
    routeKind,
    proofKind,
  ) => {
    const receiptKeys = [
      "routeId", "probeId", "selectedTarget", "probeTarget", "branchId",
      "proofKind", "cutsetObservations",
      "lastObservedNode", "blockedEdge", "runtimeGeneration", "outcome",
    ];
    if (expectsActualBoundaryObservation) receiptKeys.splice(7, 0, "actualBoundaryObservation");
    assertExactKeys(
      receipt,
      receiptKeys,
      `absence route receipt ${probeId}/${route.routeId}`,
    );
    const sourceSelection = proofKind === "source-selection";
    const routePath = sourceSelection ? route.sourcePath : route.livePath;
    const observationIds = sourceSelection
      ? route.sourceCutsetObservationIds
      : route.liveCutsetObservationIds;
    const expectedObservations = observationIds.map((observationId) =>
      cutsetObservationById.get(observationId));
    const expectedOutcome = sourceSelection
      ? "not-selected-or-retained"
      : "unreachable";
    if (
      receipt.routeId !== route.routeId
      || receipt.probeId !== probeId
      || receipt.selectedTarget !== route.observedIdentity
      || receipt.probeTarget !== probeTarget
      || receipt.branchId !== route.branchId
      || receipt.proofKind !== proofKind
      || canonicalJson(receipt.cutsetObservations)
        !== canonicalJson(expectedObservations)
      || receipt.lastObservedNode !== routePath.at(-3)
      || canonicalJson(receipt.blockedEdge) !== canonicalJson({
        from: routePath.at(-3),
        to: routePath.at(-2),
      })
      || receipt.outcome !== expectedOutcome
      || !Number.isSafeInteger(receipt.runtimeGeneration)
      || receipt.runtimeGeneration <= 0
    ) {
      throw new Error(`absence route receipt drift for ${probeId}/${route.routeId}`);
    }
    if (receipt.runtimeGeneration !== observedRuntimeGeneration) {
      throw new Error("absence route receipts crossed runtime generations");
    }
    if (!expectsActualBoundaryObservation) {
      return;
    }
    if (sourceSelection) {
      if (receipt.actualBoundaryObservation !== null || routeKind !== null) {
        throw new Error(`source route receipt carried live boundary evidence for ${probeId}`);
      }
    } else {
      validateRestrictedActualBoundaryObservation(
        receipt.actualBoundaryObservation,
        routeKind,
        probeTarget,
        `absence route receipt ${probeId}/${route.routeId}`,
      );
    }
  };
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
          "routeGraphRawContentDigest",
          "probeResults",
        ],
        `source-install proof ${observation.edgeId}`,
      );
      if (
        observation.proof.observer !== "executed-edge-source-install-closure"
        || observation.proof.probePlanRawContentDigest !== probePlanRawContentDigest
        || observation.proof.routeGraphRawContentDigest !== routeGraphRawContentDigest
      ) {
        throw new Error(`source-install proof drift for ${observation.edgeId}`);
      }
      const plannedResults = plannedByEdge.get(observation.edgeId).sourceInstall;
      if (observation.proof.probeResults.length !== plannedResults.length) {
        throw new Error(`source-install proof ${observation.edgeId} has wrong receipt count`);
      }
      for (let index = 0; index < plannedResults.length; index += 1) {
        const probe = plannedResults[index];
        const result = observation.proof.probeResults[index];
        assertExactKeys(
          result,
          ["probeId", "branchId", "enforcementBranchId", "outcome", "routeReceipt"],
          `source-install result ${probe.probeId}`,
        );
        if (
          result.probeId !== probe.probeId
          || result.branchId !== probe.branchId
          || result.enforcementBranchId !== probe.enforcementBranchId
          || result.outcome !== "not-selected-or-retained"
        ) {
          throw new Error(`source-install proof drift for ${probe.probeId}`);
        }
        const route = routeBySourceProbe.get(probe.probeId);
        if (!route) throw new Error(`source-install probe lacks route ${probe.probeId}`);
        validateRouteReceipt(
          result.routeReceipt,
          route,
          probe.probeId,
          observation.observedIdentity,
          null,
          "source-selection",
        );
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
          "routeGraphRawContentDigest",
          "probeResults",
        ],
        `live-reachability proof ${observation.edgeId}`,
      );
      if (
        observation.proof.observer !== "executed-exact-engine-edge-routes"
        || observation.proof.probePlanRawContentDigest !== probePlanRawContentDigest
        || observation.proof.routeGraphRawContentDigest !== routeGraphRawContentDigest
      ) {
        throw new Error(`live-reachability proof drift for ${observation.edgeId}`);
      }
      const plannedResults = plannedByEdge.get(observation.edgeId).liveReachability;
      if (observation.proof.probeResults.length !== plannedResults.length) {
        throw new Error(`live-reachability proof ${observation.edgeId} has wrong receipt count`);
      }
      for (let index = 0; index < plannedResults.length; index += 1) {
        const probe = plannedResults[index];
        const result = observation.proof.probeResults[index];
        assertExactKeys(
          result,
          ["probeId", "routeKind", "target", "outcome", "routeReceipts"],
          `live-reachability result ${probe.probeId}`,
        );
        if (
          result.probeId !== probe.probeId
          || result.routeKind !== probe.routeKind
          || result.target !== probe.target
          || result.outcome !== "unreachable"
        ) {
          throw new Error(`live-reachability proof drift for ${probe.probeId}`);
        }
        const routes = routesByLiveProbe.get(probe.probeId) ?? [];
        if (result.routeReceipts.length !== routes.length || routes.length === 0) {
          throw new Error(`live-reachability probe lacks complete routes ${probe.probeId}`);
        }
        for (let routeIndex = 0; routeIndex < routes.length; routeIndex += 1) {
          validateRouteReceipt(
            result.routeReceipts[routeIndex],
            routes[routeIndex],
            probe.probeId,
            probe.target,
            probe.routeKind,
            "live-reachability",
          );
        }
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
