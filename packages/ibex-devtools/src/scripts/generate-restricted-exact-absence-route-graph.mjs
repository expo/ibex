/**
 * Generate the LLP 0033 target-specific absence dominance graph.
 *
 * Unlike the probe plan, this authority records the complete linear route
 * from an attacker root through exact target selection and a digest-bound
 * implementation branch to the cut-set observation that must fail it.
 *
 * @ref LLP 0033#absence-proof-repair-after-the-second-independent-review
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

import { capsecRoot, readJsonStrict } from "./capsec-contract.mjs";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";
import {
  buildRestrictedExactBranchSourceRoute,
  resolveRestrictedExactBranchSourceBinding,
} from "./restricted-exact-source-anchors.mjs";

const repoRoot = path.dirname(capsecRoot);
const inputs = {
  projection: path.join(capsecRoot, "generated/restricted-exact-profile-projection.json"),
  coverage: path.join(capsecRoot, "registry/coverage-edges.json"),
  implementationManifest: path.join(capsecRoot, "generated/implementation-manifest.json"),
  rootManifest: path.join(capsecRoot, "generated/root-global-disposition-manifest.json"),
  probePlan: path.join(capsecRoot, "generated/restricted-exact-absence-probe-plan.json"),
};
const schemaPath = path.join(capsecRoot, "schema/restricted-profile-absence-route-graph.schema.json");
const outputPath = path.join(capsecRoot, "generated/restricted-exact-absence-route-graph.json");

function digest(bytes) {
  return `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
}

function stableDigest(value) {
  return crypto.createHash("sha256").update(value).digest("hex").slice(0, 20);
}

function sortedUnique(values, label) {
  const result = [...new Set(values)].sort();
  if (result.length !== values.length) throw new Error(`${label} contains duplicates`);
  return result;
}

function resolvedSourceBinding(branch, sourceRef) {
  const separator = sourceRef.indexOf("#");
  if (separator < 1 || separator === sourceRef.length - 1) {
    throw new Error(`source ref lacks an exact path and locator: ${sourceRef}`);
  }
  const sourcePath = sourceRef.slice(0, separator);
  const locator = sourceRef.slice(separator + 1);
  const absolute = path.resolve(repoRoot, sourcePath);
  const relative = path.relative(repoRoot, absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`source ref escapes repository: ${sourceRef}`);
  }
  const stat = fs.lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`source ref is not a regular non-symlink file: ${sourceRef}`);
  }
  const binding = resolveRestrictedExactBranchSourceBinding(branch, sourceRef, repoRoot);
  return {
    sourceRef,
    path: sourcePath,
    locator,
    rawContentDigest: digest(fs.readFileSync(absolute)),
    locatorKind: binding.locatorKind,
    resolutionPolicy: binding.resolutionPolicy,
    sites: binding.sites,
    producerPaths: binding.producerPaths,
    refusalPaths: binding.refusalPaths,
  };
}

function applicabilityForMac(row) {
  const { kind, value } = row.targetApplicability;
  if (["all", "fallback"].includes(kind)) {
    return { classification: "selected", reason: `target-applicability:${kind}` };
  }
  if (kind === "operating-system" && value === "macos") return { classification: "selected", reason: "target-applicability:operating-system:macos" };
  if (kind === "operating-system-family" && ["apple", "posix"].includes(value)) {
    return { classification: "selected", reason: `target-applicability:operating-system-family:${value}` };
  }
  if (["operating-system", "operating-system-family", "linux-backend"].includes(kind)) {
    return { classification: "platform-excluded", reason: `target-applicability:${kind}:${value}` };
  }
  if (kind === "build-condition") {
    return { classification: "compiled-but-disabled", reason: `target-applicability:build-condition:${value}` };
  }
  if (kind === "runtime-variant") {
    return { classification: "compiled-but-disabled", reason: `target-applicability:runtime-variant:${value}` };
  }
  throw new Error(`unclassified Apple target applicability ${kind}${value ? `:${value}` : ""}`);
}

function legacyApplicabilityForMac(row) {
  const { kind, value } = row.targetApplicability;
  if (kind === "all") return { classification: "selected", reason: "target-applicability:all" };
  if (kind === "operating-system" && value === "macos") return { classification: "selected", reason: "target-applicability:operating-system:macos" };
  if (kind === "operating-system-family" && ["apple", "posix"].includes(value)) {
    return { classification: "selected", reason: `target-applicability:operating-system-family:${value}` };
  }
  if (["operating-system", "operating-system-family", "linux-backend"].includes(kind)) {
    return { classification: "platform-excluded", reason: `target-applicability:${kind}:${value}` };
  }
  if (kind === "build-condition") {
    return { classification: "compiled-but-disabled", reason: `target-applicability:build-condition:${value}` };
  }
  return { classification: "runtime-disabled", reason: `target-applicability:${kind}${value ? `:${value}` : ""}` };
}

function attackerRoots(kind, liveProbes) {
  const planned = liveProbes.map((probe) => `${probe.routeKind}:${probe.target}`);
  const roots = {
    builtin: ["require", "__exactResolveModule", "__exactResolveManifestBuiltinInternal"],
    loader: ["require", "__exactResolveModule", "__exactRegisterPackage"],
    cli: ["process", "Bun", "Deno", "Ibex", "require"],
    "host-abi": ["__hostCall", "__hostCallAsync"],
    callback: ["__hostCall", "__hostCallAsync", "fetch", "WebSocket"],
    startup: ["restricted-bootstrap-selection"],
    "native-op": ["restricted-native-installer", "root-global-descriptor"],
  }[kind];
  if (!roots) throw new Error(`unknown absence surface kind ${kind}`);
  return [...new Set([...roots, ...planned])].sort();
}

function observerFor(kind) {
  return {
    builtin: "restricted-module-target-cutset",
    loader: "restricted-loader-target-cutset",
    cli: "restricted-cli-target-cutset",
    "host-abi": "restricted-abi-target-cutset",
    callback: "restricted-callback-target-cutset",
    startup: "restricted-startup-target-cutset",
    "native-op": "restricted-native-installer-target-cutset",
  }[kind];
}

function sourceSpan(
  spanId,
  sourcePath,
  startToken,
  endToken,
  readSourceFile = (relativePath) => fs.readFileSync(path.join(repoRoot, relativePath)),
) {
  const bytes = readSourceFile(sourcePath);
  const text = bytes.toString("utf8");
  const startByte = text.indexOf(startToken);
  if (startByte < 0 || text.indexOf(startToken, startByte + 1) >= 0) {
    throw new Error(`source span ${spanId} start token is missing or ambiguous`);
  }
  const endByte = text.indexOf(endToken, startByte + startToken.length);
  if (endByte < 0) throw new Error(`source span ${spanId} end token is missing`);
  const slice = bytes.subarray(startByte, endByte);
  return {
    spanId,
    path: sourcePath,
    startToken,
    endToken,
    startByte,
    endByte,
    startLine: text.slice(0, startByte).split("\n").length,
    endLine: text.slice(0, endByte).split("\n").length,
    rawContentDigest: digest(slice),
  };
}

function edgeKindForSiteRole(role) {
  return {
    alias: "alias",
    "branch-selector": "select",
    definition: "call",
    dispatch: "dispatch",
    guard: "select",
    "identity-authority": "call",
    "lazy-trigger": "lazy-activate",
    publication: "expose",
    registration: "register",
    retention: "retain",
    selector: "select",
    "symbol-provenance": "call",
    "value-producer": "call",
  }[role] ?? "call";
}

function sourceAnchor(sourceSpanId) {
  return `span:${sourceSpanId}`;
}

function siteAnchor(site) {
  if (!site) throw new Error("topology edge lacks its exact source site");
  return `site:${site.siteId}`;
}

const EDGE = Object.freeze({
  routeFamily: 0,
  from: 1,
  to: 2,
  routeClasses: 3,
  edgeKind: 4,
  sourceAnchorId: 5,
  conditionBinding: 6,
});

function topologyEdge({ from, to, routeClasses, edgeKind, routeFamily, anchor, conditionId, conditionNodeId }) {
  return [
    routeFamily,
    from,
    to,
    routeClasses,
    edgeKind,
    anchor,
    conditionId ? `condition:${conditionId}`
      : conditionNodeId ? `node:${conditionNodeId}` : null,
  ];
}

function buildSourceDerivedTopology(probePlan, implementationManifest, sourceRoutesByBranch) {
  const sourceSpans = [
    sourceSpan(
      "span.profile-selection",
      "src/engine/hermes_runtime.cc",
      "static ExactHermesRuntime* ex_hermes_create_impl(\n    uint64_t host_context_id,\n    RuntimeProfile profile) {",
      "bool captureStructuredSessionIntrinsics(",
    ),
    sourceSpan(
      "span.restricted-installer",
      "src/engine/hermes_runtime.cc",
      "void installRestrictedExactGlobals(struct ExactHermesRuntime* handle) {",
      "void installGlobals(struct ExactHermesRuntime* handle) {",
    ),
    sourceSpan(
      "span.restricted-posture",
      "src/engine/hermes_runtime.cc",
      "static bool verifyRestrictedExactRuntimePosture(ExactHermesRuntime* handle) {",
      "static void cleanupPartiallyConstructedRuntime(",
    ),
    sourceSpan(
      "span.bundle-evaluation",
      "src/engine/hermes_runtime.cc",
      "extern \"C\" int ex_hermes_run_restricted_exact_bundle(\n    ExactHermesRuntime* runtime,\n    char** out_error) {",
      "extern \"C\" int ex_hermes_eval(",
    ),
    sourceSpan(
      "span.temporal-poll",
      "src/engine/hermes_runtime.cc",
      "extern \"C\" int ex_hermes_poll(ExactHermesRuntime* runtime, uint64_t now_ms) {\n",
      "extern \"C\" int ex_hermes_poll_with_external_keep_alive(",
    ),
  ];
  const sourceCutsets = ["cutset.profile-selected", "cutset.full-installer-skipped"];
  const liveCutsets = [
    "cutset.bootstrap-posture-sealed",
    "cutset.bundle-posture-sealed",
    "cutset.temporal-poll-posture-sealed",
  ];
  const nodes = [
    {
      nodeId: sourceCutsets[0], kind: "instrumented-cutset",
      observationId: "restricted-exact.profile-selected", sourceSpanId: "span.profile-selection",
    },
    {
      nodeId: sourceCutsets[1], kind: "instrumented-cutset",
      observationId: "restricted-exact.full-installer-skipped", sourceSpanId: "span.profile-selection",
    },
    {
      nodeId: liveCutsets[0], kind: "instrumented-cutset",
      observationId: "restricted-exact.bootstrap-posture-sealed", sourceSpanId: "span.restricted-posture",
    },
    {
      nodeId: liveCutsets[1], kind: "instrumented-cutset",
      observationId: "restricted-exact.bundle-posture-sealed", sourceSpanId: "span.bundle-evaluation",
    },
    {
      nodeId: liveCutsets[2], kind: "instrumented-cutset",
      observationId: "restricted-exact.temporal-poll-posture-sealed", sourceSpanId: "span.temporal-poll",
    },
  ];
  const edges = [];
  const sourceSites = new Map();
  const branchPaths = [];
  const plannedByEdge = new Map(probePlan.edges.map((edge) => [edge.edgeId, edge]));
  for (const branch of implementationManifest.surfaces) {
    const plannedEdge = plannedByEdge.get(branch.edgeId);
    if (!plannedEdge) continue;
    const sourceRoute = sourceRoutesByBranch.get(branch.branchId);
    if (!sourceRoute || sourceRoute.status !== "executable") {
      throw new Error(`absence topology lacks executable source route: ${branch.branchId}`);
    }
    const suffix = stableDigest(branch.branchId);
    const routeFamily = `family.${suffix}`;
    const sourceRoot = `root.source.${suffix}`;
    const liveRoot = `root.live.${suffix}`;
    const branchNodeId = `target.${suffix}`;
    const terminalNodeId = `terminal.${suffix}`;
    const liveProbeIds = plannedEdge.liveReachability.map((probe) => probe.probeId).sort();
    const declaredAttackerRoots = attackerRoots(plannedEdge.surfaceKind, plannedEdge.liveReachability);
    nodes.push(
      {
        nodeId: sourceRoot, kind: "attacker-root", branchId: branch.branchId,
        observedIdentity: branch.observedKey,
        sourceSpanId: "span.profile-selection", attackerRoots: ["authenticated-restricted-constructor"],
      },
      {
        nodeId: liveRoot, kind: "attacker-root", branchId: branch.branchId,
        observedIdentity: branch.observedKey,
        sourceSpanId: "span.bundle-evaluation", attackerRoots: declaredAttackerRoots,
      },
      {
        nodeId: branchNodeId, kind: "target-selection", edgeId: branch.edgeId,
        branchId: branch.branchId, observedIdentity: branch.observedKey,
      },
    );
    edges.push(
      topologyEdge({
        from: sourceRoot, to: sourceCutsets[0], routeClasses: ["source-selection"],
        edgeKind: "select", routeFamily, anchor: sourceAnchor("span.profile-selection"),
      }),
      topologyEdge({
        from: sourceCutsets[0], to: sourceCutsets[1], routeClasses: ["source-selection"],
        edgeKind: "select", routeFamily, anchor: sourceAnchor("span.profile-selection"),
        conditionId: "runtime-profile:restricted-exact",
      }),
      topologyEdge({
        from: sourceCutsets[1], to: branchNodeId, routeClasses: ["source-selection"],
        edgeKind: "select", routeFamily, anchor: sourceAnchor("span.restricted-installer"),
        conditionId: `implementation-branch:${branch.branchId}`,
      }),
      topologyEdge({
        from: liveRoot, to: liveCutsets[0], routeClasses: ["live-reachability"],
        edgeKind: "call", routeFamily, anchor: sourceAnchor("span.restricted-posture"),
      }),
      topologyEdge({
        from: liveCutsets[0], to: liveCutsets[1], routeClasses: ["live-reachability"],
        edgeKind: "call", routeFamily, anchor: sourceAnchor("span.bundle-evaluation"),
      }),
      topologyEdge({
        from: liveCutsets[1], to: liveCutsets[2], routeClasses: ["live-reachability"],
        edgeKind: "dispatch", routeFamily, anchor: sourceAnchor("span.temporal-poll"),
      }),
      topologyEdge({
        from: liveCutsets[2], to: branchNodeId, routeClasses: ["live-reachability"],
        edgeKind: "select", routeFamily, anchor: sourceAnchor("span.temporal-poll"),
        conditionId: `exact-target:${branch.observedKey}`,
      }),
    );
    const sitesById = new Map(sourceRoute.sites.map((site) => [site.siteId, site]));
    const paths = [
      ...sourceRoute.producerPaths.map((pathRow) => ({ ...pathRow, disposition: "producer" })),
      ...sourceRoute.refusalPaths.map((pathRow) => ({ ...pathRow, disposition: "refusal" })),
    ];
    const emittedPaths = [];
    for (const pathRow of paths) {
      const pathNodeId = `path.${stableDigest(`${branch.branchId}\0${pathRow.pathId}`)}`;
      nodes.push({
        nodeId: pathNodeId,
        kind: "route-condition",
        pathId: pathRow.pathId,
        conditionId: pathRow.conditionId,
        disposition: pathRow.disposition,
      });
      const firstSite = sitesById.get(pathRow.requiredSiteIds[0]);
      edges.push(topologyEdge({
        from: branchNodeId, to: pathNodeId,
        routeClasses: ["source-selection", "live-reachability"],
        edgeKind: "select", routeFamily, anchor: siteAnchor(firstSite),
        conditionNodeId: pathNodeId,
      }));
      const siteNodeIds = [];
      let previousNode = pathNodeId;
      for (const [index, siteId] of pathRow.requiredSiteIds.entries()) {
        const site = sitesById.get(siteId);
        if (!site) throw new Error(`source route path references unknown site: ${pathRow.pathId}`);
        const priorSite = sourceSites.get(site.siteId);
        if (priorSite && JSON.stringify(priorSite) !== JSON.stringify(site)) {
          throw new Error(`source site identity collision: ${site.siteId}`);
        }
        sourceSites.set(site.siteId, site);
        const siteNodeId = `site.${stableDigest(`${branch.branchId}\0${pathRow.pathId}\0${index}\0${siteId}`)}`;
        siteNodeIds.push(siteNodeId);
        nodes.push({
          nodeId: siteNodeId,
          kind: "source-site",
          sourceSiteId: site.siteId,
        });
        const edgeKind = edgeKindForSiteRole(site.role);
        edges.push(topologyEdge({
          from: previousNode, to: siteNodeId,
          routeClasses: ["source-selection", "live-reachability"],
          edgeKind, routeFamily, anchor: siteAnchor(site), conditionNodeId: pathNodeId,
        }));
        previousNode = siteNodeId;
      }
      const finalSite = sitesById.get(pathRow.requiredSiteIds.at(-1));
      edges.push(topologyEdge({
        from: previousNode, to: terminalNodeId,
        routeClasses: ["source-selection", "live-reachability"],
        edgeKind: "expose", routeFamily, anchor: siteAnchor(finalSite), conditionNodeId: pathNodeId,
      }));
      emittedPaths.push({
        pathId: pathRow.pathId,
        conditionId: pathRow.conditionId,
        disposition: pathRow.disposition,
        pathNodeId,
        siteNodeIds,
      });
    }
    nodes.push({
      nodeId: terminalNodeId, kind: "terminal",
    });
    branchPaths.push({
      branchId: branch.branchId,
      edgeId: branch.edgeId,
      observedIdentity: branch.observedKey,
      routeFamily,
      sourceRoot,
      liveRoot,
      sourceCutsets,
      liveCutsets,
      branchNodeId,
      terminalNodeId,
      liveProbeIds,
      paths: emittedPaths,
    });
  }
  nodes.sort((left, right) => left.nodeId.localeCompare(right.nodeId));
  edges.sort((left, right) =>
    `${left[EDGE.routeFamily]}\0${left[EDGE.routeClasses].join(",")}\0${left[EDGE.from]}\0${left[EDGE.to]}`
      .localeCompare(`${right[EDGE.routeFamily]}\0${right[EDGE.routeClasses].join(",")}\0${right[EDGE.from]}\0${right[EDGE.to]}`));
  branchPaths.sort((left, right) => left.branchId.localeCompare(right.branchId));
  return {
    sourceSpans,
    sourceSites: [...sourceSites.values()].sort((left, right) => left.siteId.localeCompare(right.siteId)),
    nodes,
    edges,
    branchPaths,
  };
}

function reachableNodes(topology, root, blocked = new Set(), routeClass = null) {
  const adjacency = new Map();
  for (const edge of topology.edges) {
    if (routeClass !== null && !edge[EDGE.routeClasses].includes(routeClass)) continue;
    const targets = adjacency.get(edge[EDGE.from]) ?? [];
    targets.push(edge[EDGE.to]);
    adjacency.set(edge[EDGE.from], targets);
  }
  const reached = new Set();
  const pending = blocked.has(root) ? [] : [root];
  while (pending.length > 0) {
    const node = pending.pop();
    if (reached.has(node) || blocked.has(node)) continue;
    reached.add(node);
    for (const target of adjacency.get(node) ?? []) pending.push(target);
  }
  return reached;
}

function validateSourceDerivedTopology(
  topology,
  probePlan,
  implementationManifest,
  readSourceFile,
) {
  const nodeIds = topology.nodes.map((node) => node.nodeId);
  sortedUnique(nodeIds, "absence topology node IDs");
  const nodeSet = new Set(nodeIds);
  const nodeById = new Map(topology.nodes.map((node) => [node.nodeId, node]));
  const edgeKeys = topology.edges.map((edge) =>
    `${edge[EDGE.routeFamily]}\0${edge[EDGE.routeClasses].join(",")}\0${edge[EDGE.from]}\0${edge[EDGE.to]}`);
  sortedUnique(edgeKeys, "absence topology edges");
  if (topology.edges.some((edge) => !nodeSet.has(edge[EDGE.from]) || !nodeSet.has(edge[EDGE.to]))) {
    throw new Error("absence topology edge references an unknown node");
  }
  const indegree = new Map(nodeIds.map((nodeId) => [nodeId, 0]));
  const adjacency = new Map();
  for (const edge of topology.edges) {
    indegree.set(edge[EDGE.to], indegree.get(edge[EDGE.to]) + 1);
    const targets = adjacency.get(edge[EDGE.from]) ?? [];
    targets.push(edge[EDGE.to]);
    adjacency.set(edge[EDGE.from], targets);
  }
  const pending = nodeIds.filter((nodeId) => indegree.get(nodeId) === 0);
  let visited = 0;
  while (pending.length > 0) {
    const node = pending.pop();
    visited += 1;
    for (const target of adjacency.get(node) ?? []) {
      indegree.set(target, indegree.get(target) - 1);
      if (indegree.get(target) === 0) pending.push(target);
    }
  }
  if (visited !== nodeIds.length) throw new Error("absence topology contains a cycle");
  const spanIds = new Set(topology.sourceSpans.map((span) => span.spanId));
  const siteIds = new Set(topology.sourceSites.map((site) => site.siteId));
  if (siteIds.size !== topology.sourceSites.length) {
    throw new Error("absence topology contains duplicate source-site identities");
  }
  for (const node of topology.nodes.filter((row) => row.kind === "source-site")) {
    if (!siteIds.has(node.sourceSiteId)) {
      throw new Error(`source-site node references unknown source site: ${node.nodeId}`);
    }
  }
  for (const edge of topology.edges) {
    const routeFamily = edge[EDGE.routeFamily];
    const anchor = edge[EDGE.sourceAnchorId];
    if (anchor.startsWith("span:") && !spanIds.has(anchor.slice("span:".length))) {
      throw new Error(`topology edge references unknown source span: ${routeFamily}`);
    }
    if (anchor.startsWith("site:") && !siteIds.has(anchor.slice("site:".length))) {
      throw new Error(`topology edge references unknown source site: ${routeFamily}`);
    }
    if (!anchor.startsWith("span:") && !anchor.startsWith("site:")) {
      throw new Error(`topology edge has unclassified source anchor: ${routeFamily}`);
    }
    const conditionBinding = edge[EDGE.conditionBinding];
    if (conditionBinding?.startsWith("node:")
      && nodeById.get(conditionBinding.slice("node:".length))?.kind !== "route-condition") {
      throw new Error(`topology edge references an unknown route condition: ${routeFamily}`);
    }
  }
  const plannedEdgeIds = new Set(probePlan.edges.map((edge) => edge.edgeId));
  const expectedBranches = implementationManifest.surfaces
    .filter((branch) => plannedEdgeIds.has(branch.edgeId))
    .map((branch) => branch.branchId)
    .sort();
  const actualBranches = topology.branchPaths.map((row) => row.branchId).sort();
  if (JSON.stringify(actualBranches) !== JSON.stringify(expectedBranches)) {
    throw new Error("absence topology does not cover every implementation branch exactly once");
  }
  const branchById = new Map(implementationManifest.surfaces.map((branch) => [branch.branchId, branch]));
  const edgesByFamily = new Map();
  for (const edge of topology.edges) {
    const familyEdges = edgesByFamily.get(edge[EDGE.routeFamily]) ?? [];
    familyEdges.push(edge);
    edgesByFamily.set(edge[EDGE.routeFamily], familyEdges);
  }
  for (const branchPath of topology.branchPaths) {
    const branch = branchById.get(branchPath.branchId);
    if (!branch
      || branchPath.edgeId !== branch.edgeId
      || branchPath.observedIdentity !== branch.observedKey
      || !nodeSet.has(branchPath.terminalNodeId)) {
      throw new Error(`absence topology branch metadata drifted: ${branchPath.branchId}`);
    }
    if (branchPath.paths.length === 0) {
      throw new Error(`absence topology branch has no executable path: ${branchPath.branchId}`);
    }
    const familyEdgeRows = edgesByFamily.get(branchPath.routeFamily) ?? [];
    const familyTopology = { edges: familyEdgeRows };
    const sourceReached = reachableNodes(familyTopology, branchPath.sourceRoot, new Set(), "source-selection");
    const liveReached = reachableNodes(familyTopology, branchPath.liveRoot, new Set(), "live-reachability");
    if (!sourceReached.has(branchPath.terminalNodeId) || !liveReached.has(branchPath.terminalNodeId)) {
      throw new Error(`absence topology terminal has no exact attacker-root path: ${branchPath.branchId}`);
    }
    for (const cutset of branchPath.sourceCutsets) {
      if (reachableNodes(familyTopology, branchPath.sourceRoot, new Set([cutset]), "source-selection").has(branchPath.terminalNodeId)) {
        throw new Error(`source cut set does not dominate exact terminal: ${branchPath.branchId}/${cutset}`);
      }
    }
    for (const cutset of branchPath.liveCutsets) {
      if (reachableNodes(familyTopology, branchPath.liveRoot, new Set([cutset]), "live-reachability").has(branchPath.terminalNodeId)) {
        throw new Error(`live cut set does not dominate exact terminal: ${branchPath.branchId}/${cutset}`);
      }
    }
    const familyEdges = new Set(familyEdgeRows.flatMap((edge) =>
      edge[EDGE.routeClasses].map((routeClass) =>
        `${routeClass}\0${edge[EDGE.from]}\0${edge[EDGE.to]}`)));
    for (const pathRow of branchPath.paths) {
      const suffix = [branchPath.branchNodeId, pathRow.pathNodeId, ...pathRow.siteNodeIds, branchPath.terminalNodeId];
      const paths = [
        ["source-selection", [branchPath.sourceRoot, ...branchPath.sourceCutsets, ...suffix]],
        ["live-reachability", [branchPath.liveRoot, ...branchPath.liveCutsets, ...suffix]],
      ];
      for (const [routeClass, route] of paths) {
        if (new Set(route).size !== route.length) {
          throw new Error(`absence topology executable path contains a cycle: ${branchPath.branchId}/${pathRow.pathId}`);
        }
        for (let index = 1; index < route.length; index += 1) {
          if (!familyEdges.has(`${routeClass}\0${route[index - 1]}\0${route[index]}`)) {
            throw new Error(`absence topology executable path contains a non-edge: ${branchPath.branchId}/${pathRow.pathId}`);
          }
        }
      }
    }
  }
  for (const span of topology.sourceSpans) {
    const current = sourceSpan(
      span.spanId,
      span.path,
      span.startToken,
      span.endToken,
      readSourceFile,
    );
    if (JSON.stringify(current) !== JSON.stringify(span)) {
      throw new Error(`absence topology source span drifted: ${span.spanId}`);
    }
  }
}

function validateLegacyRestrictedExactAbsenceRouteGraph(
  graph,
  { probePlan, implementationManifest, readSourceFile },
) {
  const nodeIds = graph.topology.nodes.map((node) => node.nodeId);
  sortedUnique(nodeIds, "legacy absence topology node IDs");
  const nodeSet = new Set(nodeIds);
  const edgeKeys = graph.topology.edges.map((edge) =>
    `${edge.routeClass}\0${edge.from}\0${edge.to}`);
  sortedUnique(edgeKeys, "legacy absence topology edges");
  if (graph.topology.edges.some((edge) => !nodeSet.has(edge.from) || !nodeSet.has(edge.to))) {
    throw new Error("legacy absence topology edge references an unknown node");
  }
  const reachable = (root, blocked = new Set(), routeClass = null) => {
    const adjacency = new Map();
    for (const edge of graph.topology.edges) {
      if (routeClass !== null && edge.routeClass !== routeClass) continue;
      const targets = adjacency.get(edge.from) ?? [];
      targets.push(edge.to);
      adjacency.set(edge.from, targets);
    }
    const reached = new Set();
    const pending = blocked.has(root) ? [] : [root];
    while (pending.length > 0) {
      const node = pending.pop();
      if (reached.has(node) || blocked.has(node)) continue;
      reached.add(node);
      for (const target of adjacency.get(node) ?? []) pending.push(target);
    }
    return reached;
  };
  const allSource = reachable(graph.topology.sourceRoot);
  const allLive = reachable(graph.topology.liveRoot);
  const withoutSource = reachable(
    graph.topology.sourceRoot,
    new Set(graph.topology.sourceCutsets),
  );
  const withoutLive = reachable(
    graph.topology.liveRoot,
    new Set(graph.topology.liveCutsets),
  );
  const plannedEdgeIds = probePlan.edges.map((edge) => edge.edgeId);
  if (JSON.stringify(graph.topology.terminals.map((row) => row.edgeId))
    !== JSON.stringify(plannedEdgeIds)) {
    throw new Error("legacy absence topology terminals do not equal the probe plan");
  }
  const branchesByEdge = new Map();
  for (const branch of implementationManifest.surfaces) {
    const branches = branchesByEdge.get(branch.edgeId) ?? [];
    branches.push(branch.branchId);
    branchesByEdge.set(branch.edgeId, branches);
  }
  for (const terminal of graph.topology.terminals) {
    if (!allSource.has(terminal.nodeId) || !allLive.has(terminal.nodeId)
      || withoutSource.has(terminal.nodeId) || withoutLive.has(terminal.nodeId)) {
      throw new Error(`legacy cut sets do not dominate terminal: ${terminal.edgeId}`);
    }
    if (JSON.stringify(terminal.branchIds)
      !== JSON.stringify([...(branchesByEdge.get(terminal.edgeId) ?? [])].sort())) {
      throw new Error(`legacy absence topology omits an implementation branch: ${terminal.edgeId}`);
    }
  }
  for (const span of graph.topology.sourceSpans) {
    if (JSON.stringify(sourceSpan(
      span.spanId,
      span.path,
      span.startToken,
      span.endToken,
      readSourceFile,
    )) !== JSON.stringify(span)) {
      throw new Error(`legacy absence topology source span drifted: ${span.spanId}`);
    }
  }
  const implementationByBranch = new Map(
    implementationManifest.surfaces.map((branch) => [branch.branchId, branch]),
  );
  const plannedByEdge = new Map(probePlan.edges.map((edge) => [edge.edgeId, edge]));
  const sourceProbeIds = new Set();
  const liveProbeCounts = new Map();
  const routeIds = [];
  const sourceFileByPath = new Map(graph.sourceFiles.map((file) => [file.path, file]));
  const topologyEdges = new Set(graph.topology.edges.map((edge) => `${edge.from}\0${edge.to}`));
  for (const route of graph.routes) {
    routeIds.push(route.routeId);
    if (sourceProbeIds.has(route.sourceProbeId)) {
      throw new Error(`duplicate legacy source-probe route ${route.sourceProbeId}`);
    }
    sourceProbeIds.add(route.sourceProbeId);
    const branch = implementationByBranch.get(route.branchId);
    if (!branch || branch.edgeId !== route.edgeId
      || route.observedIdentity !== branch.observedKey) {
      throw new Error(`legacy route selects an unknown branch or target ${route.routeId}`);
    }
    if (JSON.stringify(route.applicability) !== JSON.stringify(legacyApplicabilityForMac(branch))) {
      throw new Error(`legacy route target applicability drift ${route.routeId}`);
    }
    const planned = plannedByEdge.get(route.edgeId);
    if (!planned
      || JSON.stringify(route.attackerRoots)
        !== JSON.stringify(attackerRoots(planned.surfaceKind, planned.liveReachability))) {
      throw new Error(`legacy route attacker roots drift ${route.routeId}`);
    }
    for (const routePath of [route.sourcePath, route.livePath]) {
      if (new Set(routePath).size !== routePath.length) {
        throw new Error(`legacy route path contains a cycle ${route.routeId}`);
      }
      for (let index = 1; index < routePath.length; index += 1) {
        if (!topologyEdges.has(`${routePath[index - 1]}\0${routePath[index]}`)) {
          throw new Error(`legacy route path contains a non-edge ${route.routeId}`);
        }
      }
    }
    const expectedRefs = [...new Set([
      ...branch.sourceRefs,
      ...branch.enforcementRoute.sourceRefs,
      ...branch.enforcementRoute.proofSourceRefs,
    ])].sort();
    if (JSON.stringify(route.sourceBindings.map((binding) => binding.sourceRef))
      !== JSON.stringify(expectedRefs)) {
      throw new Error(`legacy route source bindings drift ${route.routeId}`);
    }
    if (route.sourceBindings.some((binding) =>
      sourceFileByPath.get(binding.path)?.rawContentDigest !== binding.rawContentDigest)) {
      throw new Error(`legacy route source content drift ${route.routeId}`);
    }
    for (const probeId of route.liveProbeIds) {
      liveProbeCounts.set(probeId, (liveProbeCounts.get(probeId) ?? 0) + 1);
    }
  }
  sortedUnique(routeIds, "legacy absence route IDs");
  const expectedSource = probePlan.edges
    .flatMap((edge) => edge.sourceInstall.map((probe) => probe.probeId)).sort();
  if (JSON.stringify([...sourceProbeIds].sort()) !== JSON.stringify(expectedSource)) {
    throw new Error("legacy route graph does not cover every source probe");
  }
  const expectedLive = probePlan.edges
    .flatMap((edge) => edge.liveReachability.map((probe) => probe.probeId)).sort();
  if (JSON.stringify([...liveProbeCounts.keys()].sort()) !== JSON.stringify(expectedLive)
    || expectedLive.some((probeId) => (liveProbeCounts.get(probeId) ?? 0) < 1)) {
    throw new Error("legacy route graph does not cover every live probe");
  }
  return graph;
}

export function validateRestrictedExactAbsenceRouteGraph(
  graph,
  {
    probePlan,
    implementationManifest,
    readSourceFile = (relativePath) => fs.readFileSync(path.join(repoRoot, relativePath)),
    sourceFilesAreAuthenticatedGitBlobs = false,
  },
) {
  for (const sourceFile of graph.sourceFiles) {
    const absolute = path.resolve(repoRoot, sourceFile.path);
    const relative = path.relative(repoRoot, absolute);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error(`route graph source file escapes repository: ${sourceFile.path}`);
    }
    if (!sourceFilesAreAuthenticatedGitBlobs) {
      const stat = fs.lstatSync(absolute);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        throw new Error(`route graph source file is not a regular file: ${sourceFile.path}`);
      }
    }
    let sourceBytes;
    try {
      sourceBytes = readSourceFile(sourceFile.path);
    } catch {
      throw new Error(`route graph source file is unavailable: ${sourceFile.path}`);
    }
    if (!Buffer.isBuffer(sourceBytes)
      || digest(sourceBytes) !== sourceFile.rawContentDigest) {
      throw new Error(`route graph source file drifted: ${sourceFile.path}`);
    }
  }
  if (graph.routeGraphSchema === "ibex/restricted-profile-absence-route-graph/1") {
    return validateLegacyRestrictedExactAbsenceRouteGraph(graph, {
      probePlan,
      implementationManifest,
      readSourceFile,
    });
  }
  if (graph.routeGraphSchema !== "ibex/restricted-profile-absence-route-graph/2") {
    throw new Error(`unsupported restricted absence route graph schema ${graph.routeGraphSchema}`);
  }
  validateSourceDerivedTopology(
    graph.topology,
    probePlan,
    implementationManifest,
    readSourceFile,
  );
  const routesBySourceProbe = new Map();
  const liveProbeCounts = new Map();
  const implementationByBranch = new Map(implementationManifest.surfaces.map((row) => [row.branchId, row]));
  const routeIds = [];
  const probeEdgeById = new Map(probePlan.edges.map((edge) => [edge.edgeId, edge]));
  const topologyByBranch = new Map(graph.topology.branchPaths.map((row) => [row.branchId, row]));
  const topologyEdgesByFamily = new Map();
  for (const edge of graph.topology.edges) {
    const familyEdges = topologyEdgesByFamily.get(edge[EDGE.routeFamily]) ?? new Set();
    for (const routeClass of edge[EDGE.routeClasses]) {
      familyEdges.add(`${routeClass}\0${edge[EDGE.from]}\0${edge[EDGE.to]}`);
    }
    topologyEdgesByFamily.set(edge[EDGE.routeFamily], familyEdges);
  }
  const sourceFileByPath = new Map(graph.sourceFiles.map((file) => [file.path, file]));
  const sourceSiteById = new Map(graph.topology.sourceSites.map((site) => [site.siteId, site]));
  const topologyNodeById = new Map(graph.topology.nodes.map((node) => [node.nodeId, node]));
  const sourceBindingById = new Map(graph.sourceBindings.map((binding) => [binding.bindingId, binding]));
  if (sourceBindingById.size !== graph.sourceBindings.length) {
    throw new Error("route graph contains duplicate source-binding identities");
  }
  const observationByNode = new Map(graph.topology.nodes
    .filter((node) => node.kind === "instrumented-cutset")
    .map((node) => [node.nodeId, node.observationId]));
  for (const route of graph.routes) {
    routeIds.push(route.routeId);
    if (routesBySourceProbe.has(route.sourceProbeId)) throw new Error(`duplicate source-probe route ${route.sourceProbeId}`);
    routesBySourceProbe.set(route.sourceProbeId, route);
    const branch = implementationByBranch.get(route.branchId);
    if (!branch || branch.edgeId !== route.edgeId) throw new Error(`route selects unknown or cross-edge branch ${route.routeId}`);
    if (route.observedIdentity !== branch.observedKey) throw new Error(`route target disagrees with implementation branch ${route.routeId}`);
    if (JSON.stringify(route.targetApplicability) !== JSON.stringify(branch.targetApplicability)
      || JSON.stringify(route.applicability) !== JSON.stringify(applicabilityForMac(branch))) {
      throw new Error(`route target applicability disagrees with implementation branch ${route.routeId}`);
    }
    const plannedEdge = probeEdgeById.get(route.edgeId);
    if (!plannedEdge) throw new Error(`route has no absence-plan edge ${route.routeId}`);
    const expectedRoots = attackerRoots(plannedEdge.surfaceKind, plannedEdge.liveReachability);
    const branchTopology = topologyByBranch.get(route.branchId);
    if (!branchTopology) throw new Error(`route lacks its exact branch topology ${route.routeId}`);
    const liveRootNode = topologyNodeById.get(branchTopology.liveRoot);
    if (JSON.stringify(liveRootNode?.attackerRoots) !== JSON.stringify(expectedRoots)) {
      throw new Error(`route omits or invents an exact attacker root ${route.routeId}`);
    }
    if (route.branchPathId !== branchTopology.routeFamily) {
      throw new Error(`route does not bind its executable branch topology ${route.routeId}`);
    }
    const topologyEdges = topologyEdgesByFamily.get(branchTopology.routeFamily) ?? new Set();
    const validatePath = (routePath, routeClass, label) => {
      if (new Set(routePath.nodes).size !== routePath.nodes.length) throw new Error(`${label} contains a cycle`);
      for (let index = 1; index < routePath.nodes.length; index += 1) {
        if (!topologyEdges.has(`${routeClass}\0${routePath.nodes[index - 1]}\0${routePath.nodes[index]}`)) {
          throw new Error(`${label} contains a non-edge`);
        }
      }
    };
    for (const pathRow of branchTopology.paths) {
      const suffix = [branchTopology.branchNodeId, pathRow.pathNodeId, ...pathRow.siteNodeIds, branchTopology.terminalNodeId];
      validatePath(
        { nodes: [branchTopology.sourceRoot, ...branchTopology.sourceCutsets, ...suffix] },
        "source-selection",
        `${route.routeId} source path ${pathRow.pathId}`,
      );
      validatePath(
        { nodes: [branchTopology.liveRoot, ...branchTopology.liveCutsets, ...suffix] },
        "live-reachability",
        `${route.routeId} live path ${pathRow.pathId}`,
      );
    }
    const expectedSourceObservations = branchTopology.sourceCutsets.map((nodeId) => observationByNode.get(nodeId));
    const expectedLiveObservations = branchTopology.liveCutsets.map((nodeId) => observationByNode.get(nodeId));
    if (
      JSON.stringify(route.sourceCutsetObservationIds) !== JSON.stringify(expectedSourceObservations)
      || JSON.stringify(route.liveCutsetObservationIds) !== JSON.stringify(expectedLiveObservations)
    ) {
      throw new Error(`route does not bind actual cut-set observations ${route.routeId}`);
    }
    const expectedSourceBoundary = {
      observationId: expectedSourceObservations.at(-1),
      lastObservedNode: branchTopology.sourceCutsets.at(-1),
      blockedEdge: {
        from: branchTopology.sourceCutsets.at(-1),
        to: branchTopology.branchNodeId,
      },
    };
    const expectedLiveBoundary = {
      observationId: expectedLiveObservations.at(-1),
      lastObservedNode: branchTopology.liveCutsets.at(-1),
      blockedEdge: {
        from: branchTopology.liveCutsets.at(-1),
        to: branchTopology.branchNodeId,
      },
    };
    if (JSON.stringify(route.sourceBoundary) !== JSON.stringify(expectedSourceBoundary)
      || JSON.stringify(route.liveBoundary) !== JSON.stringify(expectedLiveBoundary)) {
      throw new Error(`route boundary is inferred or disagrees with its graph ${route.routeId}`);
    }
    const expectedBindings = [...new Set([
      ...branch.sourceRefs,
      ...branch.enforcementRoute.sourceRefs,
      ...branch.enforcementRoute.proofSourceRefs,
    ])].sort();
    const bindings = route.sourceBindingIds.map((bindingId) => sourceBindingById.get(bindingId));
    if (bindings.some((binding) => !binding || binding.branchId !== route.branchId)
      || JSON.stringify(bindings.map((binding) => binding.sourceRef)) !== JSON.stringify(expectedBindings)) {
      throw new Error(`route source bindings disagree with branch ${route.routeId}`);
    }
    for (const binding of bindings) {
      const sourceFile = sourceFileByPath.get(binding.path);
      if (!sourceFile || sourceFile.rawContentDigest !== binding.rawContentDigest) {
        throw new Error(`route source binding is not content-bound ${route.routeId}`);
      }
      if (binding.siteIds.some((siteId) => !sourceSiteById.has(siteId))) {
        throw new Error(`route source binding references an unknown exact source site ${route.routeId}`);
      }
    }
    for (const probeId of route.liveProbeIds) liveProbeCounts.set(probeId, (liveProbeCounts.get(probeId) ?? 0) + 1);
  }
  sortedUnique(routeIds, "route IDs");
  const plannedSource = probePlan.edges.flatMap((edge) => edge.sourceInstall.map((probe) => probe.probeId)).sort();
  const actualSource = [...routesBySourceProbe.keys()].sort();
  if (JSON.stringify(actualSource) !== JSON.stringify(plannedSource)) throw new Error("route graph does not cover every source probe exactly once");
  const absentEdgeIds = new Set(probePlan.edges.map((edge) => edge.edgeId));
  const expectedBranches = implementationManifest.surfaces
    .filter((branch) => absentEdgeIds.has(branch.edgeId))
    .map((branch) => branch.branchId)
    .sort();
  const actualBranches = graph.routes.map((route) => route.branchId).sort();
  if (JSON.stringify(actualBranches) !== JSON.stringify(expectedBranches)) {
    throw new Error("route graph does not cover every current implementation branch exactly once");
  }
  const plannedLive = probePlan.edges.flatMap((edge) => edge.liveReachability.map((probe) => probe.probeId)).sort();
  const actualLive = [...liveProbeCounts.keys()].sort();
  if (JSON.stringify(actualLive) !== JSON.stringify(plannedLive)) throw new Error("route graph has missing or extra live-probe branches");
  if (actualLive.some((probeId) => liveProbeCounts.get(probeId) < 1)) throw new Error("route graph contains an orphan live probe");
  return graph;
}

export function buildRestrictedExactAbsenceRouteGraph({ projection, coverage, implementationManifest, rootManifest, probePlan, raw }) {
  const target = implementationManifest.candidateTargets.find((candidate) => candidate.triple === "aarch64-apple-darwin");
  if (!target) throw new Error("implementation manifest lacks the preregistered Apple target");
  const branches = new Map(implementationManifest.surfaces.map((row) => [row.branchId, row]));
  const absentEdgeIds = new Set(probePlan.edges.map((edge) => edge.edgeId));
  const sourceRoutesByBranch = new Map();
  for (const branch of implementationManifest.surfaces.filter((row) => absentEdgeIds.has(row.edgeId))) {
    const sourceRefs = [...new Set([
      ...branch.sourceRefs,
      ...branch.enforcementRoute.sourceRefs,
      ...branch.enforcementRoute.proofSourceRefs,
    ])].sort();
    const sourceRoute = buildRestrictedExactBranchSourceRoute(branch, sourceRefs);
    if (sourceRoute.status !== "executable") {
      throw new Error(`implementation branch lacks executable route v2: ${branch.branchId}`);
    }
    sourceRoutesByBranch.set(branch.branchId, sourceRoute);
  }
  const topology = buildSourceDerivedTopology(probePlan, implementationManifest, sourceRoutesByBranch);
  const topologyByBranch = new Map(topology.branchPaths.map((row) => [row.branchId, row]));
  const topologySiteMap = new Map(topology.sourceSites.map((site) => [site.siteId, site]));
  const sourceFileMap = new Map();
  const sourceBindingMap = new Map();
  let sourceBindings = 0;
  let liveProbeBindings = 0;
  const routes = [];
  for (const edge of probePlan.edges) {
    const liveProbeIds = edge.liveReachability.map((probe) => probe.probeId).sort();
    for (const sourceProbe of edge.sourceInstall) {
      const branch = branches.get(sourceProbe.branchId);
      if (!branch || branch.edgeId !== edge.edgeId) throw new Error(`probe selects unknown implementation branch ${sourceProbe.probeId}`);
      const sourceRefs = [...new Set([
        ...branch.sourceRefs,
        ...branch.enforcementRoute.sourceRefs,
        ...branch.enforcementRoute.proofSourceRefs,
      ])].sort();
      const bindingIds = sourceRefs.map((sourceRef) => {
        const binding = resolvedSourceBinding(branch, sourceRef);
        const bindingId = `binding.${stableDigest(`${branch.branchId}\0${sourceRef}`)}`;
        for (const site of binding.sites) {
          const priorSite = topologySiteMap.get(site.siteId);
          if (priorSite && JSON.stringify(priorSite) !== JSON.stringify(site)) {
            throw new Error(`source binding site identity collision: ${site.siteId}`);
          }
          topologySiteMap.set(site.siteId, site);
        }
        sourceBindingMap.set(bindingId, {
          bindingId,
          branchId: branch.branchId,
          sourceRef: binding.sourceRef,
          path: binding.path,
          locator: binding.locator,
          rawContentDigest: binding.rawContentDigest,
          locatorKind: binding.locatorKind,
          resolutionPolicy: binding.resolutionPolicy,
          siteIds: binding.sites.map((site) => site.siteId),
          producerPaths: binding.producerPaths,
          refusalPaths: binding.refusalPaths,
        });
        sourceFileMap.set(binding.path, { path: binding.path, rawContentDigest: binding.rawContentDigest });
        return bindingId;
      });
      sourceBindings += bindingIds.length;
      liveProbeBindings += liveProbeIds.length;
      const routeId = `route.${stableDigest(`${edge.edgeId}\0${sourceProbe.branchId}`)}`;
      const branchTopology = topologyByBranch.get(sourceProbe.branchId);
      if (!branchTopology) throw new Error(`probe lacks branch topology ${sourceProbe.probeId}`);
      routes.push({
        routeId,
        edgeId: edge.edgeId,
        sourceProbeId: sourceProbe.probeId,
        branchId: sourceProbe.branchId,
        observedIdentity: edge.observedIdentity,
        liveProbeIds,
        targetApplicability: branch.targetApplicability,
        applicability: applicabilityForMac(branch),
        sourceBindingIds: bindingIds,
        branchPathId: branchTopology.routeFamily,
        sourceBoundary: {
          observationId: "restricted-exact.full-installer-skipped",
          lastObservedNode: branchTopology.sourceCutsets.at(-1),
          blockedEdge: {
            from: branchTopology.sourceCutsets.at(-1),
            to: branchTopology.branchNodeId,
          },
        },
        liveBoundary: {
          observationId: "restricted-exact.temporal-poll-posture-sealed",
          lastObservedNode: branchTopology.liveCutsets.at(-1),
          blockedEdge: {
            from: branchTopology.liveCutsets.at(-1),
            to: branchTopology.branchNodeId,
          },
        },
        sourceCutsetObservationIds: [
          "restricted-exact.profile-selected",
          "restricted-exact.full-installer-skipped",
        ],
        liveCutsetObservationIds: [
          "restricted-exact.bootstrap-posture-sealed",
          "restricted-exact.bundle-posture-sealed",
          "restricted-exact.temporal-poll-posture-sealed",
        ],
      });
    }
  }
  routes.sort((left, right) => left.routeId.localeCompare(right.routeId));
  topology.sourceSites = [...topologySiteMap.values()].sort((left, right) => left.siteId.localeCompare(right.siteId));
  const sourceFiles = [...sourceFileMap.values()].sort((left, right) => left.path.localeCompare(right.path));
  const resolvedSourceBindings = [...sourceBindingMap.values()].sort((left, right) => left.bindingId.localeCompare(right.bindingId));
  const graph = {
    routeGraphSchema: "ibex/restricted-profile-absence-route-graph/2",
    profile: projection.profile,
    target,
    authorityDigests: {
      projection: digest(raw.projection), coverage: digest(raw.coverage),
      implementationManifest: digest(raw.implementationManifest), rootGlobalManifest: digest(raw.rootManifest),
      probePlan: digest(raw.probePlan),
    },
    counts: { edges: probePlan.counts.edges, routes: routes.length, sourceFiles: sourceFiles.length, sourceBindings, liveProbeBindings },
    sourceFiles,
    sourceBindings: resolvedSourceBindings,
    topology,
    routes,
  };
  const validate = new Ajv2020({ strict: true, allErrors: true }).compile(readJsonStrict(schemaPath));
  if (!validate(graph)) throw new Error(`absence route graph violates schema: ${JSON.stringify(validate.errors)}`);
  return validateRestrictedExactAbsenceRouteGraph(graph, { probePlan, implementationManifest });
}

function loadGraph() {
  const raw = Object.fromEntries(Object.entries(inputs).map(([name, inputPath]) => [name, fs.readFileSync(inputPath)]));
  return buildRestrictedExactAbsenceRouteGraph({
    ...Object.fromEntries(Object.entries(inputs).map(([name, inputPath]) => [name, readJsonStrict(inputPath)])),
    raw,
  });
}

function main() {
  const write = process.argv.includes("--write");
  const graph = loadGraph();
  // One-space indentation keeps this complete, source-derived authority below
  // GitHub's per-object limit without sacrificing line-addressable review.
  const content = `${JSON.stringify(graph, null, 1)}\n`;
  if (write) {
    writeGeneratedFilesTransactionally(capsecRoot, [{ path: outputPath, content, label: "restricted Exact absence route graph" }]);
  } else {
    const { path: confined } = assertConfinedGeneratedFile(capsecRoot, outputPath, outputPath);
    if (fs.readFileSync(confined, "utf8") !== content) throw new Error("restricted Exact absence route graph is stale");
  }
  console.log(JSON.stringify({ mode: write ? "write" : "check", ...graph.counts }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
