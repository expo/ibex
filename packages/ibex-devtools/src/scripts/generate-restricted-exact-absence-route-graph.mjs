/**
 * Generate the LLP 0033 target-specific absence dominance graph.
 *
 * Unlike the probe plan, this authority records the complete linear route
 * from an attacker root through exact target selection and a digest-bound
 * implementation branch to the cut-set observation that must fail it.
 *
 * @ref LLP 0033#absence-proof-repair-after-second-independent-review
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

function splitSourceRef(sourceRef) {
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
  return { sourceRef, path: sourcePath, locator, rawContentDigest: digest(fs.readFileSync(absolute)) };
}

function applicabilityForMac(row) {
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

function sourceSpan(spanId, sourcePath, startToken, endToken) {
  const bytes = fs.readFileSync(path.join(repoRoot, sourcePath));
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

const gatewayBySurfaceKind = Object.freeze({
  builtin: "gateway.module-loader",
  callback: "gateway.callback-producer",
  cli: "gateway.external-process-cli",
  "host-abi": "gateway.javascript-native-abi",
  loader: "gateway.module-loader",
  "native-op": "gateway.native-installer",
  startup: "gateway.full-startup",
});

function buildSourceDerivedTopology(probePlan, implementationManifest) {
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
  const cutsets = [
    ["cutset.profile-selected", "restricted-exact.profile-selected", "span.profile-selection"],
    ["cutset.full-installer-skipped", "restricted-exact.full-installer-skipped", "span.profile-selection"],
    ["cutset.bootstrap-posture-sealed", "restricted-exact.bootstrap-posture-sealed", "span.restricted-posture"],
    ["cutset.bundle-posture-sealed", "restricted-exact.bundle-posture-sealed", "span.bundle-evaluation"],
    ["cutset.temporal-poll-posture-sealed", "restricted-exact.temporal-poll-posture-sealed", "span.temporal-poll"],
  ];
  const nodes = [
    { nodeId: "root.authenticated-constructor", kind: "attacker-root", sourceSpanId: "span.profile-selection" },
    { nodeId: "root.authenticated-bundle", kind: "attacker-root", sourceSpanId: "span.bundle-evaluation" },
    ...cutsets.map(([nodeId, observationId, sourceSpanId]) => ({
      nodeId, kind: "instrumented-cutset", observationId, sourceSpanId,
    })),
    ...Object.entries(gatewayBySurfaceKind).map(([surfaceKind, nodeId]) => ({
      nodeId, kind: "exposure-gateway", surfaceKind,
    })).filter((node, index, rows) => rows.findIndex((row) => row.nodeId === node.nodeId) === index),
  ];
  const edges = [
    { from: "root.authenticated-constructor", to: "cutset.profile-selected", routeClass: "source-selection" },
    { from: "cutset.profile-selected", to: "cutset.full-installer-skipped", routeClass: "source-selection" },
    { from: "root.authenticated-bundle", to: "cutset.bootstrap-posture-sealed", routeClass: "live-reachability" },
    { from: "cutset.bootstrap-posture-sealed", to: "cutset.bundle-posture-sealed", routeClass: "live-reachability" },
    { from: "cutset.bundle-posture-sealed", to: "cutset.temporal-poll-posture-sealed", routeClass: "live-reachability" },
  ];
  for (const gatewayNodeId of [...new Set(Object.values(gatewayBySurfaceKind))].sort()) {
    edges.push(
      { from: "cutset.full-installer-skipped", to: gatewayNodeId, routeClass: "source-selection" },
      { from: "cutset.temporal-poll-posture-sealed", to: gatewayNodeId, routeClass: "live-reachability" },
    );
  }
  const implementationsByEdge = new Map();
  for (const branch of implementationManifest.surfaces) {
    const rows = implementationsByEdge.get(branch.edgeId) ?? [];
    rows.push(branch.branchId);
    implementationsByEdge.set(branch.edgeId, rows);
  }
  const terminals = probePlan.edges.map((edge) => {
    const nodeId = `terminal.${edge.edgeId}`;
    const gatewayNodeId = gatewayBySurfaceKind[edge.surfaceKind];
    if (!gatewayNodeId) throw new Error(`absence edge has no exposure gateway: ${edge.edgeId}`);
    nodes.push({ nodeId, kind: "terminal", edgeId: edge.edgeId });
    edges.push({ from: gatewayNodeId, to: nodeId, routeClass: "terminal-exposure" });
    return {
      edgeId: edge.edgeId,
      nodeId,
      gatewayNodeId,
      branchIds: [...implementationsByEdge.get(edge.edgeId)].sort(),
      liveProbeIds: edge.liveReachability.map((probe) => probe.probeId).sort(),
    };
  });
  nodes.sort((left, right) => left.nodeId.localeCompare(right.nodeId));
  edges.sort((left, right) => `${left.from}\0${left.to}`.localeCompare(`${right.from}\0${right.to}`));
  return {
    sourceSpans,
    nodes,
    edges,
    sourceRoot: "root.authenticated-constructor",
    liveRoot: "root.authenticated-bundle",
    sourceCutsets: ["cutset.profile-selected", "cutset.full-installer-skipped"],
    liveCutsets: [
      "cutset.bootstrap-posture-sealed",
      "cutset.bundle-posture-sealed",
      "cutset.temporal-poll-posture-sealed",
    ],
    terminals,
  };
}

function reachableNodes(topology, root, blocked = new Set()) {
  const adjacency = new Map();
  for (const edge of topology.edges) {
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
}

function validateSourceDerivedTopology(topology, probePlan, implementationManifest) {
  const nodeIds = topology.nodes.map((node) => node.nodeId);
  sortedUnique(nodeIds, "absence topology node IDs");
  const nodeSet = new Set(nodeIds);
  const edgeKeys = topology.edges.map((edge) => `${edge.from}\0${edge.to}`);
  sortedUnique(edgeKeys, "absence topology edges");
  if (topology.edges.some((edge) => !nodeSet.has(edge.from) || !nodeSet.has(edge.to))) {
    throw new Error("absence topology edge references an unknown node");
  }
  const indegree = new Map(nodeIds.map((nodeId) => [nodeId, 0]));
  const adjacency = new Map();
  for (const edge of topology.edges) {
    indegree.set(edge.to, indegree.get(edge.to) + 1);
    const targets = adjacency.get(edge.from) ?? [];
    targets.push(edge.to);
    adjacency.set(edge.from, targets);
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
  const allSource = reachableNodes(topology, topology.sourceRoot);
  const allLive = reachableNodes(topology, topology.liveRoot);
  const withoutSourceCutsets = reachableNodes(topology, topology.sourceRoot, new Set(topology.sourceCutsets));
  const withoutLiveCutsets = reachableNodes(topology, topology.liveRoot, new Set(topology.liveCutsets));
  const plannedEdgeIds = probePlan.edges.map((edge) => edge.edgeId);
  if (JSON.stringify(topology.terminals.map((row) => row.edgeId)) !== JSON.stringify(plannedEdgeIds)) {
    throw new Error("absence topology terminals do not equal the probe-plan edges");
  }
  const branchesByEdge = new Map();
  for (const branch of implementationManifest.surfaces) {
    const branches = branchesByEdge.get(branch.edgeId) ?? [];
    branches.push(branch.branchId);
    branchesByEdge.set(branch.edgeId, branches);
  }
  for (const terminal of topology.terminals) {
    if (!allSource.has(terminal.nodeId) || !allLive.has(terminal.nodeId)) {
      throw new Error(`absence topology terminal has no attacker-root path: ${terminal.edgeId}`);
    }
    if (withoutSourceCutsets.has(terminal.nodeId) || withoutLiveCutsets.has(terminal.nodeId)) {
      throw new Error(`instrumented cut sets do not dominate terminal: ${terminal.edgeId}`);
    }
    if (JSON.stringify(terminal.branchIds) !== JSON.stringify([...branchesByEdge.get(terminal.edgeId)].sort())) {
      throw new Error(`absence topology omits an implementation branch: ${terminal.edgeId}`);
    }
  }
  for (const span of topology.sourceSpans) {
    const current = sourceSpan(span.spanId, span.path, span.startToken, span.endToken);
    if (JSON.stringify(current) !== JSON.stringify(span)) {
      throw new Error(`absence topology source span drifted: ${span.spanId}`);
    }
  }
}

export function validateRestrictedExactAbsenceRouteGraph(graph, { probePlan, implementationManifest }) {
  for (const sourceFile of graph.sourceFiles) {
    const absolute = path.resolve(repoRoot, sourceFile.path);
    const relative = path.relative(repoRoot, absolute);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error(`route graph source file escapes repository: ${sourceFile.path}`);
    }
    const stat = fs.lstatSync(absolute);
    if (!stat.isFile() || stat.isSymbolicLink()
      || digest(fs.readFileSync(absolute)) !== sourceFile.rawContentDigest) {
      throw new Error(`route graph source file drifted: ${sourceFile.path}`);
    }
  }
  validateSourceDerivedTopology(graph.topology, probePlan, implementationManifest);
  const routesBySourceProbe = new Map();
  const liveProbeCounts = new Map();
  const implementationByBranch = new Map(implementationManifest.surfaces.map((row) => [row.branchId, row]));
  const routeIds = [];
  const probeEdgeById = new Map(probePlan.edges.map((edge) => [edge.edgeId, edge]));
  for (const route of graph.routes) {
    routeIds.push(route.routeId);
    if (routesBySourceProbe.has(route.sourceProbeId)) throw new Error(`duplicate source-probe route ${route.sourceProbeId}`);
    routesBySourceProbe.set(route.sourceProbeId, route);
    const branch = implementationByBranch.get(route.branchId);
    if (!branch || branch.edgeId !== route.edgeId) throw new Error(`route selects unknown or cross-edge branch ${route.routeId}`);
    if (route.observedIdentity !== branch.observedKey) throw new Error(`route target disagrees with implementation branch ${route.routeId}`);
    if (JSON.stringify(route.applicability) !== JSON.stringify(applicabilityForMac(branch))) {
      throw new Error(`route target applicability disagrees with implementation branch ${route.routeId}`);
    }
    const plannedEdge = probeEdgeById.get(route.edgeId);
    if (!plannedEdge) throw new Error(`route has no absence-plan edge ${route.routeId}`);
    const expectedRoots = attackerRoots(plannedEdge.surfaceKind, plannedEdge.liveReachability);
    if (JSON.stringify(route.attackerRoots) !== JSON.stringify(expectedRoots)) {
      throw new Error(`route omits or invents an attacker root ${route.routeId}`);
    }
    const topologyEdges = new Set(graph.topology.edges.map((edge) => `${edge.from}\0${edge.to}`));
    const validatePath = (routePath, label) => {
      if (new Set(routePath).size !== routePath.length) throw new Error(`${label} contains a cycle`);
      for (let index = 1; index < routePath.length; index += 1) {
        if (!topologyEdges.has(`${routePath[index - 1]}\0${routePath[index]}`)) {
          throw new Error(`${label} contains a non-edge`);
        }
      }
    };
    validatePath(route.sourcePath, `${route.routeId} source path`);
    validatePath(route.livePath, `${route.routeId} live path`);
    const terminal = graph.topology.terminals.find((row) => row.edgeId === route.edgeId);
    if (
      route.sourcePath[0] !== graph.topology.sourceRoot
      || route.livePath[0] !== graph.topology.liveRoot
      || route.sourcePath.at(-1) !== terminal?.nodeId
      || route.livePath.at(-1) !== terminal?.nodeId
    ) {
      throw new Error(`route path does not bind its exact terminal ${route.routeId}`);
    }
    const observationByNode = new Map(graph.topology.nodes
      .filter((node) => node.kind === "instrumented-cutset")
      .map((node) => [node.nodeId, node.observationId]));
    const expectedSourceObservations = graph.topology.sourceCutsets.map((nodeId) => observationByNode.get(nodeId));
    const expectedLiveObservations = graph.topology.liveCutsets.map((nodeId) => observationByNode.get(nodeId));
    if (
      JSON.stringify(route.sourceCutsetObservationIds) !== JSON.stringify(expectedSourceObservations)
      || JSON.stringify(route.liveCutsetObservationIds) !== JSON.stringify(expectedLiveObservations)
    ) {
      throw new Error(`route does not bind actual cut-set observations ${route.routeId}`);
    }
    const expectedBindings = [...new Set([
      ...branch.sourceRefs,
      ...branch.enforcementRoute.sourceRefs,
      ...branch.enforcementRoute.proofSourceRefs,
    ])].sort();
    if (JSON.stringify(route.sourceBindings.map((binding) => binding.sourceRef)) !== JSON.stringify(expectedBindings)) {
      throw new Error(`route source bindings disagree with branch ${route.routeId}`);
    }
    for (const binding of route.sourceBindings) {
      const sourceFile = graph.sourceFiles.find((file) => file.path === binding.path);
      if (!sourceFile || sourceFile.rawContentDigest !== binding.rawContentDigest) {
        throw new Error(`route source binding is not content-bound ${route.routeId}`);
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
  const topology = buildSourceDerivedTopology(probePlan, implementationManifest);
  const terminalByEdge = new Map(topology.terminals.map((terminal) => [terminal.edgeId, terminal]));
  const sourceFileMap = new Map();
  let sourceBindings = 0;
  let liveProbeBindings = 0;
  const routes = [];
  for (const edge of probePlan.edges) {
    const liveProbeIds = edge.liveReachability.map((probe) => probe.probeId).sort();
    for (const sourceProbe of edge.sourceInstall) {
      const branch = branches.get(sourceProbe.branchId);
      if (!branch || branch.edgeId !== edge.edgeId) throw new Error(`probe selects unknown implementation branch ${sourceProbe.probeId}`);
      const bindings = sourceProbe.sourceRefs.map(splitSourceRef);
      for (const binding of bindings) sourceFileMap.set(binding.path, { path: binding.path, rawContentDigest: binding.rawContentDigest });
      sourceBindings += bindings.length;
      liveProbeBindings += liveProbeIds.length;
      const routeId = `route.${stableDigest(`${edge.edgeId}\0${sourceProbe.branchId}`)}`;
      const terminal = terminalByEdge.get(edge.edgeId);
      const gateway = terminal.gatewayNodeId;
      routes.push({
        routeId,
        edgeId: edge.edgeId,
        sourceProbeId: sourceProbe.probeId,
        branchId: sourceProbe.branchId,
        observedIdentity: edge.observedIdentity,
        attackerRoots: attackerRoots(edge.surfaceKind, edge.liveReachability),
        liveProbeIds,
        applicability: applicabilityForMac(branch),
        sourceBindings: bindings,
        sourcePath: [
          topology.sourceRoot,
          ...topology.sourceCutsets,
          gateway,
          terminal.nodeId,
        ],
        livePath: [
          topology.liveRoot,
          ...topology.liveCutsets,
          gateway,
          terminal.nodeId,
        ],
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
  const sourceFiles = [...sourceFileMap.values()].sort((left, right) => left.path.localeCompare(right.path));
  const graph = {
    routeGraphSchema: "ibex/restricted-profile-absence-route-graph/1",
    profile: projection.profile,
    target,
    authorityDigests: {
      projection: digest(raw.projection), coverage: digest(raw.coverage),
      implementationManifest: digest(raw.implementationManifest), rootGlobalManifest: digest(raw.rootManifest),
      probePlan: digest(raw.probePlan),
    },
    counts: { edges: probePlan.counts.edges, routes: routes.length, sourceFiles: sourceFiles.length, sourceBindings, liveProbeBindings },
    sourceFiles,
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
  const content = `${JSON.stringify(graph, null, 2)}\n`;
  if (write) {
    writeGeneratedFilesTransactionally(capsecRoot, [{ path: outputPath, content, label: "restricted Exact absence route graph" }]);
  } else {
    const { path: confined } = assertConfinedGeneratedFile(capsecRoot, outputPath, outputPath);
    if (fs.readFileSync(confined, "utf8") !== content) throw new Error("restricted Exact absence route graph is stale");
  }
  console.log(JSON.stringify({ mode: write ? "write" : "check", ...graph.counts }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
