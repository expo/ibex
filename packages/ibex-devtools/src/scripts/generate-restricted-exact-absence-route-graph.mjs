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
    const kinds = route.segments.map((segment) => segment.kind);
    if (JSON.stringify(kinds) !== JSON.stringify(["attacker-root", "target-selection", "implementation-branch", "cut-set"])) {
      throw new Error(`route is cyclic, branched, or missing a dominance segment: ${route.routeId}`);
    }
    const segmentIds = route.segments.map((segment) => segment.segmentId);
    sortedUnique(segmentIds, `${route.routeId} segment IDs`);
    const target = route.segments[1];
    const implementation = route.segments[2];
    const cutset = route.segments[3];
    if (target.expectedTarget !== route.observedIdentity) throw new Error(`target-ignoring route ${route.routeId}`);
    if (implementation.branchId !== route.branchId) throw new Error(`wrong implementation segment ${route.routeId}`);
    if (cutset.expectedFailureSegment !== cutset.segmentId) throw new Error(`wrong failed segment ${route.routeId}`);
    if (cutset.observer !== observerFor(plannedEdge.surfaceKind)) {
      throw new Error(`wrong cut-set observer ${route.routeId}`);
    }
    if (!cutset.cutsetObservationId.includes(stableDigest(`${route.routeId}\0${route.observedIdentity}`))) {
      throw new Error(`cut-set observation is not target-bound ${route.routeId}`);
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
      const cutsetId = `cutset.${stableDigest(`${routeId}\0${edge.observedIdentity}`)}`;
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
        segments: [
          { segmentId: `${routeId}.attacker`, kind: "attacker-root" },
          { segmentId: `${routeId}.target`, kind: "target-selection", expectedTarget: edge.observedIdentity },
          { segmentId: `${routeId}.implementation`, kind: "implementation-branch", branchId: sourceProbe.branchId },
          { segmentId: `${routeId}.cutset`, kind: "cut-set", cutsetObservationId: cutsetId, observer: observerFor(edge.surfaceKind), expectedFailureSegment: `${routeId}.cutset` },
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
