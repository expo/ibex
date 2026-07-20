/**
 * Generate the exhaustive LLP 0033 absence probe plan.
 *
 * The plan is an obligation authority, never evidence. Every structurally
 * absent edge receives independently identified source-install probes for all
 * implementation branches and at least one live attacker-route probe. A
 * target report may credit an edge only after the bound observers execute
 * every probe and publish its individual result.
 *
 * @ref LLP 0033#5.2-structurally-absent-v1-surface — source identity and live
 * invocation routes are both required; descriptor walking alone is incomplete.
 * @ref LLP 0033#8-generated-authority-and-conformance — broad suite success
 * cannot synthesize per-obligation passes.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

import {
  canonicalJson,
  capsecRoot,
  readJsonStrict,
} from "./capsec-contract.mjs";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";

const projectionPath = path.join(capsecRoot, "generated/restricted-exact-profile-projection.json");
const coveragePath = path.join(capsecRoot, "registry/coverage-edges.json");
const implementationPath = path.join(capsecRoot, "generated/implementation-manifest.json");
const rootManifestPath = path.join(capsecRoot, "generated/root-global-disposition-manifest.json");
const schemaPath = path.join(capsecRoot, "schema/restricted-profile-absence-probe-plan.schema.json");
const outputPath = path.join(capsecRoot, "generated/restricted-exact-absence-probe-plan.json");

function digest(bytes) {
  return `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
}

function routeKind(surfaceKind) {
  return {
    builtin: "restricted-module-resolution",
    callback: "restricted-callback-route",
    cli: "restricted-cli-entry",
    "host-abi": "restricted-js-native-abi",
    loader: "restricted-loader-entry",
    "native-op": "restricted-native-installer-route",
    startup: "restricted-startup-route",
  }[surfaceKind];
}

function assertSortedUnique(values, label) {
  if (new Set(values).size !== values.length) throw new Error(`${label} contains duplicates`);
  const sorted = [...values].sort();
  if (values.some((value, index) => value !== sorted[index])) {
    throw new Error(`${label} must be sorted`);
  }
}

function descriptorPrefixes(rootManifest, absentIds) {
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
    rows.push({ target: segments.join("."), unresolvedSegment });
    result.set(row.registryEdgeId, rows);
  }
  for (const rows of result.values()) rows.sort((left, right) => left.target.localeCompare(right.target));
  return result;
}

export function buildRestrictedExactAbsenceProbePlan({
  projection,
  coverage,
  implementationManifest,
  rootManifest,
  raw,
}) {
  const absentIds = projection.rows
    .filter((row) => row[1] === "structurally-absent")
    .map((row) => row[0]);
  assertSortedUnique(absentIds, "absent projection edge IDs");
  const absentSet = new Set(absentIds);
  const coverageById = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  const implementations = new Map();
  for (const surface of implementationManifest.surfaces) {
    const rows = implementations.get(surface.edgeId) ?? [];
    rows.push(surface);
    implementations.set(surface.edgeId, rows);
  }
  const descriptors = descriptorPrefixes(rootManifest, absentSet);

  let sourceInstallProbes = 0;
  let liveReachabilityProbes = 0;
  const edges = absentIds.map((edgeId) => {
    const edge = coverageById.get(edgeId);
    if (!edge) throw new Error(`absence probe edge is missing from coverage: ${edgeId}`);
    const branches = implementations.get(edgeId);
    if (!branches?.length) throw new Error(`absence probe edge has no implementation branch: ${edgeId}`);
    branches.sort((left, right) => left.branchId.localeCompare(right.branchId));
    const sourceInstall = branches.map((branch, index) => ({
      probeId: `source.${edgeId}.${index}`,
      branchId: branch.branchId,
      enforcementBranchId: branch.enforcementBranchId,
      enforcementRouteKind: branch.enforcementRoute.kind,
      sourceRefs: [...new Set([
        ...branch.sourceRefs,
        ...branch.enforcementRoute.sourceRefs,
        ...branch.enforcementRoute.proofSourceRefs,
      ])].sort(),
      proofPaths: [...new Set(branch.enforcementRoute.proofPaths)].sort(),
      expected: "not-selected-or-retained",
    }));
    sourceInstallProbes += sourceInstall.length;

    const descriptorRows = descriptors.get(edgeId) ?? [];
    const liveReachability = descriptorRows.map((row, index) => ({
      probeId: `live.${edgeId}.descriptor.${index}`,
      routeKind: "descriptor-prefix",
      target: row.target,
      unresolvedSegment: row.unresolvedSegment,
      expected: "unreachable",
    }));
    liveReachability.push({
      probeId: `live.${edgeId}.route.0`,
      routeKind: routeKind(edge.surface.kind),
      target: `${edge.surface.kind}:${edge.surface.name}`,
      expected: "unreachable",
    });
    liveReachabilityProbes += liveReachability.length;
    return {
      edgeId,
      surfaceKind: edge.surface.kind,
      surfaceName: edge.surface.name,
      observedIdentity: `${edge.surface.kind}:${edge.surface.name}`,
      sourceInstall,
      liveReachability,
    };
  });

  const plan = {
    probePlanSchema: "ibex/restricted-profile-absence-probe-plan/1",
    profile: projection.profile,
    projectionRawContentDigest: digest(raw.projection),
    coverageRawContentDigest: digest(raw.coverage),
    implementationManifestRawContentDigest: digest(raw.implementationManifest),
    rootGlobalManifestRawContentDigest: digest(raw.rootManifest),
    counts: {
      edges: edges.length,
      sourceInstallProbes,
      liveReachabilityProbes,
    },
    edges,
  };
  const schema = readJsonStrict(schemaPath);
  const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema);
  if (!validate(plan)) {
    throw new Error(`absence probe plan violates schema: ${JSON.stringify(validate.errors)}`);
  }
  if (plan.counts.edges !== absentIds.length) throw new Error("absence probe plan is not total");
  if (plan.edges.some((row) => row.sourceInstall.length === 0 || row.liveReachability.length === 0)) {
    throw new Error("absence probe plan contains an unprobeable edge");
  }
  return plan;
}

function loadPlan() {
  const raw = {
    projection: fs.readFileSync(projectionPath),
    coverage: fs.readFileSync(coveragePath),
    implementationManifest: fs.readFileSync(implementationPath),
    rootManifest: fs.readFileSync(rootManifestPath),
  };
  return buildRestrictedExactAbsenceProbePlan({
    projection: readJsonStrict(projectionPath),
    coverage: readJsonStrict(coveragePath),
    implementationManifest: readJsonStrict(implementationPath),
    rootManifest: readJsonStrict(rootManifestPath),
    raw,
  });
}

function main() {
  const write = process.argv.includes("--write");
  const plan = loadPlan();
  const content = `${JSON.stringify(plan, null, 2)}\n`;
  if (write) {
    writeGeneratedFilesTransactionally(capsecRoot, [{
      path: outputPath,
      content,
      label: "restricted Exact absence probe plan",
    }]);
  } else {
    const { path: confined } = assertConfinedGeneratedFile(capsecRoot, outputPath, outputPath);
    if (fs.readFileSync(confined, "utf8") !== content) {
      throw new Error("restricted Exact absence probe plan is stale; run bun run generate:restricted-exact-absence-probe-plan");
    }
  }
  console.log(JSON.stringify({ mode: write ? "write" : "check", ...plan.counts }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
