/**
 * Authored public invocation templates for exact surfaces whose safe argument
 * and authority shapes cannot be inferred from a function name alone.
 *
 * Templates identify the public operation and its inputs. They deliberately
 * do not name an enforcement terminal: the catalog's source-derived route is
 * the allow-list, and the runtime observer must derive the terminal from the
 * coverage edge carried by the decision it actually witnessed.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
 * promotion evidence must execute the selected public surface on the bound
 * engine and bind its independently observed typed decision.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const OS_SYSTEM_INFO_EXPORTS = new Map(
  Object.entries({
    arch: "architecture",
    availableParallelism: "cpus",
    cpus: "cpus",
    endianness: "architecture",
    freemem: "memory",
    homedir: "storage-paths",
    hostname: "hostname",
    loadavg: "load-average",
    machine: "architecture",
    networkInterfaces: "network-interfaces",
    platform: "platform",
    release: "os-release",
    tmpdir: "storage-paths",
    totalmem: "memory",
    type: "platform",
    uptime: "uptime",
    userInfo: "user",
    version: "os-release",
  }),
);

const BUILTIN_BATCH_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer",
  "capsec_public_builtin_recipe_batch",
  "--",
  "--test-threads=1",
  "--nocapture",
]);

function observedKeyForEdge(edge) {
  return `${edge.surface.kind}:${edge.surface.name}`;
}

function sourceDescriptor(surface, exportName) {
  const metadata = surface?.metadata;
  if (
    surface?.observedKey !== `builtin:export:node_os:${exportName}` ||
    metadata?.sourceKey !== "node_os" ||
    metadata?.exportName !== exportName ||
    metadata?.surfaceType !== "export" ||
    !Array.isArray(metadata.moduleSpecifiers) ||
    !metadata.moduleSpecifiers.includes("node:os") ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length !== 1
  ) {
    return null;
  }
  return {
    kind: "builtin-export",
    sourceKey: metadata.sourceKey,
    exportName,
    moduleSpecifiers: [...metadata.moduleSpecifiers],
    sourceRef: surface.sourceRefs[0],
  };
}

export function authoredBuiltinPublicProbe({
  plan,
  scenario,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    plan.classification !== "effects" ||
    !new Set(["allow", "deny"]).has(scenario) ||
    plan.actionIds.length !== 1 ||
    plan.actionIds[0] !== "sys:read" ||
    route.surfaceObservedKeys.length !== 1
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "builtin:export:node_os:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const exportName = surfaceObservedKey.slice(prefix.length);
  const systemInfoName = OS_SYSTEM_INFO_EXPORTS.get(exportName);
  if (!systemInfoName) return null;
  const descriptor = sourceDescriptor(
    liveByObservedKey.get(surfaceObservedKey),
    exportName,
  );
  if (!descriptor) return null;

  const allowedCoverageEdgeIds = [];
  for (const alternative of route.alternatives) {
    const edge = coverageByObservedKey.get(alternative.terminalObservedKey);
    if (!edge || observedKeyForEdge(edge) !== alternative.terminalObservedKey) {
      return null;
    }
    allowedCoverageEdgeIds.push(edge.id);
  }
  allowedCoverageEdgeIds.sort();

  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...BUILTIN_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-builtin-export-invocation/1",
      kind: "builtin-export-call",
      moduleSpecifier: "node:os",
      exportName,
      sourceDescriptor: descriptor,
      sourceDescriptorDigest: taggedDigest(descriptor),
      arguments: [],
      setup: { kind: "none" },
      requiredAuthority: [
        {
          cap: "sys:read",
          resource: { kind: "system-info", name: systemInfoName },
        },
      ],
      expectedResult: scenario === "allow" ? "return" : "permission-denied",
      expectedTypedDecisionCount: scenario === "allow" ? 2 : 1,
      expectedTypedStages:
        scenario === "allow" ? ["requested", "commit"] : ["requested"],
      allowedCoverageEdgeIds,
      expectedActionIds: ["sys:read"],
    },
  };
}

export const authoredOsSystemInfoExports = Object.freeze([
  ...OS_SYSTEM_INFO_EXPORTS.keys(),
]);
