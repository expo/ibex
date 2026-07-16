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

const EFFECT_SCENARIOS = new Set([
  "allow",
  "deny",
  "malformed",
  "missing-attribution",
  "wrong-principal",
]);

const FS_LIST_EXPORTS = new Set(["lstatSync", "readdirSync", "statSync"]);
const FS_FIXTURE_PATH = Object.freeze({
  root: "project",
  components: [{ encoding: "utf8", value: "capsec-stat-fixture.txt" }],
});
const FS_DIRECTORY_PATH = Object.freeze({
  root: "project",
  components: [{ encoding: "utf8", value: "capsec-directory-fixture" }],
});

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

function sourceDescriptor(surface, sourceKey, exportName, moduleSpecifier) {
  const metadata = surface?.metadata;
  if (
    surface?.observedKey !== `builtin:export:${sourceKey}:${exportName}` ||
    metadata?.sourceKey !== sourceKey ||
    metadata?.exportName !== exportName ||
    metadata?.surfaceType !== "export" ||
    !Array.isArray(metadata.moduleSpecifiers) ||
    !metadata.moduleSpecifiers.includes(moduleSpecifier) ||
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

function allowedCoverageEdgeIdsForRoute(route, coverageByObservedKey) {
  const edgeIds = [];
  for (const alternative of route.alternatives) {
    const edge = coverageByObservedKey.get(alternative.terminalObservedKey);
    if (!edge || observedKeyForEdge(edge) !== alternative.terminalObservedKey) {
      return null;
    }
    edgeIds.push(edge.id);
  }
  edgeIds.sort();
  return edgeIds;
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
    !EFFECT_SCENARIOS.has(scenario) ||
    route.surfaceObservedKeys.length !== 1
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const allowedCoverageEdgeIds = allowedCoverageEdgeIdsForRoute(
    route,
    coverageByObservedKey,
  );
  if (!allowedCoverageEdgeIds) return null;
  const publicDenial = scenario === "deny";

  const osPrefix = "builtin:export:node_os:";
  if (surfaceObservedKey.startsWith(osPrefix)) {
    if (plan.actionIds.length !== 1 || plan.actionIds[0] !== "sys:read") {
      return null;
    }
    const exportName = surfaceObservedKey.slice(osPrefix.length);
    const systemInfoName = OS_SYSTEM_INFO_EXPORTS.get(exportName);
    if (!systemInfoName) return null;
    const descriptor = sourceDescriptor(
      liveByObservedKey.get(surfaceObservedKey),
      "node_os",
      exportName,
      "node:os",
    );
    if (!descriptor) return null;

    // Malformed and attribution behavior is exercised by the fixture's typed
    // adapter probe. The public half independently proves that the exact source
    // export reaches a real terminal on the bound engine.
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
        expectedResult: publicDenial ? "permission-denied" : "return",
        expectedTypedDecisionCount: publicDenial ? 1 : 2,
        expectedTypedStages:
          publicDenial ? ["requested"] : ["requested", "commit"],
        allowedCoverageEdgeIds,
        expectedActionIds: ["sys:read"],
      },
    };
  }

  const fsPrefix = "builtin:export:node_fs:";
  if (!surfaceObservedKey.startsWith(fsPrefix)) return null;
  if (plan.actionIds.length !== 1 || plan.actionIds[0] !== "fs:list") {
    return null;
  }
  const exportName = surfaceObservedKey.slice(fsPrefix.length);
  if (!FS_LIST_EXPORTS.has(exportName)) return null;
  const descriptor = sourceDescriptor(
    liveByObservedKey.get(surfaceObservedKey),
    "node_fs",
    exportName,
    "node:fs",
  );
  if (!descriptor) return null;
  const directoryProbe = exportName === "readdirSync";
  const followedMetadataProbe = exportName === "statSync";
  const logicalPath = directoryProbe ? FS_DIRECTORY_PATH : FS_FIXTURE_PATH;

  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...BUILTIN_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-builtin-export-invocation/1",
      kind: "builtin-export-call",
      moduleSpecifier: "node:fs",
      exportName,
      sourceDescriptor: descriptor,
      sourceDescriptorDigest: taggedDigest(descriptor),
      arguments: [
        { kind: "filesystem-fixture-path", logicalPath },
      ],
      setup: directoryProbe
        ? {
            kind: "filesystem-directory",
            logicalPath,
            entries: [
              {
                kind: "file",
                name: "entry.txt",
                contents: "ibex-capsec-directory-entry\n",
              },
            ],
          }
        : {
            kind: "filesystem-file",
            logicalPath,
            contents: "ibex-capsec-stat-fixture\n",
          },
      requiredAuthority: [
        {
          cap: "fs:list",
          resource: { kind: "path-exact", path: logicalPath },
        },
      ],
      expectedResult: publicDenial ? "permission-denied" : "return",
      // The authenticated VFS first binds the selected project mount object,
      // then re-authorizes the exact target before its retained repeats. Stat
      // adds the followed target, while directory open and its first entry
      // each add another generation check.
      // @ref LLP 0023#21-staged-authorization-identity
      expectedTypedDecisionCount:
        publicDenial ? 1 : directoryProbe ? 7 : followedMetadataProbe ? 5 : 4,
      expectedTypedStages:
        publicDenial
          ? ["requested"]
          : directoryProbe
            ? [
                "requested",
                "discovery",
                "requested",
                "repeat",
                "repeat",
                "repeat",
                "repeat",
              ]
            : followedMetadataProbe
              ? ["requested", "discovery", "requested", "repeat", "repeat"]
              : ["requested", "discovery", "requested", "repeat"],
      allowedCoverageEdgeIds,
      expectedActionIds: ["fs:list"],
    },
  };
}

export const authoredOsSystemInfoExports = Object.freeze([
  ...OS_SYSTEM_INFO_EXPORTS.keys(),
]);
