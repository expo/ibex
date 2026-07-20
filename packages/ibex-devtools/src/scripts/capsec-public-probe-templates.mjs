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
// Module-root effects are intentionally limited to the reviewed util source
// families whose top-level body performs a typed NODE_DEBUG read. Each public
// spelling gets its own fresh-engine observation; a cached alias is never
// accepted as evidence that initialization is pure. Platform-classified and
// DNS aliases stay residual because a bare import does not execute their
// modeled effect.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
const BUILTIN_MODULE_ALIAS_SOURCES = new Map(
  [
    ["node:sys", "node_util", true, true],
    ["node:util", "node_util", true, true],
    ["node:util/types", "node_util_types_alias", true, true],
    ["sys", "node_util", true, true],
    ["util", "node_util", true, true],
    ["util/types", "util_types_alias", true, true],
  ].map(([moduleSpecifier, sourceKey, bundleExternal, moduleBuiltin]) => [
    moduleSpecifier,
    { sourceKey, bundleExternal, moduleBuiltin },
  ]),
);

const BUILTIN_MODULE_ENVIRONMENT_READ_SOURCES = new Set([
  "node_util",
  "node_util_types_alias",
  "util_types_alias",
]);
const ENVIRONMENT_AUXILIARY_OBSERVED_KEY = "native-op:__exactGetEnv";

const BUILTIN_BATCH_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer,openssl-crypto",
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
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // a reviewed cross-source property domain is presence evidence only. It
    // needs a dedicated carrier/provider invocation before execution credit.
    metadata.crossSourceExportProjection !== undefined ||
    metadata.constructorInstanceProjection !== undefined ||
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

function moduleAliasSourceDescriptor(surface, moduleSpecifier) {
  const expected = BUILTIN_MODULE_ALIAS_SOURCES.get(moduleSpecifier);
  const metadata = surface?.metadata;
  if (
    !expected ||
    surface?.kind !== "builtin" ||
    surface.name !== moduleSpecifier ||
    surface.observedKey !== `builtin:${moduleSpecifier}` ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length !== 1 ||
    surface.sourceRefs[0] !== `modules.ts#specifiers:${expected.sourceKey}` ||
    canonicalJson(metadata) !==
      canonicalJson({
        sourceKey: expected.sourceKey,
        bundleExternal: expected.bundleExternal,
        importReachability: "public",
        moduleBuiltin: expected.moduleBuiltin,
      })
  ) {
    return null;
  }
  return {
    kind: "builtin-module-alias",
    moduleSpecifier,
    sourceKey: expected.sourceKey,
    sourceRef: surface.sourceRefs[0],
    sourceMetadata: {
      sourceKey: metadata.sourceKey,
      bundleExternal: metadata.bundleExternal,
      importReachability: metadata.importReachability,
      moduleBuiltin: metadata.moduleBuiltin,
    },
  };
}

function moduleAliasEffectExpectation(sourceKey) {
  if (BUILTIN_MODULE_ENVIRONMENT_READ_SOURCES.has(sourceKey)) {
    return {
      actionIds: ["env:read"],
      requiredAuthority: [
        {
          cap: "env:read",
          resource: {
            kind: "environment-name",
            target: "principal-overlay",
            name: "NODE_DEBUG",
          },
        },
      ],
      allowedStages: ["requested", "commit"],
    };
  }
  return null;
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

  if (
    !surfaceObservedKey.startsWith("builtin:export:") &&
    surfaceObservedKey.startsWith("builtin:") &&
    route.alternatives.length === 1 &&
    route.alternatives[0].terminalObservedKey === surfaceObservedKey &&
    canonicalJson(route.alternatives[0].proofPaths) ===
      canonicalJson([surfaceObservedKey]) &&
    route.ambiguousCallees.length === 0 &&
    canonicalJson(allowedCoverageEdgeIds) ===
      canonicalJson([...plan.edgeIds].sort())
  ) {
    const moduleSpecifier = surfaceObservedKey.slice("builtin:".length);
    const descriptor = moduleAliasSourceDescriptor(
      liveByObservedKey.get(surfaceObservedKey),
      moduleSpecifier,
    );
    const expectation = descriptor
      ? moduleAliasEffectExpectation(descriptor.sourceKey)
      : null;
    const carrierEdge = coverageByObservedKey.get(surfaceObservedKey);
    const auxiliaryEdge = coverageByObservedKey.get(
      ENVIRONMENT_AUXILIARY_OBSERVED_KEY,
    );
    if (
      descriptor &&
      expectation &&
      carrierEdge?.id === plan.edgeIds[0] &&
      auxiliaryEdge?.classification === "effects" &&
      canonicalJson(
        [
          ...new Set(
            (auxiliaryEdge.effects ?? []).map((effect) => effect.cap),
          ),
        ].sort(),
      ) === canonicalJson(expectation.actionIds) &&
      expectation.allowedStages.every((stage) =>
        auxiliaryEdge.effects?.some((effect) =>
          effect.stages?.includes(stage),
        ),
      ) &&
      canonicalJson(plan.actionIds) === canonicalJson(expectation.actionIds)
    ) {
      descriptor.carrierEdgeId = carrierEdge.id;
      descriptor.auxiliaryDecisionEdgeId = auxiliaryEdge.id;
      const expectedTypedStages = publicDenial
        ? ["requested"]
        : expectation.allowedStages;
      return {
        kind: "public-surface-invocation",
        surfaceObservedKey,
        command: [...BUILTIN_BATCH_COMMAND],
        invocation: {
          invocationSchema: "ibex/capsec-builtin-module-import-invocation/1",
          kind: "builtin-module-import",
          moduleSpecifier,
          sourceDescriptor: descriptor,
          sourceDescriptorDigest: taggedDigest(descriptor),
          arguments: [],
          setup: { kind: "none" },
          requiredAuthority: expectation.requiredAuthority,
          // The armed process.env proxy records a denied exact read and
          // returns undefined. Initialization completes on both paths; the
          // requested-stage record is the independent denial evidence.
          expectedResult: "return",
          expectedTypedDecisionCount: expectedTypedStages.length,
          expectedTypedStages,
          allowedCoverageEdgeIds: [auxiliaryEdge.id],
          expectedActionIds: expectation.actionIds,
        },
      };
    }
  }

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
