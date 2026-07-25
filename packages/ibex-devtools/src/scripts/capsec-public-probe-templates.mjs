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
import { capsecSecureCargoTestCommand } from "./capsec-secure-test-command.mjs";

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

const FS_LIST_EXPORTS = new Set([
  "accessSync",
  "lstatSync",
  "readdirSync",
  "realpathSync",
  "statSync",
]);
// Synchronous, path-taking fs:read exports. Each opens the authenticated fixture
// file (an fs:list traversal credited to ambient-mount authority under LLP 0037
// D1) and then reads it (the fs:read commit gated by the static floor). The
// typed-decision sequence is observed from the bound engine, never guessed
// (LLP 0037 D3).
// @ref LLP 0037#d1--ambient-mount-authority-for-traversal-decisions
const FS_READ_EXPORTS = new Set(["readFileSync"]);
// Synchronous, path-taking fs:write exports. Each opens the authenticated
// fixture file for write (an fs:list traversal credited to ambient-mount
// authority under LLP 0037 D1) and writes the literal payload (the fs:write
// commit gated by the static floor). Same open-then-act shape as fs:read; the
// typed sequence is observed from the bound engine, never guessed (LLP 0037 D3).
// @ref LLP 0037#d1--ambient-mount-authority-for-traversal-decisions
const FS_WRITE_EXPORTS = new Set(["writeFileSync"]);
const FS_WRITE_PAYLOAD = "ibex-capsec-write-fixture\n";
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
// realpathSync authenticates its cwd and lstat preflight as separately gated
// helpers. They are admitted as exact auxiliary edges, never as substitutes
// for the allow-path realpath terminal.
// @ref LLP 0037#additional-multi-edge-metadata-evidence-realpathsync
const REALPATH_AUXILIARY_DECISIONS = new Map([
  ["native-op:__exactGetCwd", ["path:cwd-observe"]],
  ["native-op:__exactLstat", ["fs:list"]],
]);

const BUILTIN_BATCH_COMMAND = Object.freeze(
  capsecSecureCargoTestCommand("capsec_public_builtin_recipe_batch", true),
);

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

function realpathAuxiliaryDecisionEdges(coverageByObservedKey) {
  const descriptors = [];
  for (const [observedKey, actionIds] of REALPATH_AUXILIARY_DECISIONS) {
    const edge = coverageByObservedKey.get(observedKey);
    if (
      edge?.classification !== "effects" ||
      canonicalJson(
        [...new Set((edge.effects ?? []).map((effect) => effect.cap))].sort(),
      ) !== canonicalJson([...actionIds].sort())
    ) {
      return null;
    }
    descriptors.push({
      edgeId: edge.id,
      observedKey,
      actionIds: [...actionIds],
    });
  }
  return descriptors;
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
  const fsExportName = surfaceObservedKey.slice(fsPrefix.length);

  // fs:read family — synchronous, path-taking reads of the authenticated
  // fixture file. Opens (fs:list traversal, LLP 0037 D1) then reads (fs:read
  // commit). The 9-decision sequence is the value observed from the bound
  // engine (LLP 0037 D3), never guessed.
  // @ref LLP 0037#d3--observed-typed-sequences-are-pinned-from-a-run-never-authored-by-hand
  if (
    plan.actionIds.length === 1 &&
    plan.actionIds[0] === "fs:read" &&
    FS_READ_EXPORTS.has(fsExportName)
  ) {
    const descriptor = sourceDescriptor(
      liveByObservedKey.get(surfaceObservedKey),
      "node_fs",
      fsExportName,
      "node:fs",
    );
    if (!descriptor) return null;
    const logicalPath = FS_FIXTURE_PATH;
    return {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: [...BUILTIN_BATCH_COMMAND],
      invocation: {
        invocationSchema: "ibex/capsec-builtin-export-invocation/1",
        kind: "builtin-export-call",
        moduleSpecifier: "node:fs",
        exportName: fsExportName,
        sourceDescriptor: descriptor,
        sourceDescriptorDigest: taggedDigest(descriptor),
        arguments: [{ kind: "filesystem-fixture-path", logicalPath }],
        setup: {
          kind: "filesystem-file",
          logicalPath,
          contents: "ibex-capsec-stat-fixture\n",
        },
        requiredAuthority: [
          {
            cap: "fs:read",
            resource: { kind: "path-exact", path: logicalPath },
          },
        ],
        expectedResult: publicDenial ? "permission-denied" : "return",
        // Observed from the bound engine (LLP 0037 D3): readFileSync opens the
        // fixture (the fs:list discovery/bind traversal, always allowed via
        // ambient mount authority) then reads it (the fs:read commit and its
        // retained repeats). On allow that is a 9-decision sequence. On deny the
        // open still succeeds and only the fs:read commit is refused, so the
        // sequence is the 6-decision open chain ending at the denied commit
        // (LLP 0037 D4) — never guessed.
        expectedTypedDecisionCount: publicDenial ? 6 : 9,
        expectedTypedStages: publicDenial
          ? ["requested", "requested", "discovery", "requested", "repeat", "commit"]
          : [
              "requested",
              "requested",
              "discovery",
              "requested",
              "repeat",
              "commit",
              "repeat",
              "repeat",
              "repeat",
            ],
        allowedCoverageEdgeIds,
        expectedActionIds: ["fs:read"],
      },
    };
  }

  // fs:write family — synchronous, path-taking writes of the authenticated
  // fixture file. Same open-then-act shape as fs:read (LLP 0037 D1/D4): the
  // open's fs:list traversal is ambient-mount, the fs:write commit is
  // floor-gated. Takes the path plus a literal payload argument.
  // @ref LLP 0037#d1--ambient-mount-authority-for-traversal-decisions
  if (
    plan.actionIds.length === 1 &&
    plan.actionIds[0] === "fs:write" &&
    FS_WRITE_EXPORTS.has(fsExportName)
  ) {
    const descriptor = sourceDescriptor(
      liveByObservedKey.get(surfaceObservedKey),
      "node_fs",
      fsExportName,
      "node:fs",
    );
    if (!descriptor) return null;
    const logicalPath = FS_FIXTURE_PATH;
    return {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: [...BUILTIN_BATCH_COMMAND],
      invocation: {
        invocationSchema: "ibex/capsec-builtin-export-invocation/1",
        kind: "builtin-export-call",
        moduleSpecifier: "node:fs",
        exportName: fsExportName,
        sourceDescriptor: descriptor,
        sourceDescriptorDigest: taggedDigest(descriptor),
        arguments: [
          { kind: "filesystem-fixture-path", logicalPath },
          { kind: "literal-utf8", value: FS_WRITE_PAYLOAD },
        ],
        setup: {
          kind: "filesystem-file",
          logicalPath,
          contents: "ibex-capsec-stat-fixture\n",
        },
        requiredAuthority: [
          {
            cap: "fs:write",
            resource: { kind: "path-exact", path: logicalPath },
          },
        ],
        expectedResult: publicDenial ? "permission-denied" : "return",
        // Observed from the bound engine (LLP 0037 D3): writeFileSync opens the
        // fixture (the fs:list traversal, ambient-mount) then writes it (the
        // fs:write commit and one retained repeat) — a 7-decision sequence on
        // allow. On deny the open still succeeds and only the fs:write commit is
        // refused, giving the 6-decision open chain ending at the denied commit
        // (LLP 0037 D4).
        expectedTypedDecisionCount: publicDenial ? 6 : 7,
        expectedTypedStages: publicDenial
          ? ["requested", "requested", "discovery", "requested", "repeat", "commit"]
          : [
              "requested",
              "requested",
              "discovery",
              "requested",
              "repeat",
              "commit",
              "repeat",
            ],
        allowedCoverageEdgeIds,
        expectedActionIds: ["fs:write"],
      },
    };
  }

  if (plan.actionIds.length !== 1 || plan.actionIds[0] !== "fs:list") {
    return null;
  }
  const exportName = fsExportName;
  if (!FS_LIST_EXPORTS.has(exportName)) return null;
  const descriptor = sourceDescriptor(
    liveByObservedKey.get(surfaceObservedKey),
    "node_fs",
    exportName,
    "node:fs",
  );
  if (!descriptor) return null;
  const directoryProbe = exportName === "readdirSync";
  const accessMetadataProbe = exportName === "accessSync";
  const realpathMetadataProbe = exportName === "realpathSync";
  const followedMetadataProbe = exportName === "statSync";
  const logicalPath = directoryProbe ? FS_DIRECTORY_PATH : FS_FIXTURE_PATH;
  const auxiliaryDecisionEdges = realpathMetadataProbe
    ? realpathAuxiliaryDecisionEdges(coverageByObservedKey)
    : [];
  if (!auxiliaryDecisionEdges) return null;
  if (auxiliaryDecisionEdges.length > 0) {
    descriptor.auxiliaryDecisionEdges = auxiliaryDecisionEdges;
  }
  if (realpathMetadataProbe) {
    descriptor.denialTerminalEdgeId = auxiliaryDecisionEdges.find(
      ({ observedKey }) => observedKey === "native-op:__exactLstat",
    ).edgeId;
  }
  const invocationAllowedCoverageEdgeIds = [
    ...new Set([
      ...allowedCoverageEdgeIds,
      ...auxiliaryDecisionEdges.map(({ edgeId }) => edgeId),
    ]),
  ].sort();

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
        publicDenial
          ? realpathMetadataProbe
            ? 3
            : 1
          : directoryProbe
            ? 7
            : accessMetadataProbe
              ? 6
              : realpathMetadataProbe
                ? 12
              : followedMetadataProbe
                ? 5
                : 4,
      expectedTypedStages:
        publicDenial
          ? realpathMetadataProbe
            ? ["requested", "commit", "requested"]
            : ["requested"]
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
            : accessMetadataProbe
              ? [
                  "requested",
                  "discovery",
                  "requested",
                  "repeat",
                  "repeat",
                  "repeat",
                ]
              : realpathMetadataProbe
                ? [
                    "requested",
                    "commit",
                    "requested",
                    "discovery",
                    "requested",
                    "repeat",
                    "requested",
                    "discovery",
                    "requested",
                    "repeat",
                    "repeat",
                    "repeat",
                  ]
            : followedMetadataProbe
              ? ["requested", "discovery", "requested", "repeat", "repeat"]
              : ["requested", "discovery", "requested", "repeat"],
      allowedCoverageEdgeIds: invocationAllowedCoverageEdgeIds,
      expectedActionIds: ["fs:list"],
    },
  };
}

export const authoredOsSystemInfoExports = Object.freeze([
  ...OS_SYSTEM_INFO_EXPORTS.keys(),
]);
