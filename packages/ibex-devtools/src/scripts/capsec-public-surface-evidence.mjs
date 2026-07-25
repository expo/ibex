/**
 * Validate content-addressed evidence that every exact-target recipe invoked
 * its authored public surface and observed the selected enforcement terminal.
 * Typed-adapter probes are deliberately a different schema and are never
 * accepted here.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * target promotion requires executed public obligations, not adapter checks.
 */

import crypto from "node:crypto";
import path from "node:path";
import {
  assertRecipeCatalogComplete,
  validateRecipeCatalog,
} from "./capsec-conformance-recipes.mjs";
import { reviewedPublicSurfaceExecutorDescriptor } from "./capsec-public-executors.mjs";
import {
  canonicalJson,
  capsecRoot,
  readJsonStrict,
} from "./capsec-contract.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const builtinCacheSourceId = (sourceKey) =>
  `ibex-source-id-v1:${Buffer.from(
    canonicalJson({
      kind: "builtin",
      key: sourceKey,
      sourceIdSchema: "ibex.source-id.v1",
    }),
    "utf8",
  ).toString("base64url")}`;
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value), "utf8")
    .digest("base64url")}`;
const SEMANTIC_REGISTRY_IDENTITY = (() => {
  const registryBundle = readJsonStrict(
    path.join(capsecRoot, "examples/registry-digest-bundle.canonical.json"),
  );
  const digestVectors = readJsonStrict(
    path.join(capsecRoot, "examples/digest-vectors.canonical.json"),
  );
  const vocabDigest = registryBundle.members?.find(
    (member) => member.logicalName === "vocab-digest",
  )?.document?.digest;
  const registryDigest = digestVectors.vectors?.find(
    (vector) => vector.id === "registry",
  )?.expectedDigest;
  if (
    !/^sha256-[A-Za-z0-9_-]{43}$/u.test(vocabDigest ?? "") ||
    !/^sha256-[A-Za-z0-9_-]{43}$/u.test(registryDigest ?? "")
  ) {
    throw new Error("public evidence semantic digest identities are unavailable");
  }
  return Object.freeze({ vocabDigest, registryDigest });
})();
const BUILTIN_RUNTIME_INVOCATION_SCHEMAS = new Set([
  "ibex/capsec-builtin-export-invocation/1",
  "ibex/capsec-builtin-call-invocation/1",
]);
const EFFECT_BUILTIN_MODULE_IMPORT_ALIASES = new Map(
  [
    ["node:sys", "node_util", true, true, "env:read"],
    ["node:util", "node_util", true, true, "env:read"],
    ["node:util/types", "node_util_types_alias", true, true, "env:read"],
    ["sys", "node_util", true, true, "env:read"],
    ["util", "node_util", true, true, "env:read"],
    ["util/types", "util_types_alias", true, true, "env:read"],
  ].map(
    ([moduleSpecifier, sourceKey, bundleExternal, moduleBuiltin, actionId]) => [
      moduleSpecifier,
      { sourceKey, bundleExternal, moduleBuiltin, actionId },
    ],
  ),
);
const NONCAP_BUILTIN_MODULE_IMPORT_ALIASES = new Map(
  [
    ["buffer", "node_buffer", true, "object"],
    ["bun:sqlite", "exact_sqlite", false, "function"],
    ["console", "node_console", true, "object"],
    ["dns", "node_dns", true, "object"],
    ["dns/promises", "node_dns_promises", true, "object"],
    ["exact:clipboard", "exact_clipboard", false, "object"],
    ["exact:http", "exact_http", false, "object"],
    ["exact:sqlite", "exact_sqlite", false, "function"],
    ["module", "node_module", true, "object"],
    ["node:buffer", "node_buffer", true, "object"],
    ["node:console", "node_console", true, "object"],
    ["node:dns", "node_dns", true, "object"],
    ["node:dns/promises", "node_dns_promises", true, "object"],
    ["node:module", "node_module", true, "object"],
    ["node:path", "node_path", true, "object"],
    ["node:path/posix", "path_posix_alias", true, "object"],
    ["node:path/win32", "path_win32_alias", true, "object"],
    ["node:punycode", "node_punycode", true, "object"],
    ["node:querystring", "node_querystring", true, "object"],
    ["node:string_decoder", "node_string_decoder", true, "function"],
    ["node:timers", "node_timers", true, "object"],
    ["node:timers/promises", "node_timers_promises", true, "object"],
    ["node:trace_events", "node_trace_events", true, "object"],
    ["node:v8", "node_v8", true, "object"],
    ["path", "node_path", true, "object"],
    ["path/posix", "path_posix_alias", true, "object"],
    ["path/win32", "path_win32_alias", true, "object"],
    ["punycode", "node_punycode", true, "object"],
    ["querystring", "node_querystring", true, "object"],
    ["string_decoder", "node_string_decoder", true, "function"],
    ["timers", "node_timers", true, "object"],
    ["timers/promises", "node_timers_promises", true, "object"],
    ["trace_events", "node_trace_events", true, "object"],
    ["v8", "node_v8", true, "object"],
  ].map(([moduleSpecifier, sourceKey, moduleBuiltin, expectedRootType]) => [
    moduleSpecifier,
    { sourceKey, bundleExternal: true, moduleBuiltin, expectedRootType },
  ]),
);
const EFFECT_BUILTIN_IMPORT_SCENARIOS = new Set([
  "allow",
  "deny",
  "malformed",
  "missing-attribution",
  "wrong-principal",
]);
const NORMAL_RETURN_RESULT_TYPES = new Set([
  "bigint",
  "boolean",
  "function",
  "null",
  "number",
  "object",
  "string",
  "undefined",
]);
const NORMAL_RETURN_DISPATCH_KINDS = new Map([
  ["root-call", "call"],
  ["construct-target", "construct"],
  ["constructed-owner", "prototype-call"],
  ["buffer-owner", "prototype-call"],
  ["call-tracker-owner", "prototype-call"],
  ["stream-owner", "prototype-call"],
  ["zlib-owner", "prototype-call"],
]);
const PRIVATE_CWD_FACADE_SOURCE_REFS = Object.freeze([
  "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:process",
  "packages/ibex-runtime-js/src/node/process.ts#Process.prototype.cwd",
  "src/engine/bootstrap/compat-polyfills.js#process.cwd",
  "src/engine/hermes_runtime_process_setup.cc#jsi-global:process.cwd",
]);
const NATIVE_FILESYSTEM_DENIAL_GLOBALS = new Set([
  "__exactAppendFile",
  "__exactFsOpen",
  "__exactFsOpenAsync",
  "__exactFsPathAsync",
  "__exactLstat",
  "__exactMkdir",
  "__exactReadFile",
  "__exactReaddir",
  "__exactRealpath",
  "__exactStat",
  "__exactStatfs",
  "__exactTruncate",
  "__exactWriteFile",
]);
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — the
// dispatcher remains the public surface, while typed evidence must select its
// exact source-chosen worker rather than any allowed auxiliary edge.
const NATIVE_ASYNC_WORKER_TERMINALS = new Map([
  ["mkdir", "native-op:__exactMkdir"],
  ["readdir", "native-op:__exactReaddir"],
  ["realpath", "native-op:__exactRealpath"],
  ["statfs", "native-op:__exactStatfs"],
  ["truncate", "native-op:__exactTruncate"],
]);
const NATIVE_RETAINED_FS_AUXILIARY_TERMINALS = new Map(
  [
    "__exactFsFdAsync",
    "__exactFsFchmodSync",
    "__exactFsFdatasyncSync",
    "__exactFsFstatSync",
    "__exactFsFsyncSync",
    "__exactFsFtruncateSync",
    "__exactFsFutimesSync",
    "__exactFsOpenAsync",
  ].map((globalName) => [globalName, "native-op:__exactFsOpen"]),
);
const CLOSED_SQLITE_CARRIER_OPERATIONS = new Set([
  "sqlite-cr-sqlite-enable",
  "sqlite-extension-load",
]);

export function nativeAsyncWorkerTerminal(authored) {
  if (
    authored?.invocationSchema !==
      "ibex/capsec-native-global-invocation/1" ||
    authored.kind !== "native-global-function"
  ) {
    return null;
  }
  const retainedFsTerminal = NATIVE_RETAINED_FS_AUXILIARY_TERMINALS.get(
    authored.globalName,
  );
  if (retainedFsTerminal) return retainedFsTerminal;
  if (authored.globalName !== "__exactFsPathAsync") return null;
  const operation = authored.arguments?.[0];
  return operation?.kind === "json-literal"
    ? NATIVE_ASYNC_WORKER_TERMINALS.get(operation.value) ?? null
    : null;
}

export function validateNativeFilesystemDenialRecipeDescriptor(authored) {
  if (
    authored?.invocationSchema !==
      "ibex/capsec-native-global-invocation/1" ||
    authored.kind !== "native-global-function" ||
    !NATIVE_FILESYSTEM_DENIAL_GLOBALS.has(authored.globalName) ||
    authored.expectedDenyMessageFragment !== "filesystem policy denied"
  ) {
    throw new Error("unreviewed native denial expectation");
  }
  return authored;
}

// Independent verifier authority for the small curated startup family. Keep
// this separate from recipe authorship so descriptor tampering cannot change
// both the claim and its validator through one shared table.
const STARTUP_EXPECTATIONS = new Map(
  [
    [
      "runtime-create",
      "runtime-created",
      "src/engine/hermes_runtime.cc#ex_hermes_create_armed",
      ["engine-can-evaluate"],
      null,
    ],
    [
      "globals-install",
      "globals-installed",
      "src/engine/hermes_runtime.cc#installGlobals",
      ["console-installed", "timers-installed"],
      null,
    ],
    [
      "module-loader-install",
      "module-loader-installed",
      "src/engine/hermes_bootstrap.cc#installModuleLoader",
      ["module-loader-installed"],
      null,
    ],
    [
      "shared-runtime-install",
      "shared-runtime-installed",
      "src/engine/hermes_bootstrap.cc#installSharedRuntimeBundle",
      ["shared-runtime-loaded"],
      null,
    ],
    [
      "capability-hardening-seal",
      "capability-hatches-sealed",
      "src/engine/hermes_runtime.cc#kCapabilityHardeningJS",
      ["capability-hatches-absent"],
      null,
    ],
    [
      "eager-native-seal",
      "lazy-installers-sealed",
      "src/engine/hermes_runtime.cc#kEagerInstallSealJS",
      ["lazy-installers-absent"],
      null,
    ],
    [
      "lockdown-install",
      "lockdown-installed",
      "src/engine/hermes_runtime.cc#lockdownJS",
      ["lockdown-flag-pinned", "eval-tamed", "object-prototype-frozen"],
      null,
    ],
    [
      "freeze-seal",
      "freeze-hatches-sealed",
      "src/engine/hermes_runtime.cc#kFreezeSealJS",
      ["freeze-hatches-absent"],
      null,
    ],
    [
      "compartment-registry-install",
      "compartment-registry-installed",
      "src/engine/hermes_runtime.cc#kCompartmentRegistryJS",
      ["compartment-registry-pinned"],
      null,
    ],
    [
      "web-streams-install",
      "web-streams-installed",
      "src/engine/hermes_bootstrap.cc#installWebStreamsPolyfill",
      ["web-stream-constructors-installed"],
      { name: "EX_WEB_STREAMS_POLYFILL", value: "1" },
    ],
  ].map(
    ([surfaceName, postcondition, sourceRef, requiredFacts, environment]) => [
      surfaceName,
      { postcondition, sourceRef, requiredFacts, environment },
    ],
  ),
);

// Independent verifier authority for startup environment source carriers.
// This intentionally does not import the recipe template: a template edit
// must not be able to rewrite both the claim and the verifier in one place.
const STARTUP_ENVIRONMENT_EXPECTATIONS = new Map([
  [
    "NODE_DEBUG",
    {
      sourceRef: "src/builtins/http.js#process.env:NODE_DEBUG:read",
      liveSourceRefs: [
        "src/builtins/http.js#process.env:NODE_DEBUG:read",
        "src/builtins/util.js#process.env:NODE_DEBUG:read",
      ],
      mechanism: "builtin-module-load",
      moduleSpecifier: "node:http",
      preloadModuleSpecifiers: ["node:events", "node:stream", "node:util"],
    },
  ],
  [
    "EXACT_DEBUG_EMIT_LISTENER",
    {
      sourceRef:
        "src/builtins/events.js#process.env:EXACT_DEBUG_EMIT_LISTENER:read",
      liveSourceRefs: [
        "src/builtins/events.js#process.env:EXACT_DEBUG_EMIT_LISTENER:read",
      ],
      mechanism: "event-emitter-emit",
      moduleSpecifier: "node:events",
      preloadModuleSpecifiers: [],
    },
  ],
  [
    "TZ",
    {
      sourceRef:
        "packages/ibex-runtime-js/src/node/process.ts#process.env:TZ:read",
      liveSourceRefs: [
        "packages/ibex-runtime-js/src/node/process.ts#process.env:TZ:read",
        "src/bin/ibex/engine/hermes.rs#Command::env:TZ:write",
        "src/bin/ibex/runtime.rs#Command::env:TZ:write",
        "src/module_loader/mod.rs#Command::env:TZ:write",
      ],
      mechanism: "date-to-string",
      moduleSpecifier: null,
      preloadModuleSpecifiers: [],
    },
  ],
]);

function hasExactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalJson(Object.keys(value).sort(compareText)) ===
      canonicalJson([...keys].sort(compareText))
  );
}

function exactKeys(value, keys, label) {
  if (!hasExactKeys(value, keys)) {
    throw new Error(`${label} has unknown or missing fields`);
  }
}

function effectBuiltinModuleImportAuthority(actionId) {
  if (actionId === "env:read") {
    return [
      {
        cap: "env:read",
        resource: {
          kind: "environment-name",
          target: "principal-overlay",
          name: "NODE_DEBUG",
        },
      },
    ];
  }
  return null;
}

function validateEffectBuiltinModuleImportInvocation(
  invocation,
  authored,
  recipe,
) {
  const expectation = EFFECT_BUILTIN_MODULE_IMPORT_ALIASES.get(
    authored.moduleSpecifier,
  );
  const surfaceObservedKey = `builtin:${authored.moduleSpecifier}`;
  const descriptor = authored.sourceDescriptor;
  const sourceMetadata = descriptor?.sourceMetadata;
  const decisionIdentity = invocation.decisionIdentity;
  const denial = recipe.scenario === "deny";
  const expectedAuthority = expectation
    ? effectBuiltinModuleImportAuthority(expectation.actionId)
    : null;
  const expectedStages = denial ? ["requested"] : ["requested", "commit"];

  exactKeys(
    invocation,
    [
      "invocationSchema",
      "kind",
      "surfaceObservedKey",
      "moduleSpecifier",
      "sourceDescriptorDigest",
      "decisionIdentity",
      "result",
    ],
    `${recipe.fixtureId}: builtin module-import runtime invocation`,
  );
  exactKeys(
    authored,
    [
      "invocationSchema",
      "kind",
      "moduleSpecifier",
      "sourceDescriptor",
      "sourceDescriptorDigest",
      "arguments",
      "setup",
      "requiredAuthority",
      "expectedResult",
      "expectedTypedDecisionCount",
      "expectedTypedStages",
      "allowedCoverageEdgeIds",
      "expectedActionIds",
    ],
    `${recipe.fixtureId}: authored builtin module import`,
  );
  exactKeys(
    descriptor,
    [
      "kind",
      "moduleSpecifier",
      "sourceKey",
      "sourceRef",
      "sourceMetadata",
      "carrierEdgeId",
      "auxiliaryDecisionEdgeId",
    ],
    `${recipe.fixtureId}: builtin module-import source descriptor`,
  );
  exactKeys(
    sourceMetadata,
    ["sourceKey", "bundleExternal", "importReachability", "moduleBuiltin"],
    `${recipe.fixtureId}: builtin module-import source metadata`,
  );
  exactKeys(
    decisionIdentity,
    [
      "profile",
      "semanticCore",
      "vocabDigest",
      "registryDigest",
      "policyDigest",
      "armedSnapshotDigest",
    ],
    `${recipe.fixtureId}: builtin module-import decision identity`,
  );
  exactKeys(
    authored.setup,
    ["kind"],
    `${recipe.fixtureId}: builtin module-import setup`,
  );
  exactKeys(
    recipe.route,
    ["surfaceObservedKeys", "alternatives", "ambiguousCallees"],
    `${recipe.fixtureId}: builtin module-import route`,
  );
  if (recipe.route.alternatives?.length === 1) {
    exactKeys(
      recipe.route.alternatives[0],
      ["terminalObservedKey", "proofPaths"],
      `${recipe.fixtureId}: builtin module-import route alternative`,
    );
  }

  if (
    recipe.classification !== "effects" ||
    !EFFECT_BUILTIN_IMPORT_SCENARIOS.has(recipe.scenario) ||
    expectation === undefined ||
    expectedAuthority === null ||
    authored.invocationSchema !==
      "ibex/capsec-builtin-module-import-invocation/1" ||
    authored.kind !== "builtin-module-import" ||
    invocation.kind !== authored.kind ||
    invocation.moduleSpecifier !== authored.moduleSpecifier ||
    recipe.publicSurfaceProbe?.surfaceObservedKey !== surfaceObservedKey ||
    invocation.surfaceObservedKey !== surfaceObservedKey ||
    recipe.terminalObservedKey !== surfaceObservedKey ||
    canonicalJson(recipe.route.surfaceObservedKeys) !==
      canonicalJson([surfaceObservedKey]) ||
    recipe.route.alternatives?.length !== 1 ||
    recipe.route.alternatives[0].terminalObservedKey !== surfaceObservedKey ||
    canonicalJson(recipe.route.alternatives[0].proofPaths) !==
      canonicalJson([surfaceObservedKey]) ||
    canonicalJson(recipe.route.ambiguousCallees) !== canonicalJson([]) ||
    !Array.isArray(recipe.edgeIds) ||
    recipe.edgeIds.length !== 1 ||
    descriptor.carrierEdgeId !== recipe.edgeIds[0] ||
    typeof descriptor.auxiliaryDecisionEdgeId !== "string" ||
    descriptor.auxiliaryDecisionEdgeId.length === 0 ||
    canonicalJson(authored.allowedCoverageEdgeIds) !==
      canonicalJson([descriptor.auxiliaryDecisionEdgeId]) ||
    canonicalJson(recipe.actionIds) !==
      canonicalJson([expectation.actionId]) ||
    canonicalJson(authored.expectedActionIds) !==
      canonicalJson([expectation.actionId]) ||
    descriptor.kind !== "builtin-module-alias" ||
    descriptor.moduleSpecifier !== authored.moduleSpecifier ||
    descriptor.sourceKey !== expectation.sourceKey ||
    descriptor.sourceRef !==
      `modules.ts#specifiers:${expectation.sourceKey}` ||
    sourceMetadata.sourceKey !== expectation.sourceKey ||
    sourceMetadata.bundleExternal !== expectation.bundleExternal ||
    sourceMetadata.importReachability !== "public" ||
    sourceMetadata.moduleBuiltin !== expectation.moduleBuiltin ||
    decisionIdentity.profile !== "ibex/capsec/1" ||
    decisionIdentity.semanticCore !== "capsec/semantics/1" ||
    decisionIdentity.vocabDigest !== SEMANTIC_REGISTRY_IDENTITY.vocabDigest ||
    decisionIdentity.registryDigest !==
      SEMANTIC_REGISTRY_IDENTITY.registryDigest ||
    !isTaggedDigest(decisionIdentity.policyDigest) ||
    !isTaggedDigest(decisionIdentity.armedSnapshotDigest) ||
    canonicalJson(authored.arguments) !== canonicalJson([]) ||
    authored.setup.kind !== "none" ||
    canonicalJson(authored.requiredAuthority) !==
      canonicalJson(expectedAuthority) ||
    authored.expectedResult !== "return" ||
    authored.expectedTypedDecisionCount !== expectedStages.length ||
    canonicalJson(authored.expectedTypedStages) !==
      canonicalJson(expectedStages)
  ) {
    throw new Error(
      `${recipe.fixtureId}: builtin module-import invocation descriptor drift`,
    );
  }
}

function validateNonCapabilityBuiltinModuleImportInvocation(
  invocation,
  authored,
  recipe,
) {
  const expectation = NONCAP_BUILTIN_MODULE_IMPORT_ALIASES.get(
    authored.moduleSpecifier,
  );
  const surfaceObservedKey = `builtin:${authored.moduleSpecifier}`;
  const descriptor = authored.sourceDescriptor;
  const sourceMetadata = descriptor?.sourceMetadata;

  exactKeys(
    invocation,
    [
      "invocationSchema",
      "kind",
      "surfaceObservedKey",
      "moduleSpecifier",
      "sourceDescriptorDigest",
      "sourceExecution",
      "completion",
      "result",
    ],
    `${recipe.fixtureId}: non-capability builtin module-import runtime invocation`,
  );
  exactKeys(
    invocation.sourceExecution,
    [
      "schema",
      "observationId",
      "runtimeNonce",
      "moduleSpecifier",
      "sourceId",
      "cacheMiss",
      "bodyCompleted",
    ],
    `${recipe.fixtureId}: authenticated builtin source execution`,
  );
  exactKeys(
    authored,
    [
      "invocationSchema",
      "kind",
      "moduleSpecifier",
      "sourceDescriptor",
      "sourceDescriptorDigest",
      "arguments",
      "setup",
      "completion",
      "requiredAuthority",
      "expectedResult",
      "expectedTypedDecisionCount",
      "expectedTypedStages",
      "allowedCoverageEdgeIds",
      "expectedActionIds",
    ],
    `${recipe.fixtureId}: authored non-capability builtin module import`,
  );
  exactKeys(
    descriptor,
    [
      "kind",
      "moduleSpecifier",
      "sourceKey",
      "sourceRef",
      "sourceMetadata",
      "expectedRootType",
      "carrierEdgeId",
    ],
    `${recipe.fixtureId}: non-capability builtin module-import source descriptor`,
  );
  exactKeys(
    sourceMetadata,
    ["sourceKey", "bundleExternal", "importReachability", "moduleBuiltin"],
    `${recipe.fixtureId}: non-capability builtin module-import source metadata`,
  );
  exactKeys(
    authored.setup,
    ["kind"],
    `${recipe.fixtureId}: non-capability builtin module-import setup`,
  );
  exactKeys(
    authored.completion,
    ["kind", "timeoutMilliseconds"],
    `${recipe.fixtureId}: authored non-capability builtin completion`,
  );
  exactKeys(
    invocation.completion,
    ["kind", "status", "timeoutMilliseconds"],
    `${recipe.fixtureId}: non-capability builtin runtime completion`,
  );
  exactKeys(
    recipe.route,
    ["surfaceObservedKeys", "alternatives", "ambiguousCallees"],
    `${recipe.fixtureId}: non-capability builtin module-import route`,
  );
  if (recipe.route.alternatives?.length === 1) {
    exactKeys(
      recipe.route.alternatives[0],
      ["terminalObservedKey", "proofPaths"],
      `${recipe.fixtureId}: non-capability builtin module-import route alternative`,
    );
  }

  if (
    recipe.classification !== "non-capability" ||
    recipe.scenario !== "non-capability" ||
    expectation === undefined ||
    authored.invocationSchema !==
      "ibex/capsec-builtin-module-import-no-effect-invocation/1" ||
    authored.kind !== "builtin-module-import" ||
    invocation.kind !== authored.kind ||
    invocation.moduleSpecifier !== authored.moduleSpecifier ||
    recipe.publicSurfaceProbe?.surfaceObservedKey !== surfaceObservedKey ||
    invocation.surfaceObservedKey !== surfaceObservedKey ||
    recipe.terminalObservedKey !== surfaceObservedKey ||
    canonicalJson(recipe.route.surfaceObservedKeys) !==
      canonicalJson([surfaceObservedKey]) ||
    recipe.route.alternatives?.length !== 1 ||
    recipe.route.alternatives[0].terminalObservedKey !== surfaceObservedKey ||
    canonicalJson(recipe.route.alternatives[0].proofPaths) !==
      canonicalJson([surfaceObservedKey]) ||
    canonicalJson(recipe.route.ambiguousCallees) !== canonicalJson([]) ||
    !Array.isArray(recipe.edgeIds) ||
    recipe.edgeIds.length !== 1 ||
    descriptor.carrierEdgeId !== recipe.edgeIds[0] ||
    canonicalJson(recipe.actionIds) !== canonicalJson([]) ||
    descriptor.kind !== "builtin-module-alias" ||
    descriptor.moduleSpecifier !== authored.moduleSpecifier ||
    descriptor.sourceKey !== expectation.sourceKey ||
    descriptor.sourceRef !==
      `modules.ts#specifiers:${expectation.sourceKey}` ||
    sourceMetadata.sourceKey !== expectation.sourceKey ||
    sourceMetadata.bundleExternal !== expectation.bundleExternal ||
    sourceMetadata.importReachability !== "public" ||
    sourceMetadata.moduleBuiltin !== expectation.moduleBuiltin ||
    descriptor.expectedRootType !== expectation.expectedRootType ||
    canonicalJson(authored.arguments) !== canonicalJson([]) ||
    authored.setup.kind !== "none" ||
    authored.completion.kind !== "event-loop-quiescence" ||
    authored.completion.timeoutMilliseconds !== 1_000 ||
    invocation.completion.kind !== authored.completion.kind ||
    invocation.completion.timeoutMilliseconds !==
      authored.completion.timeoutMilliseconds ||
    invocation.completion.status !== "quiescent" ||
    invocation.sourceExecution.schema !==
      "ibex/capsec-authenticated-builtin-source-execution/1" ||
    invocation.sourceExecution.observationId !== recipe.fixtureId ||
    !isTaggedRuntimeNonce(invocation.sourceExecution.runtimeNonce) ||
    invocation.sourceExecution.moduleSpecifier !== authored.moduleSpecifier ||
    invocation.sourceExecution.sourceId !==
      builtinCacheSourceId(expectation.sourceKey) ||
    invocation.sourceExecution.cacheMiss !== true ||
    invocation.sourceExecution.bodyCompleted !== true ||
    canonicalJson(authored.requiredAuthority) !== canonicalJson([]) ||
    authored.expectedResult !== "return" ||
    authored.expectedTypedDecisionCount !== 0 ||
    canonicalJson(authored.expectedTypedStages) !== canonicalJson([]) ||
    canonicalJson(authored.allowedCoverageEdgeIds) !== canonicalJson([]) ||
    canonicalJson(authored.expectedActionIds) !== canonicalJson([])
  ) {
    throw new Error(
      `${recipe.fixtureId}: non-capability builtin module-import invocation descriptor drift`,
    );
  }
}

function evidenceDigest(evidence) {
  const { evidenceDigest: _digest, ...payload } = evidence;
  return taggedDigest(payload);
}

export function computePublicSurfaceExecutionDigest(artifact) {
  const { publicSurfaceExecutionDigest: _digest, ...payload } = artifact;
  return taggedDigest(payload);
}

export function mergePublicBatchExecutions({
  batches,
  recipeCatalog,
  loadedEngineIdentity,
}) {
  if (!Array.isArray(batches)) {
    throw new Error("public fixture batches must be an array");
  }
  const knownFixtures = new Set(
    recipeCatalog.recipes.map((recipe) => recipe.fixtureId),
  );
  const seen = new Set();
  const executions = [];
  for (const [index, entry] of batches.entries()) {
    exactKeys(
      entry,
      ["batch", "expectedFixtureIds"],
      `public fixture batch binding ${index}`,
    );
    const { batch, expectedFixtureIds } = entry;
    exactKeys(
      batch,
      [
        "publicBatchEvidenceSchema",
        "recipeCatalogDigest",
        "loadedEngineIdentity",
        "executions",
      ],
      `public fixture batch ${index}`,
    );
    if (
      batch.publicBatchEvidenceSchema !==
        "ibex/capsec-public-batch-evidence/1" ||
      batch.recipeCatalogDigest !== recipeCatalog.recipeCatalogDigest ||
      canonicalJson(batch.loadedEngineIdentity) !==
        canonicalJson(loadedEngineIdentity) ||
      !Array.isArray(batch.executions) ||
      !Array.isArray(expectedFixtureIds) ||
      new Set(expectedFixtureIds).size !== expectedFixtureIds.length ||
      expectedFixtureIds.some((fixtureId) => !knownFixtures.has(fixtureId))
    ) {
      throw new Error(`public fixture batch ${index} is stale or malformed`);
    }
    const observedFixtureIds = batch.executions.map(
      (execution) => execution?.fixtureId,
    );
    if (
      observedFixtureIds.some((fixtureId) => typeof fixtureId !== "string") ||
      new Set(observedFixtureIds).size !== observedFixtureIds.length ||
      canonicalJson([...observedFixtureIds].sort(compareText)) !==
        canonicalJson([...expectedFixtureIds].sort(compareText))
    ) {
      throw new Error(
        `public fixture batch ${index} is missing, duplicates, or adds fixtures`,
      );
    }
    for (const execution of batch.executions) {
      if (seen.has(execution.fixtureId)) {
        throw new Error(
          `${execution.fixtureId}: duplicate public execution across batch commands`,
        );
      }
      seen.add(execution.fixtureId);
      executions.push(structuredClone(execution));
    }
  }
  return executions.sort((left, right) =>
    compareText(left.fixtureId, right.fixtureId),
  );
}

function executionSummary(recipeCatalog, executions) {
  return {
    requiredFixtures: recipeCatalog.summary.requiredFixtures,
    executableFixtures: recipeCatalog.summary.fullyExecutableFixtures,
    internallyVerifiedFixtures:
      recipeCatalog.summary.internallyVerifiedFixtures,
    residualFixtures: recipeCatalog.summary.unresolvedFixtures,
    executedFixtures: executions.length,
    passedFixtures: executions.filter(
      (execution) => execution.outcome === "passed",
    ).length,
    failedFixtures: executions.filter(
      (execution) => execution.outcome === "failed",
    ).length,
    missingFixtures: recipeCatalog.summary.requiredFixtures - executions.length,
  };
}

export function buildPublicSurfaceExecutionArtifact({
  recipeCatalog,
  sourceRevision,
  sourceTreeDigest,
  target,
  engine,
  coverage = null,
  executions = [],
}) {
  validateRecipeCatalog(recipeCatalog, { target });
  const sortedExecutions = [...executions].sort((left, right) =>
    compareText(left.fixtureId, right.fixtureId),
  );
  const artifact = {
    publicSurfaceExecutionSchema: "ibex/capsec-public-surface-executions/1",
    profile: "ibex/capsec/1",
    sourceRevision,
    sourceTreeDigest,
    target: structuredClone(target),
    engine: structuredClone(engine),
    recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
    summary: executionSummary(recipeCatalog, sortedExecutions),
    executions: sortedExecutions,
  };
  artifact.publicSurfaceExecutionDigest =
    computePublicSurfaceExecutionDigest(artifact);
  return validatePublicSurfaceExecutionArtifact(artifact, {
    recipeCatalog,
    target,
    sourceRevision,
    sourceTreeDigest,
    engine,
    coverage,
  });
}

function coverageTerminalMap(coverage) {
  if (!Array.isArray(coverage?.edges)) {
    throw new Error(
      "runtime public evidence requires the bound coverage registry",
    );
  }
  const terminals = new Map();
  for (const edge of coverage.edges) {
    const kind = edge?.surface?.kind;
    const name = edge?.surface?.name;
    if (
      typeof edge?.id !== "string" ||
      typeof kind !== "string" ||
      typeof name !== "string" ||
      terminals.has(edge.id)
    ) {
      throw new Error(
        "bound coverage registry has malformed or duplicate edges",
      );
    }
    terminals.set(edge.id, `${kind}:${name}`);
  }
  return terminals;
}

const isTaggedDigest = (value) =>
  typeof value === "string" && /^sha256-[A-Za-z0-9_-]{43}$/u.test(value);
const isTaggedRuntimeNonce = (value) =>
  typeof value === "string" &&
  /^u64:[1-9][0-9]*$/u.test(value) &&
  BigInt(value.slice(4)) <= 18_446_744_073_709_551_615n;

const EXACT_OPERATION_MANIFEST_DIGEST =
  "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA";
const EXACT_EMBEDDER_NON_CAPABILITY_SURFACES = new Map([
  [
    "callback:exact-host-call-async-resolve",
    ["callback-attribution-carrier", "exact-host-call-round-trip"],
  ],
  [
    "callback:producer:src/engine/hermes_runtime.cc:ex_hermes_resolve_exact_host_call:pushRuntimeCallback",
    ["callback-attribution-carrier", "exact-host-call-round-trip"],
  ],
  [
    "host-abi:ex_hermes_resolve_exact_host_call",
    ["callback-attribution-carrier", "exact-host-call-round-trip"],
  ],
  [
    "host-abi:ex_hermes_set_exact_host_call_async",
    ["authority-control-plane", "exact-endowment-install"],
  ],
  [
    "host-abi:ex_host_authorize_exact_endowment",
    ["authority-control-plane", "exact-endowment-authorize"],
  ],
  [
    "host-abi:ex_host_build_exact_armed_embedder_artifacts",
    ["authority-control-plane", "exact-artifact-prepare-round-trip"],
  ],
  [
    "host-abi:ex_host_build_exact_experimental_webgpu_pre1a_armed_embedder_artifacts",
    ["authority-control-plane", "exact-gpu-artifact-prepare-round-trip"],
  ],
  [
    "host-abi:ex_host_build_exact_gpu_armed_embedder_artifacts",
    ["authority-control-plane", "exact-gpu-artifact-prepare-round-trip"],
  ],
  [
    "host-abi:ex_host_prepare_armed_embedder_artifacts",
    ["authority-control-plane", "exact-artifact-prepare-round-trip"],
  ],
  [
    "host-abi:ex_host_prepare_exact_armed_embedder_artifacts",
    ["authority-control-plane", "exact-artifact-prepare-round-trip"],
  ],
]);

function validateGenerationSet(value, label) {
  exactKeys(value, ["negative", "dynamic", "handle"], label);
  if (
    ![value.negative, value.dynamic, value.handle].every(
      (generation) => Number.isSafeInteger(generation) && generation >= 0,
    )
  ) {
    throw new Error(`${label} is not a non-negative typed generation set`);
  }
}

function validateRootPrincipal(value, label) {
  exactKeys(value, ["kind", "identity"], label);
  if (value.kind !== "root" || value.identity !== "project-root") {
    throw new Error(`${label} is not the armed project root`);
  }
}

function validateCallbackPackagePrincipal(value, label) {
  exactKeys(value, ["kind", "name", "integrity", "locator"], label);
  if (
    value.kind !== "package" ||
    value.name !== "image-lib" ||
    value.locator !== "image-lib@2.4.1" ||
    !isTaggedDigest(value.integrity)
  ) {
    throw new Error(`${label} is not the authenticated callback package`);
  }
}

function validateCallbackInvariantResult(result, authored, fixtureId) {
  exactKeys(
    result,
    ["kind", "scenario", "outcome", "checks"],
    `${fixtureId}: callback invariant runtime result`,
  );
  if (
    result.kind !== "callback-security-invariant" ||
    result.scenario !== authored.scenario ||
    result.outcome !== "passed"
  ) {
    throw new Error(
      `${fixtureId}: callback invariant did not pass its authored scenario`,
    );
  }
  const checks = result.checks;
  const label = `${fixtureId}: ${authored.scenario} checks`;
  if (authored.scenario === "attribution-missing-deny") {
    exactKeys(
      checks,
      [
        "callbackExecuted",
        "actualPrincipal",
        "invalidAttributionDenied",
        "runtimeNonce",
      ],
      label,
    );
    validateRootPrincipal(checks.actualPrincipal, `${label} actual principal`);
    if (
      checks.callbackExecuted !== true ||
      checks.invalidAttributionDenied !== true ||
      !isTaggedRuntimeNonce(checks.runtimeNonce)
    ) {
      throw new Error(
        `${label} did not prove fail-closed callback attribution`,
      );
    }
    return;
  }
  if (authored.scenario === "generation-recheck") {
    exactKeys(
      checks,
      [
        "callbackExecuted",
        "actualPrincipal",
        "generationsBefore",
        "generationsAfter",
        "generationAdvanced",
        "scheduledDecisionRechecked",
        "runtimeNonce",
      ],
      label,
    );
    validateCallbackPackagePrincipal(
      checks.actualPrincipal,
      `${label} actual principal`,
    );
    validateGenerationSet(
      checks.generationsBefore,
      `${label} generations before`,
    );
    validateGenerationSet(
      checks.generationsAfter,
      `${label} generations after`,
    );
    if (
      checks.callbackExecuted !== true ||
      checks.generationAdvanced !== true ||
      checks.scheduledDecisionRechecked !== true ||
      checks.generationsAfter.negative <= checks.generationsBefore.negative ||
      checks.generationsAfter.dynamic <= checks.generationsBefore.dynamic ||
      checks.generationsAfter.handle !== checks.generationsBefore.handle ||
      !isTaggedRuntimeNonce(checks.runtimeNonce)
    ) {
      throw new Error(
        `${label} did not prove a post-revocation decision recheck`,
      );
    }
    return;
  }
  if (authored.scenario === "principal-restore") {
    exactKeys(
      checks,
      [
        "callbackExecuted",
        "callbackPrincipal",
        "restoredPrincipal",
        "principalRestored",
        "runtimeNonce",
      ],
      label,
    );
    validateCallbackPackagePrincipal(
      checks.callbackPrincipal,
      `${label} callback principal`,
    );
    validateRootPrincipal(
      checks.restoredPrincipal,
      `${label} restored principal`,
    );
    if (
      checks.callbackExecuted !== true ||
      checks.principalRestored !== true ||
      !isTaggedRuntimeNonce(checks.runtimeNonce)
    ) {
      throw new Error(`${label} did not prove callback-principal restoration`);
    }
    return;
  }
  if (authored.scenario === "snapshot-mismatch-deny") {
    exactKeys(
      checks,
      [
        "callbackExecuted",
        "actualPrincipal",
        "sourceSnapshotDigest",
        "targetSnapshotDigest",
        "snapshotDigestsDiffer",
        "foreignBearerDenied",
        "sourceRuntimeNonce",
        "targetRuntimeNonce",
      ],
      label,
    );
    validateRootPrincipal(checks.actualPrincipal, `${label} actual principal`);
    if (
      checks.callbackExecuted !== true ||
      !isTaggedDigest(checks.sourceSnapshotDigest) ||
      !isTaggedDigest(checks.targetSnapshotDigest) ||
      checks.sourceSnapshotDigest === checks.targetSnapshotDigest ||
      checks.snapshotDigestsDiffer !== true ||
      checks.foreignBearerDenied !== true ||
      !isTaggedRuntimeNonce(checks.sourceRuntimeNonce) ||
      !isTaggedRuntimeNonce(checks.targetRuntimeNonce) ||
      checks.sourceRuntimeNonce === checks.targetRuntimeNonce
    ) {
      throw new Error(`${label} did not prove cross-snapshot bearer rejection`);
    }
    return;
  }
  if (authored.scenario === "cannot-widen-authority") {
    exactKeys(
      checks,
      [
        "bridgeExecuted",
        "requestRefused",
        "generationsBefore",
        "generationsAfter",
        "generationsUnchanged",
      ],
      label,
    );
    validateGenerationSet(
      checks.generationsBefore,
      `${label} generations before`,
    );
    validateGenerationSet(
      checks.generationsAfter,
      `${label} generations after`,
    );
    if (
      checks.bridgeExecuted !== true ||
      checks.requestRefused !== true ||
      checks.generationsUnchanged !== true ||
      canonicalJson(checks.generationsBefore) !==
        canonicalJson(checks.generationsAfter)
    ) {
      throw new Error(
        `${label} did not prove that the bridge cannot widen authority`,
      );
    }
    return;
  }
  if (authored.scenario === "post-lockdown-invariant") {
    const booleanChecks = [
      "bridgeExecuted",
      "structuralLockdown",
      "intrinsicsFrozen",
      "evaluatorsTamed",
      "hatchesAbsent",
      "compartmentWithholdsAuthority",
      "prototypeMutationBlocked",
      "authorityRequestRefused",
      "generationsUnchanged",
    ];
    exactKeys(
      checks,
      [...booleanChecks, "generationsBefore", "generationsAfter"],
      label,
    );
    validateGenerationSet(
      checks.generationsBefore,
      `${label} generations before`,
    );
    validateGenerationSet(
      checks.generationsAfter,
      `${label} generations after`,
    );
    if (
      !booleanChecks.every((name) => checks[name] === true) ||
      canonicalJson(checks.generationsBefore) !==
        canonicalJson(checks.generationsAfter)
    ) {
      throw new Error(`${label} did not prove the post-lockdown invariant`);
    }
    return;
  }
  if (authored.scenario === "non-capability") {
    const mechanism = authored.sourceDescriptor?.executionMechanism;
    if (checks.executionMechanism !== mechanism) {
      throw new Error(`${label} did not execute its source-bound mechanism`);
    }
    if (mechanism === "exact-host-call-round-trip") {
      exactKeys(
        checks,
        [
          "executionMechanism",
          "setterInstalled",
          "immutableCapability",
          "genericBridgeAbsent",
          "callbackExecuted",
          "operationId",
          "payloadLength",
          "completion",
          "completionTargetsConsumed",
          "completionCallbacksQueued",
          "completionCallbacksDelivered",
          "singleUseCompletion",
        ],
        label,
      );
      if (
        checks.setterInstalled !== true ||
        checks.immutableCapability !== true ||
        checks.genericBridgeAbsent !== true ||
        checks.callbackExecuted !== true ||
        checks.operationId !== 7 ||
        checks.payloadLength !== 3 ||
        checks.completion !== "9,8" ||
        checks.completionTargetsConsumed !== 1 ||
        checks.completionCallbacksQueued !== 1 ||
        checks.completionCallbacksDelivered !== 1 ||
        checks.singleUseCompletion !== true
      ) {
        throw new Error(
          `${label} did not prove the single-use Exact completion route`,
        );
      }
      return;
    }
    if (mechanism === "exact-endowment-install") {
      exactKeys(
        checks,
        [
          "executionMechanism",
          "setterInstalled",
          "immutableCapability",
          "genericBridgeAbsent",
          "baselineFinalized",
          "refreshHookRemoved",
          "callbackExecuted",
        ],
        label,
      );
      if (
        checks.setterInstalled !== true ||
        checks.immutableCapability !== true ||
        checks.genericBridgeAbsent !== true ||
        checks.baselineFinalized !== true ||
        checks.refreshHookRemoved !== true ||
        checks.callbackExecuted !== false
      ) {
        throw new Error(
          `${label} did not prove immutable Exact endowment installation`,
        );
      }
      return;
    }
    if (mechanism === "exact-endowment-authorize") {
      exactKeys(
        checks,
        [
          "executionMechanism",
          "contextClaimed",
          "endowmentAuthorized",
          "narrowedEndowmentRejected",
          "contextKind",
          "operationIds",
          "operationManifestDigest",
        ],
        label,
      );
      if (
        checks.contextClaimed !== true ||
        checks.endowmentAuthorized !== true ||
        checks.narrowedEndowmentRejected !== true ||
        checks.contextKind !== "app" ||
        canonicalJson(checks.operationIds) !== canonicalJson([7, 11]) ||
        checks.operationManifestDigest !== EXACT_OPERATION_MANIFEST_DIGEST
      ) {
        throw new Error(`${label} did not prove exact-set authorization`);
      }
      return;
    }
    if (mechanism === "exact-gpu-artifact-prepare-round-trip") {
      exactKeys(
        checks,
        [
          "executionMechanism",
          "artifactPrepared",
          "artifactSchema",
          "nonceFreshened",
          "digestRebound",
          "sourceDigest",
          "preparedDigest",
          "preparedPairAuthenticated",
          "descriptorAuthenticated",
          "profileProtected",
          "profileArtifactContentAuthenticated",
          "protectedArtifactCount",
          "profileId",
          "profileDigest",
          "profileArtifactDigest",
          "webgpuCVocabularyDigest",
          "operationSetDigest",
          "semanticProgramDigest",
          "operationIds",
          "topology",
        ],
        label,
      );
      const identityDigests = [
        checks.profileDigest,
        checks.webgpuCVocabularyDigest,
        checks.operationSetDigest,
        checks.semanticProgramDigest,
      ];
      if (
        checks.artifactPrepared !== true ||
        checks.artifactSchema !== "ibex/armed-embedder-artifacts/1" ||
        checks.nonceFreshened !== true ||
        checks.digestRebound !== true ||
        !isTaggedDigest(checks.sourceDigest) ||
        !isTaggedDigest(checks.preparedDigest) ||
        checks.sourceDigest === checks.preparedDigest ||
        checks.preparedPairAuthenticated !== true ||
        checks.descriptorAuthenticated !== true ||
        checks.profileProtected !== true ||
        checks.profileArtifactContentAuthenticated !== true ||
        checks.protectedArtifactCount !== 6 ||
        checks.profileId !== "fixture-v1" ||
        !identityDigests.every(isTaggedDigest) ||
        new Set(identityDigests).size !== identityDigests.length ||
        checks.profileArtifactDigest !== checks.profileDigest ||
        canonicalJson(checks.operationIds) !== canonicalJson([101, 207]) ||
        checks.topology !== "isolated-per-logical-v1"
      ) {
        throw new Error(`${label} did not prove the authenticated Exact GPU profile`);
      }
      return;
    }
    if (mechanism === "exact-artifact-prepare-round-trip") {
      exactKeys(
        checks,
        [
          "executionMechanism",
          "artifactPrepared",
          "artifactSchema",
          "nonceFreshened",
          "digestRebound",
          "sourceDigest",
          "preparedDigest",
          "preparedPairAuthenticated",
        ],
        label,
      );
      if (
        checks.artifactPrepared !== true ||
        checks.artifactSchema !== "ibex/armed-embedder-artifacts/1" ||
        checks.nonceFreshened !== true ||
        checks.digestRebound !== true ||
        !isTaggedDigest(checks.sourceDigest) ||
        !isTaggedDigest(checks.preparedDigest) ||
        checks.sourceDigest === checks.preparedDigest ||
        checks.preparedPairAuthenticated !== true
      ) {
        throw new Error(
          `${label} did not prove authenticated artifact freshening`,
        );
      }
      return;
    }
  }
  throw new Error(`${fixtureId}: unsupported callback invariant scenario`);
}

/**
 * Check a source-derived startup-environment recipe against verifier-owned
 * carrier authority. Keeping this callable independently of runtime evidence
 * lets the fast recipe suite catch inventory/authority drift before a full
 * physical conformance run reaches final artifact validation.
 */
export function validateStartupEnvironmentRecipeDescriptor(recipe) {
  const authored = recipe?.publicSurfaceProbe?.invocation;
  if (
    authored?.invocationSchema !==
    "ibex/capsec-startup-environment-invocation/1"
  ) {
    throw new Error(
      `${recipe?.fixtureId ?? "unknown fixture"}: not a startup environment recipe`,
    );
  }
  const descriptor = authored.sourceDescriptor;
  const operation = authored.operation;
  exactKeys(
    descriptor,
    [
      "kind",
      "surfaceObservedKey",
      "environmentName",
      "sourceRef",
      "liveSourceRefs",
      "carrierEdgeId",
      "implementationBranchIds",
      "enforcementBranchIds",
      "selectedBranch",
      "executionMechanism",
      "moduleSpecifier",
      "preloadModuleSpecifiers",
      "principalMode",
      "auxiliaryDecisionEdgeId",
    ],
    `${recipe.fixtureId}: startup environment source descriptor`,
  );
  exactKeys(
    operation,
    [
      "kind",
      "moduleSpecifier",
      "preloadModuleSpecifiers",
      "environment",
      "principalMode",
    ],
    `${recipe.fixtureId}: startup environment operation`,
  );
  exactKeys(
    operation.environment,
    ["name", "presence"],
    `${recipe.fixtureId}: startup environment setup`,
  );
  const environmentName = operation.environment.name;
  const sourceExpectation =
    STARTUP_ENVIRONMENT_EXPECTATIONS.get(environmentName);
  const expectedPrincipalMode =
    authored.scenario === "deny" ? "package-denied" : "root-authorized";
  if (
    authored.kind !== "startup-environment-source" ||
    authored.surfaceKind !== "startup" ||
    authored.surfaceName !== `env:${environmentName}` ||
    !["allow", "deny", "branch-selection"].includes(authored.scenario) ||
    descriptor.kind !== "startup-environment-source" ||
    descriptor.surfaceObservedKey !== `startup:env:${environmentName}` ||
    descriptor.environmentName !== environmentName ||
    sourceExpectation === undefined ||
    descriptor.sourceRef !== sourceExpectation?.sourceRef ||
    canonicalJson(descriptor.liveSourceRefs) !==
      canonicalJson(sourceExpectation?.liveSourceRefs) ||
    descriptor.carrierEdgeId !== recipe.edgeIds?.[0] ||
    canonicalJson(descriptor.implementationBranchIds) !==
      canonicalJson(recipe.implementationBranchIds) ||
    canonicalJson(descriptor.enforcementBranchIds) !==
      canonicalJson(recipe.enforcementBranchIds) ||
    descriptor.selectedBranch?.id !== "absent" ||
    descriptor.executionMechanism !== sourceExpectation?.mechanism ||
    operation.kind !== sourceExpectation?.mechanism ||
    descriptor.moduleSpecifier !== sourceExpectation?.moduleSpecifier ||
    operation.moduleSpecifier !== sourceExpectation?.moduleSpecifier ||
    canonicalJson(descriptor.preloadModuleSpecifiers) !==
      canonicalJson(sourceExpectation?.preloadModuleSpecifiers) ||
    canonicalJson(operation.preloadModuleSpecifiers) !==
      canonicalJson(sourceExpectation?.preloadModuleSpecifiers) ||
    descriptor.principalMode !== expectedPrincipalMode ||
    operation.principalMode !== expectedPrincipalMode ||
    operation.environment.presence !== "absent" ||
    !Array.isArray(operation.preloadModuleSpecifiers)
  ) {
    throw new Error(
      `${recipe.fixtureId}: startup environment runtime invocation descriptor drift`,
    );
  }
  return recipe;
}

function validateRuntimeInvocation(observation, recipe) {
  const invocation = observation.invocation;
  const authored = recipe.publicSurfaceProbe?.invocation;
  if (!authored || typeof authored.invocationSchema !== "string") {
    throw new Error(
      `${recipe.fixtureId}: public probe has no typed invocation descriptor`,
    );
  }
  const commonKeys = [
    "invocationSchema",
    "kind",
    "surfaceObservedKey",
    "sourceDescriptorDigest",
    "result",
  ];
  if (
    invocation?.invocationSchema === "ibex/capsec-native-global-invocation/1"
  ) {
    const requiresCompletion = authored.completion !== undefined;
    exactKeys(
      invocation,
      [
        ...commonKeys,
        "globalName",
        "executionProof",
        ...(requiresCompletion ? ["completion"] : []),
      ],
      `${recipe.fixtureId}: native runtime invocation`,
    );
    if (
      !new Set([
        "global-property-read",
        "native-global-function",
        "private-native-facade-function",
      ]).has(invocation.kind) ||
      invocation.kind !== authored.kind ||
      invocation.globalName !== authored.globalName
    ) {
      throw new Error(
        `${recipe.fixtureId}: native runtime invocation descriptor drift`,
      );
    }
    const hasPublicAccess = Object.hasOwn(authored, "publicAccess");
    const hasPublicAccessDigest = Object.hasOwn(authored, "publicAccessDigest");
    const hasTopLevelDenyFragment = Object.hasOwn(
      authored,
      "expectedDenyMessageFragment",
    );
    if (authored.kind === "private-native-facade-function") {
      const access = authored.publicAccess;
      exactKeys(
        access,
        [
          "kind",
          "observedKey",
          "installId",
          "path",
          "sourceRefs",
          "privateTerminal",
          "expectedDenyMessageFragment",
        ],
        `${recipe.fixtureId}: private native facade access`,
      );
      exactKeys(
        access.privateTerminal,
        ["observedKey", "installId", "privateConsumer", "liveExpectation"],
        `${recipe.fixtureId}: private native facade terminal`,
      );
      if (
        authored.globalName !== "__exactGetCwd" ||
        recipe.publicSurfaceProbe.surfaceObservedKey !==
          "native-op:__exactGetCwd" ||
        hasPublicAccess !== true ||
        hasPublicAccessDigest !== true ||
        hasTopLevelDenyFragment ||
        authored.publicAccessDigest !== taggedDigest(access) ||
        access.kind !== "captured-private-global-function" ||
        access.observedKey !== "native-op:global:process.cwd" ||
        access.installId !== "root-global.process.cwd.2583c1a2d2ca2d7b" ||
        canonicalJson(access.path) !== canonicalJson(["process", "cwd"]) ||
        canonicalJson(access.sourceRefs) !==
          canonicalJson(PRIVATE_CWD_FACADE_SOURCE_REFS) ||
        access.privateTerminal.observedKey !== "native-op:__exactGetCwd" ||
        access.privateTerminal.installId !==
          "root-global.exactgetcwd.9b3be5b1ccdb728e" ||
        access.privateTerminal.privateConsumer !==
          "trusted-path-process-builtins" ||
        access.privateTerminal.liveExpectation !== "absent" ||
        access.expectedDenyMessageFragment !== "filesystem policy denied"
      ) {
        throw new Error(
          `${recipe.fixtureId}: private native facade provenance drift`,
        );
      }
    } else {
      if (hasPublicAccess || hasPublicAccessDigest) {
        throw new Error(
          `${recipe.fixtureId}: ordinary native invocation carries private facade authority`,
        );
      }
      if (hasTopLevelDenyFragment) {
        try {
          validateNativeFilesystemDenialRecipeDescriptor(authored);
        } catch {
          throw new Error(
            `${recipe.fixtureId}: unreviewed native denial expectation`,
          );
        }
      }
    }
    if (requiresCompletion) {
      exactKeys(
        authored.completion,
        ["kind", "timeoutMilliseconds"],
        `${recipe.fixtureId}: authored native completion`,
      );
      exactKeys(
        invocation.completion,
        ["kind", "status", "timeoutMilliseconds"],
        `${recipe.fixtureId}: native runtime completion`,
      );
      if (
        authored.completion.kind !== "event-loop-quiescence" ||
        authored.completion.timeoutMilliseconds !== 1_000 ||
        invocation.completion.kind !== authored.completion.kind ||
        invocation.completion.timeoutMilliseconds !==
          authored.completion.timeoutMilliseconds ||
        invocation.completion.status !== "quiescent"
      ) {
        throw new Error(
          `${recipe.fixtureId}: native work escaped its observation session`,
        );
      }
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-host-abi-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "functionName"],
      `${recipe.fixtureId}: host ABI runtime invocation`,
    );
    const sqliteMemory = authored.operation?.kind === "sqlite-memory";
    const moduleRunner =
      authored.operation?.kind === "module-runner-source-graph";
    if (
      invocation.kind !== "host-abi-function" ||
      invocation.functionName !== authored.functionName ||
      (!sqliteMemory && !moduleRunner) ||
      authored.sourceDescriptor?.kind !== "host-abi-function" ||
      authored.sourceDescriptor?.functionName !== authored.functionName ||
      (sqliteMemory &&
        (authored.operation?.selectedBranch?.id !== "memory" ||
          canonicalJson(authored.sourceDescriptor?.selectedBranch) !==
            canonicalJson(authored.operation?.selectedBranch))) ||
      (moduleRunner &&
        canonicalJson(authored.sourceDescriptor?.sourceRefs) !==
          canonicalJson([
            `src/engine/hermes_module_runner.cc#${authored.functionName}`,
          ]))
    ) {
      throw new Error(
        `${recipe.fixtureId}: host ABI runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-module-loader-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceName"],
      `${recipe.fixtureId}: module-loader runtime invocation`,
    );
    const operations = new Map([
      ["module-runner-edge-authorization", "authorize-edge"],
      ["module-runner-trusted-source-acquisition", "source-acquisition"],
      ["module-runner-cache-access", "cache-read"],
      ["module-runner-prepared-carrier-access", "prepared-carrier-read"],
    ]);
    const expectedOperation = operations.get(authored.surfaceName);
    const expectedFunction =
      expectedOperation === "authorize-edge"
        ? "authorize"
        : "authorize_then_access";
    if (
      invocation.kind !== "module-loader-authority" ||
      invocation.surfaceName !== authored.surfaceName ||
      !expectedOperation ||
      authored.operation?.kind !== expectedOperation ||
      authored.sourceDescriptor?.kind !== "module-loader-function" ||
      authored.sourceDescriptor?.surfaceName !== authored.surfaceName ||
      canonicalJson(authored.sourceDescriptor?.sourceRefs) !==
        canonicalJson([
          `src/module_loader/security.rs#${expectedFunction}`,
        ])
    ) {
      throw new Error(
        `${recipe.fixtureId}: module-loader runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-builtin-module-import-no-effect-invocation/1"
  ) {
    validateNonCapabilityBuiltinModuleImportInvocation(
      invocation,
      authored,
      recipe,
    );
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-builtin-module-import-invocation/1"
  ) {
    validateEffectBuiltinModuleImportInvocation(invocation, authored, recipe);
  } else if (
    BUILTIN_RUNTIME_INVOCATION_SCHEMAS.has(invocation?.invocationSchema)
  ) {
    const requiresCompletion = recipe.classification === "non-capability";
    exactKeys(
      invocation,
      [
        ...commonKeys,
        "moduleSpecifier",
        "exportName",
        ...(requiresCompletion ? ["completion"] : []),
      ],
      `${recipe.fixtureId}: builtin runtime invocation`,
    );
    const expectedKind =
      invocation.invocationSchema === "ibex/capsec-builtin-call-invocation/1"
        ? "builtin-export-call"
        : null;
    if (
      (expectedKind
        ? invocation.kind !== expectedKind
        : !["builtin-export-call", "builtin-export-read"].includes(
            invocation.kind,
          )) ||
      (invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
        authored.expectedResult !== "normal-return") ||
      invocation.moduleSpecifier !== authored.moduleSpecifier ||
      invocation.exportName !== (authored.exportName ?? null)
    ) {
      throw new Error(
        `${recipe.fixtureId}: builtin runtime invocation descriptor drift`,
      );
    }
    if (requiresCompletion) {
      exactKeys(
        authored.completion,
        ["kind", "timeoutMilliseconds"],
        `${recipe.fixtureId}: authored builtin completion`,
      );
      exactKeys(
        invocation.completion,
        ["kind", "status", "timeoutMilliseconds"],
        `${recipe.fixtureId}: builtin runtime completion`,
      );
      if (
        authored.completion.kind !== "event-loop-quiescence" ||
        authored.completion.timeoutMilliseconds !== 1_000 ||
        invocation.completion.kind !== authored.completion.kind ||
        invocation.completion.timeoutMilliseconds !==
          authored.completion.timeoutMilliseconds ||
        invocation.completion.status !== "quiescent"
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin work escaped its observation session`,
        );
      }
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-startup-surface-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName"],
      `${recipe.fixtureId}: startup runtime invocation`,
    );
    const expectation = STARTUP_EXPECTATIONS.get(authored.surfaceName);
    const descriptor = authored.sourceDescriptor;
    const operation = authored.operation;
    exactKeys(
      descriptor,
      [
        "kind",
        "surfaceName",
        "postcondition",
        "requiredFacts",
        "sourceRefs",
        "sourceMetadata",
        "environment",
      ],
      `${recipe.fixtureId}: startup source descriptor`,
    );
    exactKeys(
      operation,
      ["kind", "postcondition", "requiredFacts", "environment"],
      `${recipe.fixtureId}: startup operation`,
    );
    if (
      invocation.kind !== "startup-loaded-engine" ||
      invocation.surfaceKind !== "startup" ||
      invocation.surfaceName !== authored.surfaceName ||
      expectation === undefined ||
      descriptor.kind !== "startup-loaded-engine-postcondition" ||
      descriptor.surfaceName !== authored.surfaceName ||
      descriptor.postcondition !== expectation.postcondition ||
      canonicalJson(descriptor.requiredFacts) !==
        canonicalJson(expectation.requiredFacts) ||
      canonicalJson(descriptor.sourceRefs) !==
        canonicalJson([expectation.sourceRef]) ||
      descriptor.sourceMetadata !== null ||
      canonicalJson(descriptor.environment) !==
        canonicalJson(expectation.environment) ||
      operation.kind !== "loaded-engine-startup" ||
      operation.postcondition !== expectation.postcondition ||
      canonicalJson(operation.requiredFacts) !==
        canonicalJson(expectation.requiredFacts) ||
      canonicalJson(operation.environment) !==
        canonicalJson(expectation.environment)
    ) {
      throw new Error(
        `${recipe.fixtureId}: startup runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-startup-environment-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName", "scenario"],
      `${recipe.fixtureId}: startup environment runtime invocation`,
    );
    validateStartupEnvironmentRecipeDescriptor(recipe);
    const operation = authored.operation;
    const environmentName = operation.environment.name;
    if (
      invocation.kind !== "startup-environment-source" ||
      invocation.surfaceKind !== "startup" ||
      invocation.surfaceName !== `env:${environmentName}` ||
      invocation.scenario !== authored.scenario
    ) {
      throw new Error(
        `${recipe.fixtureId}: startup environment runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-target-absence-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName", "targetTriple"],
      `${recipe.fixtureId}: target-absence runtime invocation`,
    );
    if (
      invocation.kind !== "target-absence" ||
      invocation.surfaceKind !== authored.surfaceKind ||
      invocation.surfaceName !== authored.surfaceName ||
      invocation.targetTriple !== authored.targetTriple
    ) {
      throw new Error(
        `${recipe.fixtureId}: target-absence runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-closed-surface-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName"],
      `${recipe.fixtureId}: closed-surface runtime invocation`,
    );
    if (
      invocation.kind !== "closed-surface" ||
      invocation.surfaceKind !== authored.surfaceKind ||
      invocation.surfaceName !== authored.surfaceName
    ) {
      throw new Error(
        `${recipe.fixtureId}: closed-surface runtime invocation descriptor drift`,
      );
    }
    if (authored.operation?.kind === "module-runner-namespace") {
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed module-runner source descriptor`,
      );
      exactKeys(
        authored.operation,
        ["kind", "expectedError"],
        `${recipe.fixtureId}: closed module-runner operation`,
      );
      const functionName = "ex_hermes_module_record_namespace_json";
      if (
        authored.surfaceKind !== "host-abi" ||
        authored.surfaceName !== functionName ||
        descriptor.kind !== "closed-module-runner-namespace" ||
        descriptor.surfaceObservedKey !== `host-abi:${functionName}` ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson([
            `src/engine/hermes_module_runner.cc#${functionName}`,
          ]) ||
        descriptor.sourceMetadata?.definitions?.length !== 1 ||
        descriptor.sourceMetadata.definitions[0].language !== "c++" ||
        descriptor.sourceMetadata.definitions[0].sourceRef !==
          descriptor.sourceRefs[0] ||
        authored.operation.expectedError !==
          "native ModuleRecord namespace read refused (-1): module namespace inspection is closed under armed startup"
      ) {
        throw new Error(
          `${recipe.fixtureId}: closed module-runner descriptor drift`,
        );
      }
    }
    if (authored.operation?.kind === "loader-executable-file") {
      throw new Error(
        `${recipe.fixtureId}: authenticated VFS imports cannot prove the legacy loader facet`,
      );
    }
    if (authored.operation?.kind === "terminal-builtin-import") {
      const terminalBuiltin = new Map([
        ["node_async_hooks", ["async_hooks", ["async_hooks", "node:async_hooks"]]],
        [
          "node_inspector",
          [
            "inspector",
            [
              "inspector",
              "inspector/promises",
              "node:inspector",
              "node:inspector/promises",
            ],
          ],
        ],
        ["node_vm", ["vm", ["node:vm", "vm"]]],
        ["node_wasi", ["wasi", ["node:wasi", "wasi"]]],
        [
          "node_worker_threads",
          ["worker_threads", ["node:worker_threads", "worker_threads"]],
        ],
      ]).get(authored.sourceDescriptor?.sourceKey);
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "sourceKey",
          ...(descriptor.exportName === undefined ? [] : ["exportName"]),
          "moduleSpecifiers",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed terminal builtin source descriptor`,
      );
      exactKeys(
        authored.operation,
        [
          "kind",
          "terminalBuiltinRoot",
          "moduleSpecifiers",
          "expectedRejectionFragment",
        ],
        `${recipe.fixtureId}: closed terminal builtin operation`,
      );
      const exportSurface = descriptor.exportName !== undefined;
      const expectedSurfaceName = exportSurface
        ? `export:${descriptor.sourceKey}:${descriptor.exportName}`
        : descriptor.surfaceObservedKey?.slice("builtin:".length);
      if (
        terminalBuiltin === undefined ||
        authored.surfaceKind !== "builtin" ||
        authored.surfaceName !== expectedSurfaceName ||
        recipe.terminalObservedKey !== `builtin:${expectedSurfaceName}` ||
        descriptor.kind !== "closed-terminal-builtin" ||
        descriptor.surfaceObservedKey !== recipe.terminalObservedKey ||
        canonicalJson(descriptor.moduleSpecifiers) !==
          canonicalJson(terminalBuiltin[1]) ||
        !Array.isArray(descriptor.sourceRefs) ||
        descriptor.sourceRefs.length !== 1 ||
        descriptor.sourceMetadata?.sourceKey !== descriptor.sourceKey ||
        descriptor.sourceMetadata?.importReachability !== "public" ||
        authored.operation.terminalBuiltinRoot !== terminalBuiltin[0] ||
        canonicalJson(authored.operation.moduleSpecifiers) !==
          canonicalJson(terminalBuiltin[1]) ||
        authored.operation.expectedRejectionFragment !== "Import denied:" ||
        (exportSurface
          ? descriptor.sourceMetadata?.surfaceType !== "export" ||
            descriptor.sourceMetadata?.exportName !== descriptor.exportName ||
            canonicalJson(
              descriptor.sourceMetadata?.publicModuleSpecifiers,
            ) !== canonicalJson(terminalBuiltin[1])
          : descriptor.sourceMetadata?.surfaceType !== undefined ||
            descriptor.sourceMetadata?.moduleBuiltin !== true ||
            descriptor.sourceMetadata?.bundleExternal !== true ||
            !terminalBuiltin[1].includes(expectedSurfaceName) ||
            descriptor.sourceRefs[0] !==
              `modules.ts#specifiers:${descriptor.sourceKey}`)
      ) {
        throw new Error(
          `${recipe.fixtureId}: terminal builtin closure is not bound to the authenticated import gate`,
        );
      }
    }
    if (authored.operation?.kind === "sqlite-extension-load") {
      const descriptor = authored.sourceDescriptor;
      const constructorExportName = new Map([
        ["Database.loadExtension", "Database"],
        ["default.loadExtension", "default"],
      ]).get(descriptor?.exportName);
      const moduleSpecifiers = ["bun:sqlite", "exact:sqlite"];
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "sourceKey",
          "exportName",
          "constructorExportName",
          "moduleSpecifiers",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed SQLite extension source descriptor`,
      );
      exactKeys(
        authored.operation,
        [
          "kind",
          "constructorExportName",
          "methodName",
          "moduleSpecifiers",
          "databasePath",
          "extensionPath",
          "expectedRejectionFragment",
        ],
        `${recipe.fixtureId}: closed SQLite extension operation`,
      );
      const expectedSurfaceName =
        `export:exact_sqlite:${descriptor.exportName}`;
      if (
        constructorExportName === undefined ||
        authored.surfaceKind !== "builtin" ||
        authored.surfaceName !== expectedSurfaceName ||
        recipe.terminalObservedKey !== `builtin:${expectedSurfaceName}` ||
        descriptor.kind !== "closed-sqlite-extension-load" ||
        descriptor.surfaceObservedKey !== recipe.terminalObservedKey ||
        descriptor.sourceKey !== "exact_sqlite" ||
        descriptor.constructorExportName !== constructorExportName ||
        canonicalJson(descriptor.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson([
            `packages/ibex-runtime-js/src/sqlite/module.js#exports:${descriptor.exportName}`,
          ]) ||
        descriptor.sourceMetadata?.sourceKey !== "exact_sqlite" ||
        descriptor.sourceMetadata?.surfaceType !== "export" ||
        descriptor.sourceMetadata?.exportName !== descriptor.exportName ||
        descriptor.sourceMetadata?.valueShape !== "callable" ||
        descriptor.sourceMetadata?.importReachability !== "public" ||
        canonicalJson(descriptor.sourceMetadata?.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(descriptor.sourceMetadata?.publicModuleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(
          descriptor.sourceMetadata?.enforcementRouteEvidence?.terminals,
        ) !== canonicalJson(["__exactSqliteLoadExtension"]) ||
        canonicalJson(recipe.route?.surfaceObservedKeys) !==
          canonicalJson([recipe.terminalObservedKey]) ||
        canonicalJson(
          recipe.route?.alternatives?.map(
            (alternative) => alternative.terminalObservedKey,
          ),
        ) !== canonicalJson(["native-op:__exactSqliteLoadExtension"]) ||
        authored.operation.constructorExportName !== constructorExportName ||
        authored.operation.methodName !== "loadExtension" ||
        canonicalJson(authored.operation.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        authored.operation.databasePath !== ":memory:" ||
        authored.operation.extensionPath !==
          "ibex-capsec-closed-extension" ||
        authored.operation.expectedRejectionFragment !==
          "Extension loading not supported"
      ) {
        throw new Error(
          `${recipe.fixtureId}: SQLite extension closure is not bound to the public memory-database call`,
        );
      }
    }
    if (authored.operation?.kind === "sqlite-cr-sqlite-enable") {
      const descriptor = authored.sourceDescriptor;
      const constructorExportName = new Map([
        ["Database.enableCrSqlite", "Database"],
        ["default.enableCrSqlite", "default"],
      ]).get(descriptor?.exportName);
      const moduleSpecifiers = ["bun:sqlite", "exact:sqlite"];
      const expectedTerminals = [
        "__exactCrSqlitePath",
        "__exactSqliteLoadCrSqlite",
        "__exactSqliteLoadExtension",
      ];
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "sourceKey",
          "exportName",
          "constructorExportName",
          "moduleSpecifiers",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed cr-sqlite source descriptor`,
      );
      exactKeys(
        authored.operation,
        [
          "kind",
          "constructorExportName",
          "methodName",
          "moduleSpecifiers",
          "databasePath",
          "expectedRejectionFragment",
        ],
        `${recipe.fixtureId}: closed cr-sqlite operation`,
      );
      const expectedSurfaceName =
        `export:exact_sqlite:${descriptor.exportName}`;
      if (
        constructorExportName === undefined ||
        authored.surfaceKind !== "builtin" ||
        authored.surfaceName !== expectedSurfaceName ||
        recipe.terminalObservedKey !== `builtin:${expectedSurfaceName}` ||
        descriptor.kind !== "closed-sqlite-crsqlite-enable" ||
        descriptor.surfaceObservedKey !== recipe.terminalObservedKey ||
        descriptor.sourceKey !== "exact_sqlite" ||
        descriptor.constructorExportName !== constructorExportName ||
        canonicalJson(descriptor.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson([
            `packages/ibex-runtime-js/src/sqlite/module.js#exports:${descriptor.exportName}`,
          ]) ||
        descriptor.sourceMetadata?.sourceKey !== "exact_sqlite" ||
        descriptor.sourceMetadata?.surfaceType !== "export" ||
        descriptor.sourceMetadata?.exportName !== descriptor.exportName ||
        descriptor.sourceMetadata?.valueShape !== "callable" ||
        descriptor.sourceMetadata?.importReachability !== "public" ||
        canonicalJson(descriptor.sourceMetadata?.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(descriptor.sourceMetadata?.publicModuleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(
          [...(
            descriptor.sourceMetadata?.enforcementRouteEvidence?.terminals ??
            []
          )].sort(),
        ) !== canonicalJson([...expectedTerminals].sort()) ||
        canonicalJson(recipe.route?.surfaceObservedKeys) !==
          canonicalJson([recipe.terminalObservedKey]) ||
        canonicalJson(
          [
            ...(recipe.route?.alternatives?.map(
              (alternative) => alternative.terminalObservedKey,
            ) ?? []),
          ].sort(),
        ) !==
          canonicalJson(
            expectedTerminals.map((terminal) => `native-op:${terminal}`).sort(),
          ) ||
        authored.operation.constructorExportName !== constructorExportName ||
        authored.operation.methodName !== "enableCrSqlite" ||
        canonicalJson(authored.operation.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        authored.operation.databasePath !== ":memory:" ||
        authored.operation.expectedRejectionFragment !==
          "cr-sqlite extension not available. The Ibex runtime must be built with cr-sqlite support."
      ) {
        throw new Error(
          `${recipe.fixtureId}: cr-sqlite closure is not bound to the public memory-database call`,
        );
      }
    }
    if (authored.operation?.kind === "debugger-abi-disabled") {
      const debuggerExpectation = new Map([
        ["enable", ["ex_hermes_debugger_enable", "integer-zero"]],
        ["eval", ["ex_hermes_debugger_eval", "null-pointer"]],
        [
          "get-script-source",
          ["ex_hermes_debugger_get_script_source", "null-pointer"],
        ],
        ["get-scripts", ["ex_hermes_debugger_get_scripts", "null-pointer"]],
        ["next-event", ["ex_hermes_debugger_next_event", "null-pointer"]],
        ["pause", ["ex_hermes_debugger_pause", "no-event"]],
        [
          "remove-breakpoint",
          ["ex_hermes_debugger_remove_breakpoint", "no-event"],
        ],
        ["resume", ["ex_hermes_debugger_resume", "no-event"]],
        [
          "set-breakpoint",
          ["ex_hermes_debugger_set_breakpoint", "null-pointer"],
        ],
      ]);
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "functionName",
          "selectedSourceRef",
          "targetTriple",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed debugger ABI source descriptor`,
      );
      exactKeys(
        authored.operation,
        ["kind", "functionName", "expectedCallResult", "expectedError"],
        `${recipe.fixtureId}: closed debugger ABI operation`,
      );
      const operationSlug = [...debuggerExpectation].find(
        ([, [functionName]]) =>
          functionName === authored.operation.functionName,
      )?.[0];
      const expected = debuggerExpectation.get(operationSlug);
      const functionName = authored.operation.functionName;
      const defaultSourceRef =
        `src/engine/hermes_runtime_debugger.cc#${functionName}`;
      const windowsSourceRef =
        `src/engine/hermes_runtime_platform_windows.cc#${functionName}`;
      const selectedSourceRefByTarget = new Map([
        ["aarch64-apple-darwin", defaultSourceRef],
        ["x86_64-pc-windows-msvc", windowsSourceRef],
      ]);
      const expectedSelectedSourceRef = selectedSourceRefByTarget.get(
        descriptor.targetTriple,
      );
      const expectedSurfaceName =
        authored.surfaceKind === "host-abi"
          ? functionName
          : `inspector.debugger-${operationSlug}`;
      const alternative = (targetVariant, sourceRef) => ({
        id: targetVariant,
        kind: "alternative",
        sourceRefs: [sourceRef],
        stubDisposition: "not-structurally-proven",
        targetVariant,
      });
      const alternatives = [
        alternative("default", defaultSourceRef),
        alternative("windows", windowsSourceRef),
      ];
      const expectedReturnKind = new Map([
        ["integer-zero", "scalar"],
        ["no-event", "void"],
        ["null-pointer", "pointer"],
      ]).get(expected?.[1]);
      const metadata = descriptor.sourceMetadata;
      const definitions = metadata?.definitions;
      const outputContracts = metadata?.outputContracts;
      const metadataSources = [
        ["default", defaultSourceRef],
        ["windows", windowsSourceRef],
      ];
      const resolvedOutputContract = (contract, sourceRef) => {
        if (
          !hasExactKeys(contract, [
            "bufferLengthPairs",
            "functionName",
            "language",
            "outputChannels",
            "parameters",
            "return",
            "schema",
            "sourceRef",
            "status",
            "unresolved",
          ]) ||
          contract.schema !== "ibex/host-abi-output-contract/1" ||
          contract.language !== "c++" ||
          contract.functionName !== functionName ||
          contract.sourceRef !== sourceRef ||
          contract.status !== "resolved" ||
          !Array.isArray(contract.bufferLengthPairs) ||
          !Array.isArray(contract.outputChannels) ||
          !Array.isArray(contract.parameters) ||
          !hasExactKeys(contract.return, ["kind", "ownership", "role", "type"]) ||
          contract.return.kind !== expectedReturnKind ||
          canonicalJson(contract.unresolved) !== canonicalJson([])
        ) {
          return false;
        }
        return expectedReturnKind === "void"
          ? contract.outputChannels.length === 0
          : contract.outputChannels.length === 1 &&
              contract.outputChannels[0]?.kind === expectedReturnKind &&
              contract.outputChannels[0]?.role === "return" &&
              contract.outputChannels[0]?.selector === "[[return]]";
      };
      const hostMetadataBound =
        hasExactKeys(metadata, [
          "alternatives",
          "branches",
          "definitions",
          "outputContracts",
          "provenanceLimitation",
        ]) &&
        canonicalJson(metadata.alternatives) === canonicalJson(alternatives) &&
        canonicalJson(metadata.branches) === canonicalJson(alternatives) &&
        metadata.provenanceLimitation ===
          "ABI definitions are source-structural evidence; supported/unsupported target semantics require fixtures." &&
        Array.isArray(definitions) &&
        definitions.length === metadataSources.length &&
        Array.isArray(outputContracts) &&
        outputContracts.length === metadataSources.length &&
        metadataSources.every(([targetVariant, sourceRef], index) => {
          const definition = definitions[index];
          const contract = outputContracts[index];
          return (
            hasExactKeys(definition, [
              "language",
              "outputContract",
              "sourceRef",
              "targetVariant",
              "unsafe",
              "weak",
            ]) &&
            definition.language === "c++" &&
            definition.sourceRef === sourceRef &&
            definition.targetVariant === targetVariant &&
            definition.unsafe === false &&
            definition.weak === false &&
            canonicalJson(definition.outputContract) ===
              canonicalJson(contract) &&
            resolvedOutputContract(contract, sourceRef)
          );
        });
      const sourceMetadataBound =
        authored.surfaceKind === "host-abi"
          ? hostMetadataBound
          : descriptor.sourceMetadata === null;
      if (
        expected === undefined ||
        !["host-abi", "native-op"].includes(authored.surfaceKind) ||
        authored.surfaceName !== expectedSurfaceName ||
        recipe.terminalObservedKey !==
          `${authored.surfaceKind}:${expectedSurfaceName}` ||
        descriptor.kind !== "closed-debugger-abi" ||
        descriptor.surfaceObservedKey !== recipe.terminalObservedKey ||
        descriptor.functionName !== functionName ||
        expectedSelectedSourceRef === undefined ||
        descriptor.selectedSourceRef !== expectedSelectedSourceRef ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson([defaultSourceRef, windowsSourceRef]) ||
        sourceMetadataBound !== true ||
        authored.operation.expectedCallResult !== expected[1] ||
        authored.operation.expectedError !==
          `debugger ABI ${functionName} is unavailable in the no-debugger exact target`
      ) {
        throw new Error(
          `${recipe.fixtureId}: debugger ABI closure is not bound to the physical no-debugger target`,
        );
      }
    }
    if (authored.operation?.kind === "shared-runtime-global-absence") {
      const reviewedSurfaces = new Set([
        "__exactAllowNativesSyntax",
        "__exactCompatEval",
        "__exactDebugModuleSource",
        "__exactDebugModuleSources",
        "__exactDebugModuleSources.length",
        "__exactInstallAsyncIpcListenerPatch",
        "__exactInstallProcessIpcBootstrap",
        "__exactNativeWrapState",
        "__exactNativeWrapState.Pipe",
        "__exactNativeWrapState.TCP",
        "__exactNativeWrapState.TCPConnectWrap",
        "__exactNativeWrapState.UV_EINVAL",
        "__exactNativeWrapState.byFd",
        "__exactNativeWrapState.pipeConstants",
        "__exactNativeWrapState.tcpConstants",
        "__exactStreamWrapState",
        "__exactSyncTrackedIpcListenersAfterDispatch",
        "global:Bun.gc",
        "global:Cache",
        "global:Cache.add",
        "global:Cache.addAll",
        "global:Cache.delete",
        "global:Cache.keys",
        "global:Cache.match",
        "global:Cache.matchAll",
        "global:Cache.put",
        "global:CacheStorage",
        "global:CacheStorage.delete",
        "global:CacheStorage.has",
        "global:CacheStorage.keys",
        "global:CacheStorage.match",
        "global:CacheStorage.open",
        "global:Bun.accessibility",
        "global:Bun.accessibility.addEventListener",
        "global:Bun.accessibility.announce",
        "global:Bun.accessibility.colorScheme",
        "global:Bun.accessibility.dynamicTypeSize",
        "global:Bun.accessibility.fontScale",
        "global:Bun.accessibility.get",
        "global:Bun.accessibility.isBoldTextEnabled",
        "global:Bun.accessibility.isGrayscaleEnabled",
        "global:Bun.accessibility.isInvertColorsEnabled",
        "global:Bun.accessibility.isScreenReaderEnabled",
        "global:Bun.accessibility.prefersHighContrast",
        "global:Bun.accessibility.prefersReducedMotion",
        "global:Bun.accessibility.prefersReducedTransparency",
        "global:Exact.accessibility",
        "global:Exact.accessibility.addEventListener",
        "global:Exact.accessibility.announce",
        "global:Exact.accessibility.colorScheme",
        "global:Exact.accessibility.dynamicTypeSize",
        "global:Exact.accessibility.fontScale",
        "global:Exact.accessibility.get",
        "global:Exact.accessibility.isBoldTextEnabled",
        "global:Exact.accessibility.isGrayscaleEnabled",
        "global:Exact.accessibility.isInvertColorsEnabled",
        "global:Exact.accessibility.isScreenReaderEnabled",
        "global:Exact.accessibility.prefersHighContrast",
        "global:Exact.accessibility.prefersReducedMotion",
        "global:Exact.accessibility.prefersReducedTransparency",
        "global:Exact.gc",
      ]);
      const reviewedRoots = new Set([
        "BroadcastChannel",
        "caches",
        "IDBCursor",
        "IDBCursorWithValue",
        "IDBDatabase",
        "IDBIndex",
        "IDBKeyRange",
        "IDBObjectStore",
        "IDBOpenDBRequest",
        "IDBRequest",
        "IDBTransaction",
        "indexedDB",
        "localStorage",
        "MessageChannel",
        "MessagePort",
        "sessionStorage",
      ]);
      const reviewedSurface =
        reviewedSurfaces.has(authored.surfaceName) ||
        (authored.surfaceName.startsWith("global:") &&
          reviewedRoots.has(
            authored.surfaceName.slice("global:".length).split(".", 1)[0],
          ));
      const descriptor = authored.sourceDescriptor;
      const exactTarget = new Set([
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
      ]).has(descriptor.targetTriple);
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "globalName",
          ...(descriptor.memberName === undefined ? [] : ["memberName"]),
          "targetTriple",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed shared-runtime global descriptor`,
      );
      exactKeys(
        authored.operation,
        ["kind", "globalName", "memberName", "expectedError"],
        `${recipe.fixtureId}: closed shared-runtime global operation`,
      );
      const metadata = descriptor.sourceMetadata;
      const memberName = authored.operation.memberName;
      const exportName =
        memberName === null
          ? authored.operation.globalName
          : `${authored.operation.globalName}.${memberName}`;
      const branches = metadata?.installationBranches;
      const branch = branches?.[0];
      const sharedRuntimeInstallation =
        metadata?.sourceKey === "shared_runtime";
      const reviewedSharedRuntimeBranch =
        branch?.route === "shared-runtime" &&
        branch.targetVariant === "all" &&
        canonicalJson(branch.routes) === canonicalJson(["shared-runtime"]);
      const reviewedComposedSharedRuntimeBranch =
        branch?.route === "composed:legacy-bootstrap+shared-runtime" &&
        branch.targetVariant === "default" &&
        canonicalJson(branch.routes) ===
          canonicalJson(["legacy-bootstrap", "shared-runtime"]);
      const reviewedLegacySourceKeys = new Set([
        "global_compat_polyfills",
        "global_exact_global",
        "global_ipc_listener",
        "global_module_loader",
        "global_process_compat_fix",
        "global_web_storage",
      ]);
      const reviewedLegacyBranch =
        reviewedLegacySourceKeys.has(metadata?.sourceKey) &&
        branch?.route === "legacy-bootstrap" &&
        branch.targetVariant === "default" &&
        canonicalJson(branch.routes) === canonicalJson(["legacy-bootstrap"]);
      const reviewedInstallation =
        Array.isArray(branches) &&
        branches.length === 1 &&
        canonicalJson(branch.sourceRefs) === canonicalJson(descriptor.sourceRefs) &&
        (sharedRuntimeInstallation
          ? reviewedSharedRuntimeBranch ||
            reviewedComposedSharedRuntimeBranch
          : reviewedLegacyBranch);
      if (
        !reviewedSurface ||
        authored.surfaceKind !== "native-op" ||
        descriptor.kind !== "closed-shared-runtime-global-absence" ||
        descriptor.surfaceObservedKey !==
          `native-op:${authored.surfaceName}` ||
        recipe.terminalObservedKey !== descriptor.surfaceObservedKey ||
        descriptor.globalName !== authored.operation.globalName ||
        (descriptor.memberName ?? null) !== memberName ||
        !exactTarget ||
        !Array.isArray(descriptor.sourceRefs) ||
        descriptor.sourceRefs.length === 0 ||
        metadata?.surfaceType !== "global-api" ||
        metadata.globalName !== authored.operation.globalName ||
        metadata.memberName !== memberName ||
        metadata.exportName !== exportName ||
        !reviewedInstallation ||
        authored.operation.expectedError !==
          `armed shared runtime does not expose ${exportName}`
      ) {
        throw new Error(
          `${recipe.fixtureId}: shared-runtime global closure is not bound to a reviewed installation path`,
        );
      }
    }
    if (authored.operation?.kind === "armed-native-global-absence") {
      const reviewedDirectGlobals = new Set([
        "__exactExit",
        "__exactGetGCStats",
        "__exactGetHeapInfo",
        "__exactGetSourceCacheStats",
        "__exactIpcRecvMsg",
        "__exactIpcSendMsg",
        "__exactPollSignal",
        "__exactResetSignal",
        "__exactSetCwd",
      ]);
      const reviewedWorkletGlobals = new Set([
        "global:measure",
        "global:scheduleOnAppRuntime",
        "global:worklet",
        "global:worklet.capture",
        "global:worklet.captureGet",
        "global:worklet.captureSet",
        "global:worklet.clamp",
        "global:worklet.lerp",
        "global:worklet.output",
        "global:worklet.runOnJS",
        "global:worklet.sharedValue",
      ]);
      const directArmedGlobal = reviewedDirectGlobals.has(
        authored.surfaceName,
      );
      const appRuntimeAbsentWorkletGlobal = reviewedWorkletGlobals.has(
        authored.surfaceName,
      );
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "globalName",
          ...(descriptor.memberName === undefined ? [] : ["memberName"]),
          "targetTriple",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed armed native global descriptor`,
      );
      exactKeys(
        authored.operation,
        [
          "kind",
          "globalName",
          ...(authored.operation.memberName === undefined
            ? []
            : ["memberName"]),
          "expectedError",
        ],
        `${recipe.fixtureId}: closed armed native global operation`,
      );
      const metadata = descriptor.sourceMetadata;
      const branches = metadata?.installationBranches;
      const publicInvocation = metadata?.publicInvocation;
      const memberName = authored.operation.memberName ?? null;
      const exportName =
        memberName === null
          ? authored.operation.globalName
          : `${authored.operation.globalName}.${memberName}`;
      const defaultBranch = branches?.find(
        (branch) =>
          branch.route === "native-jsi-global" &&
          branch.targetVariant === "default",
      );
      const workletBranch = branches?.find(
        (branch) =>
          ["evaluated-native-script", "native-jsi-global"].includes(
            branch.route,
          ) && branch.targetVariant === "worklet",
      );
      const exactTarget = new Set([
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
      ]).has(descriptor.targetTriple);
      const reviewedDirectGlobal =
        directArmedGlobal &&
        metadata?.sourceKey === "native_jsi_global" &&
        metadata.globalName === authored.surfaceName &&
        metadata.memberName === null &&
        canonicalJson(metadata.memberKinds) ===
          canonicalJson(["native-root"]) &&
        publicInvocation?.kind === "native-global-function" &&
        publicInvocation.globalName === metadata.globalName &&
        Number.isSafeInteger(publicInvocation.arity) &&
        publicInvocation.arity >= 0 &&
        typeof publicInvocation.sourceRef === "string" &&
        descriptor.sourceRefs.includes(publicInvocation.sourceRef) &&
        defaultBranch?.sourceRefs.includes(publicInvocation.sourceRef);
      const reviewedWorkletGlobal =
        appRuntimeAbsentWorkletGlobal &&
        authored.surfaceName === `global:${exportName}` &&
        Array.isArray(branches) &&
        branches.length === 1 &&
        canonicalJson(workletBranch?.sourceRefs) ===
          canonicalJson(descriptor.sourceRefs) &&
        (metadata?.sourceKey === "native_jsi_global"
          ? workletBranch?.route === "native-jsi-global" &&
            canonicalJson(workletBranch.routes) ===
              canonicalJson(["native-jsi-global"]) &&
            canonicalJson(metadata.memberKinds) ===
              canonicalJson([
                memberName === null ? "native-root" : "native-object-member",
              ]) &&
            publicInvocation?.kind === "native-global-function" &&
            publicInvocation.globalName === metadata.globalName &&
            Number.isSafeInteger(publicInvocation.arity) &&
            publicInvocation.arity >= 0 &&
            typeof publicInvocation.sourceRef === "string" &&
            descriptor.sourceRefs.includes(publicInvocation.sourceRef)
          : metadata?.sourceKey === "evaluated_native_script" &&
            workletBranch?.route === "evaluated-native-script" &&
            canonicalJson(workletBranch.routes) ===
              canonicalJson(["evaluated-native-script"]) &&
            metadata.evaluatedScript === "kPrelude" &&
            canonicalJson(metadata.sourceUrls) ===
              canonicalJson(["worklet-prelude.js"]));
      if (
        (!directArmedGlobal && !appRuntimeAbsentWorkletGlobal) ||
        authored.surfaceKind !== "native-op" ||
        descriptor.kind !== "closed-armed-native-global-absence" ||
        descriptor.surfaceObservedKey !== `native-op:${authored.surfaceName}` ||
        recipe.terminalObservedKey !== descriptor.surfaceObservedKey ||
        descriptor.globalName !== authored.operation.globalName ||
        (descriptor.memberName ?? null) !== memberName ||
        !exactTarget ||
        !Array.isArray(descriptor.sourceRefs) ||
        descriptor.sourceRefs.length === 0 ||
        metadata?.surfaceType !== "global-api" ||
        metadata.globalName !== authored.operation.globalName ||
        metadata.memberName !== memberName ||
        metadata.exportName !== exportName ||
        !Array.isArray(branches) ||
        (!reviewedDirectGlobal && !reviewedWorkletGlobal) ||
        authored.operation.expectedError !==
          `armed runtime does not expose ${exportName}`
      ) {
        throw new Error(
          `${recipe.fixtureId}: armed native global closure is not bound to the reviewed source-derived JSI path`,
        );
      }
    }
    if (authored.operation?.kind === "exact-unendowed-operation") {
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "globalName",
          "memberName",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed Exact source descriptor`,
      );
      exactKeys(
        authored.operation,
        [
          "kind",
          "contextKind",
          "operationManifestDigest",
          "endowedOperationIds",
          "selectedOperationId",
          "expectedError",
        ],
        `${recipe.fixtureId}: closed Exact operation`,
      );
      if (
        authored.surfaceKind !== "native-op" ||
        authored.surfaceName !== "global:exact.invokeHostAsync" ||
        recipe.terminalObservedKey !==
          "native-op:global:exact.invokeHostAsync" ||
        descriptor.kind !== "closed-exact-unendowed-operation" ||
        descriptor.surfaceObservedKey !== recipe.terminalObservedKey ||
        descriptor.globalName !== "exact" ||
        descriptor.memberName !== "invokeHostAsync" ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson([
            "src/engine/hermes_runtime.cc#jsi-global:exact.invokeHostAsync",
          ]) ||
        descriptor.sourceMetadata?.surfaceType !== "global-api" ||
        descriptor.sourceMetadata?.sourceKey !== "native_jsi_global" ||
        descriptor.sourceMetadata?.globalName !== "exact" ||
        descriptor.sourceMetadata?.memberName !== "invokeHostAsync" ||
        canonicalJson(descriptor.sourceMetadata?.memberKinds) !==
          canonicalJson(["native-object-member"]) ||
        authored.operation.contextKind !== "app" ||
        authored.operation.operationManifestDigest !==
          EXACT_OPERATION_MANIFEST_DIGEST ||
        canonicalJson(authored.operation.endowedOperationIds) !==
          canonicalJson([7, 11]) ||
        authored.operation.selectedOperationId !== 8 ||
        authored.operation.endowedOperationIds.includes(
          authored.operation.selectedOperationId,
        ) ||
        authored.operation.expectedError !==
          "exact.invokeHostAsync operation is not endowed"
      ) {
        throw new Error(
          `${recipe.fixtureId}: closed Exact invocation is not bound to the authenticated unendowed operation`,
        );
      }
    }
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-callback-invariant-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName", "scenario"],
      `${recipe.fixtureId}: callback invariant runtime invocation`,
    );
    if (
      invocation.kind !== "callback-security-invariant" ||
      invocation.surfaceKind !== authored.surfaceKind ||
      invocation.surfaceName !== authored.surfaceName ||
      invocation.scenario !== authored.scenario ||
      recipe.publicSurfaceProbe.kind !== "public-surface-invocation" ||
      authored.scenario !== "non-capability" ||
      authored.sourceDescriptor?.proofScope !== "source-bound-exact-mechanism"
    ) {
      throw new Error(
        `${recipe.fixtureId}: callback invariant runtime invocation descriptor drift`,
      );
    }
    const expected = EXACT_EMBEDDER_NON_CAPABILITY_SURFACES.get(
      recipe.publicSurfaceProbe.surfaceObservedKey,
    );
    const descriptor = authored.sourceDescriptor;
    exactKeys(
      descriptor,
      [
        "kind",
        "proofScope",
        "scenario",
        "rationaleId",
        "surfaceObservedKey",
        "edgeId",
        "branchId",
        "sourceRefs",
        "coverageEdge",
        "implementationBranch",
        "liveSurface",
        "executionMechanism",
        "auxiliaryDecisionEdgeId",
      ],
      `${recipe.fixtureId}: Exact non-capability source descriptor`,
    );
    if (
      recipe.classification !== "non-capability" ||
      expected === undefined ||
      descriptor.kind !== "callback-security-invariant" ||
      descriptor.proofScope !== "source-bound-exact-mechanism" ||
      descriptor.scenario !== "non-capability" ||
      descriptor.rationaleId !== expected[0] ||
      descriptor.executionMechanism !== expected[1] ||
      descriptor.surfaceObservedKey !==
        recipe.publicSurfaceProbe.surfaceObservedKey ||
      descriptor.edgeId !== recipe.edgeIds[0] ||
      descriptor.branchId !== recipe.implementationBranchIds[0] ||
      descriptor.auxiliaryDecisionEdgeId !== null ||
      descriptor.coverageEdge?.id !== recipe.edgeIds[0] ||
      descriptor.implementationBranch?.branchId !==
        recipe.implementationBranchIds[0] ||
      descriptor.liveSurface?.observedKey !==
        recipe.publicSurfaceProbe.surfaceObservedKey ||
      !Array.isArray(descriptor.sourceRefs) ||
      descriptor.sourceRefs.length === 0 ||
      !descriptor.sourceRefs.some((sourceRef) =>
        descriptor.liveSurface?.sourceRefs?.includes(sourceRef),
      )
    ) {
      throw new Error(
        `${recipe.fixtureId}: Exact non-capability invocation is not source-bound`,
      );
    }
  } else {
    throw new Error(
      `${recipe.fixtureId}: unsupported runtime invocation schema`,
    );
  }
  if (
    invocation.invocationSchema !== authored.invocationSchema ||
    invocation.kind !== authored.kind ||
    invocation.surfaceObservedKey !==
      recipe.publicSurfaceProbe.surfaceObservedKey ||
    invocation.sourceDescriptorDigest !== authored.sourceDescriptorDigest ||
    authored.sourceDescriptorDigest !== taggedDigest(authored.sourceDescriptor)
  ) {
    throw new Error(
      `${recipe.fixtureId}: runtime invocation is not source-descriptor bound`,
    );
  }
  const callbackInvariant =
    authored.invocationSchema === "ibex/capsec-callback-invariant-invocation/1";
  const startupEnvironment =
    authored.invocationSchema ===
    "ibex/capsec-startup-environment-invocation/1";
  const effectBuiltinModuleImport =
    authored.invocationSchema ===
    "ibex/capsec-builtin-module-import-invocation/1";
  const noncapBuiltinModuleImport =
    authored.invocationSchema ===
    "ibex/capsec-builtin-module-import-no-effect-invocation/1";
  const outcomeDeclaredCarrier = callbackInvariant || startupEnvironment;
  const auxiliaryCarrier =
    outcomeDeclaredCarrier || effectBuiltinModuleImport;
  if (
    !Number.isSafeInteger(authored.expectedTypedDecisionCount) ||
    authored.expectedTypedDecisionCount < 0 ||
    !Array.isArray(authored.expectedTypedStages) ||
    authored.expectedTypedDecisionCount !==
      authored.expectedTypedStages.length ||
    !Array.isArray(authored.allowedCoverageEdgeIds) ||
    !Array.isArray(authored.expectedActionIds) ||
    !authored.expectedTypedStages.every(
      (stage) => typeof stage === "string" && stage.length > 0,
    ) ||
    !authored.allowedCoverageEdgeIds.every(
      (edgeId) => typeof edgeId === "string" && edgeId.length > 0,
    ) ||
    !authored.expectedActionIds.every(
      (actionId) => typeof actionId === "string" && actionId.length > 0,
    ) ||
    (!auxiliaryCarrier &&
      authored.expectedActionIds.some(
        (actionId) => !recipe.actionIds.includes(actionId),
      )) ||
    (authored.expectedTypedDecisionCount > 0 &&
      authored.expectedActionIds.length === 0) ||
    canonicalJson(authored.allowedCoverageEdgeIds) !==
      canonicalJson(canonicalSet(authored.allowedCoverageEdgeIds)) ||
    canonicalJson(authored.expectedActionIds) !==
      canonicalJson(canonicalSet(authored.expectedActionIds))
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed authored runtime expectations`,
    );
  }
  if (
    outcomeDeclaredCarrier &&
    (!Array.isArray(authored.expectedTypedOutcomes) ||
      authored.expectedTypedOutcomes.length !==
        authored.expectedTypedDecisionCount ||
      !authored.expectedTypedOutcomes.every((outcome) =>
        ["allow", "deny"].includes(outcome),
      ) ||
      !Array.isArray(authored.expectedTypedReasons) ||
      authored.expectedTypedReasons.length !==
        authored.expectedTypedDecisionCount ||
      !authored.expectedTypedReasons.every(
        (reason) => typeof reason === "string" && reason.length > 0,
      ))
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed auxiliary carrier expectations`,
    );
  }
  if (
    startupEnvironment &&
    (!Array.isArray(authored.expectedResourceNames) ||
      canonicalJson(authored.expectedResourceNames) !==
        canonicalJson(canonicalSet(authored.expectedResourceNames)) ||
      authored.expectedResourceNames.length !== 1 ||
      authored.expectedResourceNames[0] !== authored.operation.environment.name)
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed startup environment resource binding`,
    );
  }
  if (!invocation.result || typeof invocation.result !== "object") {
    throw new Error(`${recipe.fixtureId}: runtime invocation has no result`);
  }
  if (authored.expectedResult === "normal-return") {
    if (
      authored.invocationSchema !== "ibex/capsec-builtin-call-invocation/1" ||
      authored.kind !== "builtin-export-call" ||
      !authored.bodyEntryProof ||
      authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
      !NORMAL_RETURN_RESULT_TYPES.has(authored.bodyEntryProof.resultType) ||
      !authored.setup ||
      typeof authored.setup.kind !== "string"
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored normal-return proof`,
      );
    }
    if (!NORMAL_RETURN_DISPATCH_KINDS.has(authored.setup.kind)) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored normal-return setup`,
      );
    }
    const cleanupRequired = authored.setup.kind === "zlib-owner";
    exactKeys(
      invocation.result,
      [
        "kind",
        "moduleSpecifier",
        "exportName",
        "valueType",
        "dispatchKind",
        "bodyEntryProof",
        ...(cleanupRequired ? ["cleanupPerformed"] : []),
      ],
      `${recipe.fixtureId}: builtin normal-return result`,
    );
    const expectedDispatchKind = NORMAL_RETURN_DISPATCH_KINDS.get(
      authored.setup.kind,
    );
    if (
      invocation.result.kind !== "return" ||
      invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
      invocation.result.exportName !== authored.exportName ||
      invocation.result.valueType !== authored.bodyEntryProof.resultType ||
      invocation.result.dispatchKind !== expectedDispatchKind ||
      invocation.result.bodyEntryProof !== authored.bodyEntryProof.kind ||
      (cleanupRequired && invocation.result.cleanupPerformed !== true)
    ) {
      throw new Error(
        `${recipe.fixtureId}: builtin call did not prove its exact normal return`,
      );
    }
  } else if (authored.expectedResult === "return") {
    if (invocation.result.kind !== "return") {
      throw new Error(`${recipe.fixtureId}: public invocation did not return`);
    }
    if (authored.expectedStringValue !== undefined) {
      exactKeys(
        invocation.result,
        [
          "kind",
          "moduleSpecifier",
          "exportName",
          "valueType",
          "stringValue",
        ],
        `${recipe.fixtureId}: builtin string result`,
      );
      if (
        authored.invocationSchema !==
          "ibex/capsec-builtin-export-invocation/1" ||
        authored.kind !== "builtin-export-call" ||
        authored.moduleSpecifier !== "node:fs" ||
        authored.exportName !== "readlinkSync" ||
        typeof authored.expectedStringValue !== "string" ||
        authored.expectedStringValue.length === 0 ||
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        invocation.result.exportName !== authored.exportName ||
        invocation.result.valueType !== "string" ||
        invocation.result.stringValue !== authored.expectedStringValue
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin string return did not match its authored value`,
        );
      }
    }
    if (
      (effectBuiltinModuleImport || noncapBuiltinModuleImport)
    ) {
      exactKeys(
        invocation.result,
        ["kind", "moduleSpecifier", "valueType"],
        `${recipe.fixtureId}: builtin module-import result`,
      );
      if (
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        invocation.result.valueType !==
          (noncapBuiltinModuleImport
            ? authored.sourceDescriptor.expectedRootType
            : "object")
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin module import returned the wrong module`,
        );
      }
    }
    if (authored.kind === "builtin-export-read") {
      exactKeys(
        invocation.result,
        ["kind", "moduleSpecifier", "exportName", "valueType"],
        `${recipe.fixtureId}: builtin read result`,
      );
      if (
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        invocation.result.exportName !== authored.exportName ||
        typeof invocation.result.valueType !== "string"
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin read returned the wrong export`,
        );
      }
    }
    if (
      authored.invocationSchema === "ibex/capsec-native-global-invocation/1" &&
      authored.kind === "native-global-function"
    ) {
      const armedEnvironmentEnumeration =
        authored.globalName === "__exactGetAllEnv";
      exactKeys(
        invocation.result,
        [
          "kind",
          "globalName",
          "valueType",
          "cleanup",
          ...(armedEnvironmentEnumeration ? ["valuePropertyCount"] : []),
        ],
        `${recipe.fixtureId}: native call result`,
      );
      if (
        invocation.result.globalName !== authored.globalName ||
        typeof invocation.result.valueType !== "string" ||
        typeof invocation.result.cleanup !== "string" ||
        (armedEnvironmentEnumeration &&
          (invocation.result.valueType !== "object" ||
            invocation.result.valuePropertyCount !== 0 ||
            invocation.result.cleanup !== "none")) ||
        (authored.expectedCleanup !== undefined &&
          invocation.result.cleanup !== authored.expectedCleanup)
      ) {
        throw new Error(
          `${recipe.fixtureId}: native call did not prove its authored cleanup`,
        );
      }
    }
    if (
      authored.invocationSchema === "ibex/capsec-native-global-invocation/1" &&
      authored.kind === "global-property-read"
    ) {
      exactKeys(
        invocation.result,
        ["kind", "globalName", "valueType", "ownerDepths", "cleanup"],
        `${recipe.fixtureId}: global read result`,
      );
      const descriptor = authored.sourceDescriptor;
      const inherited = descriptor?.memberKinds?.includes("inherited") === true;
      const ownerDepths = invocation.result.ownerDepths;
      const valueType = invocation.result.valueType;
      if (
        invocation.result.globalName !== authored.globalName ||
        !new Set([
          "bigint",
          "boolean",
          "function",
          "null",
          "number",
          "object",
          "string",
          "symbol",
          "undefined",
        ]).has(valueType) ||
        (descriptor?.valueShape === "data" && valueType === "function") ||
        invocation.result.cleanup !== "none" ||
        !Array.isArray(descriptor?.access?.path) ||
        !Array.isArray(ownerDepths) ||
        ownerDepths.length !== descriptor.access.path.length ||
        !ownerDepths.every(
          (depth) => Number.isSafeInteger(depth) && depth >= 0,
        ) ||
        (inherited &&
          (descriptor.valueShape !== "data" ||
            !descriptor.memberKinds.includes("static") ||
            ownerDepths.at(-1) === 0))
      ) {
        throw new Error(
          `${recipe.fixtureId}: global read did not prove its exact property owner chain`,
        );
      }
    }
    if (
      authored.invocationSchema === "ibex/capsec-host-abi-invocation/1"
    ) {
      if (authored.operation.kind === "sqlite-memory") {
        exactKeys(
          invocation.result,
          ["kind", "functionName", "operation", "cleanup"],
          `${recipe.fixtureId}: host ABI runtime result`,
        );
        if (
          invocation.result.functionName !== authored.functionName ||
          invocation.result.operation !== "sqlite-memory" ||
          invocation.result.cleanup !== "released-sqlite-memory-state"
        ) {
          throw new Error(
            `${recipe.fixtureId}: host ABI runtime result did not prove bounded cleanup`,
          );
        }
      } else {
        exactKeys(
          invocation.result,
          [
            "kind",
            "functionName",
            "operation",
            "observedFunctionNames",
            "cleanup",
          ],
          `${recipe.fixtureId}: module-runner host ABI runtime result`,
        );
        if (
          invocation.result.functionName !== authored.functionName ||
          invocation.result.operation !== "module-runner-source-graph" ||
          invocation.result.cleanup !== "released-module-graph" ||
          !Array.isArray(invocation.result.observedFunctionNames) ||
          !invocation.result.observedFunctionNames.includes(
            authored.functionName,
          )
        ) {
          throw new Error(
            `${recipe.fixtureId}: module-runner graph did not enter the exact host ABI`,
          );
        }
      }
    } else if (
      authored.invocationSchema ===
      "ibex/capsec-module-loader-invocation/1"
    ) {
      exactKeys(
        invocation.result,
        ["kind", "surfaceName", "operation", "accessExecuted", "cleanup"],
        `${recipe.fixtureId}: module-loader runtime result`,
      );
      const isAccess = authored.operation.kind !== "authorize-edge";
      if (
        invocation.result.surfaceName !== authored.surfaceName ||
        invocation.result.operation !== authored.operation.kind ||
        invocation.result.accessExecuted !== isAccess ||
        invocation.result.cleanup !== "none"
      ) {
        throw new Error(
          `${recipe.fixtureId}: module-loader runtime result did not prove its exact access`,
        );
      }
    } else if (
      authored.invocationSchema === "ibex/capsec-startup-surface-invocation/1"
    ) {
      exactKeys(
        invocation.result,
        [
          "kind",
          "surfaceKind",
          "surfaceName",
          "mechanism",
          "postcondition",
          "engineExecuted",
          "projectCodeExecuted",
          "observedFacts",
        ],
        `${recipe.fixtureId}: startup runtime result`,
      );
      const expectation = STARTUP_EXPECTATIONS.get(authored.surfaceName);
      exactKeys(
        invocation.result.observedFacts,
        expectation.requiredFacts,
        `${recipe.fixtureId}: startup observed facts`,
      );
      if (
        invocation.result.surfaceKind !== "startup" ||
        invocation.result.surfaceName !== authored.surfaceName ||
        invocation.result.mechanism !== "loaded-engine-startup" ||
        invocation.result.postcondition !== expectation.postcondition ||
        invocation.result.engineExecuted !== true ||
        invocation.result.projectCodeExecuted !== true ||
        !expectation.requiredFacts.every(
          (fact) => invocation.result.observedFacts[fact] === true,
        )
      ) {
        throw new Error(
          `${recipe.fixtureId}: loaded engine did not prove the startup postcondition`,
        );
      }
    } else if (startupEnvironment) {
      exactKeys(
        invocation.result,
        [
          "kind",
          "surfaceKind",
          "surfaceName",
          "mechanism",
          "moduleSpecifier",
          "environmentName",
          "environmentPresence",
          "principalMode",
          "engineExecuted",
          "projectCodeExecuted",
          "sourceOutcome",
          "errorName",
          "errorMessage",
        ],
        `${recipe.fixtureId}: startup environment runtime result`,
      );
      const operation = authored.operation;
      const denial = authored.scenario === "deny";
      if (
        invocation.result.surfaceKind !== "startup" ||
        invocation.result.surfaceName !== authored.surfaceName ||
        invocation.result.mechanism !== operation.kind ||
        invocation.result.moduleSpecifier !== operation.moduleSpecifier ||
        invocation.result.environmentName !== operation.environment.name ||
        invocation.result.environmentPresence !== "absent" ||
        invocation.result.principalMode !== operation.principalMode ||
        invocation.result.engineExecuted !== true ||
        invocation.result.projectCodeExecuted !== true ||
        invocation.result.sourceOutcome !==
          (denial ? "denied-as-absent" : "source-observed") ||
        invocation.result.errorName !== null ||
        invocation.result.errorMessage !== null
      ) {
        throw new Error(
          `${recipe.fixtureId}: loaded engine did not prove the startup environment source outcome`,
        );
      }
    }
  } else if (authored.expectedResult === "boolean-return") {
    exactKeys(
      invocation.result,
      [
        "kind",
        "moduleSpecifier",
        "exportName",
        "valueType",
        "booleanValue",
      ],
      `${recipe.fixtureId}: builtin boolean-return result`,
    );
    if (
      authored.invocationSchema !==
        "ibex/capsec-builtin-export-invocation/1" ||
      authored.kind !== "builtin-export-call" ||
      authored.moduleSpecifier !== "node:fs" ||
      authored.exportName !== "existsSync" ||
      typeof authored.expectedBooleanValue !== "boolean" ||
      authored.expectedBooleanValue !== (recipe.scenario !== "deny") ||
      invocation.result.kind !== "return" ||
      invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
      invocation.result.exportName !== authored.exportName ||
      invocation.result.valueType !== "boolean" ||
      invocation.result.booleanValue !== authored.expectedBooleanValue
    ) {
      throw new Error(
        `${recipe.fixtureId}: builtin boolean return did not match its authored value`,
      );
    }
  } else if (authored.expectedResult === "permission-denied") {
    const builtinModuleImport =
      authored.invocationSchema ===
      "ibex/capsec-builtin-module-import-invocation/1";
    if (builtinModuleImport) {
      exactKeys(
        invocation.result,
        ["kind", "moduleSpecifier", "errorName", "errorMessage"],
        `${recipe.fixtureId}: denied builtin module-import result`,
      );
      if (
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        typeof invocation.result.errorName !== "string" ||
        invocation.result.errorName.length === 0
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin module import denied the wrong module`,
        );
      }
    }
    const authoredFragment =
      authored.expectedDenyMessageFragment ??
      authored.publicAccess?.expectedDenyMessageFragment;
    const expectedFragment = authoredFragment ?? "Permission denied";
    const errorMessage = invocation.result.errorMessage;
    const fragmentMatched =
      typeof errorMessage === "string" &&
      (authoredFragment === undefined
        ? errorMessage.toLowerCase().includes(expectedFragment.toLowerCase())
        : errorMessage.includes(expectedFragment));
    if (
      invocation.result.kind !== "throw" ||
      !fragmentMatched
    ) {
      throw new Error(`${recipe.fixtureId}: public invocation did not deny`);
    }
  } else if (authored.expectedResult === "invalid-handle") {
    exactKeys(
      invocation.result,
      ["kind", "globalName", "errorName", "errorMessage"],
      `${recipe.fixtureId}: retained-object refusal result`,
    );
    if (
      invocation.result.kind !== "throw" ||
      invocation.result.globalName !== authored.globalName ||
      invocation.result.errorName !== "Error" ||
      typeof invocation.result.errorMessage !== "string" ||
      !invocation.result.errorMessage.endsWith(": invalid handle")
    ) {
      throw new Error(
        `${recipe.fixtureId}: public invocation did not prove its exact retained-object refusal`,
      );
    }
  } else if (authored.expectedResult === "absent") {
    if (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-export-invocation/1" &&
      invocation.kind === "builtin-export-read"
    ) {
      exactKeys(
        invocation.result,
        ["kind", "moduleSpecifier", "exportName", "segment", "available"],
        `${recipe.fixtureId}: target-absent builtin result`,
      );
      const availability = authored.sourceDescriptor?.platformAvailability;
      const accessPath = authored.sourceDescriptor?.access?.path;
      if (
        invocation.result.kind !== "missing" ||
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        invocation.result.exportName !== authored.exportName ||
        invocation.result.segment !== authored.exportName ||
        !Array.isArray(invocation.result.available) ||
        invocation.result.available.includes(authored.exportName) ||
        !Array.isArray(availability) ||
        availability.length === 0 ||
        availability.includes("darwin") ||
        !Array.isArray(accessPath) ||
        accessPath.at(-1) !== authored.exportName
      ) {
        throw new Error(
          `${recipe.fixtureId}: public builtin did not prove source-bound target absence`,
        );
      }
    } else if (
      invocation.invocationSchema === "ibex/capsec-native-global-invocation/1"
    ) {
      if (invocation.result.kind !== "missing") {
        throw new Error(
          `${recipe.fixtureId}: public native global was not absent`,
        );
      }
    } else {
      const probeMode = authored.sourceDescriptor?.probeMode;
      if (
        invocation.result.kind !== "absent" ||
        invocation.result.surfaceKind !== authored.surfaceKind ||
        invocation.result.surfaceName !== authored.surfaceName ||
        invocation.result.targetTriple !== authored.targetTriple ||
        invocation.result.compiledTargetOs !== "macos" ||
        invocation.result.compiledTargetArch !== "aarch64" ||
        invocation.result.probeMode !== probeMode?.kind
      ) {
        throw new Error(
          `${recipe.fixtureId}: target-absence probe did not prove absence`,
        );
      }
      if (probeMode?.kind === "runtime-global-property") {
        exactKeys(
          invocation.result,
          [
            "kind",
            "surfaceKind",
            "surfaceName",
            "targetTriple",
            "compiledTargetOs",
            "compiledTargetArch",
            "probeMode",
            "globalName",
            "memberName",
            "surfacePresent",
          ],
          `${recipe.fixtureId}: native-global target-absence runtime result`,
        );
        if (
          invocation.result.globalName !== probeMode.globalName ||
          invocation.result.memberName !== probeMode.memberName ||
          invocation.result.surfacePresent !== false
        ) {
          throw new Error(
            `${recipe.fixtureId}: runtime-global probe did not prove absence`,
          );
        }
      } else {
        exactKeys(
          invocation.result,
          [
            "kind",
            "surfaceKind",
            "surfaceName",
            "targetTriple",
            "compiledTargetOs",
            "compiledTargetArch",
            "probeMode",
            "symbolName",
            "symbolPresent",
          ],
          `${recipe.fixtureId}: symbol target-absence runtime result`,
        );
        if (
          !["dynamic-symbol", "platform-bridge"].includes(probeMode?.kind) ||
          invocation.result.symbolName !== probeMode.symbolName ||
          invocation.result.symbolPresent !== false
        ) {
          throw new Error(
            `${recipe.fixtureId}: symbol probe did not prove absence`,
          );
        }
      }
    }
  } else if (authored.expectedResult === "closed") {
    exactKeys(
      invocation.result,
      [
        "kind",
        "surfaceKind",
        "surfaceName",
        "mechanism",
        "errorName",
        "errorMessage",
        ...(authored.operation?.kind === "loader-executable-file"
          ? ["errorCode"]
          : []),
        "engineExecuted",
        "projectCodeExecuted",
      ],
      `${recipe.fixtureId}: closed-surface runtime result`,
    );
    if (
      invocation.result.kind !== "closed" ||
      invocation.result.surfaceKind !== authored.surfaceKind ||
      invocation.result.surfaceName !== authored.surfaceName ||
      invocation.result.mechanism !== authored.operation?.kind ||
      invocation.result.errorName !== "ClosedSurface" ||
      typeof invocation.result.errorMessage !== "string" ||
      invocation.result.errorMessage.length === 0 ||
      typeof invocation.result.engineExecuted !== "boolean" ||
      invocation.result.projectCodeExecuted !== false
    ) {
      throw new Error(
        `${recipe.fixtureId}: public closed surface did not fail closed`,
      );
    }
    if (
      authored.operation?.kind === "startup-environment" &&
      (invocation.result.engineExecuted !== false ||
        !invocation.result.errorMessage.includes(
          "rejects closed environment controls",
        ) ||
        !invocation.result.errorMessage.includes(
          authored.operation.environmentName,
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: closed startup control reached engine execution or the wrong rejection`,
      );
    }
    if (
      authored.operation?.kind === "cli-control" &&
      (invocation.result.engineExecuted !== false ||
        !Array.isArray(authored.operation.expectedRejectionFragments) ||
        authored.operation.expectedRejectionFragments.length === 0 ||
        !authored.operation.expectedRejectionFragments.every(
          (fragment) =>
            typeof fragment === "string" &&
            fragment.length > 0 &&
            invocation.result.errorMessage.includes(fragment),
        ) ||
        !Array.isArray(authored.operation.argumentVectors) ||
        authored.operation.argumentVectors.length === 0)
    ) {
      throw new Error(
        `${recipe.fixtureId}: closed CLI control reached execution or the wrong rejection`,
      );
    }
    if (
      authored.operation?.kind === "tamed-evaluator" &&
      (invocation.result.engineExecuted !== true ||
        !invocation.result.errorMessage.includes("disabled under lockdown") ||
        !new Set([
          "global-eval",
          "global-function",
          "async-function-constructor",
          "generator-function-constructor",
        ]).has(authored.operation.accessMode))
    ) {
      throw new Error(
        `${recipe.fixtureId}: evaluator was not closed by the reviewed loaded-engine taming path`,
      );
    }
    if (
      authored.operation?.kind === "exact-unendowed-operation" &&
      (invocation.result.engineExecuted !== true ||
        invocation.result.errorMessage !== authored.operation.expectedError)
    ) {
      throw new Error(
        `${recipe.fixtureId}: Exact invocation did not fail closed before the embedder callback`,
      );
    }
    if (
      authored.operation?.kind === "module-runner-namespace" &&
      (invocation.result.engineExecuted !== true ||
        invocation.result.errorMessage !== authored.operation.expectedError)
    ) {
      throw new Error(
        `${recipe.fixtureId}: armed module namespace inspection did not fail closed`,
      );
    }
    if (
      authored.operation?.kind === "terminal-builtin-import" &&
      (invocation.result.engineExecuted !== true ||
        !invocation.result.errorMessage.includes(
          authored.operation.expectedRejectionFragment,
        ) ||
        !authored.operation.moduleSpecifiers.every(
          (specifier) =>
            invocation.result.errorMessage
              .split("\n")
              .some(
                (line) =>
                  line.startsWith(`${specifier}: `) &&
                  line.includes(authored.operation.expectedRejectionFragment),
              ),
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: terminal builtin aliases did not fail closed at the authenticated import gate`,
      );
    }
    if (
      authored.operation?.kind === "sqlite-extension-load" &&
      (invocation.result.engineExecuted !== true ||
        !authored.operation.moduleSpecifiers.every(
          (specifier) =>
            invocation.result.errorMessage
              .split("\n")
              .some(
                (line) =>
                  line.startsWith(`${specifier}: `) &&
                  line.includes(
                    authored.operation.expectedRejectionFragment,
                  ),
              ),
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: SQLite extension loading did not fail closed through every public alias`,
      );
    }
    if (
      authored.operation?.kind === "sqlite-cr-sqlite-enable" &&
      (invocation.result.engineExecuted !== true ||
        !authored.operation.moduleSpecifiers.every(
          (specifier) =>
            invocation.result.errorMessage
              .split("\n")
              .some(
                (line) =>
                  line.startsWith(`${specifier}: `) &&
                  line.includes(
                    authored.operation.expectedRejectionFragment,
                  ),
              ),
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: cr-sqlite enablement did not fail closed through every public alias`,
      );
    }
    if (
      authored.operation?.kind === "debugger-abi-disabled" &&
      (invocation.result.engineExecuted !== true ||
        invocation.result.errorMessage !== authored.operation.expectedError)
    ) {
      throw new Error(
        `${recipe.fixtureId}: debugger ABI did not prove the no-debugger physical result`,
      );
    }
    if (
      authored.operation?.kind === "shared-runtime-global-absence" &&
      (invocation.result.engineExecuted !== true ||
        invocation.result.errorMessage !== authored.operation.expectedError)
    ) {
      throw new Error(
        `${recipe.fixtureId}: armed shared-runtime global was not physically absent`,
      );
    }
    if (
      authored.operation?.kind === "armed-native-global-absence" &&
      (invocation.result.engineExecuted !== true ||
        invocation.result.errorMessage !== authored.operation.expectedError)
    ) {
      throw new Error(
        `${recipe.fixtureId}: armed native global was not physically absent`,
      );
    }
    const loaderExecutableExpectation = new Map([
      [
        "native-addon",
        { extension: ".node", rejectionFragment: "Native addons are closed" },
      ],
      [
        "wasm",
        {
          extension: ".wasm",
          rejectionFragment: "WebAssembly modules are closed",
        },
      ],
    ]).get(authored.operation?.loaderKind);
    if (
      authored.operation?.kind === "loader-executable-file" &&
      (invocation.result.engineExecuted !== true ||
        authored.surfaceKind !== "loader" ||
        loaderExecutableExpectation === undefined ||
        authored.operation.extension !==
          loaderExecutableExpectation.extension ||
        authored.operation.rejectionFragment !==
          loaderExecutableExpectation.rejectionFragment ||
        authored.operation.publicErrorCode !== "ERR_IBEX_MODULE_RESOLUTION" ||
        authored.operation.publicErrorMessage !== "Module resolution failed" ||
        invocation.result.errorCode !== authored.operation.publicErrorCode ||
        invocation.result.errorMessage !==
          authored.operation.publicErrorMessage)
    ) {
      throw new Error(
        `${recipe.fixtureId}: executable loader kind did not fail closed at resolution`,
      );
    }
  } else if (authored.expectedResult === "invariant-passed") {
    if (!callbackInvariant) {
      throw new Error(
        `${recipe.fixtureId}: non-callback probe claimed an invariant result`,
      );
    }
    validateCallbackInvariantResult(
      invocation.result,
      authored,
      recipe.fixtureId,
    );
  } else {
    throw new Error(`${recipe.fixtureId}: unsupported expected public result`);
  }
  if (
    invocation.invocationSchema === "ibex/capsec-native-global-invocation/1"
  ) {
    const armedEnvironmentEnumeration =
      authored.globalName === "__exactGetAllEnv" &&
      authored.expectedResult === "return";
    exactKeys(
      invocation.executionProof,
      [
        "kind",
        "bodyEntered",
        ...(armedEnvironmentEnumeration ? ["propertyCount"] : []),
      ],
      `${recipe.fixtureId}: native execution proof`,
    );
    const expectedProof =
      armedEnvironmentEnumeration
        ? ["armed-empty-environment-enumeration", true]
        : authored.expectedResult === "return"
        ? [
            authored.kind === "global-property-read"
              ? "global-property-read"
              : "native-return",
            true,
          ]
        : authored.expectedResult === "permission-denied"
          ? ["typed-permission-denial", true]
          : authored.expectedResult === "invalid-handle"
            ? ["retained-object-refusal", true]
          : ["exact-global-absence", false];
    if (
      invocation.executionProof.kind !== expectedProof[0] ||
      invocation.executionProof.bodyEntered !== expectedProof[1] ||
      (armedEnvironmentEnumeration &&
        invocation.executionProof.propertyCount !== 0)
    ) {
      throw new Error(
        `${recipe.fixtureId}: native execution proof disagrees with result`,
      );
    }
  }
}

export function validatePublicFixtureRuntimeObservation(
  observation,
  recipe,
  coverage,
) {
  exactKeys(
    observation,
    [
      "observationSchema",
      "invocation",
      "legacyObservationCount",
      "typedDecisions",
    ],
    `${recipe.fixtureId}: runtime public observation`,
  );
  validateRuntimeInvocation(observation, recipe);
  const authored = recipe.publicSurfaceProbe.invocation;
  if (
    observation.observationSchema !==
      "ibex/capsec-runtime-public-observation/1" ||
    observation.legacyObservationCount !== 0 ||
    !Array.isArray(observation.typedDecisions) ||
    observation.typedDecisions.length !== authored?.expectedTypedDecisionCount
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed runtime public observation`,
    );
  }
  const stages = [];
  const actions = new Set();
  const edgeIds = new Set();
  const terminals = new Set();
  const terminalByEdge =
    observation.typedDecisions.length === 0
      ? null
      : coverageTerminalMap(coverage);
  const callbackInvariant =
    authored.invocationSchema === "ibex/capsec-callback-invariant-invocation/1";
  const startupEnvironment =
    authored.invocationSchema ===
    "ibex/capsec-startup-environment-invocation/1";
  const effectBuiltinModuleImport =
    authored.invocationSchema ===
    "ibex/capsec-builtin-module-import-invocation/1";
  const nonCapabilityBuiltinModuleImport =
    authored.invocationSchema ===
    "ibex/capsec-builtin-module-import-no-effect-invocation/1";
  // The aggregate independently repeats the producer's narrow D2 allowance:
  // only these reviewed open-then-act exports may observe fs:list in addition
  // to their declared semantic operation.
  // @ref LLP 0037#d2--declared-vs-incidental-capabilities-in-the-coverage-edge
  const builtinOpenThenActDescriptor = new Map([
    ["appendFileSync", { action: "fs:write", operationPrefix: "fs-open:" }],
    ["mkdirSync", { action: "fs:write", operationPrefix: "fs-mkdir:" }],
    ["readFileSync", { action: "fs:read", operationPrefix: "fs-open:" }],
    ["readlinkSync", { action: "fs:read", operationPrefix: "fs-readlink:" }],
    [
      "truncateSync",
      { action: "fs:write", operationPrefix: "fs-truncate:" },
    ],
    ["writeFileSync", { action: "fs:write", operationPrefix: "fs-open:" }],
  ]).get(authored.exportName);
  const builtinOpenThenAct =
    authored.invocationSchema ===
      "ibex/capsec-builtin-export-invocation/1" &&
    authored.kind === "builtin-export-call" &&
    authored.moduleSpecifier === "node:fs" &&
    typeof builtinOpenThenActDescriptor?.action === "string" &&
    typeof builtinOpenThenActDescriptor.operationPrefix === "string" &&
    canonicalJson(authored.expectedActionIds) ===
      canonicalJson([builtinOpenThenActDescriptor.action]);
  const outcomeDeclaredCarrier = callbackInvariant || startupEnvironment;
  const auxiliaryCarrier =
    outcomeDeclaredCarrier ||
    effectBuiltinModuleImport ||
    nonCapabilityBuiltinModuleImport;
  const effectBuiltinAuxiliaryDescriptors =
    authored.invocationSchema ===
      "ibex/capsec-builtin-export-invocation/1" &&
    authored.kind === "builtin-export-call" &&
    Array.isArray(authored.sourceDescriptor?.auxiliaryDecisionEdges)
      ? authored.sourceDescriptor.auxiliaryDecisionEdges
      : [];
  const effectBuiltinAuxiliaryCarrier =
    effectBuiltinAuxiliaryDescriptors.length > 0;
  const effectBuiltinAuxiliaryByEdge = new Map();
  const effectBuiltinDenialTerminalEdgeId =
    effectBuiltinAuxiliaryCarrier
      ? authored.sourceDescriptor.denialTerminalEdgeId
      : null;
  if (effectBuiltinAuxiliaryCarrier) {
    for (const descriptor of effectBuiltinAuxiliaryDescriptors) {
      exactKeys(
        descriptor,
        ["edgeId", "observedKey", "actionIds"],
        `${recipe.fixtureId}: effect-builtin auxiliary descriptor`,
      );
      const edge = coverage?.edges?.find(
        (candidate) => candidate.id === descriptor.edgeId,
      );
      const observedKey = edge
        ? `${edge.surface?.kind}:${edge.surface?.name}`
        : null;
      const actionIds = canonicalSet(
        (edge?.effects ?? []).map((effect) => effect.cap),
      );
      if (
        edge?.classification !== "effects" ||
        observedKey !== descriptor.observedKey ||
        canonicalJson(actionIds) !==
          canonicalJson(canonicalSet(descriptor.actionIds)) ||
        effectBuiltinAuxiliaryByEdge.has(descriptor.edgeId)
      ) {
        throw new Error(
          `${recipe.fixtureId}: effect-builtin auxiliary decision is not coverage-bound`,
        );
      }
      effectBuiltinAuxiliaryByEdge.set(
        descriptor.edgeId,
        new Set(actionIds),
      );
    }
    const exactRealpathCarrier =
      authored.moduleSpecifier === "node:fs" &&
      authored.exportName === "realpathSync" &&
      canonicalJson(
        effectBuiltinAuxiliaryDescriptors.map(
          ({ observedKey, actionIds }) => ({
            observedKey,
            actionIds,
          }),
        ),
      ) ===
        canonicalJson([
          {
            observedKey: "native-op:__exactGetCwd",
            actionIds: ["path:cwd-observe"],
          },
          {
            observedKey: "native-op:__exactLstat",
            actionIds: ["fs:list"],
          },
        ]) &&
      effectBuiltinAuxiliaryDescriptors.find(
        ({ observedKey }) => observedKey === "native-op:__exactLstat",
      )?.edgeId === effectBuiltinDenialTerminalEdgeId;
    const routeEdgeIds = (recipe.route?.alternatives ?? []).map(
      ({ terminalObservedKey }) =>
        coverage?.edges?.find(
          (edge) =>
            `${edge.surface?.kind}:${edge.surface?.name}` ===
            terminalObservedKey,
        )?.id,
    );
    const expectedAllowedEdges = canonicalSet([
      ...routeEdgeIds,
      ...effectBuiltinAuxiliaryByEdge.keys(),
    ]);
    if (
      !exactRealpathCarrier ||
      routeEdgeIds.some((edgeId) => typeof edgeId !== "string") ||
      !effectBuiltinAuxiliaryByEdge.has(
        effectBuiltinDenialTerminalEdgeId,
      ) ||
      canonicalJson(authored.allowedCoverageEdgeIds) !==
        canonicalJson(expectedAllowedEdges)
    ) {
      throw new Error(
        `${recipe.fixtureId}: unsupported effect-builtin auxiliary carrier`,
      );
    }
  } else if (
    authored.sourceDescriptor?.denialTerminalEdgeId !== undefined
  ) {
    throw new Error(
      `${recipe.fixtureId}: denial terminal has no authenticated auxiliary edge`,
    );
  }
  const effectBuiltinDenialCarrier =
    effectBuiltinAuxiliaryCarrier && recipe.scenario === "deny";
  const runtimeAuxiliaryCarrier =
    auxiliaryCarrier || effectBuiltinDenialCarrier;
  const nativeWorkerTerminal = nativeAsyncWorkerTerminal(authored);
  let effectBuiltinModuleImportIdentity = null;
  if (callbackInvariant) {
    // Callback/control surfaces are non-capabilities, but their invariant can
    // exercise one separately reviewed effect edge. Bind that auxiliary
    // decision to checked coverage instead of attributing it to the carrier.
    const auxiliaryEdgeId =
      authored.sourceDescriptor?.auxiliaryDecisionEdgeId ?? null;
    const expectedAuxiliaryEdgeIds = auxiliaryEdgeId ? [auxiliaryEdgeId] : [];
    const auxiliaryEdge = auxiliaryEdgeId
      ? coverage?.edges?.find((edge) => edge.id === auxiliaryEdgeId)
      : null;
    const auxiliaryActions = auxiliaryEdge
      ? canonicalSet((auxiliaryEdge.effects ?? []).map((effect) => effect.cap))
      : [];
    const auxiliaryStages = auxiliaryEdge
      ? new Set(
          (auxiliaryEdge.effects ?? []).flatMap(
            (effect) => effect.stages ?? [],
          ),
        )
      : new Set();
    if (
      canonicalJson(authored.allowedCoverageEdgeIds) !==
        canonicalJson(expectedAuxiliaryEdgeIds) ||
      (auxiliaryEdgeId !== null &&
        (auxiliaryEdge?.classification !== "effects" ||
          canonicalJson(auxiliaryActions) !==
            canonicalJson(authored.expectedActionIds) ||
          !authored.expectedTypedStages.every((stage) =>
            auxiliaryStages.has(stage),
          ))) ||
      (auxiliaryEdgeId === null &&
        (authored.expectedTypedDecisionCount !== 0 ||
          authored.expectedActionIds.length !== 0 ||
          authored.expectedTypedStages.length !== 0))
    ) {
      throw new Error(
        `${recipe.fixtureId}: callback auxiliary decision is not coverage-bound`,
      );
    }
  }
  if (startupEnvironment) {
    const descriptor = authored.sourceDescriptor;
    const auxiliaryEdgeId = descriptor?.auxiliaryDecisionEdgeId ?? null;
    const auxiliaryEdge = coverage?.edges?.find(
      (edge) => edge.id === auxiliaryEdgeId,
    );
    const carrierEdge = coverage?.edges?.find(
      (edge) => edge.id === descriptor?.carrierEdgeId,
    );
    const selectedBranch = carrierEdge?.logicalBranches?.find(
      (branch) => branch.id === descriptor?.selectedBranch?.id,
    );
    const environmentName = authored.operation?.environment?.name;
    const expectedFact = `environment.startup.${environmentName?.toLowerCase()}`;
    const auxiliaryActions = canonicalSet(
      (auxiliaryEdge?.effects ?? []).map((effect) => effect.cap),
    );
    const auxiliaryStages = new Set(
      (auxiliaryEdge?.effects ?? []).flatMap((effect) => effect.stages ?? []),
    );
    if (
      auxiliaryEdge?.classification !== "effects" ||
      canonicalJson(auxiliaryActions) !== canonicalJson(["env:read"]) ||
      !authored.expectedTypedStages.every((stage) =>
        auxiliaryStages.has(stage),
      ) ||
      canonicalJson(authored.allowedCoverageEdgeIds) !==
        canonicalJson([auxiliaryEdgeId]) ||
      canonicalJson(authored.expectedActionIds) !==
        canonicalJson(["env:read"]) ||
      carrierEdge?.classification !== "effects" ||
      carrierEdge?.surface?.kind !== "startup" ||
      carrierEdge?.surface?.name !== `env:${environmentName}` ||
      carrierEdge?.id !== recipe.edgeIds?.[0] ||
      canonicalJson(selectedBranch) !==
        canonicalJson(descriptor.selectedBranch) ||
      canonicalJson(selectedBranch?.when) !==
        canonicalJson([{ fact: expectedFact, equals: "absent" }]) ||
      canonicalJson(
        canonicalSet(
          (selectedBranch?.effects ?? []).map((effect) => effect.cap),
        ),
      ) !== canonicalJson(recipe.actionIds) ||
      recipe.terminalObservedKey !== `startup:env:${environmentName}` ||
      descriptor.surfaceObservedKey !== recipe.terminalObservedKey
    ) {
      throw new Error(
        `${recipe.fixtureId}: startup environment auxiliary decision is not coverage-bound`,
      );
    }
  }
  if (effectBuiltinModuleImport) {
    const descriptor = authored.sourceDescriptor;
    const auxiliaryEdge = coverage?.edges?.find(
      (edge) => edge.id === descriptor?.auxiliaryDecisionEdgeId,
    );
    const carrierEdge = coverage?.edges?.find(
      (edge) => edge.id === descriptor?.carrierEdgeId,
    );
    const auxiliaryActions = canonicalSet(
      (auxiliaryEdge?.effects ?? []).map((effect) => effect.cap),
    );
    const auxiliaryStages = new Set(
      (auxiliaryEdge?.effects ?? []).flatMap((effect) => effect.stages ?? []),
    );
    if (
      auxiliaryEdge?.classification !== "effects" ||
      auxiliaryEdge?.surface?.kind !== "native-op" ||
      auxiliaryEdge?.surface?.name !== "__exactGetEnv" ||
      canonicalJson(auxiliaryActions) !== canonicalJson(["env:read"]) ||
      !authored.expectedTypedStages.every((stage) =>
        auxiliaryStages.has(stage),
      ) ||
      canonicalJson(authored.allowedCoverageEdgeIds) !==
        canonicalJson([descriptor.auxiliaryDecisionEdgeId]) ||
      canonicalJson(authored.expectedActionIds) !==
        canonicalJson(["env:read"]) ||
      carrierEdge?.classification !== "effects" ||
      carrierEdge?.surface?.kind !== "builtin" ||
      carrierEdge?.surface?.name !== authored.moduleSpecifier ||
      carrierEdge?.id !== recipe.edgeIds?.[0] ||
      descriptor.carrierEdgeId !== carrierEdge.id ||
      recipe.terminalObservedKey !== `builtin:${authored.moduleSpecifier}`
    ) {
      throw new Error(
        `${recipe.fixtureId}: builtin module-import auxiliary decision is not coverage-bound`,
      );
    }
  }
  if (nonCapabilityBuiltinModuleImport) {
    const descriptor = authored.sourceDescriptor;
    const carrierEdge = coverage?.edges?.find(
      (edge) => edge.id === descriptor?.carrierEdgeId,
    );
    const expectation = NONCAP_BUILTIN_MODULE_IMPORT_ALIASES.get(
      authored.moduleSpecifier,
    );
    if (
      expectation === undefined ||
      carrierEdge?.classification !== "non-capability" ||
      carrierEdge?.surface?.kind !== "builtin" ||
      carrierEdge?.surface?.name !== authored.moduleSpecifier ||
      carrierEdge?.rationaleId !== "module-reachability-only" ||
      (carrierEdge.effects?.length ?? 0) !== 0 ||
      carrierEdge?.id !== recipe.edgeIds?.[0] ||
      descriptor.carrierEdgeId !== carrierEdge.id ||
      descriptor.sourceKey !== expectation.sourceKey ||
      descriptor.sourceMetadata?.sourceKey !== expectation.sourceKey ||
      descriptor.expectedRootType !== expectation.expectedRootType ||
      recipe.terminalObservedKey !== `builtin:${authored.moduleSpecifier}`
    ) {
      throw new Error(
        `${recipe.fixtureId}: non-capability builtin module import is not coverage-bound`,
      );
    }
  }
  for (const [
    decisionIndex,
    decision,
  ] of observation.typedDecisions.entries()) {
    exactKeys(
      decision,
      ["decisionSet", "gates", "evidence"],
      `${recipe.fixtureId}: observed typed decision`,
    );
    const set = decision.decisionSet;
    if (
      !set?.context ||
      typeof set.context.stage !== "string" ||
      !Array.isArray(set.effects) ||
      !Array.isArray(decision.gates) ||
      decision.gates.length !== set.effects.length
    ) {
      throw new Error(`${recipe.fixtureId}: malformed observed typed decision`);
    }
    stages.push(set.context.stage);
    const decisionEdgeIds = decision.gates.map(
      (gate) => gate?.coverageEdgeId,
    );
    const decisionIsAuxiliary =
      effectBuiltinAuxiliaryCarrier &&
      decisionEdgeIds.every((edgeId) =>
        effectBuiltinAuxiliaryByEdge.has(edgeId),
      );
    const decisionHasAuxiliary =
      effectBuiltinAuxiliaryCarrier &&
      decisionEdgeIds.some((edgeId) =>
        effectBuiltinAuxiliaryByEdge.has(edgeId),
      );
    const decisionIsDesignatedDenialTerminal =
      effectBuiltinDenialCarrier &&
      decisionEdgeIds.every(
        (edgeId) => edgeId === effectBuiltinDenialTerminalEdgeId,
      );
    if (decisionHasAuxiliary && !decisionIsAuxiliary) {
      throw new Error(
        `${recipe.fixtureId}: auxiliary and operation effects share one decision`,
      );
    }
    for (const [effectIndex, effect] of set.effects.entries()) {
      if (typeof effect?.cap !== "string") {
        throw new Error(`${recipe.fixtureId}: observed effect has no action`);
      }
      const edgeId = decision.gates[effectIndex]?.coverageEdgeId;
      const auxiliaryActions = effectBuiltinAuxiliaryByEdge.get(edgeId);
      if (
        auxiliaryActions !== undefined &&
        !auxiliaryActions.has(effect.cap)
      ) {
        throw new Error(
          `${recipe.fixtureId}: auxiliary decision observed an unbound action`,
        );
      }
      if (!decisionIsAuxiliary || decisionIsDesignatedDenialTerminal) {
        actions.add(effect.cap);
      }
    }
    for (const gate of decision.gates) {
      const edgeId = gate?.coverageEdgeId;
      if (
        typeof edgeId !== "string" ||
        gate.targetCell !== "complete" ||
        gate.definitionAndEdgePredicatesSatisfied !== true ||
        set.atomicityGroup !== `${edgeId}.decision` ||
        !authored.allowedCoverageEdgeIds.includes(edgeId)
      ) {
        throw new Error(
          `${recipe.fixtureId}: observed an unbound or incomplete typed gate`,
        );
      }
      edgeIds.add(edgeId);
      const terminal = terminalByEdge.get(edgeId);
      if (!terminal) {
        throw new Error(
          `${recipe.fixtureId}: observed an unknown coverage edge`,
        );
      }
      if (
        !effectBuiltinAuxiliaryByEdge.has(edgeId) ||
        decisionIsDesignatedDenialTerminal
      ) {
        terminals.add(terminal);
      }
    }
    const deniedReturningModuleImport =
      authored.invocationSchema ===
        "ibex/capsec-builtin-module-import-invocation/1" &&
      recipe.scenario === "deny";
    const decisionActions = canonicalSet(
      set.effects.map((effect) => effect.cap),
    );
    const openTraversalDecision =
      builtinOpenThenAct &&
      canonicalJson(decisionActions) === canonicalJson(["fs:list"]);
    if (
      builtinOpenThenAct &&
      decisionActions.includes("fs:list") &&
      !openTraversalDecision
    ) {
      throw new Error(
        `${recipe.fixtureId}: incidental fs:list was mixed into an operation decision`,
      );
    }
    if (openTraversalDecision) {
      // Surplus fs:list is accepted only when the decision itself proves an
      // ambient path-opening traversal. A directory-listing operation cannot
      // borrow this exception by carrying the same capability name.
      const actor = set.context.actor;
      const decisiveEvidence = decision.evidence?.evidence;
      const decisiveEntry = decisiveEvidence?.[0];
      if (
        !new Set(["requested", "discovery", "repeat"]).has(
          set.context.stage,
        ) ||
        typeof set.operationId !== "string" ||
        !set.operationId.startsWith(
          builtinOpenThenActDescriptor.operationPrefix,
        ) ||
        !set.effects.every(
          (effect) =>
            effect.resource?.kind === "path-occurrence" &&
            canonicalJson(effect.effectOwner) === canonicalJson(actor),
        ) ||
        !Array.isArray(decisiveEvidence) ||
        decisiveEvidence.length !== 1 ||
        decisiveEntry?.effectIndex !== 0 ||
        canonicalJson(decisiveEntry?.principal) !== canonicalJson(actor) ||
        decisiveEntry?.stratum !== "ambient-root" ||
        decisiveEntry?.reason !== "ambient-root" ||
        decisiveEntry?.sourceId !== null
      ) {
        throw new Error(
          `${recipe.fixtureId}: incidental fs:list decision is not an ambient open traversal`,
        );
      }
    }
    const deniedByExpectedResult =
      (authored.expectedResult === "permission-denied" ||
        (authored.expectedResult === "boolean-return" &&
          recipe.scenario === "deny")) &&
      !openTraversalDecision &&
      (!decisionIsAuxiliary || decisionIsDesignatedDenialTerminal);
    const expectedOutcome = outcomeDeclaredCarrier
      ? authored.expectedTypedOutcomes[decisionIndex]
      : deniedByExpectedResult || deniedReturningModuleImport
        ? "deny"
        : "allow";
    if (decision.evidence?.outcome !== expectedOutcome) {
      throw new Error(
        `${recipe.fixtureId}: observed typed outcome disagrees with invocation`,
      );
    }
    if (
      outcomeDeclaredCarrier &&
      (!Array.isArray(decision.evidence?.evidence) ||
        decision.evidence.evidence.length === 0 ||
        decision.evidence.evidence.find(
          (entry) =>
            canonicalJson(entry?.principal) ===
            canonicalJson(decision.decisionSet.context.actor),
        )?.reason !== authored.expectedTypedReasons[decisionIndex])
    ) {
      throw new Error(
        `${recipe.fixtureId}: observed typed reason disagrees with carrier`,
      );
    }
    if (startupEnvironment) {
      const environmentName = authored.operation.environment.name;
      const actor = set.context.actor;
      const packageMode = authored.operation.principalMode === "package-denied";
      const expectedActor = packageMode
        ? actor?.kind === "package" &&
          actor.name === "image-lib" &&
          actor.locator === "image-lib@2.4.1" &&
          typeof actor.integrity === "string" &&
          /^sha256-[A-Za-z0-9_-]{43}$/.test(actor.integrity)
        : canonicalJson(actor) ===
          canonicalJson({ kind: "root", identity: "project-root" });
      const expectedConstrained = packageMode
        ? [{ kind: "root", identity: "project-root" }, actor]
        : [actor];
      const effect = set.effects[0];
      if (
        set.effects.length !== 1 ||
        decision.gates.length !== 1 ||
        expectedActor !== true ||
        canonicalJson(set.context.constrainedPrincipals) !==
          canonicalJson(expectedConstrained) ||
        canonicalJson(effect?.effectOwner) !== canonicalJson(actor) ||
        effect?.cap !== "env:read" ||
        canonicalJson(effect?.resource) !==
          canonicalJson({
            kind: "environment-occurrence",
            requested: {
              kind: "environment-name",
              target: "principal-overlay",
              name: environmentName,
            },
            valueOrigin: "principal-overlay",
          })
      ) {
        throw new Error(
          `${recipe.fixtureId}: startup environment decision lost its exact resource or principal binding`,
        );
      }
    }
    if (effectBuiltinModuleImport) {
      const actor = { kind: "root", identity: "project-root" };
      const context = set.context;
      const effect = set.effects[0];
      const gate = decision.gates[0];
      const typedEvidence = decision.evidence;
      const identity = typedEvidence?.identity;
      const generations = typedEvidence?.generations;
      const decisiveEvidence = decision.evidence?.evidence;
      const decisiveEntry = decisiveEvidence?.[0];
      const denial = recipe.scenario === "deny";
      const expectedStratum = denial ? "principal-denial" : "static-floor";
      const expectedSourceKind = denial ? "denial" : "floor";
      const expectedOperationId =
        'environment-read:0:{"kind":"environment-name","target":"principal-overlay","name":"NODE_DEBUG"}';
      const canonicalIdentity = identity ? canonicalJson(identity) : null;
      if (decisiveEntry !== undefined) {
        exactKeys(
          decisiveEntry,
          ["effectIndex", "principal", "stratum", "reason", "sourceId"],
          `${recipe.fixtureId}: builtin module-import decisive evidence`,
        );
      }
      if (
        !hasExactKeys(set, [
          "decisionSetSchema",
          "operationId",
          "atomicityGroup",
          "combination",
          "context",
          "effects",
        ]) ||
        !hasExactKeys(context, [
          "stage",
          "actor",
          "constrainedPrincipals",
          "presentedHandleIds",
        ]) ||
        !hasExactKeys(effect, ["cap", "effectOwner", "resource"]) ||
        !hasExactKeys(gate, [
          "coverageEdgeId",
          "targetCell",
          "definitionAndEdgePredicatesSatisfied",
        ]) ||
        !hasExactKeys(typedEvidence, [
          "identity",
          "generations",
          "operationId",
          "stage",
          "actor",
          "effectOwners",
          "constrainedPrincipals",
          "outcome",
          "evidence",
        ]) ||
        !hasExactKeys(identity, [
          "profile",
          "semanticCore",
          "vocabDigest",
          "registryDigest",
          "policyDigest",
          "armedSnapshotDigest",
        ]) ||
        !hasExactKeys(generations, ["negative", "dynamic", "handle"]) ||
        set.decisionSetSchema !== "ibex/capsec-decision-set/1" ||
        set.operationId !== expectedOperationId ||
        set.combination !== "conjunction" ||
        typedEvidence.operationId !== set.operationId ||
        typedEvidence.stage !== context.stage ||
        canonicalJson(typedEvidence.actor) !== canonicalJson(actor) ||
        canonicalJson(typedEvidence.effectOwners) !== canonicalJson([actor]) ||
        canonicalJson(typedEvidence.constrainedPrincipals) !==
          canonicalJson([actor]) ||
        identity.profile !== "ibex/capsec/1" ||
        identity.semanticCore !== "capsec/semantics/1" ||
        ![
          identity.vocabDigest,
          identity.registryDigest,
          identity.policyDigest,
          identity.armedSnapshotDigest,
        ].every(isTaggedDigest) ||
        canonicalIdentity !==
          canonicalJson(observation.invocation.decisionIdentity) ||
        (effectBuiltinModuleImportIdentity !== null &&
          canonicalIdentity !== effectBuiltinModuleImportIdentity) ||
        canonicalJson(generations) !==
          canonicalJson({ negative: 0, dynamic: 0, handle: 0 })
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin module-import decision lost its exact typed envelope`,
        );
      }
      effectBuiltinModuleImportIdentity = canonicalIdentity;
      if (
        set.effects.length !== 1 ||
        decision.gates.length !== 1 ||
        canonicalJson(context.actor) !== canonicalJson(actor) ||
        canonicalJson(context.constrainedPrincipals) !==
          canonicalJson([actor]) ||
        canonicalJson(context.presentedHandleIds) !== canonicalJson([]) ||
        canonicalJson(effect?.effectOwner) !== canonicalJson(actor) ||
        effect?.cap !== "env:read" ||
        canonicalJson(effect?.resource) !==
          canonicalJson({
            kind: "environment-occurrence",
            requested: {
              kind: "environment-name",
              target: "principal-overlay",
              name: "NODE_DEBUG",
            },
            valueOrigin: "principal-overlay",
          }) ||
        gate?.coverageEdgeId !==
          authored.sourceDescriptor.auxiliaryDecisionEdgeId ||
        !Array.isArray(decisiveEvidence) ||
        decisiveEvidence.length !== 1 ||
        decisiveEntry?.effectIndex !== 0 ||
        canonicalJson(decisiveEntry?.principal) !== canonicalJson(actor) ||
        decisiveEntry?.stratum !== expectedStratum ||
        decisiveEntry?.reason !== expectedStratum ||
        typeof decisiveEntry?.sourceId !== "string" ||
        !new RegExp(
          `^principal\\.[0-9]{6}\\.${expectedSourceKind}\\.[0-9]{6}$`,
          "u",
        ).test(decisiveEntry.sourceId)
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin module-import decision lost its exact NODE_DEBUG authority binding`,
        );
      }
    }
  }
  if (callbackInvariant) {
    const checks = observation.invocation.result.checks;
    const actorAt = (index) =>
      observation.typedDecisions[index]?.decisionSet?.context?.actor;
    const same = (left, right) => canonicalJson(left) === canonicalJson(right);
    if (
      authored.scenario === "attribution-missing-deny" &&
      !observation.typedDecisions.every((decision) =>
        same(decision.decisionSet.context.actor, checks.actualPrincipal),
      )
    ) {
      throw new Error(
        `${recipe.fixtureId}: attribution evidence used the wrong actor`,
      );
    }
    if (
      authored.scenario === "generation-recheck" &&
      (!observation.typedDecisions.every((decision) =>
        same(decision.decisionSet.context.actor, checks.actualPrincipal),
      ) ||
        !same(
          observation.typedDecisions[0]?.evidence?.generations,
          checks.generationsBefore,
        ) ||
        !same(
          observation.typedDecisions[1]?.evidence?.generations,
          checks.generationsBefore,
        ) ||
        !same(
          observation.typedDecisions[2]?.evidence?.generations,
          checks.generationsAfter,
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: generation evidence is not decision-bound`,
      );
    }
    if (
      authored.scenario === "principal-restore" &&
      (!same(actorAt(0), checks.callbackPrincipal) ||
        !same(actorAt(1), checks.callbackPrincipal) ||
        !same(actorAt(2), checks.restoredPrincipal) ||
        !same(actorAt(3), checks.restoredPrincipal))
    ) {
      throw new Error(
        `${recipe.fixtureId}: principal restoration is not decision-bound`,
      );
    }
    if (
      authored.scenario === "snapshot-mismatch-deny" &&
      observation.typedDecisions.length !== 0
    ) {
      throw new Error(
        `${recipe.fixtureId}: snapshot evidence is not decision-bound`,
      );
    }
  }
  const expectedActions =
    authored.expectedResult === "absent" ? [] : authored.expectedActionIds;
  const observedActions = [...actions].sort(compareText);
  const observedActionSet = new Set(observedActions);
  const actionSetMatches = builtinOpenThenAct
    ? expectedActions.every((action) => observedActionSet.has(action)) &&
      observedActions.every(
        (action) => expectedActions.includes(action) || action === "fs:list",
      )
    : canonicalJson(observedActions) ===
      canonicalJson([...expectedActions].sort(compareText));
  if (
    canonicalJson(stages) !== canonicalJson(authored.expectedTypedStages) ||
    !actionSetMatches ||
    (observation.typedDecisions.length > 0 && edgeIds.size === 0)
  ) {
    throw new Error(
      `${recipe.fixtureId}: observed typed stages, actions, or gates drifted`,
    );
  }

  let terminalObservedKey;
  if (runtimeAuxiliaryCarrier) {
    if (observation.typedDecisions.length > 0 && terminals.size !== 1) {
      throw new Error(
        `${recipe.fixtureId}: carrier evidence selected multiple auxiliaries`,
      );
    }
    if (
      effectBuiltinDenialCarrier &&
      !terminals.has(
        terminalByEdge.get(effectBuiltinDenialTerminalEdgeId),
      )
    ) {
      throw new Error(
        `${recipe.fixtureId}: public denial reached the wrong auxiliary terminal`,
      );
    }
    terminalObservedKey = observation.invocation.surfaceObservedKey;
  } else if (observation.typedDecisions.length === 0) {
    const validZeroDecisionScenario =
      (recipe.classification === "non-capability" &&
        recipe.scenario === "non-capability") ||
      (recipe.classification === "closed" && recipe.scenario === "closed") ||
      (recipe.classification === "effects" &&
        recipe.actionIds.length === 0 &&
        ["branch-selection", "no-effect"].includes(recipe.scenario)) ||
      recipe.scenario === "absent";
    if (
      !validZeroDecisionScenario ||
      authored.expectedTypedStages.length !== 0 ||
      (authored.expectedResult !== "absent" &&
        authored.expectedActionIds.length !== 0)
    ) {
      throw new Error(
        `${recipe.fixtureId}: absence of a typed decision is not evidence here`,
      );
    }
    const nativeExactAbsence =
      authored.expectedResult === "absent" &&
      observation.invocation.invocationSchema ===
        "ibex/capsec-native-global-invocation/1";
    if (
      nativeExactAbsence &&
      observation.invocation.surfaceObservedKey !== recipe.terminalObservedKey
    ) {
      throw new Error(`${recipe.fixtureId}: malformed exact-absence evidence`);
    }
    const builtinTargetAbsence =
      authored.expectedResult === "absent" &&
      observation.invocation.invocationSchema ===
        "ibex/capsec-builtin-export-invocation/1";
    const sourceVariantAbsence =
      authored.expectedResult === "absent" &&
      !builtinTargetAbsence &&
      observation.invocation.invocationSchema !==
        "ibex/capsec-native-global-invocation/1";
    terminalObservedKey = builtinTargetAbsence
      ? observation.invocation.surfaceObservedKey
      : sourceVariantAbsence
        ? `${observation.invocation.result.surfaceKind}:${observation.invocation.result.surfaceName}`
        : observation.invocation.surfaceObservedKey;
  } else if (nativeWorkerTerminal !== null) {
    if (
      terminals.size !== 1 ||
      !terminals.has(nativeWorkerTerminal)
    ) {
      throw new Error(
        `${recipe.fixtureId}: async invocation did not remain on its source-selected worker`,
      );
    }
    terminalObservedKey = observation.invocation.surfaceObservedKey;
  } else {
    if (terminals.size !== 1) {
      throw new Error(
        `${recipe.fixtureId}: typed gates selected multiple terminals`,
      );
    }
    terminalObservedKey = [...terminals][0];
  }
  const directTerminalBuiltinClosure =
    recipe.classification === "closed" &&
    recipe.scenario === "closed" &&
    authored.operation?.kind === "terminal-builtin-import" &&
    recipe.route?.alternatives?.length === 0 &&
    canonicalJson(recipe.route?.surfaceObservedKeys) ===
      canonicalJson([terminalObservedKey]);
  const closedSqliteCarrierClosure =
    recipe.classification === "closed" &&
    recipe.scenario === "closed" &&
    CLOSED_SQLITE_CARRIER_OPERATIONS.has(authored.operation?.kind) &&
    observation.typedDecisions.length === 0 &&
    terminalObservedKey === recipe.terminalObservedKey;
  const allowed = runtimeAuxiliaryCarrier
    ? [recipe.publicSurfaceProbe.surfaceObservedKey]
    : directTerminalBuiltinClosure || closedSqliteCarrierClosure
      ? [terminalObservedKey]
      : recipe.route?.alternatives?.map(
          (alternative) => alternative.terminalObservedKey,
        );
  const exactTargetAbsence =
    authored.expectedResult === "absent" &&
    recipe.expectedObservation?.kind === "target-absence";
  if (
    runtimeAuxiliaryCarrier
      ? !allowed.includes(terminalObservedKey)
      : exactTargetAbsence
        ? allowed?.length !== 0 ||
          terminalObservedKey !== recipe.terminalObservedKey
        : !allowed?.includes(terminalObservedKey)
  ) {
    throw new Error(
      `${recipe.fixtureId}: runtime-derived terminal is outside the bound route`,
    );
  }
  return terminalObservedKey;
}

function validateExecution(execution, recipe, engineBinaryDigest, coverage) {
  exactKeys(
    execution,
    ["fixtureId", "outcome", "executor", "evidence"],
    `${recipe.fixtureId}: public execution`,
  );
  exactKeys(
    execution.evidence,
    [
      "evidenceSchema",
      "fixtureId",
      "planDigest",
      "engineBinaryDigest",
      "probe",
      "terminalObservedKey",
      "exitCode",
      "resultMarker",
      "observation",
      "runtimeObservation",
      "evidenceDigest",
    ],
    `${recipe.fixtureId}: public execution evidence`,
  );
  const evidence = execution.evidence;
  const expectedExecutor = reviewedPublicSurfaceExecutorDescriptor(
    recipe.publicSurfaceProbe?.command,
  )?.executor;
  if (
    execution.fixtureId !== recipe.fixtureId ||
    evidence.evidenceSchema !==
      "ibex/capsec-public-surface-fixture-evidence/2" ||
    evidence.fixtureId !== recipe.fixtureId ||
    typeof execution.executor !== "string" ||
    execution.executor.length === 0 ||
    /adapter/iu.test(execution.executor) ||
    (expectedExecutor !== undefined && execution.executor !== expectedExecutor) ||
    evidence.planDigest !== recipe.planDigest ||
    evidence.engineBinaryDigest !== engineBinaryDigest ||
    canonicalJson(evidence.probe) !==
      canonicalJson(recipe.publicSurfaceProbe) ||
    evidence.evidenceDigest !== evidenceDigest(evidence)
  ) {
    throw new Error(
      `${recipe.fixtureId}: adapter-only, stale, or malformed public-surface evidence`,
    );
  }
  const runtimeTerminal = validatePublicFixtureRuntimeObservation(
    evidence.runtimeObservation,
    recipe,
    coverage,
  );
  const passedMarker = `ibex-capsec-public-fixture:${recipe.fixtureId}:passed`;
  const failedMarker = `ibex-capsec-public-fixture:${recipe.fixtureId}:failed`;
  const derivedOutcome =
    evidence.exitCode === 0 && evidence.resultMarker === passedMarker
      ? "passed"
      : evidence.exitCode !== 0 || evidence.resultMarker === failedMarker
        ? "failed"
        : null;
  if (!derivedOutcome || derivedOutcome !== execution.outcome) {
    throw new Error(
      `${recipe.fixtureId}: public result marker disagrees with outcome`,
    );
  }
  const expectedObservation = {
    ...recipe.expectedObservation,
    result: derivedOutcome,
  };
  if (
    canonicalJson(evidence.observation) !== canonicalJson(expectedObservation)
  ) {
    throw new Error(
      `${recipe.fixtureId}: public observation selected the wrong branch`,
    );
  }
  if (runtimeTerminal !== evidence.terminalObservedKey) {
    throw new Error(
      `${recipe.fixtureId}: claimed terminal differs from runtime typed gates`,
    );
  }
}

export function validatePublicSurfaceExecutionArtifact(
  artifact,
  {
    recipeCatalog,
    target = null,
    sourceRevision = null,
    sourceTreeDigest = null,
    engine = null,
    coverage = null,
  },
) {
  if (artifact?.adapterEvidenceSchema) {
    throw new Error("adapter-only evidence cannot advertise a target");
  }
  exactKeys(
    artifact,
    [
      "publicSurfaceExecutionSchema",
      "profile",
      "sourceRevision",
      "sourceTreeDigest",
      "target",
      "engine",
      "recipeCatalogDigest",
      "summary",
      "executions",
      "publicSurfaceExecutionDigest",
    ],
    "public-surface execution artifact",
  );
  if (
    artifact.publicSurfaceExecutionSchema !==
      "ibex/capsec-public-surface-executions/1" ||
    artifact.profile !== "ibex/capsec/1" ||
    !Array.isArray(artifact.executions) ||
    artifact.recipeCatalogDigest !== recipeCatalog.recipeCatalogDigest ||
    artifact.publicSurfaceExecutionDigest !==
      computePublicSurfaceExecutionDigest(artifact) ||
    (target && canonicalJson(artifact.target) !== canonicalJson(target)) ||
    (sourceRevision && artifact.sourceRevision !== sourceRevision) ||
    (sourceTreeDigest && artifact.sourceTreeDigest !== sourceTreeDigest) ||
    (engine && canonicalJson(artifact.engine) !== canonicalJson(engine))
  ) {
    throw new Error(
      "public-surface execution artifact has stale or mismatched bindings",
    );
  }
  validateRecipeCatalog(recipeCatalog, { target: artifact.target });
  const recipes = new Map(
    recipeCatalog.recipes.map((recipe) => [recipe.fixtureId, recipe]),
  );
  const seen = new Set();
  const authenticatedBuiltinRuntimeNonces = new Set();
  for (const execution of artifact.executions) {
    const recipe = recipes.get(execution?.fixtureId);
    if (!recipe || seen.has(execution.fixtureId)) {
      throw new Error(
        "public-surface executions contain an unknown or duplicate fixture",
      );
    }
    seen.add(execution.fixtureId);
    validateExecution(
      execution,
      recipe,
      artifact.engine?.binaryDigest,
      coverage,
    );
    const authenticatedBuiltinRuntimeNonce =
      execution.evidence?.runtimeObservation?.invocation?.sourceExecution
        ?.runtimeNonce;
    if (authenticatedBuiltinRuntimeNonce !== undefined) {
      if (
        authenticatedBuiltinRuntimeNonces.has(authenticatedBuiltinRuntimeNonce)
      ) {
        throw new Error(
          "authenticated builtin source executions reused a runtime nonce",
        );
      }
      authenticatedBuiltinRuntimeNonces.add(authenticatedBuiltinRuntimeNonce);
    }
  }
  if (
    canonicalJson(artifact.executions.map((row) => row.fixtureId)) !==
    canonicalJson([...seen].sort(compareText))
  ) {
    throw new Error(
      "public-surface executions are not in canonical fixture order",
    );
  }
  if (
    canonicalJson(artifact.summary) !==
    canonicalJson(executionSummary(recipeCatalog, artifact.executions))
  ) {
    throw new Error(
      "public-surface execution summary disagrees with its evidence",
    );
  }
  return artifact;
}

export function assertPublicSurfaceExecutionComplete(
  artifact,
  recipeCatalog,
  options = {},
) {
  assertRecipeCatalogComplete(recipeCatalog, {
    target: options.target ?? artifact.target,
    expectedFixtureIds: options.expectedFixtureIds ?? null,
  });
  validatePublicSurfaceExecutionArtifact(artifact, {
    ...options,
    recipeCatalog,
  });
  if (
    artifact.summary.residualFixtures !== 0 ||
    artifact.summary.failedFixtures !== 0 ||
    artifact.summary.missingFixtures !==
      artifact.summary.internallyVerifiedFixtures ||
    artifact.summary.executedFixtures !==
      artifact.summary.executableFixtures ||
    artifact.summary.passedFixtures !== artifact.summary.executableFixtures
  ) {
    throw new Error(
      "public-surface execution artifact cannot advertise with residual, failed, or missing public obligations",
    );
  }
}

export function buildPublicFixtureEvidence({
  recipe,
  engineBinaryDigest,
  runtimeObservation,
  coverage,
  outcome = "passed",
  executor = "ibex-public-surface-harness",
}) {
  const terminalObservedKey = validatePublicFixtureRuntimeObservation(
    runtimeObservation,
    recipe,
    coverage,
  );
  const evidence = {
    evidenceSchema: "ibex/capsec-public-surface-fixture-evidence/2",
    fixtureId: recipe.fixtureId,
    planDigest: recipe.planDigest,
    engineBinaryDigest,
    probe: structuredClone(recipe.publicSurfaceProbe),
    terminalObservedKey,
    exitCode: outcome === "passed" ? 0 : 1,
    resultMarker: `ibex-capsec-public-fixture:${recipe.fixtureId}:${outcome}`,
    observation: { ...recipe.expectedObservation, result: outcome },
    runtimeObservation: structuredClone(runtimeObservation),
  };
  evidence.evidenceDigest = evidenceDigest(evidence);
  return {
    fixtureId: recipe.fixtureId,
    outcome,
    executor,
    evidence,
  };
}
