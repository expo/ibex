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
import {
  assertRecipeCatalogComplete,
  validateRecipeCatalog,
} from "./capsec-conformance-recipes.mjs";
import { canonicalJson } from "./capsec-contract.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value), "utf8")
    .digest("base64url")}`;
const BUILTIN_RUNTIME_INVOCATION_SCHEMAS = new Set([
  "ibex/capsec-builtin-export-invocation/1",
  "ibex/capsec-builtin-call-invocation/1",
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
      preloadModuleSpecifiers: ["node:util"],
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
      preloadModuleSpecifiers: ["node:events"],
    },
  ],
  [
    "TZ",
    {
      sourceRef:
        "packages/ibex-runtime-js/src/node/process.ts#process.env:TZ:read",
      liveSourceRefs: [
        "packages/ibex-runtime-js/src/node/process.ts#process.env:TZ:read",
      ],
      mechanism: "date-to-string",
      moduleSpecifier: null,
      preloadModuleSpecifiers: [],
    },
  ],
]);

function exactKeys(value, keys, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort(compareText)) !==
      canonicalJson([...keys].sort(compareText))
  ) {
    throw new Error(`${label} has unknown or missing fields`);
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
  typeof value === "string" && /^u64:[1-9][0-9]*$/u.test(value);

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
    "host-abi:ex_host_prepare_armed_embedder_artifacts",
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
    throw new Error(`${fixtureId}: callback invariant did not pass its authored scenario`);
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
      throw new Error(`${label} did not prove fail-closed callback attribution`);
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
    validateGenerationSet(checks.generationsBefore, `${label} generations before`);
    validateGenerationSet(checks.generationsAfter, `${label} generations after`);
    if (
      checks.callbackExecuted !== true ||
      checks.generationAdvanced !== true ||
      checks.scheduledDecisionRechecked !== true ||
      checks.generationsAfter.negative <= checks.generationsBefore.negative ||
      checks.generationsAfter.dynamic <= checks.generationsBefore.dynamic ||
      checks.generationsAfter.handle !== checks.generationsBefore.handle ||
      !isTaggedRuntimeNonce(checks.runtimeNonce)
    ) {
      throw new Error(`${label} did not prove a post-revocation decision recheck`);
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
    validateRootPrincipal(checks.restoredPrincipal, `${label} restored principal`);
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
    validateGenerationSet(checks.generationsBefore, `${label} generations before`);
    validateGenerationSet(checks.generationsAfter, `${label} generations after`);
    if (
      checks.bridgeExecuted !== true ||
      checks.requestRefused !== true ||
      checks.generationsUnchanged !== true ||
      canonicalJson(checks.generationsBefore) !== canonicalJson(checks.generationsAfter)
    ) {
      throw new Error(`${label} did not prove that the bridge cannot widen authority`);
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
    validateGenerationSet(checks.generationsBefore, `${label} generations before`);
    validateGenerationSet(checks.generationsAfter, `${label} generations after`);
    if (
      !booleanChecks.every((name) => checks[name] === true) ||
      canonicalJson(checks.generationsBefore) !== canonicalJson(checks.generationsAfter)
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
        throw new Error(`${label} did not prove the single-use Exact completion route`);
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
        throw new Error(`${label} did not prove immutable Exact endowment installation`);
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
        throw new Error(`${label} did not prove authenticated artifact freshening`);
      }
      return;
    }
  }
  throw new Error(`${fixtureId}: unsupported callback invariant scenario`);
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
      !new Set(["global-property-read", "native-global-function"]).has(
        invocation.kind,
      ) ||
      invocation.globalName !== authored.globalName
    ) {
      throw new Error(
        `${recipe.fixtureId}: native runtime invocation descriptor drift`,
      );
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
    if (
      invocation.kind !== "host-abi-function" ||
      invocation.functionName !== authored.functionName ||
      authored.operation?.kind !== "sqlite-memory" ||
      authored.operation?.selectedBranch?.id !== "memory" ||
      authored.sourceDescriptor?.kind !== "host-abi-function" ||
      authored.sourceDescriptor?.functionName !== authored.functionName ||
      canonicalJson(authored.sourceDescriptor?.selectedBranch) !==
        canonicalJson(authored.operation?.selectedBranch)
    ) {
      throw new Error(
        `${recipe.fixtureId}: host ABI runtime invocation descriptor drift`,
      );
    }
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
      invocation.invocationSchema ===
      "ibex/capsec-builtin-call-invocation/1"
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
    invocation?.invocationSchema ===
    "ibex/capsec-startup-surface-invocation/1"
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
      invocation.kind !== "startup-environment-source" ||
      invocation.surfaceKind !== "startup" ||
      invocation.surfaceName !== `env:${environmentName}` ||
      invocation.scenario !== authored.scenario ||
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
    if (authored.operation?.kind === "loader-executable-file") {
      const loaderExpectation = new Map([
        [
          "native-addon",
          {
            extension: ".node",
            rejectionFragment: "Native addons are closed",
          },
        ],
        [
          "wasm",
          {
            extension: ".wasm",
            rejectionFragment: "WebAssembly modules are closed",
          },
        ],
      ]).get(authored.operation.loaderKind);
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "loaderKind",
          "extension",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed loader source descriptor`,
      );
      exactKeys(
        authored.operation,
        ["kind", "loaderKind", "extension", "rejectionFragment"],
        `${recipe.fixtureId}: closed loader operation`,
      );
      if (
        loaderExpectation === undefined ||
        authored.surfaceKind !== "loader" ||
        authored.surfaceName !==
          `${authored.operation.loaderKind}-module` ||
        recipe.terminalObservedKey !==
          `loader:${authored.operation.loaderKind}-module` ||
        descriptor.kind !== "closed-loader-executable-kind" ||
        descriptor.loaderKind !== authored.operation.loaderKind ||
        descriptor.extension !== loaderExpectation.extension ||
        authored.operation.extension !== loaderExpectation.extension ||
        authored.operation.rejectionFragment !==
          loaderExpectation.rejectionFragment ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson(["src/module_loader/mod.rs#resolve_with_oxc"]) ||
        descriptor.sourceMetadata !== null
      ) {
        throw new Error(
          `${recipe.fixtureId}: closed loader invocation is not bound to the executed extension guard`,
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
      invocation.scenario !== authored.scenario
    ) {
      throw new Error(
        `${recipe.fixtureId}: callback invariant runtime invocation descriptor drift`,
      );
    }
    if (authored.scenario === "non-capability") {
      const expected = EXACT_EMBEDDER_NON_CAPABILITY_SURFACES.get(
        recipe.publicSurfaceProbe.surfaceObservedKey,
      );
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
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
  const auxiliaryCarrier = callbackInvariant || startupEnvironment;
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
    auxiliaryCarrier &&
    (!Array.isArray(authored.expectedTypedOutcomes) ||
      authored.expectedTypedOutcomes.length !== authored.expectedTypedDecisionCount ||
      !authored.expectedTypedOutcomes.every((outcome) =>
        ["allow", "deny"].includes(outcome),
      ) ||
      !Array.isArray(authored.expectedTypedReasons) ||
      authored.expectedTypedReasons.length !== authored.expectedTypedDecisionCount ||
      !authored.expectedTypedReasons.every(
        (reason) => typeof reason === "string" && reason.length > 0,
      ))
  ) {
    throw new Error(`${recipe.fixtureId}: malformed auxiliary carrier expectations`);
  }
  if (
    startupEnvironment &&
    (!Array.isArray(authored.expectedResourceNames) ||
      canonicalJson(authored.expectedResourceNames) !==
        canonicalJson(canonicalSet(authored.expectedResourceNames)) ||
      authored.expectedResourceNames.length !== 1 ||
      authored.expectedResourceNames[0] !== authored.operation.environment.name)
  ) {
    throw new Error(`${recipe.fixtureId}: malformed startup environment resource binding`);
  }
  if (!invocation.result || typeof invocation.result !== "object") {
    throw new Error(`${recipe.fixtureId}: runtime invocation has no result`);
  }
  if (authored.expectedResult === "normal-return") {
    if (
      authored.invocationSchema !==
        "ibex/capsec-builtin-call-invocation/1" ||
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
      authored.invocationSchema ===
        "ibex/capsec-native-global-invocation/1" &&
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
    } else if (
      authored.invocationSchema ===
      "ibex/capsec-startup-surface-invocation/1"
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
  } else if (authored.expectedResult === "permission-denied") {
    if (
      invocation.result.kind !== "throw" ||
      typeof invocation.result.errorMessage !== "string" ||
      !invocation.result.errorMessage.includes("Permission denied")
    ) {
      throw new Error(`${recipe.fixtureId}: public invocation did not deny`);
    }
  } else if (authored.expectedResult === "absent") {
    if (
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
        !invocation.result.errorMessage.includes(
          authored.operation.rejectionFragment,
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: executable loader kind did not fail closed at resolution`,
      );
    }
  } else if (authored.expectedResult === "invariant-passed") {
    if (!callbackInvariant) {
      throw new Error(`${recipe.fixtureId}: non-callback probe claimed an invariant result`);
    }
    validateCallbackInvariantResult(invocation.result, authored, recipe.fixtureId);
  } else {
    throw new Error(`${recipe.fixtureId}: unsupported expected public result`);
  }
  if (
    invocation.invocationSchema === "ibex/capsec-native-global-invocation/1"
  ) {
    exactKeys(
      invocation.executionProof,
      ["kind", "bodyEntered"],
      `${recipe.fixtureId}: native execution proof`,
    );
    const expectedProof =
      authored.expectedResult === "return"
        ? [
            authored.kind === "global-property-read"
              ? "global-property-read"
              : "native-return",
            true,
          ]
        : authored.expectedResult === "permission-denied"
          ? ["typed-permission-denial", true]
          : ["exact-global-absence", false];
    if (
      invocation.executionProof.kind !== expectedProof[0] ||
      invocation.executionProof.bodyEntered !== expectedProof[1]
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
  const auxiliaryCarrier = callbackInvariant || startupEnvironment;
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
        canonicalSet((selectedBranch?.effects ?? []).map((effect) => effect.cap)),
      ) !== canonicalJson(recipe.actionIds) ||
      recipe.terminalObservedKey !== `startup:env:${environmentName}` ||
      descriptor.surfaceObservedKey !== recipe.terminalObservedKey
    ) {
      throw new Error(
        `${recipe.fixtureId}: startup environment auxiliary decision is not coverage-bound`,
      );
    }
  }
  for (const [decisionIndex, decision] of observation.typedDecisions.entries()) {
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
    for (const effect of set.effects) {
      if (typeof effect?.cap !== "string") {
        throw new Error(`${recipe.fixtureId}: observed effect has no action`);
      }
      actions.add(effect.cap);
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
      terminals.add(terminal);
    }
    const expectedOutcome = auxiliaryCarrier
      ? authored.expectedTypedOutcomes[decisionIndex]
      : authored.expectedResult === "permission-denied"
        ? "deny"
        : "allow";
    if (decision.evidence?.outcome !== expectedOutcome) {
      throw new Error(
        `${recipe.fixtureId}: observed typed outcome disagrees with invocation`,
      );
    }
    if (
      auxiliaryCarrier &&
      (!Array.isArray(decision.evidence?.evidence) ||
        decision.evidence.evidence.length === 0 ||
        decision.evidence.evidence.find((entry) =>
          canonicalJson(entry?.principal) ===
          canonicalJson(decision.decisionSet.context.actor),
        )?.reason !==
          authored.expectedTypedReasons[decisionIndex])
    ) {
      throw new Error(`${recipe.fixtureId}: observed typed reason disagrees with carrier`);
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
              target: "broker-base",
              name: environmentName,
            },
            valueOrigin: "broker-base",
          })
      ) {
        throw new Error(
          `${recipe.fixtureId}: startup environment decision lost its exact resource or principal binding`,
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
      throw new Error(`${recipe.fixtureId}: attribution evidence used the wrong actor`);
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
      throw new Error(`${recipe.fixtureId}: generation evidence is not decision-bound`);
    }
    if (
      authored.scenario === "principal-restore" &&
      (!same(actorAt(0), checks.callbackPrincipal) ||
        !same(actorAt(1), checks.callbackPrincipal) ||
        !same(actorAt(2), checks.restoredPrincipal) ||
        !same(actorAt(3), checks.restoredPrincipal))
    ) {
      throw new Error(`${recipe.fixtureId}: principal restoration is not decision-bound`);
    }
    if (
      authored.scenario === "snapshot-mismatch-deny" &&
      observation.typedDecisions.length !== 0
    ) {
      throw new Error(`${recipe.fixtureId}: snapshot evidence is not decision-bound`);
    }
  }
  if (
    canonicalJson(stages) !== canonicalJson(authored.expectedTypedStages) ||
    canonicalJson([...actions].sort(compareText)) !==
      canonicalJson(
        [
          ...(authored.expectedResult === "absent"
            ? []
            : authored.expectedActionIds),
        ].sort(compareText),
      ) ||
    (observation.typedDecisions.length > 0 && edgeIds.size === 0)
  ) {
    throw new Error(
      `${recipe.fixtureId}: observed typed stages, actions, or gates drifted`,
    );
  }

  let terminalObservedKey;
  if (auxiliaryCarrier) {
    if (observation.typedDecisions.length > 0 && terminals.size !== 1) {
      throw new Error(`${recipe.fixtureId}: carrier evidence selected multiple auxiliaries`);
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
    const sourceVariantAbsence =
      authored.expectedResult === "absent" &&
      observation.invocation.invocationSchema !==
        "ibex/capsec-native-global-invocation/1";
    terminalObservedKey = sourceVariantAbsence
      ? `${observation.invocation.result.surfaceKind}:${observation.invocation.result.surfaceName}`
      : observation.invocation.surfaceObservedKey;
  } else {
    if (terminals.size !== 1) {
      throw new Error(
        `${recipe.fixtureId}: typed gates selected multiple terminals`,
      );
    }
    terminalObservedKey = [...terminals][0];
  }
  const allowed = auxiliaryCarrier
    ? [recipe.publicSurfaceProbe.surfaceObservedKey]
    : recipe.route?.alternatives?.map(
        (alternative) => alternative.terminalObservedKey,
      );
  const exactTargetAbsence =
    authored.expectedResult === "absent" &&
    recipe.expectedObservation?.kind === "target-absence";
  if (
    auxiliaryCarrier
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
  if (
    execution.fixtureId !== recipe.fixtureId ||
    evidence.evidenceSchema !==
      "ibex/capsec-public-surface-fixture-evidence/2" ||
    evidence.fixtureId !== recipe.fixtureId ||
    typeof execution.executor !== "string" ||
    execution.executor.length === 0 ||
    /adapter/iu.test(execution.executor) ||
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
    artifact.summary.missingFixtures !== 0 ||
    artifact.summary.failedFixtures !== 0 ||
    artifact.summary.executedFixtures !== artifact.summary.requiredFixtures ||
    artifact.summary.passedFixtures !== artifact.summary.requiredFixtures
  ) {
    throw new Error(
      "public-surface execution artifact cannot advertise with residual, missing, or failed obligations",
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
