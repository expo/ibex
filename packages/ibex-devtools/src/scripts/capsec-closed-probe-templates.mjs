/**
 * Source-bound public probes for deny-only surfaces. Closed surfaces do not
 * enter the typed authority evaluator: the production boundary must reject
 * them before project code and report zero typed and legacy decisions.
 *
 * @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
 * deny-only startup controls must fail at the authenticated entry boundary.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import {
  reviewedArmedNativeAbsentSurface,
  reviewedArmedSharedRuntimeSealedSurface,
} from "./capsec-armed-root-closures.mjs";

const CLOSED_BATCH_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer,openssl-crypto",
  "capsec_public_closed_recipe_batch",
  "--",
  "--test-threads=1",
]);

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const PROJECT_CODE_PLACEHOLDER = "{ibex-capsec-closed-project-code}";
const EVALUATION_MARKER =
  "globalThis.__IBEX_CAPSEC_CLOSED_CLI_EVALUATED__ = true";

const CLI_OPTION_TEMPLATES = new Map([
  ["ibex\0allow_all", { value: null, rejection: "legacy" }],
  ["ibex\0allow_env_endowments", { value: null, rejection: "legacy" }],
  ["ibex\0capsec", { value: null, rejection: "legacy" }],
  ["ibex\0capsec_allow_advisory", { value: null, rejection: "legacy" }],
  ["ibex\0eval_code", { value: EVALUATION_MARKER, rejection: "evaluation" }],
  ["ibex\0expose_internals", { value: null, rejection: "inspector" }],
  ["ibex\0inspect", { value: null, rejection: "inspector" }],
  ["ibex\0inspect_host", { value: "127.0.0.1", rejection: "inspector" }],
  ["ibex\0inspect_open", { value: null, rejection: "inspector" }],
  ["ibex\0inspect_pause", { value: null, rejection: "inspector" }],
  ["ibex\0inspect_port", { value: "9230", rejection: "inspector" }],
  ["ibex\0inspect_wait", { value: null, rejection: "inspector" }],
  ["ibex\0print_eval", { value: EVALUATION_MARKER, rejection: "evaluation" }],
  ["ibex run\0inspect", { value: null, rejection: "inspector" }],
  ["ibex run\0inspect_host", { value: "127.0.0.1", rejection: "inspector" }],
  ["ibex run\0inspect_open", { value: null, rejection: "inspector" }],
  ["ibex run\0inspect_pause", { value: null, rejection: "inspector" }],
  ["ibex run\0inspect_port", { value: "9230", rejection: "inspector" }],
  ["ibex run\0inspect_wait", { value: null, rejection: "inspector" }],
]);

const CLI_COMMAND_TEMPLATES = new Map([
  ["ibex debug", { args: ["debug", "modules"], rejection: "evaluation" }],
  ["ibex debug modules", { args: ["debug", "modules"], rejection: "evaluation" }],
  ["ibex eval", { args: ["eval", EVALUATION_MARKER], rejection: "evaluation" }],
  ["ibex repl", { args: ["repl"], rejection: "evaluation" }],
]);

const REJECTION_FRAGMENTS = Object.freeze({
  evaluation: [
    "production capability enforcement closes debug commands",
  ],
  inspector: [
    "closes compatibility, inspector",
    "runtime-fidelity overrides",
  ],
  legacy: [
    "rejects legacy allow/deny",
    "environment endowment widening",
  ],
});

const TAMED_EVALUATOR_ACCESS = new Map([
  ["global:eval", "global-eval"],
  ["global:Function", "global-function"],
  ["global:AsyncFunction", "async-function-constructor"],
  ["global:GeneratorFunction", "generator-function-constructor"],
]);

const TERMINAL_BUILTIN_SPECIFIERS = new Map([
  ["node_async_hooks", ["async_hooks", "node:async_hooks"]],
  [
    "node_inspector",
    [
      "inspector",
      "inspector/promises",
      "node:inspector",
      "node:inspector/promises",
    ],
  ],
  ["node_vm", ["node:vm", "vm"]],
  ["node_wasi", ["node:wasi", "wasi"]],
  ["node_worker_threads", ["node:worker_threads", "worker_threads"]],
]);

const CLOSED_SQLITE_EXTENSION_EXPORTS = new Map([
  ["Database.loadExtension", "Database"],
  ["default.loadExtension", "default"],
]);
const CLOSED_SQLITE_CRSQLITE_EXPORTS = new Map([
  ["Database.enableCrSqlite", "Database"],
  ["default.enableCrSqlite", "default"],
]);
const CLOSED_SQLITE_MODULE_SPECIFIERS = Object.freeze([
  "bun:sqlite",
  "exact:sqlite",
]);
const CLOSED_SQLITE_CRSQLITE_TERMINALS = Object.freeze([
  "__exactCrSqlitePath",
  "__exactSqliteLoadCrSqlite",
  "__exactSqliteLoadExtension",
]);

const DEBUGGER_ABI_FUNCTIONS = new Map([
  ["enable", ["ex_hermes_debugger_enable", "integer-zero"]],
  ["eval", ["ex_hermes_debugger_eval", "null-pointer"]],
  ["get-script-source", ["ex_hermes_debugger_get_script_source", "null-pointer"]],
  ["get-scripts", ["ex_hermes_debugger_get_scripts", "null-pointer"]],
  ["next-event", ["ex_hermes_debugger_next_event", "null-pointer"]],
  ["pause", ["ex_hermes_debugger_pause", "no-event"]],
  [
    "remove-breakpoint",
    ["ex_hermes_debugger_remove_breakpoint", "no-event"],
  ],
  ["resume", ["ex_hermes_debugger_resume", "no-event"]],
  ["set-breakpoint", ["ex_hermes_debugger_set_breakpoint", "null-pointer"]],
]);

const SHARED_RUNTIME_ABSENT_GLOBALS = new Set([
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
  "global:Exact.gc",
]);

const EXACT_RUNTIME_CANDIDATE_TRIPLES = new Set([
  "aarch64-apple-darwin",
  "x86_64-pc-windows-msvc",
]);

function reviewedSharedRuntimeAbsentSurface(surfaceName) {
  return (
    SHARED_RUNTIME_ABSENT_GLOBALS.has(surfaceName) ||
    reviewedArmedSharedRuntimeSealedSurface(surfaceName)
  );
}

const APP_RUNTIME_ABSENT_WORKLET_GLOBALS = new Set([
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

const EXACT_OPERATION_MANIFEST_DIGEST =
  "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA";
const EXACT_APP_OPERATION_IDS = Object.freeze([7, 11]);
const EXACT_UNENDOWED_OPERATION_ID = 8;

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalStrings(values) {
  return [...new Set(values)].sort(compareText);
}

function liveRows(liveByObservedKey) {
  return [...liveByObservedKey.values()];
}

function optionControlDescriptor(live, liveByObservedKey) {
  const metadata = live.metadata ?? {};
  let commandPath = metadata.commandPath;
  let argumentId = metadata.argumentId;
  const rows = liveRows(liveByObservedKey);
  let route = null;
  if (commandPath && argumentId) {
    route = rows.find(
      (row) =>
        row.kind === "cli" &&
        row.metadata?.evidenceType === "cli-option-route" &&
        row.metadata.commandPath === commandPath &&
        row.metadata.id === argumentId,
    );
  } else {
    route = rows.find(
      (row) =>
        row.kind === "cli" &&
        row.metadata?.evidenceType === "cli-option-route" &&
        row.sourceRefs.some((sourceRef) => live.sourceRefs.includes(sourceRef)),
    );
    commandPath = route?.metadata?.commandPath;
    argumentId = route?.metadata?.id;
  }
  if (!route || !commandPath || !argumentId) return null;
  const template = CLI_OPTION_TEMPLATES.get(`${commandPath}\0${argumentId}`);
  const evidenceType = metadata.evidenceType;
  if (!template) return null;
  if (
    evidenceType === "cli-default-value" &&
    !route.metadata.valueShape?.defaultValues?.includes(metadata.value)
  ) {
    return null;
  }

  let value = template.value;
  if (evidenceType === "cli-enum-value") {
    if (
      commandPath !== "ibex" ||
      argumentId !== "capsec" ||
      !["audit", "permissive"].includes(metadata.value)
    ) {
      return null;
    }
    value = metadata.value;
  }
  if (argumentId === "capsec") {
    if (evidenceType !== "cli-enum-value") return null;
  }

  const optionNameRows = rows.filter(
    (row) =>
      row.kind === "cli" &&
      row.metadata?.evidenceType === "cli-option-name" &&
      row.sourceRefs.some((sourceRef) => route.sourceRefs.includes(sourceRef)),
  );
  const optionSpellings = canonicalStrings(
    optionNameRows.map((row) => row.metadata.name),
  );
  if (optionSpellings.length === 0) return null;
  const selectedSpellings =
    evidenceType === "cli-option-name" ? [metadata.name] : optionSpellings;
  if (selectedSpellings.some((spelling) => !optionSpellings.includes(spelling))) {
    return null;
  }
  const parser = rows.find(
    (row) =>
      row.kind === "cli" &&
      row.metadata?.evidenceType === "cli-non-enumerated-parser" &&
      row.metadata.commandPath === commandPath &&
      row.metadata.argumentId === argumentId,
  );
  const argumentVectors = selectedSpellings.map((spelling) => {
    const option = value === null ? [spelling] : [spelling, value];
    const prefix = commandPath.split(" ").slice(1);
    return {
      spelling,
      args:
        commandPath === "ibex run"
          ? [...prefix, ...option, PROJECT_CODE_PLACEHOLDER]
          : [...option, PROJECT_CODE_PLACEHOLDER],
    };
  });
  return {
    controlDescriptor: {
      kind: "clap-option",
      commandPath,
      argumentId,
      optionSpellings,
      valueShape: structuredClone(route.metadata.valueShape),
      hidden: route.metadata.hidden === true,
      parserKind: parser?.metadata?.parserKind ?? null,
    },
    argumentVectors,
    rejection: template.rejection,
  };
}

function tamedEvaluatorProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "native-op:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const surfaceName = surfaceObservedKey.slice(prefix.length);
  const accessMode = TAMED_EVALUATOR_ACCESS.get(surfaceName);
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  if (
    !accessMode ||
    live?.kind !== "native-op" ||
    live.name !== surfaceName ||
    metadata?.evidenceType !== "hermes-evaluator-reachability" ||
    metadata?.exportName !== surfaceName.slice("global:".length) ||
    typeof metadata.engineIdentityReviewId !== "string" ||
    typeof metadata.lockdownTamingDigest !== "string" ||
    metadata.tamingEvidence !== "lockdownJS" ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-tamed-evaluator",
    surfaceObservedKey,
    globalName: metadata.exportName,
    accessMode,
    engineIdentityReviewId: metadata.engineIdentityReviewId,
    lockdownTamingDigest: metadata.lockdownTamingDigest,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "native-op",
      surfaceName,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "tamed-evaluator",
        globalName: metadata.exportName,
        accessMode,
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function moduleRunnerNamespaceProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const surfaceName = "ex_hermes_module_record_namespace_json";
  if (surfaceObservedKey !== `host-abi:${surfaceName}`) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  if (
    live?.kind !== "host-abi" ||
    live.name !== surfaceName ||
    !Array.isArray(live.sourceRefs) ||
    canonicalJson(live.sourceRefs) !==
      canonicalJson([`src/engine/hermes_module_runner.cc#${surfaceName}`]) ||
    live.metadata?.definitions?.length !== 1 ||
    live.metadata.definitions[0].language !== "c++" ||
    live.metadata.definitions[0].sourceRef !== live.sourceRefs[0] ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    edge.cap !== "runtime:inspect" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-module-runner-namespace",
    surfaceObservedKey,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(live.metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "host-abi",
      surfaceName,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "module-runner-namespace",
        expectedError:
          "native ModuleRecord namespace read refused (-1): module namespace inspection is closed under armed startup",
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function exactUnendowedOperationProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  if (surfaceObservedKey !== "native-op:global:exact.invokeHostAsync") {
    return null;
  }
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  if (
    live?.kind !== "native-op" ||
    live.name !== "global:exact.invokeHostAsync" ||
    metadata?.surfaceType !== "global-api" ||
    metadata?.sourceKey !== "native_jsi_global" ||
    metadata?.globalName !== "exact" ||
    metadata?.memberName !== "invokeHostAsync" ||
    metadata?.exportName !== "exact.invokeHostAsync" ||
    canonicalJson(metadata?.memberKinds) !==
      canonicalJson(["native-object-member"]) ||
    canonicalJson(live.sourceRefs) !==
      canonicalJson([
        "src/engine/hermes_runtime.cc#jsi-global:exact.invokeHostAsync",
      ]) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-exact-unendowed-operation",
    surfaceObservedKey,
    globalName: "exact",
    memberName: "invokeHostAsync",
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "native-op",
      surfaceName: "global:exact.invokeHostAsync",
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "exact-unendowed-operation",
        contextKind: "app",
        operationManifestDigest: EXACT_OPERATION_MANIFEST_DIGEST,
        endowedOperationIds: [...EXACT_APP_OPERATION_IDS],
        selectedOperationId: EXACT_UNENDOWED_OPERATION_ID,
        expectedError: "exact.invokeHostAsync operation is not endowed",
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function commandControlDescriptor(live, liveByObservedKey) {
  const rows = liveRows(liveByObservedKey);
  const evidenceType = live.metadata?.evidenceType;
  let commandPath = evidenceType === "cli-command-route"
    ? live.metadata.path
    : null;
  if (!commandPath && live.variant === "visible") {
    commandPath = `ibex ${live.name}`;
  }
  if (!commandPath && evidenceType === "cli-positional-route") {
    commandPath = live.metadata.commandPath;
  }
  if (!commandPath) {
    const route = rows.find(
      (row) =>
        row.kind === "cli" &&
        row.metadata?.evidenceType === "cli-positional-route" &&
        row.sourceRefs.some((sourceRef) => live.sourceRefs.includes(sourceRef)),
    );
    commandPath = route?.metadata?.commandPath;
  }
  const template = CLI_COMMAND_TEMPLATES.get(commandPath);
  if (!template) return null;
  const commandRoute = rows.find(
    (row) =>
      row.kind === "cli" &&
      row.metadata?.evidenceType === "cli-command-route" &&
      row.metadata.path === commandPath,
  );
  const positionalRoute = rows.find(
    (row) =>
      row.kind === "cli" &&
      row.metadata?.evidenceType === "cli-positional-route" &&
      row.metadata.commandPath === commandPath,
  );
  return {
    controlDescriptor: {
      kind: positionalRoute && live.sourceRefs.some((sourceRef) =>
        positionalRoute.sourceRefs.includes(sourceRef))
        ? "clap-positional"
        : "clap-command",
      commandPath,
      commandMetadata: structuredClone(commandRoute?.metadata ?? null),
      positionalMetadata: structuredClone(positionalRoute?.metadata ?? null),
    },
    argumentVectors: [{ spelling: commandPath, args: [...template.args] }],
    rejection: template.rejection,
  };
}

function cliControlProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  if (!surfaceObservedKey.startsWith("cli:")) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  if (
    live?.kind !== "cli" ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const selected =
    optionControlDescriptor(live, liveByObservedKey) ??
    commandControlDescriptor(live, liveByObservedKey);
  if (!selected) return null;
  const sourceDescriptor = {
    kind: "closed-cli-control",
    surfaceObservedKey,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(live.metadata),
    controlDescriptor: selected.controlDescriptor,
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "cli",
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "cli-control",
        argumentVectors: selected.argumentVectors,
        expectedRejectionFragments: REJECTION_FRAGMENTS[selected.rejection],
        projectCodePlaceholder: PROJECT_CODE_PLACEHOLDER,
        evaluationMarker: EVALUATION_MARKER,
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function startupEnvironmentProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "startup:env:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const environmentName = surfaceObservedKey.slice(prefix.length);
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  if (
    !environmentName ||
    live?.kind !== "startup" ||
    live.name !== `env:${environmentName}` ||
    live.metadata?.evidenceType !== "static-runtime-environment-control" ||
    canonicalJson(live.metadata.authoredNames) !==
      canonicalJson([environmentName]) ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-startup-environment",
    environmentName,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(live.metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "startup",
      surfaceName: `env:${environmentName}`,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: { kind: "startup-environment", environmentName },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function loaderExecutableKindProbe({
  plan: _plan,
  route: _route,
  liveByObservedKey: _liveByObservedKey,
  coverageByObservedKey: _coverageByObservedKey,
}) {
  // Armed project imports resolve through the authenticated VFS resolver, not
  // the older `resolve_with_oxc` facet named by these inventory rows. Its
  // public error is intentionally normalized, so a failed `.node`/`.wasm`
  // import cannot prove which private branch rejected it. Leave both claims
  // residual until an exact source-bound executor exists.
  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
  return null;
}

function terminalBuiltinImportProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length > 1
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  if (!surfaceObservedKey.startsWith("builtin:")) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const moduleSpecifiers = TERMINAL_BUILTIN_SPECIFIERS.get(
    metadata?.sourceKey,
  );
  if (!moduleSpecifiers) return null;
  const terminalBuiltinRoot = moduleSpecifiers[0]
    .replace(/^node:/u, "")
    .split("/")[0];
  const exportSurface = metadata.surfaceType === "export";
  const expectedSurfaceName = exportSurface
    ? `export:${metadata.sourceKey}:${metadata.exportName}`
    : live.name;
  if (
    live.kind !== "builtin" ||
    live.name !== expectedSurfaceName ||
    live.observedKey !== `builtin:${expectedSurfaceName}` ||
    metadata.importReachability !== "public" ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length !== 1 ||
    (exportSurface
      ? canonicalJson(metadata.publicModuleSpecifiers) !==
        canonicalJson(moduleSpecifiers)
      : metadata.moduleBuiltin !== true ||
        metadata.bundleExternal !== true ||
        !moduleSpecifiers.includes(live.name)) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    (route.alternatives.length === 1 &&
      route.alternatives[0].terminalObservedKey !== surfaceObservedKey)
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-terminal-builtin",
    surfaceObservedKey,
    sourceKey: metadata.sourceKey,
    ...(exportSurface ? { exportName: metadata.exportName } : {}),
    moduleSpecifiers: [...moduleSpecifiers],
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "builtin",
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "terminal-builtin-import",
        terminalBuiltinRoot,
        moduleSpecifiers: [...moduleSpecifiers],
        expectedRejectionFragment: "Import denied:",
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function sqliteExtensionLoadProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const constructorExportName = CLOSED_SQLITE_EXTENSION_EXPORTS.get(
    metadata?.exportName,
  );
  const expectedSourceRef =
    `packages/ibex-runtime-js/src/sqlite/module.js#exports:${metadata?.exportName}`;
  if (
    constructorExportName === undefined ||
    live?.kind !== "builtin" ||
    live.name !== `export:exact_sqlite:${metadata.exportName}` ||
    live.observedKey !== `builtin:${live.name}` ||
    metadata.sourceKey !== "exact_sqlite" ||
    metadata.surfaceType !== "export" ||
    metadata.valueShape !== "callable" ||
    metadata.importReachability !== "public" ||
    canonicalJson(metadata.publicModuleSpecifiers) !==
      canonicalJson(CLOSED_SQLITE_MODULE_SPECIFIERS) ||
    canonicalJson(metadata.moduleSpecifiers) !==
      canonicalJson(CLOSED_SQLITE_MODULE_SPECIFIERS) ||
    canonicalJson(metadata.enforcementRouteEvidence?.terminals) !==
      canonicalJson(["__exactSqliteLoadExtension"]) ||
    canonicalJson(live.sourceRefs) !== canonicalJson([expectedSourceRef]) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    edge.cap !== "ffi:load" ||
    route.alternatives[0].terminalObservedKey !==
      "native-op:__exactSqliteLoadExtension"
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-sqlite-extension-load",
    surfaceObservedKey,
    sourceKey: metadata.sourceKey,
    exportName: metadata.exportName,
    constructorExportName,
    moduleSpecifiers: [...CLOSED_SQLITE_MODULE_SPECIFIERS],
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "builtin",
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "sqlite-extension-load",
        constructorExportName,
        methodName: "loadExtension",
        moduleSpecifiers: [...CLOSED_SQLITE_MODULE_SPECIFIERS],
        databasePath: ":memory:",
        extensionPath: "ibex-capsec-closed-extension",
        expectedRejectionFragment: "Extension loading not supported",
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function sqliteCrSqliteEnableProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== CLOSED_SQLITE_CRSQLITE_TERMINALS.length ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const constructorExportName = CLOSED_SQLITE_CRSQLITE_EXPORTS.get(
    metadata?.exportName,
  );
  const expectedSourceRef =
    `packages/ibex-runtime-js/src/sqlite/module.js#exports:${metadata?.exportName}`;
  const routeTerminals = route.alternatives
    .map((alternative) => alternative.terminalObservedKey)
    .sort();
  const expectedRouteTerminals = CLOSED_SQLITE_CRSQLITE_TERMINALS.map(
    (terminal) => `native-op:${terminal}`,
  ).sort();
  if (
    constructorExportName === undefined ||
    live?.kind !== "builtin" ||
    live.name !== `export:exact_sqlite:${metadata.exportName}` ||
    live.observedKey !== `builtin:${live.name}` ||
    metadata.sourceKey !== "exact_sqlite" ||
    metadata.surfaceType !== "export" ||
    metadata.valueShape !== "callable" ||
    metadata.importReachability !== "public" ||
    canonicalJson(metadata.publicModuleSpecifiers) !==
      canonicalJson(CLOSED_SQLITE_MODULE_SPECIFIERS) ||
    canonicalJson(metadata.moduleSpecifiers) !==
      canonicalJson(CLOSED_SQLITE_MODULE_SPECIFIERS) ||
    canonicalJson(
      [...(metadata.enforcementRouteEvidence?.terminals ?? [])].sort(),
    ) !==
      canonicalJson([...CLOSED_SQLITE_CRSQLITE_TERMINALS].sort()) ||
    canonicalJson(live.sourceRefs) !== canonicalJson([expectedSourceRef]) ||
    canonicalJson(routeTerminals) !== canonicalJson(expectedRouteTerminals) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    edge.cap !== "ffi:load"
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-sqlite-crsqlite-enable",
    surfaceObservedKey,
    sourceKey: metadata.sourceKey,
    exportName: metadata.exportName,
    constructorExportName,
    moduleSpecifiers: [...CLOSED_SQLITE_MODULE_SPECIFIERS],
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "builtin",
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "sqlite-cr-sqlite-enable",
        constructorExportName,
        methodName: "enableCrSqlite",
        moduleSpecifiers: [...CLOSED_SQLITE_MODULE_SPECIFIERS],
        databasePath: ":memory:",
        expectedRejectionFragment:
          "cr-sqlite extension not available. The Ibex runtime must be built with cr-sqlite support.",
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function debuggerAbiDisabledProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
  target,
}) {
  if (
    !EXACT_RUNTIME_CANDIDATE_TRIPLES.has(target?.triple) ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const hostAbi = surfaceObservedKey.startsWith("host-abi:");
  const nativePrefix = "native-op:inspector.debugger-";
  const selected = hostAbi
    ? [...DEBUGGER_ABI_FUNCTIONS].find(
        ([, [functionName]]) =>
          surfaceObservedKey === `host-abi:${functionName}`,
      )
    : surfaceObservedKey.startsWith(nativePrefix)
      ? [
          surfaceObservedKey.slice(nativePrefix.length),
          DEBUGGER_ABI_FUNCTIONS.get(
            surfaceObservedKey.slice(nativePrefix.length),
          ),
        ]
      : null;
  if (!selected) return null;
  const [operationSlug, operation] = selected;
  if (!operation) return null;
  const [functionName, expectedCallResult] = operation;
  const defaultSourceRef =
    `src/engine/hermes_runtime_debugger.cc#${functionName}`;
  const windowsSourceRef =
    `src/engine/hermes_runtime_platform_windows.cc#${functionName}`;
  if (
    !live ||
    live.observedKey !== surfaceObservedKey ||
    !new Set(["host-abi", "native-op"]).has(live.kind) ||
    canonicalJson(live.sourceRefs) !==
      canonicalJson([defaultSourceRef, windowsSourceRef]) ||
    (hostAbi
      ? live.name !== functionName ||
        canonicalJson(
          live.metadata?.definitions?.map((definition) => [
            definition.targetVariant,
            definition.sourceRef,
          ]),
        ) !==
          canonicalJson([
            ["default", defaultSourceRef],
            ["windows", windowsSourceRef],
          ])
      : live.name !== `inspector.debugger-${operationSlug}` ||
        live.metadata != null) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const selectedSourceRef =
    target.triple === "x86_64-pc-windows-msvc"
      ? windowsSourceRef
      : defaultSourceRef;
  const sourceDescriptor = {
    kind: "closed-debugger-abi",
    surfaceObservedKey,
    functionName,
    selectedSourceRef,
    targetTriple: target.triple,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(live.metadata ?? null),
  };
  const expectedError =
    `debugger ABI ${functionName} is unavailable in the no-debugger exact target`;
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: live.kind,
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "debugger-abi-disabled",
        functionName,
        expectedCallResult,
        expectedError,
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function sharedRuntimeGlobalAbsenceProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
  target,
}) {
  if (
    !EXACT_RUNTIME_CANDIDATE_TRIPLES.has(target?.triple) ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "native-op:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const surfaceName = surfaceObservedKey.slice(prefix.length);
  if (!reviewedSharedRuntimeAbsentSurface(surfaceName)) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const branches = metadata?.installationBranches;
  const sharedRuntimeInstallation = metadata?.sourceKey === "shared_runtime";
  const reviewedSharedRuntimeBranch =
    branches?.[0]?.route === "shared-runtime" &&
    branches[0].targetVariant === "all";
  const reviewedComposedSharedRuntimeBranch =
    branches?.[0]?.route === "composed:legacy-bootstrap+shared-runtime" &&
    branches[0].targetVariant === "default" &&
    canonicalJson(branches[0].routes) ===
      canonicalJson(["legacy-bootstrap", "shared-runtime"]);
  const reviewedInstallation =
    Array.isArray(branches) &&
    branches.length === 1 &&
    canonicalJson(branches[0].sourceRefs) === canonicalJson(live?.sourceRefs) &&
    (sharedRuntimeInstallation
      ? reviewedSharedRuntimeBranch || reviewedComposedSharedRuntimeBranch
      : branches[0].route === "legacy-bootstrap" &&
        branches[0].targetVariant === "default");
  const expectedExportName =
    metadata?.memberName == null
      ? metadata?.globalName
      : `${metadata?.globalName}.${metadata?.memberName}`;
  if (
    live?.kind !== "native-op" ||
    live.name !== surfaceName ||
    metadata?.surfaceType !== "global-api" ||
    typeof metadata.globalName !== "string" ||
    !["string", "object"].includes(typeof metadata.memberName) ||
    (metadata.memberName !== null && typeof metadata.memberName !== "string") ||
    metadata.exportName !== expectedExportName ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    !reviewedInstallation ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-shared-runtime-global-absence",
    surfaceObservedKey,
    globalName: metadata.globalName,
    ...(metadata.memberName === null
      ? {}
      : { memberName: metadata.memberName }),
    targetTriple: target.triple,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(metadata),
  };
  const expectedError =
    `armed shared runtime does not expose ${metadata.exportName}`;
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "native-op",
      surfaceName,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "shared-runtime-global-absence",
        globalName: metadata.globalName,
        memberName: metadata.memberName,
        expectedError,
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function armedNativeGlobalAbsenceProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
  target,
}) {
  if (
    !EXACT_RUNTIME_CANDIDATE_TRIPLES.has(target?.triple) ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "native-op:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const surfaceName = surfaceObservedKey.slice(prefix.length);
  const directArmedGlobal = reviewedArmedNativeAbsentSurface(surfaceName);
  const appRuntimeAbsentWorkletGlobal =
    APP_RUNTIME_ABSENT_WORKLET_GLOBALS.has(surfaceName);
  if (!directArmedGlobal && !appRuntimeAbsentWorkletGlobal) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const branches = metadata?.installationBranches;
  const publicInvocation = metadata?.publicInvocation;
  const defaultBranch = branches?.find(
    (branch) =>
      branch.route === "native-jsi-global" &&
      branch.targetVariant === "default",
  );
  const workletBranch = branches?.find(
    (branch) =>
      ["evaluated-native-script", "native-jsi-global"].includes(
        branch.route,
      ) &&
      branch.targetVariant === "worklet",
  );
  const globalName = metadata?.globalName;
  const expectedExportName =
    metadata?.memberName == null
      ? globalName
      : `${globalName}.${metadata.memberName}`;
  const reviewedDirectGlobal =
    directArmedGlobal &&
    metadata?.sourceKey === "native_jsi_global" &&
    globalName === surfaceName &&
    metadata?.memberName === null &&
    canonicalJson(metadata?.memberKinds) === canonicalJson(["native-root"]) &&
    publicInvocation?.kind === "native-global-function" &&
    publicInvocation.globalName === globalName &&
    Number.isSafeInteger(publicInvocation.arity) &&
    publicInvocation.arity >= 0 &&
    typeof publicInvocation.sourceRef === "string" &&
    defaultBranch?.sourceRefs.includes(publicInvocation.sourceRef);
  const reviewedWorkletGlobal =
    appRuntimeAbsentWorkletGlobal &&
    `global:${expectedExportName}` === surfaceName &&
    Array.isArray(branches) &&
    branches.length === 1 &&
    canonicalJson(workletBranch?.sourceRefs) === canonicalJson(live?.sourceRefs) &&
    (metadata?.sourceKey === "native_jsi_global"
      ? workletBranch?.route === "native-jsi-global" &&
        canonicalJson(metadata?.memberKinds) ===
          canonicalJson([
            metadata?.memberName === null
              ? "native-root"
              : "native-object-member",
          ])
      : metadata?.sourceKey === "evaluated_native_script" &&
        workletBranch?.route === "evaluated-native-script" &&
        metadata.evaluatedScript === "kPrelude" &&
        canonicalJson(metadata.sourceUrls) ===
          canonicalJson(["worklet-prelude.js"]));
  if (
    live?.kind !== "native-op" ||
    live.name !== surfaceName ||
    metadata?.surfaceType !== "global-api" ||
    metadata?.exportName !== expectedExportName ||
    (!reviewedDirectGlobal && !reviewedWorkletGlobal) ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    !Array.isArray(branches) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-armed-native-global-absence",
    surfaceObservedKey,
    globalName,
    ...(metadata.memberName === null
      ? {}
      : { memberName: metadata.memberName }),
    targetTriple: target.triple,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(metadata),
  };
  const expectedError = `armed runtime does not expose ${expectedExportName}`;
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "native-op",
      surfaceName,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "armed-native-global-absence",
        globalName,
        memberName: metadata.memberName,
        expectedError,
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

export function authoredClosedPublicProbe(options) {
  const { plan, scenario } = options;
  if (
    plan.classification !== "closed" ||
    scenario !== "closed" ||
    plan.expectedObservation?.kind !== "enforcement-branch" ||
    plan.edgeIds.length !== 1 ||
    plan.actionIds.length !== 0
  ) {
    return null;
  }
  return (
    startupEnvironmentProbe(options) ??
    cliControlProbe(options) ??
    exactUnendowedOperationProbe(options) ??
    tamedEvaluatorProbe(options) ??
    moduleRunnerNamespaceProbe(options) ??
    loaderExecutableKindProbe(options) ??
    sqliteExtensionLoadProbe(options) ??
    sqliteCrSqliteEnableProbe(options) ??
    terminalBuiltinImportProbe(options) ??
    debuggerAbiDisabledProbe(options) ??
    armedNativeGlobalAbsenceProbe(options) ??
    sharedRuntimeGlobalAbsenceProbe(options)
  );
}

export const closedBatchCommand = CLOSED_BATCH_COMMAND;
