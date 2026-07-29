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
import { capsecSecureCargoTestCommand } from "./capsec-secure-test-command.mjs";

const CLOSED_BATCH_COMMAND = Object.freeze(
  capsecSecureCargoTestCommand("capsec_public_closed_recipe_batch"),
);

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
    "node_diagnostics_channel",
    ["diagnostics_channel", "node:diagnostics_channel"],
  ],
  ["node_domain", ["domain", "node:domain"]],
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
  "__exactMemoryDebug",
  "__exactMemoryDebug.clearModuleDebugSources",
  "__exactMemoryDebug.formatBytes",
  "__exactMemoryDebug.samples",
  "__exactMemoryDebug.snapshot",
  "__exactMemoryDebug.start",
  "__exactMemoryDebug.state",
  "__exactMemoryDebug.stop",
  "__exactMemoryDebug.summary",
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
  "global:Bun.inspect",
  "global:Exact.gc",
  "global:Exact.inspect",
  "global:process.__exactAsyncIpcListenerPatch",
  "global:process.__exactLateIpcListenerPatch",
  "global:process.__exactProcessIpcBootstrapInstalled",
  "global:process.__exactStreamPinned",
  "global:process.__exactStreamStabilityPatched",
  "global:process._uncaughtExceptionHandler",
  "global:process._unhandledRejectionHandler",
  "global:process._umask",
  "global:process.domain",
]);

const REVIEWED_POSIX_PROCESS_HANDLER_ALIASES = new Set([
  "global:process._uncaughtExceptionHandler",
  "global:process._unhandledRejectionHandler",
]);

const EXACT_RUNTIME_CANDIDATE_TRIPLES = new Set([
  "aarch64-apple-darwin",
  "x86_64-pc-windows-msvc",
]);

const PROCESS_EVENT_METHOD_ARGUMENT_SHAPES = new Map([
  ["addListener", "event-listener"],
  ["emit", "event"],
  ["emitWarning", "warning"],
  ["eventNames", "none"],
  ["getMaxListeners", "none"],
  ["hasUncaughtExceptionCaptureCallback", "none"],
  ["listenerCount", "event"],
  ["listeners", "event"],
  ["off", "event-listener"],
  ["on", "event-listener"],
  ["once", "event-listener"],
  ["prependListener", "event-listener"],
  ["prependOnceListener", "event-listener"],
  ["rawListeners", "event"],
  ["removeAllListeners", "event"],
  ["removeListener", "event-listener"],
  ["setMaxListeners", "listener-limit"],
  ["setUncaughtExceptionCaptureCallback", "null-capture-callback"],
]);
const PROCESS_EVENT_ENFORCEMENT_SOURCE_REF =
  "src/engine/hermes_runtime.cc#armed-process-event-methods";
const PROCESS_SHARED_STATE_ENFORCEMENT_SOURCE_REF =
  "src/engine/hermes_runtime.cc#armed-process-shared-state-members";
const CLOSED_PROCESS_REPORT_MEMBERS = new Map([
  ["compact", "data"],
  ["directory", "data"],
  ["filename", "data"],
  ["getReport", "callable"],
  ["reportOnFatalError", "data"],
  ["reportOnSignal", "data"],
  ["reportOnUncaughtException", "data"],
  ["signal", "data"],
  ["writeReport", "callable"],
]);
const CLOSED_PROCESS_SHARED_STATE_MEMBERS = new Map([
  [
    "_getActiveHandles",
    {
      memberForm: "method",
      permission: "ProcessInspection",
      cap: "runtime:inspect",
    },
  ],
  [
    "_getActiveRequests",
    {
      memberForm: "method",
      permission: "ProcessInspection",
      cap: "runtime:inspect",
    },
  ],
  [
    "_kill",
    {
      memberForm: "method",
      permission: "ProcessSignals",
      cap: "process:signal",
    },
  ],
  [
    "abort",
    {
      memberForm: "method",
      permission: "ProcessLifecycle",
      cap: "process:signal",
    },
  ],
  [
    "binding",
    {
      memberForm: "method",
      permission: "ProcessBinding",
      cap: "ffi:load",
    },
  ],
  [
    "kill",
    {
      memberForm: "method",
      permission: "ProcessSignals",
      cap: "process:signal",
    },
  ],
  [
    "setegid",
    {
      memberForm: "method",
      permission: "ProcessCredentials",
      cap: "process:identity",
    },
  ],
  [
    "seteuid",
    {
      memberForm: "method",
      permission: "ProcessCredentials",
      cap: "process:identity",
    },
  ],
  [
    "setgid",
    {
      memberForm: "method",
      permission: "ProcessCredentials",
      cap: "process:identity",
    },
  ],
  [
    "setuid",
    {
      memberForm: "method",
      permission: "ProcessCredentials",
      cap: "process:identity",
    },
  ],
  [
    "title",
    {
      memberForm: "property",
      permission: "ProcessTitle",
      cap: "runtime:inspect",
    },
  ],
  [
    "report",
    {
      memberForm: "property",
      permission: "ProcessReport",
      cap: "runtime:inspect",
    },
  ],
]);
const PROCESS_LIFECYCLE_RESULT_KINDS = new Map([
  ["addListener", "process"],
  ["listenerCount", "zero"],
  ["listeners", "empty-array"],
  ["off", "process"],
  ["on", "process"],
  ["once", "process"],
  ["prependListener", "process"],
  ["prependOnceListener", "process"],
  ["rawListeners", "empty-array"],
  ["removeAllListeners", "process"],
  ["removeListener", "process"],
]);

const CLOSED_FS_BUILTIN_INVOCATION_SHAPES = new Map([
  ["chmod", ["chmod", "path-mode"]],
  ["chown", ["chown", "path-owner"]],
  ["copyfile", ["copyfile", "two-paths"]],
  ["cp", ["cp", "two-paths"]],
  ["fchmod", ["fchmod", "descriptor-mode"]],
  ["fchown", ["fchown", "descriptor-owner"]],
  ["futimes", ["futimes", "descriptor-times"]],
  ["lchmod", ["lchmod", "path-mode"]],
  ["lchown", ["lchown", "path-owner"]],
  ["link", ["link", "two-paths"]],
  ["lutimes", ["lutimes", "path-times"]],
  ["mkdtemp", ["mkdtemp", "path-prefix"]],
  ["mkdtempdisposable", ["mkdtemp", "path-prefix"]],
  ["rename", ["rename", "two-paths"]],
  ["rm", ["rm", "path"]],
  ["rmdir", ["rmdir", "path"]],
  ["symlink", ["symlink", "two-paths"]],
  ["unlink", ["unlink", "path"]],
  ["utimes", ["utime", "path-times"]],
  ["watch", ["watch", "path"]],
  ["watchfile", ["watchFile", "path"]],
]);

const CLOSED_FS_FILE_HANDLE_INVOCATION_SHAPES = new Map([
  ["chmod", ["fchmod", "filehandle-mode"]],
  ["chown", ["fchown", "filehandle-owner"]],
  ["utimes", ["futimes", "filehandle-times"]],
]);

const CLOSED_FS_NATIVE_INVOCATION_SHAPES = new Map([
  ["__exactChmod", ["chmod", "path-mode"]],
  ["__exactChown", ["chown", "path-owner"]],
  ["__exactCopyFile", ["copyfile", "two-paths"]],
  ["__exactFsFchmod", ["fchmod", "descriptor-mode"]],
  ["__exactFsFchmodSync", ["fchmod", "descriptor-mode"]],
  ["__exactFsFchown", ["fchown", "descriptor-owner"]],
  ["__exactFsFchownSync", ["fchown", "descriptor-owner"]],
  ["__exactFsFutimesSync", ["futimes", "descriptor-times"]],
  ["__exactLchmod", ["lchmod", "path-mode"]],
  ["__exactLchmodSync", ["lchmod", "path-mode"]],
  ["__exactLchown", ["lchown", "path-owner"]],
  ["__exactLink", ["link", "two-paths"]],
  ["__exactLutimes", ["lutimes", "path-times"]],
  ["__exactLutimesSync", ["lutimes", "path-times"]],
  ["__exactMkdtemp", ["mkdtemp", "path-prefix"]],
  ["__exactRename", ["rename", "two-paths"]],
  ["__exactRmdir", ["rmdir", "path"]],
  ["__exactSymlink", ["symlink", "two-paths"]],
  ["__exactUnlink", ["unlink", "path"]],
  ["__exactUtimes", ["utime", "path-times"]],
]);

const CLOSED_FS_DISPATCHER_INVOCATION_SHAPES = new Map([
  [
    "__exactFsPathAsync",
    new Map([
      ["chmod-windows", ["chmod", "path-dispatcher"]],
      ["chown", ["chown", "path-dispatcher"]],
      ["copyfile", ["copyfile", "path-dispatcher"]],
      ["copyfile-excl", ["copyfile_excl", "path-dispatcher"]],
      ["lchmod", ["lchmod", "path-dispatcher"]],
      ["lchown", ["lchown", "path-dispatcher"]],
      ["link", ["link", "path-dispatcher"]],
      ["lutime", ["lutime", "path-dispatcher"]],
      ["mkdir-recursive", ["mkdir", "path-dispatcher-recursive"]],
      ["mkdtemp", ["mkdtemp", "path-dispatcher"]],
      ["rename", ["rename", "path-dispatcher"]],
      ["rmdir", ["rmdir", "path-dispatcher"]],
      ["symlink", ["symlink", "path-dispatcher"]],
      ["unlink", ["unlink", "path-dispatcher"]],
      ["utime-windows", ["utime", "path-dispatcher"]],
    ]),
  ],
  [
    "__exactFsFdAsync",
    new Map([
      ["fchmod", ["fchmod", "descriptor-dispatcher"]],
      ["fchown", ["fchown", "descriptor-dispatcher"]],
      ["futimes", ["futimes", "descriptor-dispatcher"]],
    ]),
  ],
  [
    "__exactMkdir",
    new Map([
      ["recursive", ["mkdir", "recursive-mkdir"]],
    ]),
  ],
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
  const reviewedComposedEvaluatedLegacyBranch =
    metadata?.sourceKey === "evaluated_native_script" &&
    branches?.[0]?.route ===
      "composed:evaluated-native-script+legacy-bootstrap" &&
    branches[0].targetVariant === "default" &&
    canonicalJson(branches[0].routes) ===
      canonicalJson(["evaluated-native-script", "legacy-bootstrap"]) &&
    canonicalJson(metadata.sourceKeys) ===
      canonicalJson(["evaluated_native_script", "global_compat_polyfills"]);
  const reviewedPosixProcessHandlerBranch =
    REVIEWED_POSIX_PROCESS_HANDLER_ALIASES.has(surfaceName) &&
    target.triple === "aarch64-apple-darwin" &&
    metadata?.sourceKey === "global_stream_enhance" &&
    branches?.[0]?.route === "legacy-bootstrap" &&
    branches[0].targetVariant === "posix" &&
    canonicalJson(branches[0].routes) === canonicalJson(["legacy-bootstrap"]);
  const reviewedInstallation =
    Array.isArray(branches) &&
    branches.length === 1 &&
    canonicalJson(branches[0].sourceRefs) === canonicalJson(live?.sourceRefs) &&
    (sharedRuntimeInstallation
      ? reviewedSharedRuntimeBranch || reviewedComposedSharedRuntimeBranch
      : reviewedComposedEvaluatedLegacyBranch ||
        reviewedPosixProcessHandlerBranch ||
        (branches[0].route === "legacy-bootstrap" &&
          branches[0].targetVariant === "default"));
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

function processEventClosureProbe({
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
  const prefix = "native-op:global:process.";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const methodName = surfaceObservedKey.slice(prefix.length);
  const argumentShape = PROCESS_EVENT_METHOD_ARGUMENT_SHAPES.get(methodName);
  if (!argumentShape) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const selectedBranches = metadata?.installationBranches?.filter((branch) =>
    plan.implementationBranchIds.some((branchId) =>
      branchId.endsWith(`.${branch.id}`),
    ),
  );
  if (
    live?.kind !== "native-op" ||
    live.name !== `global:process.${methodName}` ||
    metadata?.surfaceType !== "global-api" ||
    metadata.globalName !== "process" ||
    metadata.memberName !== methodName ||
    metadata.exportName !== `process.${methodName}` ||
    (metadata.valueShape !== "callable" &&
      !metadata.memberKinds?.includes("prototype-method")) ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    !Array.isArray(selectedBranches) ||
    selectedBranches.length !== 1 ||
    selectedBranches[0].sourceRefs.some(
      (sourceRef) => !live.sourceRefs.includes(sourceRef),
    ) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    !new Set(["runtime:inspect", "ipc:channel"]).has(edge.cap) ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-process-event-method",
    surfaceObservedKey,
    globalName: "process",
    memberName: methodName,
    argumentShape,
    targetTriple: target.triple,
    implementationBranchIds: structuredClone(plan.implementationBranchIds),
    enforcementBranchIds: structuredClone(plan.enforcementBranchIds),
    enforcementSourceRef: PROCESS_EVENT_ENFORCEMENT_SOURCE_REF,
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
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "process-event-closure",
        methodName,
        argumentShape,
        eventName:
          argumentShape === "event" || argumentShape === "event-listener"
            ? "ibex-capsec-shared-event"
            : null,
        expectedErrorCode: "ERR_ACCESS_DENIED",
        expectedPermission: "ProcessEvents",
        expectedError:
          `process.${methodName} is disabled for this event in an armed runtime`,
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function processUmaskClosureProbe({
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
  if (surfaceObservedKey !== "native-op:global:process.umask") return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const selectedBranches = metadata?.installationBranches?.filter((branch) =>
    plan.implementationBranchIds.some((branchId) =>
      branchId.endsWith(`.${branch.id}`),
    ),
  );
  if (
    live?.kind !== "native-op" ||
    live.name !== "global:process.umask" ||
    metadata?.surfaceType !== "global-api" ||
    metadata.globalName !== "process" ||
    metadata.memberName !== "umask" ||
    metadata.exportName !== "process.umask" ||
    metadata.valueShape !== "callable" ||
    canonicalJson(metadata.memberKinds) !==
      canonicalJson(["instance-property", "member-assignment"]) ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    !Array.isArray(selectedBranches) ||
    selectedBranches.length !== 1 ||
    selectedBranches[0].sourceRefs.some(
      (sourceRef) => !live.sourceRefs.includes(sourceRef),
    ) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    edge.cap !== "process:umask" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-process-umask",
    surfaceObservedKey,
    globalName: "process",
    memberName: "umask",
    targetTriple: target.triple,
    implementationBranchIds: structuredClone(plan.implementationBranchIds),
    enforcementBranchIds: structuredClone(plan.enforcementBranchIds),
    enforcementSourceRef: PROCESS_EVENT_ENFORCEMENT_SOURCE_REF,
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
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "process-umask-closure",
        argumentCases: [
          { id: "read", arguments: [] },
          { id: "write", arguments: [0] },
        ],
        expectedErrorCode: "ERR_ACCESS_DENIED",
        expectedPermission: "ProcessUmask",
        expectedError: "process.umask is disabled in an armed runtime",
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function processSharedStateClosureProbe({
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
  const prefix = "native-op:global:process.";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const memberName = surfaceObservedKey.slice(prefix.length);
  const reviewed = CLOSED_PROCESS_SHARED_STATE_MEMBERS.get(memberName);
  if (!reviewed) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const selectedBranches = metadata?.installationBranches?.filter((branch) =>
    plan.implementationBranchIds.some((branchId) =>
      branchId.endsWith(`.${branch.id}`),
    ),
  );
  const sourceShapeMatches =
    reviewed.memberForm === "method"
      ? metadata?.valueShape === "callable" &&
        metadata.memberKinds?.includes("prototype-method")
      : memberName === "title"
        ? metadata?.memberKinds?.includes("prototype-accessor")
        : canonicalJson(metadata?.memberKinds) ===
          canonicalJson(["instance-property", "member-assignment"]);
  if (
    live?.kind !== "native-op" ||
    live.name !== `global:process.${memberName}` ||
    metadata?.surfaceType !== "global-api" ||
    metadata.globalName !== "process" ||
    metadata.memberName !== memberName ||
    metadata.exportName !== `process.${memberName}` ||
    !sourceShapeMatches ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    !Array.isArray(selectedBranches) ||
    selectedBranches.length !== 1 ||
    selectedBranches[0].sourceRefs.some(
      (sourceRef) => !live.sourceRefs.includes(sourceRef),
    ) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    edge.cap !== reviewed.cap ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-process-shared-state-member",
    surfaceObservedKey,
    globalName: "process",
    memberName,
    memberForm: reviewed.memberForm,
    targetTriple: target.triple,
    implementationBranchIds: structuredClone(plan.implementationBranchIds),
    enforcementBranchIds: structuredClone(plan.enforcementBranchIds),
    enforcementSourceRef: PROCESS_SHARED_STATE_ENFORCEMENT_SOURCE_REF,
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
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "process-shared-state-closure",
        memberName,
        memberForm: reviewed.memberForm,
        accessCases:
          reviewed.memberForm === "method"
            ? ["direct", "prototype", "replacement"]
            : memberName === "title"
              ? [
                  "read",
                  "write",
                  "prototype-read",
                  "prototype-write",
                  "replacement-read",
                ]
              : ["read", "write", "replacement-read"],
        expectedErrorCode: "ERR_ACCESS_DENIED",
        expectedPermission: reviewed.permission,
        expectedError:
          `process.${memberName} is disabled in an armed runtime`,
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function processReportMemberClosureProbe({
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
  const prefix = "native-op:global:process.report.";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const reportMemberName = surfaceObservedKey.slice(prefix.length);
  const memberForm = CLOSED_PROCESS_REPORT_MEMBERS.get(reportMemberName);
  if (!memberForm) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const selectedBranches = metadata?.installationBranches?.filter((branch) =>
    plan.implementationBranchIds.some((branchId) =>
      branchId.endsWith(`.${branch.id}`),
    ),
  );
  if (
    live?.kind !== "native-op" ||
    live.name !== `global:process.report.${reportMemberName}` ||
    metadata?.surfaceType !== "global-api" ||
    metadata.globalName !== "process" ||
    metadata.memberName !== `report.${reportMemberName}` ||
    metadata.exportName !== `process.report.${reportMemberName}` ||
    canonicalJson(metadata.memberKinds) !==
      canonicalJson(["source-derived-member"]) ||
    metadata.valueShape !== memberForm ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    !Array.isArray(selectedBranches) ||
    selectedBranches.length !== 1 ||
    selectedBranches[0].sourceRefs.some(
      (sourceRef) => !live.sourceRefs.includes(sourceRef),
    ) ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    edge.cap !== "runtime:inspect" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-process-report-member",
    surfaceObservedKey,
    globalName: "process",
    memberName: reportMemberName,
    memberPath: ["report", reportMemberName],
    memberForm,
    blockedAtMember: "report",
    targetTriple: target.triple,
    implementationBranchIds: structuredClone(plan.implementationBranchIds),
    enforcementBranchIds: structuredClone(plan.enforcementBranchIds),
    enforcementSourceRef: PROCESS_SHARED_STATE_ENFORCEMENT_SOURCE_REF,
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
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "process-report-member-closure",
        memberName: reportMemberName,
        memberPath: ["report", reportMemberName],
        memberForm,
        blockedAtMember: "report",
        accessCases:
          memberForm === "callable"
            ? ["read", "call", "replacement-read"]
            : ["read", "write", "replacement-read"],
        expectedErrorCode: "ERR_ACCESS_DENIED",
        expectedPermission: "ProcessReport",
        expectedError: "process.report is disabled in an armed runtime",
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
  const directBranch = branches?.find(
    (branch) =>
      branch.route === "native-jsi-global" &&
      (branch.targetVariant === "default" ||
        (branch.targetVariant === "posix" &&
          target.triple !== "x86_64-pc-windows-msvc")),
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
    directBranch?.sourceRefs.includes(publicInvocation.sourceRef);
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

function filesystemMutationProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
  target,
}) {
  if (
    !EXACT_RUNTIME_CANDIDATE_TRIPLES.has(target?.triple) ||
    route.surfaceObservedKeys.length !== 1
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const selectedLogicalBranch = edge?.logicalBranches?.find((branch) =>
    plan.fixtureId.includes(`.logical.${branch.id}.`),
  );
  const closureCap =
    selectedLogicalBranch?.disposition === "closed"
      ? selectedLogicalBranch.cap
      : edge?.classification === "closed"
        ? edge.cap
        : null;
  if (
    edge?.id !== plan.edgeIds[0] ||
    closureCap !== "fs:unbound-mutation" ||
    !Array.isArray(live?.sourceRefs) ||
    live.sourceRefs.length === 0
  ) {
    return null;
  }

  let surfaceForm;
  let guardOperation;
  let argumentShape;
  let invocationStyle;
  let sourceKey;
  let exportName;
  let moduleSpecifier;
  let nativeName;
  if (live.kind === "builtin") {
    sourceKey = live.metadata?.sourceKey;
    exportName = live.metadata?.exportName;
    if (
      live.metadata?.surfaceType !== "export" ||
      !["node_fs", "node_fs_promises"].includes(sourceKey) ||
      typeof exportName !== "string" ||
      live.name !== `export:${sourceKey}:${exportName}`
    ) {
      return null;
    }
    const nestedExport = exportName.toLowerCase();
    const normalizedExport = nestedExport
      .replace(/^filehandle\./u, "")
      .replace(/sync$/u, "");
    const fileHandle = nestedExport.startsWith("filehandle.");
    const shape = fileHandle
      ? CLOSED_FS_FILE_HANDLE_INVOCATION_SHAPES.get(normalizedExport)
      : CLOSED_FS_BUILTIN_INVOCATION_SHAPES.get(normalizedExport);
    if (!shape) return null;
    [guardOperation, argumentShape] = shape;
    surfaceForm = "builtin-export";
    moduleSpecifier =
      sourceKey === "node_fs" ? "node:fs" : "node:fs/promises";
    if (
      !live.metadata.publicModuleSpecifiers?.includes(moduleSpecifier)
    ) {
      return null;
    }
    invocationStyle = fileHandle
      ? "file-handle-promise"
      : sourceKey === "node_fs_promises"
        ? "promise"
        : normalizedExport === "mkdtempdisposable" &&
            !nestedExport.endsWith("sync")
          ? "callback-deferred"
        : ["watch", "watchfile"].includes(normalizedExport)
          ? "sync-listener"
          : nestedExport.endsWith("sync")
            ? "sync"
            : "callback";
  } else if (live.kind === "native-op") {
    const dispatcherShape =
      selectedLogicalBranch?.disposition === "closed"
        ? CLOSED_FS_DISPATCHER_INVOCATION_SHAPES.get(live.name)?.get(
            selectedLogicalBranch.id,
          )
        : null;
    const shape =
      dispatcherShape ?? CLOSED_FS_NATIVE_INVOCATION_SHAPES.get(live.name);
    if (
      !shape ||
      route.alternatives.length !== 1 ||
      route.ambiguousCallees.length !== 0 ||
      route.alternatives[0].terminalObservedKey !== surfaceObservedKey
    ) {
      return null;
    }
    [guardOperation, argumentShape] = shape;
    surfaceForm = dispatcherShape ? "native-dispatcher" : "native-global";
    invocationStyle = "sync";
    nativeName = live.name;
  } else {
    return null;
  }

  // @ref LLP 0023#41-the-v1-mutation-surface-small-object-bound-and-completely-specified — closure evidence binds the public spelling while the production refusal remains before lookup and mutation.
  const sourceDescriptor = {
    kind: "closed-filesystem-unbound-mutation",
    surfaceObservedKey,
    targetTriple: target.triple,
    surfaceForm,
    ...(sourceKey === undefined ? {} : { sourceKey }),
    ...(exportName === undefined ? {} : { exportName }),
    ...(moduleSpecifier === undefined ? {} : { moduleSpecifier }),
    ...(nativeName === undefined ? {} : { functionName: nativeName }),
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(live.metadata ?? {}),
  };
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
        kind: "filesystem-unbound-mutation",
        targetTriple: target.triple,
        surfaceForm,
        ...(sourceKey === undefined ? {} : { sourceKey }),
        ...(exportName === undefined ? {} : { exportName }),
        ...(moduleSpecifier === undefined ? {} : { moduleSpecifier }),
        ...(nativeName === undefined ? {} : { nativeName }),
        invocationStyle,
        guardOperation,
        argumentShape,
        expectedErrorCode: "EPERM",
        expectedErrorFragment: "operation not permitted",
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

function processLifecycleNoEffectProbe({
  plan,
  scenario,
  route,
  liveByObservedKey,
  coverageByObservedKey,
  coverageByEdge,
  target,
}) {
  if (
    !["branch-selection", "no-effect"].includes(scenario) ||
    !EXACT_RUNTIME_CANDIDATE_TRIPLES.has(target?.triple) ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "native-op:global:process.";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const methodName = surfaceObservedKey.slice(prefix.length);
  const argumentShape = PROCESS_EVENT_METHOD_ARGUMENT_SHAPES.get(methodName);
  const expectedReturnKind = PROCESS_LIFECYCLE_RESULT_KINDS.get(methodName);
  if (!argumentShape || !expectedReturnKind) return null;
  const edge = coverageByEdge.get(plan.edgeIds[0]);
  const logicalBranch = edge?.logicalBranches?.find((branch) =>
    plan.fixtureId.endsWith(`.logical.${branch.id}.${scenario}`),
  );
  const eventName = new Map([
    ["before-exit", "beforeExit"],
    ["exit", "exit"],
  ]).get(logicalBranch?.id);
  const live = liveByObservedKey.get(surfaceObservedKey);
  const observedEdge = coverageByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const selectedBranches = metadata?.installationBranches?.filter((branch) =>
    plan.implementationBranchIds.some((branchId) =>
      branchId.endsWith(`.${branch.id}`),
    ),
  );
  if (
    eventName === undefined ||
    logicalBranch.disposition !== "no-effect" ||
    canonicalJson(logicalBranch.when) !==
      canonicalJson([
        {
          fact: "process.listener.event",
          equals: logicalBranch.id,
        },
      ]) ||
    live?.kind !== "native-op" ||
    live.name !== `global:process.${methodName}` ||
    metadata?.surfaceType !== "global-api" ||
    metadata.globalName !== "process" ||
    metadata.memberName !== methodName ||
    metadata.exportName !== `process.${methodName}` ||
    !metadata.memberKinds?.includes("prototype-method") ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    !Array.isArray(selectedBranches) ||
    selectedBranches.length !== 1 ||
    selectedBranches[0].sourceRefs.some(
      (sourceRef) => !live.sourceRefs.includes(sourceRef),
    ) ||
    observedEdge?.id !== edge.id ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const selectedLogicalBranch = structuredClone(logicalBranch);
  const sourceDescriptor = {
    kind: "closed-process-lifecycle-no-effect",
    surfaceObservedKey,
    globalName: "process",
    memberName: methodName,
    argumentShape,
    targetTriple: target.triple,
    implementationBranchIds: structuredClone(plan.implementationBranchIds),
    enforcementBranchIds: structuredClone(plan.enforcementBranchIds),
    enforcementSourceRef: PROCESS_EVENT_ENFORCEMENT_SOURCE_REF,
    selectedLogicalBranch,
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
      surfaceName: live.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "process-event-lifecycle-no-effect",
        scenario,
        methodName,
        argumentShape,
        eventName,
        logicalBranchId: logicalBranch.id,
        expectedReturnKind,
      },
      expectedResult: "no-effect",
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
    !["closed", "branch-selection", "no-effect"].includes(scenario) ||
    plan.expectedObservation?.kind !== "enforcement-branch" ||
    plan.edgeIds.length !== 1 ||
    plan.actionIds.length !== 0
  ) {
    return null;
  }
  const lifecycleNoEffect = processLifecycleNoEffectProbe(options);
  if (lifecycleNoEffect) return lifecycleNoEffect;
  if (scenario !== "closed") return null;
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
    processUmaskClosureProbe(options) ??
    processEventClosureProbe(options) ??
    processSharedStateClosureProbe(options) ??
    processReportMemberClosureProbe(options) ??
    armedNativeGlobalAbsenceProbe(options) ??
    sharedRuntimeGlobalAbsenceProbe(options) ??
    filesystemMutationProbe(options)
  );
}

export const closedBatchCommand = CLOSED_BATCH_COMMAND;
