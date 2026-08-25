/**
 * Generate the reviewed host-task ingress inventory required by LLP 0002.
 *
 * Discovery finds every user-execution gate, Hermes eval/prepare operation, and JSI
 * Function call in the engine files participating in the checkpoint change.
 * Each discovered site must belong to a reviewed function classification;
 * sites in a new function fail closed instead of inheriting a file-wide
 * default. The checked artifact then makes additions inside an already
 * reviewed function visible as ordinary generated drift.
 *
 * @ref LLP 0040
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const repoRoot = path.resolve(__dirname, "..", "..", "..", "..");
export const hostTaskIngressInventoryPath = path.join(
  repoRoot,
  "capsec",
  "registry",
  "host-task-ingress-inventory.json",
);
export const HOST_TASK_INGRESS_INVENTORY_SCHEMA =
  "ibex/host-task-ingress-inventory/1";

export const HOST_TASK_INGRESS_FILES = Object.freeze([
  "src/engine/hermes_module_runner.cc",
  "src/engine/hermes_runtime.cc",
  "src/engine/hermes_runtime_debugger.cc",
  "src/engine/hermes_runtime_ios.cc",
  "src/engine/hermes_runtime_worklet.cc",
]);

const VALID_DISPOSITIONS = new Set([
  "admission-no-app-code",
  "construction-no-app-code",
  "internal-checkpoint",
  "joins-outer-host-task",
  "outer-host-task",
  "restricted-no-app-code",
  "test-only",
  "trusted-bootstrap-no-app-code",
]);

function classification(pathname, functionName, disposition, rationale) {
  return Object.freeze({
    id: `${pathname}#${functionName}`,
    path: pathname,
    function: functionName,
    disposition,
    rationale,
  });
}

function classificationsFor(pathname, disposition, rationale, functions) {
  return functions.map((functionName) =>
    classification(pathname, functionName, disposition, rationale)
  );
}

const RATIONALE = Object.freeze({
  construction:
    "Construction/bootstrap code runs before app execution and invokes only captured bootstrap or pristine intrinsic functions.",
  namedSeal:
    "The named owner transition evaluates fixed native-owned seal bytes before any user-execution ingress; no app-controlled source or callback can run, and any failure quarantines the generation.",
  internal:
    "The helper runs only while an existing outer host task is finalizing its nextTick/microtask or runtime-extension checkpoint closure.",
  nested:
    "The helper or retained callback is reached only from an already classified outer host task and joins that task identity.",
  outer:
    "The runtime-owner ingress creates and explicitly finishes an outer ScopedRuntimeExtensionHostTask before publishing its result.",
  restricted:
    "The restricted UI-worklet runtime is structurally denied the app runtime's extension projections.",
  testOnly:
    "The call exists only behind an Ibex test-hook build and is absent from production artifacts.",
  admission:
    "The entry performs admission/gating only and executes no app JavaScript; the later execution entry owns the task boundary.",
});

// Closed reviewed function table. A scanner hit in any other function is an
// unclassified ingress and fails before an artifact can be rendered.
export const HOST_TASK_INGRESS_CLASSIFICATIONS = Object.freeze([
  ...classificationsFor(
    "src/engine/hermes_module_runner.cc",
    "outer-host-task",
    RATIONALE.outer,
    [
      "ex_hermes_commonjs_record_evaluate",
      "ex_hermes_commonjs_record_create_esm_adapter",
      "ex_hermes_module_compile_factory",
      "ex_hermes_module_complete_dynamic_activation",
      "ex_hermes_module_load_carrier_factory",
      "ex_hermes_module_invoke_export",
      "ex_hermes_module_record_instantiate",
      "ex_hermes_module_record_namespace_json",
      "ex_hermes_module_record_run_declare",
      "ex_hermes_module_record_run_execute",
    ],
  ),
  ...classificationsFor(
    "src/engine/hermes_module_runner.cc",
    "joins-outer-host-task",
    RATIONALE.nested,
    [
      "beginRecordExecute",
      "evaluateCommonJsRecord",
      "finalizeCommonJsAdapter",
      "pendingDynamicActivationPromise",
    ],
  ),

  ...classificationsFor(
    "src/engine/hermes_runtime.cc",
    "outer-host-task",
    RATIONALE.outer,
    [
      "evalRuntimeUnchecked",
      "evaluateStructuredSource",
      "ex_hermes_eval_lowered_session",
      "ex_hermes_poll",
      "ex_hermes_poll_with_external_keep_alive",
      "ex_hermes_run_prepared_app_v1",
      "ex_hermes_stage_prepared_native_startup_v1",
      "pollRuntime",
    ],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime.cc",
    "admission-no-app-code",
    RATIONALE.admission,
    [
      "driveDevServedModuleTableLifecycle",
      "ex_hermes_begin_app_bundle_evaluation_v1",
      "ex_hermes_structured_session_bind",
      "ex_hermes_structured_submission_admit",
    ],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime.cc",
    "internal-checkpoint",
    RATIONALE.internal,
    [
      "flushPendingPromiseRejections",
      "handlePendingPromiseRejection",
      "runNextTickQueue",
      "runStructuredCancellationProbe",
    ],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime.cc",
    "construction-no-app-code",
    RATIONALE.construction,
    [
      "capturePrivateBridgeConsumers",
      "defineExactCapability",
      "deleteRootGlobalOwnProperty",
      "ex_hermes_create_impl",
      "finalizeCompartmentBaselineForEmbedder",
      "findRootGlobalDescriptorWithoutGet",
      "forEachRootGlobalOwnKey",
      "installBootstrapCompatibilityModes",
      "installCompartmentRegistry",
      "installGlobals",
      "installStructuredLastValueAccessor",
      "installStructuredLifecycleAccessors",
      "removeProvisionalExactCapability",
      "rootGlobalDescriptorField",
      "rootGlobalOwnDescriptor",
      "sealGlobalHostFunction",
      "sealUnarmedProcessExitCodeDescriptor",
      "verifyRootGlobalDisposition",
    ],
  ),
  classification(
    "src/engine/hermes_runtime.cc",
    "ex_hermes_seal_armed_shared_runtime_globals_v1",
    "trusted-bootstrap-no-app-code",
    RATIONALE.namedSeal,
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime.cc",
    "test-only",
    RATIONALE.testOnly,
    ["injectRootGlobalDispositionTestAccessor"],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime.cc",
    "joins-outer-host-task",
    RATIONALE.nested,
    [
      "cleanupFetchCallbacks",
      "decodeHostCallPayload",
      "defineStructuredGlobal",
      "defineStructuredObjectDataProperty",
      "dispatchStructuredModuleCacheAction",
      "evaluateLoweredPreparedSession",
      "evaluateStructuredCommonJsEntry",
      "evaluateStructuredGeneratedCommonJsEntry",
      "ex_hermes_resolve_exact_host_call",
      "ex_hermes_resolve_host_call",
      "ex_hermes_set_exact_host_call_async",
      "ex_hermes_set_exact_host_call_async_v2",
      "ex_hermes_set_host_call_async",
      "exactCreateReferenceError",
      "exactCreateSyntaxError",
      "exactCreateTypeError",
      "exactHermesEvalImmediateNoJobs",
      "hostCallArgsToJson",
      "hostCallOpToString",
      "invokeUncaughtHandler",
      "makeStructuredSessionHooks",
      "materializeStructuredStaticImports",
      "normalizeLifecycleExitCode",
      "pollTypedAuthorityGenerations",
      "preparedNativeStartupMatchesV1",
      "preparedNativeStartupObjectHasExactKeysV1",
      "structuredGlobalIsExtensible",
      "structuredLastValueAccessorIntact",
      "structuredOwnDescriptor",
      "valueToString",
      "writeStructuredSessionName",
    ],
  ),

  ...classificationsFor(
    "src/engine/hermes_runtime_debugger.cc",
    "outer-host-task",
    RATIONALE.outer,
    ["ex_hermes_debugger_eval"],
  ),

  ...classificationsFor(
    "src/engine/hermes_runtime_ios.cc",
    "outer-host-task",
    RATIONALE.outer,
    ["emit_module_event_impl", "ex_hermes_dispatch_event"],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime_ios.cc",
    "construction-no-app-code",
    RATIONALE.construction,
    [
      "ex_hermes_set_dispatch_with_debug_context_callback",
      "ex_hermes_set_kernel_handle",
    ],
  ),
  classification(
    "src/engine/hermes_runtime_ios.cc",
    "ex_hermes_deliver_animation_frame",
    "joins-outer-host-task",
    RATIONALE.nested,
  ),

  ...classificationsFor(
    "src/engine/hermes_runtime_worklet.cc",
    "restricted-no-app-code",
    RATIONALE.restricted,
    [
      "ex_worklet_install",
      "ex_worklet_install_typed",
      "ex_worklet_invoke",
      "ex_worklet_invoke_typed",
      "installWorkletGlobals",
    ],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime_worklet.cc",
    "outer-host-task",
    RATIONALE.outer,
    [
      "ex_hermes_dispatch_motion_rated_publish",
      "ex_hermes_dispatch_worklet_calls",
      "ex_hermes_dispatch_worklet_json_batch",
    ],
  ),
]);

// The route inventory is intentionally smaller than the lexical site
// inventory. It names the actual runtime-owner entries (plus the two internal
// checkpoint dispatchers) so helpers cannot substitute for an ingress review.
// Rows without a direct lexical hit are still resolved to a real C++ function
// definition and emitted in the checked artifact.
export const REQUIRED_HOST_TASK_INGRESS_ROWS = Object.freeze([
  ...classificationsFor(
    "src/engine/hermes_module_runner.cc",
    "outer-host-task",
    RATIONALE.outer,
    [
      "ex_hermes_commonjs_record_create_esm_adapter",
      "ex_hermes_commonjs_record_evaluate",
      "ex_hermes_module_compile_factory",
      "ex_hermes_module_complete_dynamic_activation",
      "ex_hermes_module_load_carrier_factory",
      "ex_hermes_module_invoke_export",
      "ex_hermes_module_record_instantiate",
      "ex_hermes_module_record_namespace_json",
      "ex_hermes_module_record_run_declare",
      "ex_hermes_module_record_run_execute",
    ],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime.cc",
    "outer-host-task",
    RATIONALE.outer,
    [
      "evalRuntimeUnchecked",
      "evaluateStructuredSource",
      "ex_hermes_eval_lowered_session",
      "ex_hermes_eval_structured_session",
      "ex_hermes_poll",
      "ex_hermes_poll_with_external_keep_alive",
      "ex_hermes_run_prepared_app_v1",
      "ex_hermes_stage_prepared_native_startup_v1",
      "pollRuntime",
    ],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime.cc",
    "admission-no-app-code",
    RATIONALE.admission,
    ["ex_hermes_begin_app_bundle_evaluation_v1"],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime.cc",
    "internal-checkpoint",
    RATIONALE.internal,
    ["handlePendingPromiseRejection", "runNextTickQueue"],
  ),
  classification(
    "src/engine/hermes_runtime_debugger.cc",
    "ex_hermes_debugger_eval",
    "outer-host-task",
    RATIONALE.outer,
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime_ios.cc",
    "outer-host-task",
    RATIONALE.outer,
    [
      "emit_module_event_impl",
      "ex_hermes_dispatch_event",
      "ex_hermes_emit_module_event",
      "ex_hermes_emit_module_view_event",
    ],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime_worklet.cc",
    "restricted-no-app-code",
    RATIONALE.restricted,
    [
      "ex_worklet_install",
      "ex_worklet_install_typed",
      "ex_worklet_invoke",
      "ex_worklet_invoke_typed",
      "installWorkletGlobals",
    ],
  ),
  ...classificationsFor(
    "src/engine/hermes_runtime_worklet.cc",
    "outer-host-task",
    RATIONALE.outer,
    [
      "ex_hermes_dispatch_motion_rated_publish",
      "ex_hermes_dispatch_worklet_calls",
      "ex_hermes_dispatch_worklet_json_batch",
    ],
  ),
]);

function compareText(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function relativeTo(root, filePath) {
  return path.relative(root, filePath).split(path.sep).join("/");
}

function confinedPath(root, pathname, label) {
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, pathname);
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${path.sep}`)) {
    throw new Error(`${label}: path escapes the repository`);
  }
  return resolved;
}

/** Replace comments and literals with spaces while preserving byte offsets. */
function sanitizeCpp(source) {
  const output = source.split("");
  const blank = (index) => {
    if (output[index] !== "\n" && output[index] !== "\r") output[index] = " ";
  };
  let index = 0;
  while (index < source.length) {
    if (source.startsWith("//", index)) {
      blank(index++);
      blank(index++);
      while (index < source.length && source[index] !== "\n") blank(index++);
      continue;
    }
    if (source.startsWith("/*", index)) {
      blank(index++);
      blank(index++);
      while (index < source.length && !source.startsWith("*/", index)) {
        blank(index++);
      }
      if (index < source.length) {
        blank(index++);
        blank(index++);
      }
      continue;
    }
    if (source[index] === "R" && source[index + 1] === '"') {
      const delimiterEnd = source.indexOf("(", index + 2);
      if (delimiterEnd >= 0 && delimiterEnd - (index + 2) <= 16) {
        const delimiter = source.slice(index + 2, delimiterEnd);
        const terminator = `)${delimiter}\"`;
        const literalEnd = source.indexOf(terminator, delimiterEnd + 1);
        const end = literalEnd < 0
          ? source.length
          : literalEnd + terminator.length;
        while (index < end) blank(index++);
        continue;
      }
    }
    if (source[index] === '"' || source[index] === "'") {
      const quote = source[index];
      blank(index++);
      while (index < source.length) {
        if (source[index] === "\\") {
          blank(index++);
          if (index < source.length) blank(index++);
          continue;
        }
        const current = source[index];
        blank(index++);
        if (current === quote) break;
      }
      continue;
    }
    index += 1;
  }
  return output.join("");
}

function matchingPairs(source, open, close) {
  const pairs = new Map();
  const stack = [];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === open) stack.push(index);
    if (source[index] !== close) continue;
    const start = stack.pop();
    if (start !== undefined) pairs.set(start, index);
  }
  return pairs;
}

const CONTROL_WORDS = new Set([
  "alignas",
  "catch",
  "defined",
  "for",
  "if",
  "requires",
  "sizeof",
  "switch",
  "while",
]);

function discoverFunctionRanges(sanitized) {
  const parentheses = matchingPairs(sanitized, "(", ")");
  const closingToOpeningParenthesis = new Map(
    [...parentheses.entries()].map(([opening, closing]) => [closing, opening]),
  );
  const braces = matchingPairs(sanitized, "{", "}");
  const ranges = [];
  for (const [bodyStart, bodyEnd] of braces) {
    let cursor = bodyStart - 1;
    while (cursor >= 0 && /\s/.test(sanitized[cursor])) cursor -= 1;
    let closeParenthesis = -1;
    for (let index = cursor; index >= 0; index -= 1) {
      if (sanitized[index] === ")") {
        closeParenthesis = index;
        break;
      }
      if (";{}".includes(sanitized[index])) break;
    }
    if (closeParenthesis < 0) continue;
    const signatureTail = sanitized.slice(closeParenthesis + 1, bodyStart);
    if (/[;{}]/.test(signatureTail)) continue;
    const openParenthesis = closingToOpeningParenthesis.get(closeParenthesis);
    if (openParenthesis === undefined) continue;
    let nameEnd = openParenthesis - 1;
    while (nameEnd >= 0 && /\s/.test(sanitized[nameEnd])) nameEnd -= 1;
    let nameStart = nameEnd;
    while (nameStart >= 0 && /[~A-Za-z0-9_:]/.test(sanitized[nameStart])) {
      nameStart -= 1;
    }
    const functionName = sanitized.slice(nameStart + 1, nameEnd + 1);
    if (!/^[~A-Za-z_][A-Za-z0-9_]*(?:::[~A-Za-z_][A-Za-z0-9_]*)*$/.test(functionName)) {
      continue;
    }
    const unqualified = functionName.split("::").at(-1);
    if (CONTROL_WORDS.has(unqualified)) continue;
    ranges.push({ bodyStart, bodyEnd, functionName });
  }
  return ranges.sort((left, right) =>
    left.bodyStart - right.bodyStart || right.bodyEnd - left.bodyEnd
  );
}

function enclosingFunction(ranges, offset) {
  let selected;
  for (const range of ranges) {
    if (range.bodyStart >= offset || range.bodyEnd < offset) continue;
    if (!selected || range.bodyStart > selected.bodyStart) selected = range;
  }
  return selected?.functionName;
}

function lineAndColumn(source, offset) {
  const lineStart = source.lastIndexOf("\n", offset - 1) + 1;
  let line = 1;
  for (let index = 0; index < lineStart; index += 1) {
    if (source[index] === "\n") line += 1;
  }
  return { line, column: offset - lineStart + 1, lineStart };
}

function readableSourceLine(source, lineStart) {
  const lineEnd = source.indexOf("\n", lineStart);
  return source.slice(lineStart, lineEnd < 0 ? source.length : lineEnd).trim();
}

const SITE_PATTERNS = Object.freeze([
  Object.freeze({
    kind: "user-execution-gate",
    expression: /\bexactRuntimeEnterUserExecution\s*\(/g,
    operation: () => "exactRuntimeEnterUserExecution",
  }),
  Object.freeze({
    kind: "engine-eval-or-prepare",
    expression:
      /(?:->|\.)\s*(evaluateJavaScript|evaluatePreparedJavaScript|prepareJavaScript|evalWhilePaused)\s*\(/g,
    operation: (match) => match[1],
  }),
  Object.freeze({
    kind: "jsi-function-call",
    expression: /(?:->|\.)\s*(call|callAsConstructor)\s*\(/g,
    operation: (match) => match[1],
  }),
]);

export function discoverHostTaskIngressSites(root = repoRoot) {
  const sites = [];
  for (const pathname of HOST_TASK_INGRESS_FILES) {
    const filePath = confinedPath(root, pathname, `host-task source ${pathname}`);
    const source = fs.readFileSync(filePath, "utf8");
    const sanitized = sanitizeCpp(source);
    const functions = discoverFunctionRanges(sanitized);
    for (const pattern of SITE_PATTERNS) {
      pattern.expression.lastIndex = 0;
      let match;
      while ((match = pattern.expression.exec(sanitized)) !== null) {
        const functionName = enclosingFunction(functions, match.index);
        const location = lineAndColumn(source, match.index);
        sites.push({
          path: pathname,
          function: functionName ?? null,
          kind: pattern.kind,
          operation: pattern.operation(match),
          line: location.line,
          column: location.column,
          source: readableSourceLine(source, location.lineStart),
        });
      }
    }
  }
  sites.sort((left, right) =>
    compareText(
      `${left.path}\0${String(left.line).padStart(8, "0")}\0${String(left.column).padStart(8, "0")}\0${left.kind}`,
      `${right.path}\0${String(right.line).padStart(8, "0")}\0${String(right.column).padStart(8, "0")}\0${right.kind}`,
    )
  );
  const ordinals = new Map();
  return sites.map((site) => {
    const ordinalKey = `${site.path}\0${site.function ?? "<global>"}\0${site.kind}`;
    const ordinal = ordinals.get(ordinalKey) ?? 0;
    ordinals.set(ordinalKey, ordinal + 1);
    return { ...site, ordinal };
  });
}

function discoverHostTaskFunctionKeys(root = repoRoot) {
  const keys = new Set();
  for (const pathname of HOST_TASK_INGRESS_FILES) {
    const filePath = confinedPath(root, pathname, `host-task source ${pathname}`);
    const source = fs.readFileSync(filePath, "utf8");
    for (const range of discoverFunctionRanges(sanitizeCpp(source))) {
      keys.add(`${pathname}\0${range.functionName}`);
    }
  }
  return keys;
}

function classificationKey(row) {
  return `${row.path}\0${row.function}`;
}

function validateClassifications() {
  const byKey = new Map();
  for (const row of [
    ...HOST_TASK_INGRESS_CLASSIFICATIONS,
    ...REQUIRED_HOST_TASK_INGRESS_ROWS,
  ]) {
    if (!HOST_TASK_INGRESS_FILES.includes(row.path)) {
      throw new Error(`${row.id}: classification path is not tracked`);
    }
    if (!VALID_DISPOSITIONS.has(row.disposition)) {
      throw new Error(`${row.id}: unknown disposition ${row.disposition}`);
    }
    const key = classificationKey(row);
    const existing = byKey.get(key);
    if (existing) {
      if (
        existing.id !== row.id ||
        existing.disposition !== row.disposition ||
        existing.rationale !== row.rationale
      ) {
        throw new Error(`${row.id}: conflicting duplicate classification`);
      }
      continue;
    }
    byKey.set(key, row);
  }
  return byKey;
}

export function buildHostTaskIngressInventory(root = repoRoot) {
  const classifications = validateClassifications();
  const sites = discoverHostTaskIngressSites(root);
  const functionKeys = discoverHostTaskFunctionKeys(root);
  const unclassified = sites.filter(
    (site) => !site.function || !classifications.has(classificationKey(site)),
  );
  if (unclassified.length > 0) {
    const summary = unclassified
      .map((site) =>
        `${site.path}:${site.line}:${site.column} ${site.kind} in ${site.function ?? "<global>"}`
      )
      .join("\n");
    throw new Error(`unclassified host-task ingress sites:\n${summary}`);
  }

  const grouped = new Map();
  for (const site of sites) {
    const key = classificationKey(site);
    const row = classifications.get(key);
    if (!grouped.has(key)) grouped.set(key, { row, sites: [] });
    grouped.get(key).sites.push({
      kind: site.kind,
      operation: site.operation,
      line: site.line,
      column: site.column,
      source: site.source,
    });
  }

  const staleClassifications = [...classifications.entries()]
    .filter(([key]) => !functionKeys.has(key))
    .map(([, row]) => row.id);
  if (staleClassifications.length > 0) {
    throw new Error(
      `host-task classifications have no discovered sites: ${staleClassifications.join(", ")}`,
    );
  }

  const rows = [...grouped.values()]
    .map(({ row, sites: rowSites }) => ({
      id: row.id,
      path: row.path,
      function: row.function,
      disposition: row.disposition,
      sites: rowSites,
    }))
    .sort((left, right) => compareText(left.id, right.id));
  const ingressRows = REQUIRED_HOST_TASK_INGRESS_ROWS
    .map((row) => ({
      id: row.id,
      path: row.path,
      function: row.function,
      disposition: row.disposition,
      discoveredSiteCount:
        grouped.get(classificationKey(row))?.sites.length ?? 0,
    }))
    .sort((left, right) => compareText(left.id, right.id));
  if (new Set(ingressRows.map((row) => row.id)).size !== ingressRows.length) {
    throw new Error("required host-task ingress rows contain duplicate ids");
  }
  const counts = Object.fromEntries(
    SITE_PATTERNS.map(({ kind }) => [
      kind,
      sites.filter((site) => site.kind === kind).length,
    ]),
  );
  for (const [kind, count] of Object.entries(counts)) {
    if (count === 0) throw new Error(`host-task inventory discovered no ${kind} sites`);
  }
  const dispositions = {};
  for (const row of classifications.values()) {
    const existing = dispositions[row.disposition];
    if (existing !== undefined && existing !== row.rationale) {
      throw new Error(
        `${row.disposition}: classifications disagree on their rationale`,
      );
    }
    dispositions[row.disposition] = row.rationale;
  }
  return {
    inventorySchema: HOST_TASK_INGRESS_INVENTORY_SCHEMA,
    trackedFiles: [...HOST_TASK_INGRESS_FILES],
    dispositions: Object.fromEntries(
      Object.entries(dispositions).sort(([left], [right]) =>
        compareText(left, right)
      ),
    ),
    counts,
    ingressRows,
    rows,
  };
}

export function renderHostTaskIngressInventory(root = repoRoot) {
  return canonicalJson(buildHostTaskIngressInventory(root));
}

export function checkHostTaskIngressInventory({
  root = repoRoot,
  artifactPath = root === repoRoot
    ? hostTaskIngressInventoryPath
    : path.join(root, "capsec", "registry", "host-task-ingress-inventory.json"),
} = {}) {
  const expected = renderHostTaskIngressInventory(root);
  let actual;
  try {
    actual = fs.readFileSync(artifactPath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`${relativeTo(root, artifactPath)} is missing`);
    }
    throw error;
  }
  let parsed;
  try {
    parsed = JSON.parse(actual);
  } catch (error) {
    throw new Error(`${relativeTo(root, artifactPath)} is invalid JSON: ${error.message}`);
  }
  if (canonicalJson(parsed) !== actual) {
    throw new Error(`${relativeTo(root, artifactPath)} is not canonical JSON`);
  }
  if (actual !== expected) {
    throw new Error(`${relativeTo(root, artifactPath)} is stale`);
  }
  return parsed;
}

export function writeHostTaskIngressInventory() {
  const content = renderHostTaskIngressInventory(repoRoot);
  writeGeneratedFilesTransactionally(
    repoRoot,
    [{
      path: hostTaskIngressInventoryPath,
      content,
      label: "host-task ingress inventory",
    }],
    () => {
      assertConfinedGeneratedFile(
        repoRoot,
        hostTaskIngressInventoryPath,
        "host-task ingress inventory",
      );
    },
  );
}

function listDiscoveredScopes() {
  const groups = new Map();
  for (const site of discoverHostTaskIngressSites(repoRoot)) {
    const key = `${site.path}#${site.function ?? "<global>"}`;
    if (!groups.has(key)) groups.set(key, new Set());
    groups.get(key).add(site.kind);
  }
  for (const [key, kinds] of [...groups].sort(([left], [right]) =>
    compareText(left, right)
  )) {
    console.log(`${key}\t${[...kinds].sort(compareText).join(",")}`);
  }
}

function main(argv) {
  const modes = new Set(argv);
  if (argv.length !== 1 ||
      !["--check", "--write", "--list"].some((mode) => modes.has(mode))) {
    throw new Error(
      "usage: generate-host-task-ingress-inventory.mjs (--check|--write|--list)",
    );
  }
  if (modes.has("--list")) {
    listDiscoveredScopes();
    return;
  }
  if (modes.has("--write")) {
    writeHostTaskIngressInventory();
    console.log(
      `wrote ${relativeTo(repoRoot, hostTaskIngressInventoryPath)}`,
    );
    return;
  }
  const artifact = checkHostTaskIngressInventory();
  console.log(
    `host-task ingress inventory checked: ${artifact.rows.length} classified functions, ${Object.values(artifact.counts).reduce((sum, count) => sum + count, 0)} sites`,
  );
}

if (path.resolve(process.argv[1] ?? "") === __filename) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.stack : String(error));
    process.exitCode = 1;
  }
}
