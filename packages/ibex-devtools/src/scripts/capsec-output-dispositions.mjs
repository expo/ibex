/**
 * Generate and validate LLP 0023's output-disposition dataset.
 *
 * The output-shape catalog is derived from the source inventory and explicit
 * source assertions below. The reviewed policy is a separate input and pins
 * the complete catalog-key digest, so discovering a new output cannot silently
 * inherit `non-path`. Loaded-engine observations are a third input and must
 * join the generated dataset exactly before the evidence state is promotable.
 *
 * @ref LLP 0023#6-path-bearing-observables — output dispositions are total over
 * one canonical seven-part key and are checked against an independent catalog
 * whose surface accounts are exactly equal to the coverage registry.
 * @ref LLP 0021#generated-semantic-datasets — generated semantic datasets are
 * reproducible, digest-bound inputs rather than duplicate runtime matchers.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { validateConformanceRunnerBinding } from "./capsec-conformance-runner-binding.mjs";
import {
  CALLBACK_OUTPUT_CONTRACT_SCHEMA,
  deriveHostAbiOutputCatalogAccount,
} from "./capsec-surface-inventory.mjs";
import {
  auditInspectorCdpStructuralClosure,
  inspectorCdpStructuralAccountBindings,
  validateInspectorCdpStructuralCatalog,
} from "./capsec-inspector-cdp-output-templates.mjs";
import {
  auditDebuggerNativeAliasClosure,
  debuggerNativeAliasStructuralAccountBindings,
  validateDebuggerNativeAliasStructuralCatalog,
} from "./capsec-debugger-native-alias-accounts.mjs";
import {
  auditNativeGlobalMarkerAliasClosure,
  capsecContextObserverOutputCatalogBinding,
  nativeGlobalMarkerStructuralAccountBindings,
  validateNativeGlobalMarkerAliasCatalog,
} from "./capsec-native-global-marker-alias-accounts.mjs";
import {
  auditCanonicalEnvironmentOutputSources,
  canonicalEnvironmentOutputContract,
  ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD,
  environmentParameterizedOutputCatalogBindings,
  environmentStructuralAccountBindings,
  validateEnvironmentOutputCatalog,
} from "./capsec-environment-output-templates.mjs";

export const OUTPUT_DISPOSITIONS = Object.freeze([
  "absent",
  "closed",
  "non-path",
  "private-native-path",
  "refused",
  "reserved-constant",
  "synthetic-source-id",
  "typed-logical",
  "virtual-absolute",
  "virtual-basename",
  "virtual-relative",
]);

export const OUTPUT_KEY_FIELDS = Object.freeze([
  "surfaceId",
  "output",
  "alias",
  "mode",
  "sourceKind",
  "returnVariant",
  "contextId",
]);

const PROFILE = "ibex/capsec/1";
export const OUTPUT_DISPOSITION_EVIDENCE_EXECUTOR =
  "ibex-public-surface-harness/output-shape-sweep-v3";
const CATALOG_DIGEST_DOMAIN = "ibex:capsec:output-shape-catalog-keys:2";
const PARAMETERIZED_BINDING_DIGEST_DOMAIN =
  "ibex:capsec:output-parameterized-bindings:1";
const DIGEST_PATTERN = /^sha256-[A-Za-z0-9_-]{43}$/u;
const REVISION_PATTERN = /^[0-9a-f]{40}$/u;
const TARGET_FIELDS = Object.freeze(["triple", "features"]);
const ENGINE_FIELDS = Object.freeze([
  "binaryDigest",
  "engineArtifactPath",
  "kind",
  "object",
  "structuralFeatures",
  "targetArchitecture",
]);
const ENGINE_OBJECT_FIELDS = Object.freeze(["file", "platform", "volume"]);
const ENGINE_OBJECT_PLATFORMS = new Set([
  "android",
  "apple",
  "unix",
  "windows",
]);

const OUTPUT_EXECUTION_CONTEXTS = Object.freeze({
  "host.private-native-call-initialized": Object.freeze({
    contextId: "host.private-native-call-initialized",
    principalClass: "host",
    accessPhase: "abi-call",
    runtimeState: "initialized",
    targetScope: "candidate-target-cell",
  }),
  "javascript.package-call-loaded": Object.freeze({
    contextId: "javascript.package-call-loaded",
    principalClass: "package",
    accessPhase: "call",
    runtimeState: "loaded",
    targetScope: "candidate-target-cell",
  }),
  "javascript.package-callback-loaded": Object.freeze({
    contextId: "javascript.package-callback-loaded",
    principalClass: "package",
    accessPhase: "callback-delivery",
    runtimeState: "loaded",
    targetScope: "candidate-target-cell",
  }),
  "javascript.package-import-fresh": Object.freeze({
    contextId: "javascript.package-import-fresh",
    principalClass: "package",
    accessPhase: "import",
    runtimeState: "fresh",
    targetScope: "candidate-target-cell",
  }),
  "javascript.package-module-load": Object.freeze({
    contextId: "javascript.package-module-load",
    principalClass: "package",
    accessPhase: "module-load",
    runtimeState: "loaded",
    targetScope: "candidate-target-cell",
  }),
  "javascript.package-property-read-loaded": Object.freeze({
    contextId: "javascript.package-property-read-loaded",
    principalClass: "package",
    accessPhase: "property-read",
    runtimeState: "loaded",
    targetScope: "candidate-target-cell",
  }),
  "runtime.bootstrap-native-call-loaded": Object.freeze({
    contextId: "runtime.bootstrap-native-call-loaded",
    principalClass: "runtime-bootstrap",
    accessPhase: "call",
    runtimeState: "loaded",
    targetScope: "candidate-target-cell",
  }),
});

const LIVE_VALUE_PROOF_KINDS = new Set([
  "compiled-runtime-return-record",
  "loaded-engine-descriptor",
  "loaded-engine-return-record",
]);

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort(compareText)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function taggedDigest(domain, value) {
  const hash = crypto.createHash("sha256");
  hash.update(domain, "utf8");
  hash.update(Buffer.from([0]));
  hash.update(canonicalJson(value), "utf8");
  return `sha256-${hash.digest("base64url")}`;
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}: expected object`);
  }
  const actual = Object.keys(value).sort(compareText);
  const wanted = [...expected].sort(compareText);
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    throw new Error(
      `${label}: expected exact keys [${wanted.join(", ")}], got [${actual.join(", ")}]`,
    );
  }
}

function validateCanonicalStableIdSet(value, label) {
  if (
    !Array.isArray(value) ||
    value.some(
      (item) => typeof item !== "string" || !/^[a-z][a-z0-9.-]*$/u.test(item),
    ) ||
    canonicalJson(value) !==
      canonicalJson([...new Set(value)].sort(compareText))
  ) {
    throw new Error(`${label}: expected a canonical stable-id set`);
  }
  return value;
}

function validateExactOutputTarget(target, label) {
  exactKeys(target, TARGET_FIELDS, label);
  if (!/^[a-z0-9_]+(?:-[a-z0-9_]+){2,}$/u.test(target.triple ?? "")) {
    throw new Error(`${label}.triple: expected an exact target triple`);
  }
  validateCanonicalStableIdSet(target.features, `${label}.features`);
  return target;
}

function validateExactOutputEngine(engine, target, label) {
  exactKeys(engine, ENGINE_FIELDS, label);
  exactKeys(engine.object, ENGINE_OBJECT_FIELDS, `${label}.object`);
  validateCanonicalStableIdSet(
    engine.structuralFeatures,
    `${label}.structuralFeatures`,
  );
  const expectedObjectPlatform = target.triple.includes("-windows-")
    ? "windows"
    : target.triple.includes("-android")
      ? "android"
      : target.triple.includes("-apple-")
        ? "apple"
        : "unix";
  if (
    engine.kind !== "hermes" ||
    typeof engine.engineArtifactPath !== "string" ||
    engine.engineArtifactPath.length === 0 ||
    !DIGEST_PATTERN.test(engine.binaryDigest ?? "") ||
    !ENGINE_OBJECT_PLATFORMS.has(engine.object.platform) ||
    engine.object.platform !== expectedObjectPlatform ||
    typeof engine.object.volume !== "string" ||
    engine.object.volume.length === 0 ||
    typeof engine.object.file !== "string" ||
    engine.object.file.length === 0 ||
    !/^[a-z0-9_]+$/u.test(engine.targetArchitecture ?? "") ||
    engine.targetArchitecture !== target.triple.split("-")[0] ||
    canonicalJson(engine.structuralFeatures) !== canonicalJson(target.features)
  ) {
    throw new Error(`${label}: expected the exact target-bound Hermes image`);
  }
  return engine;
}

export function canonicalOutputDispositionKey(key, label = "output key") {
  exactKeys(key, OUTPUT_KEY_FIELDS, label);
  for (const field of OUTPUT_KEY_FIELDS) {
    if (typeof key[field] !== "string" || key[field].length === 0) {
      throw new Error(`${label}.${field}: expected non-empty string`);
    }
  }
  if (!/^surface\.[a-z0-9.]+$/u.test(key.surfaceId)) {
    throw new Error(`${label}.surfaceId: expected a stable surface id`);
  }
  return canonicalJson(OUTPUT_KEY_FIELDS.map((field) => key[field]));
}

/**
 * Select the execution context from source-discovered reachability and value
 * shape. Coverage classification is intentionally absent from this API: the
 * catalog describes which values exist, while policy separately decides how
 * an armed principal may observe them.
 */
export function defaultContextIdForCatalogRow(key, sourceSurface) {
  if (!key || typeof key !== "object" || Array.isArray(key)) {
    throw new Error("catalog row context: expected a key object");
  }
  if (
    key.mode === "private-native" ||
    (key.sourceKind === "host-abi" && key.mode !== "javascript")
  ) {
    return "host.private-native-call-initialized";
  }
  if (key.sourceKind === "host-abi") {
    return "javascript.package-property-read-loaded";
  }
  if (key.output?.startsWith("callback:")) {
    return "javascript.package-callback-loaded";
  }
  if (key.sourceKind === "bridge") {
    return "runtime.bootstrap-native-call-loaded";
  }
  if (sourceSurface?.kind === "startup") {
    return "javascript.package-module-load";
  }
  if (sourceSurface?.kind === "builtin") {
    if (sourceSurface.metadata?.surfaceType !== "export") {
      return "javascript.package-import-fresh";
    }
    return sourceSurface.metadata?.valueShape === "callable"
      ? "javascript.package-call-loaded"
      : "javascript.package-property-read-loaded";
  }
  if (sourceSurface?.kind === "native-op") {
    if (
      sourceSurface.metadata?.publicInvocation?.kind ===
      "native-global-function"
    ) {
      return "runtime.bootstrap-native-call-loaded";
    }
    return sourceSurface.metadata?.valueShape === "callable"
      ? "javascript.package-call-loaded"
      : "javascript.package-property-read-loaded";
  }
  return "javascript.package-call-loaded";
}

export function outputExecutionContextsForRows(rows) {
  const contextIds = [
    ...new Set(
      rows.map((row, index) => {
        const contextId = row?.key?.contextId;
        if (
          typeof contextId !== "string" ||
          !Object.hasOwn(OUTPUT_EXECUTION_CONTEXTS, contextId)
        ) {
          throw new Error(
            `output catalog row ${index}: unknown execution context ${JSON.stringify(contextId)}`,
          );
        }
        return contextId;
      }),
    ),
  ].sort(compareText);
  return contextIds.map((contextId) =>
    structuredClone(OUTPUT_EXECUTION_CONTEXTS[contextId]),
  );
}

export function validateOutputValueProofKind(
  proofKind,
  label = "output value proof",
) {
  if (proofKind === "compiled-registrar") {
    throw new Error(
      `${label}: compiled registrar presence cannot satisfy a value observation`,
    );
  }
  if (!LIVE_VALUE_PROOF_KINDS.has(proofKind)) {
    throw new Error(`${label}: unsupported live value proof kind ${proofKind}`);
  }
  return proofKind;
}

function sortRows(rows) {
  return [...rows].sort((left, right) =>
    compareText(
      canonicalOutputDispositionKey(left.key),
      canonicalOutputDispositionKey(right.key),
    ),
  );
}

function assertUniqueRows(rows, label) {
  const seen = new Set();
  for (const [index, row] of rows.entries()) {
    const key = canonicalOutputDispositionKey(
      row.key,
      `${label}[${index}].key`,
    );
    if (seen.has(key)) {
      throw new Error(`${label}: duplicate canonical output key ${key}`);
    }
    seen.add(key);
  }
}

export function outputShapeCatalogKeyDigest(rows) {
  const keys = sortRows(rows).map((row) =>
    OUTPUT_KEY_FIELDS.map((field) => row.key[field]),
  );
  return taggedDigest(CATALOG_DIGEST_DOMAIN, keys);
}

export function outputParameterizedBindingDigest(bindings) {
  if (!Array.isArray(bindings)) {
    throw new Error("parameterized output bindings must be an array");
  }
  return taggedDigest(PARAMETERIZED_BINDING_DIGEST_DOMAIN, bindings);
}

function sourceAssertion(repoRoot, assertion, label) {
  const filePath = path.join(repoRoot, assertion.path);
  const source = fs.readFileSync(filePath, "utf8");
  let assertedSource = source;
  let regionRef = "";
  if (assertion.region) {
    const start = source.indexOf(assertion.region.start);
    const duplicateStart = source.indexOf(assertion.region.start, start + 1);
    const end = source.indexOf(assertion.region.end, start);
    if (start < 0 || duplicateStart >= 0 || end < start) {
      throw new Error(
        `${label}: ${assertion.path} lacks one exact asserted source region`,
      );
    }
    assertedSource = source.slice(start, end + assertion.region.end.length);
    regionRef = `#region:${assertion.region.start}..${assertion.region.end}`;
  }
  for (const token of assertion.tokens) {
    if (!assertedSource.includes(token)) {
      throw new Error(
        `${label}: ${assertion.path} lacks token ${JSON.stringify(token)}`,
      );
    }
  }
  return `${assertion.path}${regionRef}#tokens:${assertion.tokens.join("+")}`;
}

function ibexBinaryRustSources(repoRoot) {
  const binaryRoot = path.join(repoRoot, "src/bin/ibex");
  return Object.fromEntries(
    fs
      .readdirSync(binaryRoot, { recursive: true })
      .filter((relativePath) => String(relativePath).endsWith(".rs"))
      .map((relativePath) => {
        const absolutePath = path.join(binaryRoot, String(relativePath));
        const repositoryPath = path
          .relative(repoRoot, absolutePath)
          .split(path.sep)
          .join("/");
        return [repositoryPath, fs.readFileSync(absolutePath, "utf8")];
      }),
  );
}

function inspectorCdpAuditSources(repoRoot) {
  const requiredPaths = [
    "src/bin/ibex/main.rs",
    "src/bin/ibex/runtime.rs",
    "src/bin/ibex/engine/hermes.rs",
    "src/bin/ibex/cdp/mod.rs",
  ];
  const sourceFiles = Object.fromEntries(
    requiredPaths.map((relativePath) => [
      relativePath,
      fs.readFileSync(path.join(repoRoot, relativePath), "utf8"),
    ]),
  );
  return { sourceFiles, binaryRustSources: ibexBinaryRustSources(repoRoot) };
}

function debuggerNativeAliasAuditSources(repoRoot) {
  const requiredPaths = [
    "src/engine/hermes_runtime_debugger.cc",
    "src/engine/hermes_runtime_platform_windows.cc",
    "src/bin/ibex/engine/hermes.rs",
    "src/bin/ibex/cdp/mod.rs",
    "src/bin/ibex/runtime.rs",
  ];
  return {
    sourceFiles: Object.fromEntries(
      requiredPaths.map((relativePath) => [
        relativePath,
        fs.readFileSync(path.join(repoRoot, relativePath), "utf8"),
      ]),
    ),
    binaryRustSources: ibexBinaryRustSources(repoRoot),
  };
}

function environmentOutputAuditSources(repoRoot) {
  const read = (relativePath) =>
    fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
  return {
    armedRuntimeSource: read("src/bin/ibex/runtime.rs"),
    builtinProcessSource: read("src/builtins/process.js"),
    compatibilityReaderSources: Object.fromEntries(
      [
        "packages/ibex-runtime-js/src/fetch/Headers.ts",
        "packages/ibex-runtime-js/src/fetch/Request.ts",
        "packages/ibex-runtime-js/src/fetch/Response.ts",
        "packages/ibex-runtime-js/src/fetch/body.ts",
        "packages/ibex-runtime-js/src/fetch/fetch.ts",
        "packages/ibex-runtime-js/src/streams/ReadableStream.ts",
      ].map((sourcePath) => [sourcePath, read(sourcePath)]),
    ),
    exactGlobalSource: read("src/engine/bootstrap/exact-global.js"),
    hostInputsSource: read("packages/ibex-runtime-js/src/core/host-inputs.ts"),
    hostEnvironmentAbiSource: read("src/host/abi.rs"),
    hostEnvironmentSource: read("src/host/mod.rs"),
    nativeAuthorizationSource: read("src/engine/hermes_runtime_internal.h"),
    nativeEnvironmentSource: read("src/engine/hermes_runtime.cc"),
    processSetupSource: read("src/engine/hermes_runtime_process_setup.cc"),
    processFacadeSource: read("packages/ibex-runtime-js/src/node/process.ts"),
    runtimeInstallSource: read("src/engine/hermes_runtime.cc"),
    sharedBootstrapSource: read("packages/ibex-runtime-js/src/bootstrap.ts"),
    snapshotFactorySource: read("src/bin/ibex/runtime.rs"),
    snapshotSchemaSource: read("capsec/schema/armed-snapshot.schema.json"),
  };
}

// These inventory entries are implementation/control tokens rather than
// values. Keep that decision source-pinned here: a spelling match by itself is
// not enough to demote a newly value-bearing native surface to structural.
// @ref LLP 0023#6-path-bearing-observables — total output accounting permits a
// structural account only when the source proves that no value slot belongs to
// the inventoried operation.
const SOURCE_ASSERTED_STRUCTURAL_CONTRACTS = Object.freeze([
  ...[
    ["__exact", "'__exact'"],
    ["__ibex", "'__ibex'"],
  ].map(([surfaceName, prefixLiteral]) =>
    Object.freeze({
      surfaceName,
      reasonCode: "reserved-native-prefix-literal",
      assertions: [
        {
          path: "src/engine/hermes_runtime.cc",
          region: {
            start: "function startsWithRawPrefix(name, prefix)",
            end: "return POWERFUL_SET[name] === true && !isEndowed(pkg, name);",
          },
          tokens: [
            "function startsWithRawPrefix(name, prefix)",
            `startsWithRawPrefix(name, ${prefixLiteral})`,
            "Raw host primitives (__exact* / __ibex*) must never be reachable",
          ],
        },
      ],
    }),
  ),
  Object.freeze({
    surfaceName: "__exactHttpWaitExecutor",
    reasonCode: "promise-executor-control",
    assertions: [
      {
        path: "src/engine/hermes_runtime_http.cc",
        region: {
          start: 'PropNameID::forAscii(runtime, "__exactHttpWaitExecutor")',
          end: 'rt.global().setProperty(rt, "__exactHttpWait", std::move(httpWaitFn));',
        },
        tokens: [
          'PropNameID::forAscii(runtime, "__exactHttpWaitExecutor")',
          "struct WaitTask",
          "static WaitWorkerPool* workerPool = new WaitWorkerPool();",
          "return facebook::jsi::Value::undefined();",
          "return promiseCtor.callAsConstructor(runtime, executor);",
        ],
      },
    ],
  }),
  Object.freeze({
    surfaceName: "__exactHttpAwaitWritableExecutor",
    reasonCode: "promise-executor-control",
    assertions: [
      {
        path: "src/engine/hermes_runtime_http.cc",
        region: {
          start:
            'PropNameID::forAscii(runtime, "__exactHttpAwaitWritableExecutor")',
          end: 'rt.global().setProperty(rt, "__exactHttpAwaitWritable", std::move(httpAwaitWritableFn));',
        },
        tokens: [
          'PropNameID::forAscii(runtime, "__exactHttpAwaitWritableExecutor")',
          "struct WritableTask",
          "static WritableWorkerPool* writablePool = new WritableWorkerPool();",
          "return facebook::jsi::Value::undefined();",
          "return promiseCtor.callAsConstructor(runtime, executor);",
        ],
      },
    ],
  }),
  Object.freeze({
    surfaceName:
      "__exactGeneratedImportGrantKeys.[[dynamic-table:call-result-354b628423c4-properties]]",
    reasonCode: "private-root-dynamic-descendant",
    assertions: [
      {
        path: "src/engine/bootstrap/import-grant-keys.generated.js",
        region: {
          start: "(function installGeneratedImportGrantKeys(globalObject) {",
          end: "})(globalThis);",
        },
        tokens: [
          'Object.defineProperty(globalObject, "__exactGeneratedImportGrantKeys", {',
          "value: Object.freeze(",
          "enumerable: false",
          "configurable: true",
        ],
      },
      {
        path: "src/engine/bootstrap/module-loader.js",
        region: {
          start:
            "var __reservedImportGrantKeys = Array.isArray(g.__exactGeneratedImportGrantKeys)",
          end: "try { delete g.__exactGeneratedImportGrantKeys; } catch (_generatedKeyCleanupError) {}",
        },
        tokens: [
          "? g.__exactGeneratedImportGrantKeys",
          ": Object.freeze([])",
          "delete g.__exactGeneratedImportGrantKeys",
        ],
      },
    ],
  }),
  Object.freeze({
    surfaceName: "global:localStorage.persistence",
    reasonCode: "semantic-effect-marker-no-value-slot",
    assertions: [
      {
        path: "src/engine/bootstrap/web-storage.js",
        region: {
          start: "function StorageImpl(persistent) {",
          end: "globalThis.sessionStorage = new StorageImpl(false);",
        },
        tokens: [
          "this._persistent = persistent",
          "if (this._persistent) _save(this._data)",
          "globalThis.localStorage = new StorageImpl(true)",
          "globalThis.sessionStorage = new StorageImpl(false)",
        ],
      },
    ],
  }),
  ...[
    [
      "inspector.debugger-pause",
      "ex_hermes_debugger_pause",
      "debugger.triggerAsyncPause(",
      'extern "C" void ex_hermes_debugger_resume(',
    ],
    [
      "inspector.debugger-remove-breakpoint",
      "ex_hermes_debugger_remove_breakpoint",
      "debugger.deleteBreakpoint(breakpoint_id);",
      'extern "C" void ex_hermes_debugger_pause(',
    ],
    [
      "inspector.debugger-resume",
      "ex_hermes_debugger_resume",
      "debugger->resumeFromPaused(cmd)",
      'extern "C" char* ex_hermes_debugger_next_event(',
    ],
  ].map(([surfaceName, symbol, operationToken, nextSignature]) =>
    Object.freeze({
      surfaceName,
      reasonCode: "debugger-void-control",
      assertions: [
        {
          path: "src/engine/hermes_runtime_debugger.cc",
          region: {
            start: `extern "C" void ${symbol}(`,
            end: nextSignature,
          },
          tokens: [`extern "C" void ${symbol}(`, operationToken],
        },
        {
          path: "src/engine/hermes_runtime_platform_windows.cc",
          tokens: [`extern "C" void ${symbol}(`],
        },
      ],
    }),
  ),
]);

function shape(
  output,
  alias,
  { mode = "all", sourceKind = "runtime", returnVariant = "default" } = {},
) {
  return { output, alias, mode, sourceKind, returnVariant };
}

function typedLogicalPathShapes(outputPrefix, aliasPrefix, options) {
  return [
    shape(`${outputPrefix}.schema`, `${aliasPrefix}.schema`, options),
    shape(
      `${outputPrefix}.sessionHandle`,
      `${aliasPrefix}.sessionHandle`,
      options,
    ),
    shape(`${outputPrefix}.virtualPath`, `${aliasPrefix}.virtualPath`, options),
    shape(`${outputPrefix}.logicalPath`, `${aliasPrefix}.logicalPath`, options),
    shape(
      `${outputPrefix}.logicalPath.root`,
      `${aliasPrefix}.logicalPath.root`,
      options,
    ),
    shape(
      `${outputPrefix}.logicalPath.components`,
      `${aliasPrefix}.logicalPath.components`,
      options,
    ),
    shape(
      `${outputPrefix}.logicalPath.components[]`,
      `${aliasPrefix}.logicalPath.components[]`,
      options,
    ),
    shape(
      `${outputPrefix}.logicalPath.components[].encoding`,
      `${aliasPrefix}.logicalPath.components[].encoding`,
      options,
    ),
    shape(
      `${outputPrefix}.logicalPath.components[].value`,
      `${aliasPrefix}.logicalPath.components[].value`,
      options,
    ),
    shape(
      `${outputPrefix}.logicalPath.hostBound`,
      `${aliasPrefix}.logicalPath.hostBound`,
      options,
    ),
    shape(
      `${outputPrefix}.bindingOwner`,
      `${aliasPrefix}.bindingOwner`,
      options,
    ),
    shape(
      `${outputPrefix}.bindingOwner.kind`,
      `${aliasPrefix}.bindingOwner.kind`,
      options,
    ),
    shape(
      `${outputPrefix}.bindingOwner.name`,
      `${aliasPrefix}.bindingOwner.name`,
      options,
    ),
    shape(
      `${outputPrefix}.bindingOwner.integrity`,
      `${aliasPrefix}.bindingOwner.integrity`,
      options,
    ),
    shape(
      `${outputPrefix}.bindingOwner.locator`,
      `${aliasPrefix}.bindingOwner.locator`,
      options,
    ),
  ];
}

function privateResolverPathShapes(outputPrefix, aliasPrefix) {
  const options = {
    sourceKind: "bridge",
    returnVariant: "private-compat",
  };
  return [
    shape(outputPrefix, aliasPrefix, options),
    shape(`${outputPrefix}.schema`, `${aliasPrefix}.schema`, options),
    shape(
      `${outputPrefix}.sessionHandle`,
      `${aliasPrefix}.sessionHandle`,
      options,
    ),
    shape(`${outputPrefix}.handle`, `${aliasPrefix}.handle`, options),
    shape(`${outputPrefix}.virtualPath`, `${aliasPrefix}.virtualPath`, options),
  ];
}

export function resolverRecordShapes(surfaceName) {
  const recordShapes = [
    shape("[[return]]", surfaceName, { sourceKind: "native-op" }),
    shape("field:schema", "resolver.schema", {
      sourceKind: "bridge",
      returnVariant: "record",
    }),
    shape("field:id", "resolver.id", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
    shape("field:id", "resolver.id", {
      sourceKind: "bridge",
      returnVariant: "builtin",
    }),
    shape("field:kind", "resolver.kind", {
      sourceKind: "bridge",
      returnVariant: "record",
    }),
    shape("field:error", "resolver.error", {
      sourceKind: "bridge",
      returnVariant: "refused",
    }),
    shape("field:errorCode", "resolver.errorCode", {
      sourceKind: "bridge",
      returnVariant: "refused",
    }),
    shape("field:path", "resolver.path", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
    ...typedLogicalPathShapes("field:path", "resolver.path", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
    ...privateResolverPathShapes("field:path", "resolver.path"),
    shape("field:pkgName", "resolver.pkgName", {
      sourceKind: "bridge",
      returnVariant: "package",
    }),
    shape("field:pkgRoot", "resolver.pkgRoot", {
      sourceKind: "bridge",
      returnVariant: "package",
    }),
    ...typedLogicalPathShapes("field:pkgRoot", "resolver.pkgRoot", {
      sourceKind: "bridge",
      returnVariant: "package",
    }),
    ...privateResolverPathShapes("field:pkgRoot", "resolver.pkgRoot"),
    shape("field:pkgVersion", "resolver.pkgVersion", {
      sourceKind: "bridge",
      returnVariant: "package",
    }),
    shape("field:pkgIntegrity", "resolver.pkgIntegrity", {
      sourceKind: "bridge",
      returnVariant: "package",
    }),
    shape("field:sourceId", "resolver.sourceId", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
    shape("field:sourceLabel", "resolver.sourceLabel", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
    shape("field:virtualPath", "resolver.virtualPath", {
      sourceKind: "bridge",
      returnVariant: "file-backed",
    }),
  ];
  if (!surfaceName.endsWith("Meta")) {
    recordShapes.push(
      shape("field:source", "resolver.source", {
        sourceKind: "bridge",
        returnVariant: "file-backed",
      }),
    );
  }
  return recordShapes;
}

export function modulePackageRootShapes() {
  const options = { sourceKind: "package", returnVariant: "present" };
  return [
    shape("field:__exactPackageRoot", "module.__exactPackageRoot", options),
    ...typedLogicalPathShapes(
      "field:__exactPackageRoot",
      "module.__exactPackageRoot",
      options,
    ),
  ];
}

const VFS_HOST_ABI_NAMES = Object.freeze([
  "ex_host_vfs_bind_runtime",
  "ex_host_vfs_chdir",
  "ex_host_vfs_get_cwd",
  "ex_host_vfs_resolve_path",
  "ex_host_vfs_unbind_runtime",
]);

const LEGACY_HOST_PATH_OUTPUT_NAMES = Object.freeze([
  "ex_host_fs_mkdir_recursive_result",
  "ex_host_fs_mkdtemp",
  "ex_host_fs_realpath",
]);

// These compatibility symbols return physical spellings only when the Host is
// unarmed. Their armed behavior is a source-pinned EPERM refusal before lookup,
// randomness, or mutation, so one all/default row would conflate incompatible
// value classes.
// @ref LLP 0023#6-path-bearing-observables
export function legacyHostPathOutputShapes(surfaceName) {
  if (!LEGACY_HOST_PATH_OUTPUT_NAMES.includes(surfaceName)) {
    throw new Error(`unknown legacy Host path output ${surfaceName}`);
  }
  return [
    shape("[[return]]", surfaceName, {
      mode: "unarmed",
      sourceKind: "host-abi",
      returnVariant: "success",
    }),
    shape("[[return]]", surfaceName, {
      mode: "unarmed",
      sourceKind: "host-abi",
      returnVariant: "error",
    }),
    shape("[[return]]", surfaceName, {
      mode: "armed",
      sourceKind: "host-abi",
      returnVariant: "refused",
    }),
  ];
}

// @ref LLP 0023#6-path-bearing-observables — the VFS callbacks remain native
// private, while their separately typed virtual outputs are cataloged so a
// future JavaScript projection cannot silently inherit a backing path.
export function vfsHostAbiShapes(surfaceName) {
  if (!VFS_HOST_ABI_NAMES.includes(surfaceName)) {
    throw new Error(`unknown private VFS host ABI ${surfaceName}`);
  }
  const shapes = [
    shape("[[return]]", surfaceName, {
      mode: "javascript",
      sourceKind: "host-abi",
      returnVariant: "absent",
    }),
  ];
  if (
    surfaceName === "ex_host_vfs_chdir" ||
    surfaceName === "ex_host_vfs_get_cwd" ||
    surfaceName === "ex_host_vfs_resolve_path"
  ) {
    shapes.push(
      shape("out:virtual", `${surfaceName}.out_virtual`, {
        mode: "private-native",
        sourceKind: "host-abi",
        returnVariant: "success",
      }),
    );
  }
  if (surfaceName === "ex_host_vfs_resolve_path") {
    shapes.push(
      shape("out:backing", `${surfaceName}.out_backing`, {
        mode: "javascript",
        sourceKind: "host-abi",
        returnVariant: "absent",
      }),
    );
  }
  return shapes;
}

// These recipes describe structured outputs the source inventory cannot infer
// from an export descriptor alone. They intentionally contain no disposition
// or expected value. Each recipe is asserted against the named source bytes;
// the separately committed policy owns every classification decision.
const TAMED_EVALUATOR_MARKER_ALIASES = Object.freeze([
  "globalThis.Function.__ibexTamed",
  "globalThis.eval.__ibexTamed",
  "Object.getPrototypeOf(function*(){}).constructor.__ibexTamed",
  "Object.getPrototypeOf(async function(){}).constructor.__ibexTamed",
]);

function sameAsArgumentZeroShapes(surfaceName) {
  return ["primitive-sentinel", "object-sentinel"].map((mode) =>
    shape("[[return]]", surfaceName, {
      mode,
      sourceKind: "native-op",
      returnVariant: "same-as-argument-0",
    }),
  );
}

const STRUCTURED_OUTPUT_RECIPES = Object.freeze([
  Object.freeze({
    surfaceName: "global:process.argv",
    assertions: [
      { path: "src/builtins/process.js", tokens: ["argv", "execArgv"] },
    ],
    shapes: [
      shape("index:0", "process.argv[0]", { mode: "file" }),
      shape("index:1", "process.argv[1]", { mode: "file" }),
      shape("index:0", "process.argv[0]", { mode: "program-stdin" }),
      shape("index:1", "process.argv[1]", {
        mode: "program-stdin",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "process.argv[0]", { mode: "eval" }),
      shape("index:1", "process.argv[1]", {
        mode: "eval",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "process.argv[0]", { mode: "repl" }),
      shape("index:1", "process.argv[1]", {
        mode: "repl",
        returnVariant: "absent",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "global:process.execArgv",
    assertions: [
      {
        path: "src/builtins/process.js",
        tokens: ["Array.isArray(proc.execArgv)", "__exactExecArgv"],
      },
    ],
    shapes: [shape("array-items", "process.execArgv[]")],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:exact_process:execArgv",
    assertions: [
      {
        path: "src/builtins/process.js",
        tokens: ["Array.isArray(process.execArgv)", "String(execArgv[ai])"],
      },
    ],
    shapes: [shape("array-items", "exact:process.execArgv[]")],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "global:Exact.argv",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["argv", "process.argv"],
      },
    ],
    shapes: [
      shape("index:0", "Exact.argv[0]", { mode: "file" }),
      shape("index:1", "Exact.argv[1]", { mode: "file" }),
      shape("index:0", "Exact.argv[0]", { mode: "program-stdin" }),
      shape("index:1", "Exact.argv[1]", {
        mode: "program-stdin",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "Exact.argv[0]", { mode: "eval" }),
      shape("index:1", "Exact.argv[1]", {
        mode: "eval",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "Exact.argv[0]", { mode: "repl" }),
      shape("index:1", "Exact.argv[1]", {
        mode: "repl",
        returnVariant: "absent",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "global:Bun.argv",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["g.Bun = E", "argv"],
      },
    ],
    shapes: [
      shape("index:0", "Bun.argv[0]", { mode: "file" }),
      shape("index:1", "Bun.argv[1]", { mode: "file" }),
      shape("index:0", "Bun.argv[0]", { mode: "program-stdin" }),
      shape("index:1", "Bun.argv[1]", {
        mode: "program-stdin",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "Bun.argv[0]", { mode: "eval" }),
      shape("index:1", "Bun.argv[1]", {
        mode: "eval",
        returnVariant: "argument-or-absent",
      }),
      shape("index:0", "Bun.argv[0]", { mode: "repl" }),
      shape("index:1", "Bun.argv[1]", {
        mode: "repl",
        returnVariant: "absent",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "global:Exact.main",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["E.main =", "process.argv[1]"],
      },
    ],
    shapes: [
      shape("[[return]]", "Exact.main", {
        mode: "file",
        returnVariant: "entry",
      }),
      shape("[[return]]", "Exact.main", {
        mode: "program-stdin",
        returnVariant: "argument-or-empty",
      }),
      shape("[[return]]", "Exact.main", {
        mode: "eval",
        returnVariant: "argument-or-empty",
      }),
      shape("[[return]]", "Exact.main", {
        mode: "repl",
        returnVariant: "empty",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "global:Bun.main",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["g.Bun = E", "process.argv[1]"],
      },
    ],
    shapes: [
      shape("[[return]]", "Bun.main", { mode: "file", returnVariant: "entry" }),
      shape("[[return]]", "Bun.main", {
        mode: "program-stdin",
        returnVariant: "argument-or-empty",
      }),
      shape("[[return]]", "Bun.main", {
        mode: "eval",
        returnVariant: "argument-or-empty",
      }),
      shape("[[return]]", "Bun.main", { mode: "repl", returnVariant: "empty" }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "__filename",
    assertions: [
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: ["__filename", "filename"],
      },
    ],
    shapes: [
      shape("[[return]]", "__filename", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("[[return]]", "__filename", {
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "__dirname",
    assertions: [
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: ["__dirname", "dirname"],
      },
    ],
    shapes: [
      shape("[[return]]", "__dirname", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("[[return]]", "__dirname", {
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_os:userInfo",
    assertions: [
      {
        path: "src/builtins/os.js",
        tokens: ["function userInfo", "homedir", "shell"],
      },
    ],
    shapes: [
      shape("field:homedir", "os.userInfo().homedir"),
      shape("field:shell", "os.userInfo().shell"),
      shape("[[return]]", "os.userInfo()"),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "global:require.resolve",
    assertions: [
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: ["require.resolve", "record.id"],
      },
    ],
    shapes: [
      shape("[[return]]", "require.resolve", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("[[return]]", "require.resolve", {
        sourceKind: "builtin",
        returnVariant: "builtin",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "module-loader-install",
    assertions: [
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: ["importMeta", "filename", "dirname", "__exactPackageRoot"],
      },
    ],
    shapes: [
      shape("field:url", "import.meta.url", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:url", "import.meta.url", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "ibex-stdin",
      }),
      shape("field:url", "import.meta.url", {
        mode: "eval",
        sourceKind: "synthetic",
        returnVariant: "ibex-eval",
      }),
      shape("field:url", "import.meta.url", {
        mode: "repl",
        sourceKind: "synthetic",
        returnVariant: "repl-cell",
      }),
      shape("field:path", "import.meta.path", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:path", "import.meta.path", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
      shape("field:filename", "import.meta.filename", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:filename", "import.meta.filename", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
      shape("field:dirname", "import.meta.dirname", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:dirname", "import.meta.dirname", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
      shape("field:dirname", "import.meta.dir", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:dirname", "import.meta.dir", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "absent",
      }),
      shape("field:file", "import.meta.file", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("field:file", "import.meta.file", {
        mode: "program-stdin",
        sourceKind: "synthetic",
        returnVariant: "empty",
      }),
      shape("field:id", "module.id", { sourceKind: "file" }),
      shape("field:filename", "module.filename", { sourceKind: "file" }),
      shape("field:path", "module.path", { sourceKind: "file" }),
      shape("field:paths[]", "module.paths[]", { sourceKind: "file" }),
      shape("field:parent", "module.parent", { sourceKind: "file" }),
      shape("field:children", "module.children", { sourceKind: "file" }),
      ...modulePackageRootShapes(),
      shape("field:__exactPackageRoot", "module.__exactPackageRoot", {
        sourceKind: "project",
        returnVariant: "absent",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "export:node_fs:default",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: [
          "fsErr.path = resolvedPath",
          "fsErr.filename = resolvedFilename",
          "fsErr.dest = resolvedDest",
        ],
      },
    ],
    shapes: [
      shape("throw-field:path", "error.path", { returnVariant: "fs-error" }),
      shape("throw-field:filename", "error.filename", {
        returnVariant: "fs-error",
      }),
      shape("throw-field:dest", "error.dest", { returnVariant: "fs-error" }),
    ],
  }),
  Object.freeze({
    surfaceName: "module-loader-install",
    assertions: [
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: ["sourceURL=", "filename"],
      },
      {
        path: "src/bin/ibex/engine/hermes.rs",
        tokens: ["rewrite_staged_source_map", '.get_mut("sources")'],
      },
      {
        path: "src/engine/evaluation.rs",
        tokens: ["pub struct SourceLabel", "repl:", "ibex:stdin", "ibex:eval"],
      },
    ],
    shapes: [
      shape("stack-frame:source", "Error.stack frame source", {
        sourceKind: "runtime-owned",
        returnVariant: "builtin-or-runtime",
      }),
      shape("source-map:sources[]", "source-map.sources[]", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("source-map:sources[]", "source-map.sources[]", {
        sourceKind: "synthetic",
        returnVariant: "source-label",
      }),
      shape("source-map:sourceURL", "sourceURL", {
        sourceKind: "file",
        returnVariant: "file-backed",
      }),
      shape("source-map:sourceURL", "sourceURL", {
        sourceKind: "synthetic",
        returnVariant: "source-label",
      }),
    ],
  }),
  ...[
    ["__exactModuleResolve", "ex_host_module_resolve"],
    ["__exactModuleResolveMeta", "ex_host_module_resolve_meta"],
    ["__exactNativeModuleResolve", "ex_host_module_resolve"],
    ["__exactNativeModuleResolveMeta", "ex_host_module_resolve_meta"],
  ].map(([surfaceName, abiName]) =>
    Object.freeze({
      surfaceName,
      assertions: [
        {
          path: "src/host/abi.rs",
          tokens: [
            abiName,
            "ex_host_session_static_import_resolve",
            "ibex/module-resolution/1",
            "resolver_package_root",
            "resolver_path",
            "private_resolver_package_root",
            "private_resolver_path",
            "pkgIntegrity",
            "pkgName",
            "pkgRoot",
            "pkgVersion",
            "sourceId",
            "sourceLabel",
            "virtualPath",
          ],
        },
        {
          path: "src/engine/hermes_runtime.cc",
          tokens: [surfaceName, abiName],
        },
      ],
      shapes: resolverRecordShapes(surfaceName),
      replaceDefault: true,
    }),
  ),
  ...VFS_HOST_ABI_NAMES.map((surfaceName) =>
    Object.freeze({
      surfaceName,
      assertions: [
        {
          path: "src/host/abi.rs",
          tokens: [surfaceName, "runtime_vfs_session"],
        },
        {
          path: "src/engine/hermes_runtime.cc",
          tokens: [surfaceName],
        },
      ],
      shapes: vfsHostAbiShapes(surfaceName),
    }),
  ),
  ...LEGACY_HOST_PATH_OUTPUT_NAMES.map((surfaceName) =>
    Object.freeze({
      surfaceName,
      assertions: [
        {
          path: "src/host/abi.rs",
          tokens: [
            surfaceName,
            "refuse_armed_legacy_path_output",
            "set_fs_error_code(libc::EPERM)",
          ],
        },
      ],
      shapes: legacyHostPathOutputShapes(surfaceName),
      replaceDefault: true,
    }),
  ),
  Object.freeze({
    surfaceName: "ex_host_fs_readdir",
    assertions: [
      {
        path: "src/host/abi.rs",
        tokens: [
          "ex_host_fs_readdir",
          "std::fs::read_dir",
          "file_name().to_string_lossy().to_string()",
          "serde_json::to_string(&names)",
        ],
      },
    ],
    shapes: [
      shape("array-items", "ex_host_fs_readdir[]", {
        sourceKind: "host-abi",
        returnVariant: "success",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "export:node_fs:readlink",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function readlink", "__exactReadlink"],
      },
    ],
    shapes: [
      shape("[[return]]", "fs.readlink", { returnVariant: "mapped" }),
      shape("[[return]]", "fs.readlink", { returnVariant: "unmappable" }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs:readlinkSync",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function readlinkSync", "__exactReadlink"],
      },
    ],
    shapes: [
      shape("[[return]]", "fs.readlinkSync", { returnVariant: "mapped" }),
      shape("[[return]]", "fs.readlinkSync", { returnVariant: "unmappable" }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs_promises:readlink",
    assertions: [
      { path: "src/builtins/fs.js", tokens: ["readlink", "promises"] },
    ],
    shapes: [
      shape("[[return]]", "fs.promises.readlink", { returnVariant: "mapped" }),
      shape("[[return]]", "fs.promises.readlink", {
        returnVariant: "unmappable",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs:glob",
    assertions: [
      { path: "src/builtins/fs.js", tokens: ["function glob", "globSync"] },
    ],
    shapes: [
      shape("array-items", "fs.glob", { returnVariant: "relative-pattern" }),
      shape("array-items", "fs.glob", { returnVariant: "absolute-pattern" }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs:globSync",
    assertions: [
      { path: "src/builtins/fs.js", tokens: ["function globSync", "glob"] },
    ],
    shapes: [
      shape("array-items", "fs.globSync", {
        returnVariant: "relative-pattern",
      }),
      shape("array-items", "fs.globSync", {
        returnVariant: "absolute-pattern",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_path:posix",
    assertions: [
      {
        path: "src/builtins/path.js",
        tokens: ["posix", "resolve", "relative"],
      },
    ],
    shapes: [
      shape("field:resolve", "path.posix.resolve"),
      shape("field:relative", "path.posix.relative"),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_path:win32",
    assertions: [
      {
        path: "src/builtins/path.js",
        tokens: ["win32", "resolve", "relative"],
      },
    ],
    shapes: [
      shape("field:resolve", "path.win32.resolve", {
        sourceKind: "foreign-dialect",
      }),
      shape("field:relative", "path.win32.relative", {
        sourceKind: "foreign-dialect",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs:watch",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function watch", "recursive", "filename"],
      },
    ],
    shapes: [
      shape("callback:filename", "fs.watch event path", {
        returnVariant: "non-recursive",
      }),
      shape("callback:filename", "fs.watch event path", {
        returnVariant: "recursive",
      }),
    ],
    replaceDefault: true,
  }),
  Object.freeze({
    surfaceName: "export:node_fs:Dirent",
    assertions: [
      { path: "src/builtins/fs.js", tokens: ["function Dirent", "parentPath"] },
    ],
    shapes: [
      shape("field:parentPath", "Dirent.parentPath"),
      shape("field:path", "Dirent.path"),
      shape("field:name", "Dirent.name"),
    ],
  }),
  Object.freeze({
    surfaceName: "export:node_fs_promises:FileHandle",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function FileHandlePromise", "this.path"],
      },
    ],
    shapes: [shape("field:path", "FileHandle.path")],
  }),
  Object.freeze({
    surfaceName: "export:node_fs:ReadStream",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function ReadStream", "rs.path"],
      },
    ],
    shapes: [shape("field:path", "ReadStream.path")],
  }),
  Object.freeze({
    surfaceName: "export:node_fs:WriteStream",
    assertions: [
      {
        path: "src/builtins/fs.js",
        tokens: ["function WriteStream", "ws.path"],
      },
    ],
    shapes: [shape("field:path", "WriteStream.path")],
  }),
  // These globals are JavaScript receivers for native delivery. Their
  // callback arguments cross into JavaScript and are output channels; each
  // C++ call site discards the JavaScript callback's return value, so no
  // `[[return]]` row belongs to the five delivery surfaces below.
  Object.freeze({
    surfaceName: "__exactDispatchEvent",
    assertions: [
      {
        path: "src/engine/hermes_runtime_ios.cc",
        region: {
          start: 'extern "C" int ex_hermes_dispatch_event(',
          end: "// =============================================================================",
        },
        tokens: [
          'getProperty(rt, "__exactDispatchEvent")',
          "parseJsonValue(rt, payload_json)",
          "facebook::jsi::Value(static_cast<double>(handler_id))",
          "std::move(payload)",
          "return 0;",
        ],
      },
      {
        path: "src/engine/hermes_runtime_ios.cc",
        region: {
          start: 'extern "C" int32_t ex_hermes_dispatch_event_attested_v1(',
          end: "// =============================================================================",
        },
        tokens: [
          "runtime->clock_i_dispatcher->call(",
          "facebook::jsi::Value(static_cast<double>(handler_id))",
          "std::move(payload)",
          "std::move(attestor)",
          "return EX_HERMES_CLOCK_I_DISPATCH_OK_V1;",
        ],
      },
    ],
    shapes: [
      shape("callback:dispatch/0", "__exactDispatchEvent.handlerId", {
        mode: "json-payload",
        sourceKind: "native-op",
        returnVariant: "number",
      }),
      shape("callback:dispatch/1", "__exactDispatchEvent.payload", {
        mode: "json-payload",
        sourceKind: "native-op",
        returnVariant: "json-value",
      }),
      shape("callback:dispatch/1", "__exactDispatchEvent.payload", {
        mode: "empty-payload",
        sourceKind: "native-op",
        returnVariant: "undefined",
      }),
      shape(
        "callback:dispatch/2",
        "__exactDispatchEvent.attestClockICarrier",
        {
          mode: "attested",
          sourceKind: "native-op",
          returnVariant: "call-scoped-host-function",
        },
      ),
    ],
  }),
  Object.freeze({
    surfaceName: "__exactModuleEvent",
    assertions: [
      {
        path: "src/engine/hermes_runtime_ios.cc",
        region: {
          start: "static int emit_module_event_impl(",
          end: "// Emit a module event to JS (for native -> JS events)",
        },
        tokens: [
          'getProperty(rt, "__exactModuleEvent")',
          "facebook::jsi::String::createFromUtf8(rt, module_name)",
          "facebook::jsi::String::createFromUtf8(rt, event_name)",
          "facebook::jsi::Value(static_cast<double>(*node_id))",
          'getPropertyAsFunction(rt, "Uint8Array")',
          "std::move(payloadArray)",
          "handler.call(rt, std::move(moduleStr), std::move(eventStr));",
        ],
      },
      {
        path: "src/engine/hermes_runtime_ios.cc",
        region: {
          start: 'extern "C" int ex_hermes_emit_module_event(',
          end: 'extern "C" int ex_hermes_dispatch_event(',
        },
        tokens: [
          'extern "C" int ex_hermes_emit_module_event(',
          'extern "C" int ex_hermes_emit_module_view_event(',
          "nullptr,",
          "&node_id,",
          "payload_len);",
        ],
      },
    ],
    shapes: [
      ...["module-payload", "module-empty"].flatMap((mode) => [
        shape("callback:module-event/0", "__exactModuleEvent.moduleName", {
          mode,
          sourceKind: "native-op",
          returnVariant: "string",
        }),
        shape("callback:module-event/1", "__exactModuleEvent.eventName", {
          mode,
          sourceKind: "native-op",
          returnVariant: "string",
        }),
        shape("callback:module-event/2", "__exactModuleEvent.payload", {
          mode,
          sourceKind: "native-op",
          returnVariant: mode === "module-payload" ? "uint8-array" : "absent",
        }),
      ]),
      ...["view-payload", "view-empty"].flatMap((mode) => [
        shape("callback:module-view-event/0", "__exactModuleEvent.moduleName", {
          mode,
          sourceKind: "native-op",
          returnVariant: "string",
        }),
        shape("callback:module-view-event/1", "__exactModuleEvent.eventName", {
          mode,
          sourceKind: "native-op",
          returnVariant: "string",
        }),
        shape("callback:module-view-event/2", "__exactModuleEvent.nodeId", {
          mode,
          sourceKind: "native-op",
          returnVariant: "number",
        }),
        shape("callback:module-view-event/3", "__exactModuleEvent.payload", {
          mode,
          sourceKind: "native-op",
          returnVariant: mode === "view-payload" ? "uint8-array" : "absent",
        }),
      ]),
    ],
  }),
  Object.freeze({
    surfaceName: "__exactRunOnJS",
    assertions: [
      {
        path: "src/engine/hermes_runtime_worklet.cc",
        region: {
          start: 'extern "C" int ex_hermes_dispatch_worklet_calls(',
          end: 'extern "C" int ex_hermes_dispatch_worklet_json_batch(',
        },
        tokens: [
          'getProperty(rt, "__exactRunOnJS")',
          '"sourceIdentity"',
          '"sourceSequence"',
          '"generation"',
          "Value(static_cast<double>(call.callback_identity))",
          "Value(static_cast<double>(call.arguments[argument_index]))",
          "(void)dispatcher.call(",
          "(*out_delivered)++;",
        ],
      },
      {
        path: "src/engine/mod.rs",
        tokens: [
          "fn motion_worklet_typed_abi_captures_and_run_on_js_are_bounded()",
          "globalThis.__exactRunOnJS=function(id,meta,a,b)",
          "ex_hermes_dispatch_worklet_calls(",
          "assert_eq!(delivered, 256)",
          "__runOnJSSeen.length",
        ],
      },
    ],
    shapes: [
      shape("callback:run-on-js/0", "__exactRunOnJS.callbackIdentity", {
        mode: "bounded-batch",
        sourceKind: "native-op",
        returnVariant: "number",
      }),
      shape("callback:run-on-js/1", "__exactRunOnJS.metadata", {
        mode: "bounded-batch",
        sourceKind: "native-op",
        returnVariant: "metadata-object",
      }),
      ...["sourceIdentity", "sourceSequence", "generation"].map((field) =>
        shape(`callback:run-on-js/1.${field}`, `__exactRunOnJS.${field}`, {
          mode: "bounded-batch",
          sourceKind: "native-op",
          returnVariant: "u64-decimal-string",
        }),
      ),
      shape("callback:run-on-js/arguments[]", "__exactRunOnJS.arguments[]", {
        mode: "bounded-batch",
        sourceKind: "native-op",
        returnVariant: "finite-number",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "__exactScheduleOnAppRuntime",
    assertions: [
      {
        path: "src/engine/hermes_runtime_worklet.cc",
        region: {
          start: 'extern "C" int ex_hermes_dispatch_worklet_json_batch(',
          end: 'extern "C" int ex_hermes_dispatch_motion_rated_publish(',
        },
        tokens: [
          'getProperty(rt, "__exactScheduleOnAppRuntime")',
          "parseJsonValue(rt, encoded.c_str())",
          "(void)dispatcher.call(",
          "rt, std::move(batch), static_cast<double>(generation)",
          "return EX_WORKLET_OK;",
        ],
      },
      {
        path: "src/engine/mod.rs",
        tokens: [
          "fn schedule_on_app_runtime_json_dispatches_on_app_runtime()",
          "globalThis.__exactScheduleOnAppRuntime=function(batch,generation)",
          "ex_hermes_dispatch_worklet_json_batch(",
          "JSON.stringify(__scheduled)",
          "refreshBadge",
        ],
      },
    ],
    shapes: [
      shape(
        "callback:schedule-on-app-runtime/0",
        "__exactScheduleOnAppRuntime.batch",
        {
          mode: "json-batch",
          sourceKind: "native-op",
          returnVariant: "array",
        },
      ),
      shape(
        "callback:schedule-on-app-runtime/0[].name",
        "__exactScheduleOnAppRuntime.batch[].name",
        {
          mode: "json-batch",
          sourceKind: "native-op",
          returnVariant: "string",
        },
      ),
      shape(
        "callback:schedule-on-app-runtime/0[].args",
        "__exactScheduleOnAppRuntime.batch[].args",
        {
          mode: "json-batch",
          sourceKind: "native-op",
          returnVariant: "json-value",
        },
      ),
      shape(
        "callback:schedule-on-app-runtime/1",
        "__exactScheduleOnAppRuntime.generation",
        {
          mode: "json-batch",
          sourceKind: "native-op",
          returnVariant: "number",
        },
      ),
    ],
  }),
  Object.freeze({
    surfaceName: "__exactMotionRatedPublish",
    assertions: [
      {
        path: "src/engine/hermes_runtime_worklet.cc",
        tokens: [
          'extern "C" int ex_hermes_dispatch_motion_rated_publish(',
          'getProperty(rt, "__exactMotionRatedPublish")',
          "values.setValueAtIndex(",
          '"dirtyGeneration"',
          '"sampleTimeNs"',
          'metadata.setProperty(rt, "heartbeat"',
          'metadata.setProperty(rt, "programmatic"',
          "std::to_string(sample->channel_identity)",
          "std::move(values)",
          "std::move(metadata)",
          "(void)dispatcher.call(",
        ],
      },
      {
        path: "src/engine/mod.rs",
        tokens: [
          "fn motion_rated_publish_dispatches_fixed_sample_on_app_runtime()",
          "globalThis.__exactMotionRatedPublish=function(id,values,metadata)",
          "ex_hermes_dispatch_motion_rated_publish(app, &sample)",
          "JSON.stringify(__rated)",
          "dirtyGeneration",
          "sampleTimeNs",
        ],
      },
    ],
    shapes: [
      shape(
        "callback:motion-rated-publish/0",
        "__exactMotionRatedPublish.channelIdentity",
        {
          mode: "fixed-sample",
          sourceKind: "native-op",
          returnVariant: "u64-decimal-string",
        },
      ),
      shape(
        "callback:motion-rated-publish/1",
        "__exactMotionRatedPublish.values",
        {
          mode: "fixed-sample",
          sourceKind: "native-op",
          returnVariant: "array",
        },
      ),
      shape(
        "callback:motion-rated-publish/1[]",
        "__exactMotionRatedPublish.values[]",
        {
          mode: "fixed-sample",
          sourceKind: "native-op",
          returnVariant: "finite-number",
        },
      ),
      shape(
        "callback:motion-rated-publish/2",
        "__exactMotionRatedPublish.metadata",
        {
          mode: "fixed-sample",
          sourceKind: "native-op",
          returnVariant: "metadata-object",
        },
      ),
      ...["dirtyGeneration", "sampleTimeNs"].map((field) =>
        shape(
          `callback:motion-rated-publish/2.${field}`,
          `__exactMotionRatedPublish.${field}`,
          {
            mode: "fixed-sample",
            sourceKind: "native-op",
            returnVariant: "u64-decimal-string",
          },
        ),
      ),
      ...["heartbeat", "programmatic"].map((field) =>
        shape(
          `callback:motion-rated-publish/2.${field}`,
          `__exactMotionRatedPublish.${field}`,
          {
            mode: "fixed-sample",
            sourceKind: "native-op",
            returnVariant: "boolean",
          },
        ),
      ),
    ],
  }),
  Object.freeze({
    surfaceName: "__exactCancel",
    contextId: "javascript.package-call-loaded",
    assertions: [
      {
        path: "src/engine/hermes_runtime_fetch.cc",
        region: {
          start: 'PropNameID::forAscii(runtime, "__exactCancel")',
          end: 'promise.setProperty(runtime, "__exactCancel", std::move(cancelFn));',
        },
        tokens: [
          'PropNameID::forAscii(runtime, "__exactCancel")',
          "native_fetch_cancel(requestId, handle->runtime_nonce);",
          "return facebook::jsi::Value::undefined();",
          'promise.setProperty(runtime, "__exactCancel", std::move(cancelFn));',
        ],
      },
      {
        path: "packages/ibex-runtime-js/src/fetch/fetch.ts",
        tokens: [
          "type CancelableNativeResponsePromise",
          "__exactCancel?: () => void;",
          "typeof nativeFetchPromise.__exactCancel === 'function'",
          "cancelRequest = nativeCancel;",
        ],
      },
    ],
    shapes: [
      shape("[[return]]", "nativeFetchPromise.__exactCancel", {
        sourceKind: "native-op",
        returnVariant: "undefined",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "__exactNativeFreeze",
    contextId: "runtime.bootstrap-native-call-loaded",
    assertions: [
      {
        path: "patches/hermes/0005-native-compartment-refinements.patch",
        region: {
          start:
            "CallResult<HermesValue> exactNativeFreeze(void *, Runtime &runtime)",
          end: "return args.getArg(0);",
        },
        tokens: [
          "Handle<JSObject> obj = args.dyncastArg<JSObject>(0);",
          "JSObject::freeze(obj, runtime)",
          "return args.getArg(0);",
        ],
      },
      {
        path: "patches/hermes/0005-native-compartment-refinements.patch",
        region: {
          start: 'runtime, createASCIIRef("__exactNativeFreeze")',
          end: "exactNativeFreeze,",
        },
        tokens: [
          'runtime, createASCIIRef("__exactNativeFreeze")',
          "exactNativeFreeze,",
        ],
      },
    ],
    shapes: sameAsArgumentZeroShapes("__exactNativeFreeze"),
  }),
  Object.freeze({
    surfaceName: "__exactDeepFreeze",
    contextId: "runtime.bootstrap-native-call-loaded",
    assertions: [
      {
        path: "patches/hermes/0006-eval-binding-and-native-deep-freeze.patch",
        region: {
          start:
            "CallResult<HermesValue> exactDeepFreeze(void *, Runtime &runtime)",
          end: "return args.getArg(0);",
        },
        tokens: [
          "Handle<JSObject> obj = args.dyncastArg<JSObject>(0);",
          "exactDeepFreezeGraph(runtime, obj)",
          "return args.getArg(0);",
        ],
      },
      {
        path: "patches/hermes/0006-eval-binding-and-native-deep-freeze.patch",
        region: {
          start: 'runtime, createASCIIRef("__exactDeepFreeze")',
          end: "exactDeepFreeze,",
        },
        tokens: [
          'runtime, createASCIIRef("__exactDeepFreeze")',
          "exactDeepFreeze,",
        ],
      },
    ],
    shapes: sameAsArgumentZeroShapes("__exactDeepFreeze"),
  }),
  Object.freeze({
    surfaceName: "__exactSetCompartmentFor",
    contextId: "runtime.bootstrap-native-call-loaded",
    assertions: [
      {
        path: "patches/hermes/0004-native-compartment-globals.patch",
        tokens: [
          "CallResult<HermesValue> exactSetCompartmentFor(void *, Runtime &runtime)",
          "domain->setCompartmentGlobal(runtime, obj);",
          "return HermesValue::encodeBoolValue(true);",
          "return HermesValue::encodeBoolValue(false);",
          'createASCIIRef("__exactSetCompartmentFor")',
        ],
      },
      {
        path: "src/engine/bootstrap/module-loader.js",
        tokens: [
          "var __privSetCompartmentFor",
          "g.__exactSetCompartmentFor",
          "the loader is its only caller",
          "__privSetCompartmentFor(fn, compartment) !== true",
        ],
      },
      {
        path: "src/engine/hermes_runtime.cc",
        tokens: [
          "'__exactCheckImport', '__exactSetCompartmentFor'",
          "delete g[hatches[j]]",
        ],
      },
    ],
    shapes: [
      shape("[[return]]", "__privSetCompartmentFor", {
        sourceKind: "native-op",
        returnVariant: "boolean",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "__ibexLockedDown",
    assertions: [
      {
        path: "src/engine/hermes_runtime.cc",
        region: {
          start: "// @ref LLP 0013#mechanism-1 — Lockdown.",
          end: 'handle->runtime->evaluateJavaScript(buffer, "<lockdown>");',
        },
        tokens: [
          "if (handle->structural_lockdown) {",
          "if (g.__ibexLockedDown) return;",
          "defineProp(g, '__ibexLockedDown', { value: true",
        ],
      },
    ],
    shapes: [
      shape("[[value]]", "globalThis.__ibexLockedDown", {
        mode: "lockdown",
        sourceKind: "native-op",
        returnVariant: "true",
      }),
      shape("[[value]]", "globalThis.__ibexLockedDown", {
        mode: "no-lockdown",
        sourceKind: "native-op",
        returnVariant: "absent",
      }),
    ],
  }),
  Object.freeze({
    surfaceName: "__ibexTamed",
    assertions: [
      {
        path: "src/engine/hermes_runtime.cc",
        region: {
          start: "// @ref LLP 0013#mechanism-1 — Lockdown.",
          end: 'handle->runtime->evaluateJavaScript(buffer, "<lockdown>");',
        },
        tokens: [
          "if (handle->structural_lockdown) {",
          "tamedEvaluator.__ibexTamed = true;",
          "var tamedFunction = tameCtor(Function.prototype, 'Function');",
          "tameCtor(getProto(function*(){}), 'GeneratorFunction')",
          "tameCtor(getProto(async function(){}), 'AsyncFunction')",
          "var tamedEval = makeTamed('eval');",
        ],
      },
    ],
    shapes: TAMED_EVALUATOR_MARKER_ALIASES.flatMap((alias) => [
      shape("[[value]]", alias, {
        mode: "lockdown",
        sourceKind: "native-op",
        returnVariant: "true",
      }),
      shape("[[value]]", alias, {
        mode: "no-lockdown",
        sourceKind: "native-op",
        returnVariant: "absent",
      }),
    ]),
  }),
  Object.freeze({
    surfaceName: "global:Exact.file",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["defineExactValue('file'", "ExactFile", "this.name"],
      },
    ],
    shapes: [shape("field:name", "ExactFile.name")],
  }),
  Object.freeze({
    surfaceName: "global:Bun.file",
    assertions: [
      {
        path: "src/engine/bootstrap/exact-global.js",
        tokens: ["g.Bun = E", "ExactFile", "this.name"],
      },
    ],
    shapes: [shape("field:name", "Bun.ExactFile.name")],
  }),
]);

function implementationEvidenceByEdge(implementationRows) {
  const byEdge = new Map();
  for (const row of implementationRows) {
    const entry = byEdge.get(row.edgeId) ?? {
      observedKeys: new Set(),
      sourceRefs: new Set(),
    };
    entry.observedKeys.add(row.observedKey);
    row.sourceRefs.forEach((sourceRef) => entry.sourceRefs.add(sourceRef));
    byEdge.set(row.edgeId, entry);
  }
  return byEdge;
}

function sourceSurfaceMap(surfaces) {
  const rows = Array.isArray(surfaces) ? surfaces : surfaces?.surfaces;
  if (!Array.isArray(rows)) {
    throw new Error(
      "output catalog requires the live source surface inventory",
    );
  }
  const byObservedKey = new Map();
  for (const [index, surface] of rows.entries()) {
    const observedKey = `${surface?.kind}:${surface?.name}`;
    if (
      typeof surface?.kind !== "string" ||
      typeof surface?.name !== "string" ||
      surface.observedKey !== observedKey
    ) {
      throw new Error(
        `output catalog source surface ${index}: malformed observed identity`,
      );
    }
    if (byObservedKey.has(observedKey)) {
      throw new Error(
        `output catalog source inventory duplicates ${observedKey}`,
      );
    }
    byObservedKey.set(observedKey, surface);
  }
  return byObservedKey;
}

const SHARED_RUNTIME_GLOBAL_VALUE_SHAPES = new Set([
  "accessor",
  "callable",
  "data",
]);

function genericOutputContract(surface) {
  const metadata = surface.metadata ?? {};
  if (surface.kind === "builtin" && metadata.importReachability === "public") {
    if (metadata.surfaceType !== "export") {
      return { output: "[[binding]]", outputKind: "public-import" };
    }
    if (metadata.valueShape === "callable") {
      return { output: "[[return]]", outputKind: "public-invocation" };
    }
    return { output: "[[value]]", outputKind: "public-property-read" };
  }
  if (
    surface.kind === "native-op" &&
    metadata.surfaceType === "global-api" &&
    metadata.publicInvocation?.kind === "native-global-function"
  ) {
    return { output: "[[return]]", outputKind: "native-invocation" };
  }
  if (
    surface.kind === "native-op" &&
    metadata.surfaceType === "global-api" &&
    metadata.publicReadAccessSourceProven === true
  ) {
    const publicOutputAccess = metadata.publicOutputAccess;
    let alias;
    if (publicOutputAccess !== undefined) {
      exactKeys(
        publicOutputAccess,
        ["alias", "kind"],
        `${surface.observedKey}.publicOutputAccess`,
      );
      const expectedAlias =
        metadata.memberName === null || metadata.memberName === undefined
          ? metadata.globalName
          : `${metadata.globalName}.${metadata.memberName}`;
      if (
        publicOutputAccess.kind !== "property-read" ||
        publicOutputAccess.alias !== expectedAlias ||
        metadata.exportName !== expectedAlias ||
        metadata.valueShape === "callable"
      ) {
        throw new Error(
          `${surface.observedKey}: malformed source-bound public output access`,
        );
      }
      alias = publicOutputAccess.alias;
    }
    return metadata.valueShape === "callable"
      ? { output: "[[return]]", outputKind: "public-invocation" }
      : {
          output: "[[value]]",
          outputKind: "public-property-read",
          ...(alias === undefined ? {} : { alias }),
        };
  }
  if (
    surface.kind === "native-op" &&
    metadata.surfaceType === "global-api" &&
    metadata.sourceKey === "shared_runtime" &&
    metadata.publicReadAccessSourceProven !== true &&
    SHARED_RUNTIME_GLOBAL_VALUE_SHAPES.has(metadata.valueShape)
  ) {
    return metadata.valueShape === "callable"
      ? { output: "[[return]]", outputKind: "public-invocation" }
      : { output: "[[value]]", outputKind: "public-property-read" };
  }
  return null;
}

const CALLBACK_OUTPUT_DIRECTIONS = new Set([
  "javascript-to-native",
  "native-to-javascript",
]);
const CALLBACK_OUTPUT_ROLES = new Set(["error", "payload", "return"]);
const CALLBACK_OUTPUT_VALUE_SHAPES = new Set([
  "array-buffer",
  "boolean",
  "bytes",
  "error",
  "float32x4",
  "json-string",
  "json-value",
  "null",
  "number",
  "object",
  "string",
  "uint8-array",
  "undefined",
]);

function callbackOutputContracts(surface) {
  const metadata = surface.metadata ?? {};
  const schema = metadata.callbackOutputContractSchema;
  const contracts = metadata.callbackOutputContracts;
  if (schema === undefined && contracts === undefined) return [];
  if (
    surface.kind !== "callback" ||
    schema !== CALLBACK_OUTPUT_CONTRACT_SCHEMA ||
    !Array.isArray(contracts) ||
    contracts.length === 0
  ) {
    throw new Error(
      `${surface.observedKey}: malformed callback output contract metadata`,
    );
  }
  const sourceEvidence = new Set(surface.sourceRefs ?? []);
  const keys = new Set();
  return contracts.map((contract, index) => {
    const label = `${surface.observedKey}.callbackOutputContracts[${index}]`;
    exactKeys(
      contract,
      [
        "direction",
        "returnVariant",
        "role",
        "selector",
        "sourceRefs",
        "valueShape",
      ],
      label,
    );
    if (
      typeof contract.selector !== "string" ||
      !/^callback:[A-Za-z_$][A-Za-z0-9_$-]*\/(?:[0-9]+|return)$/u.test(
        contract.selector,
      ) ||
      typeof contract.returnVariant !== "string" ||
      !/^[a-z][a-z0-9-]*$/u.test(contract.returnVariant) ||
      !CALLBACK_OUTPUT_DIRECTIONS.has(contract.direction) ||
      !CALLBACK_OUTPUT_ROLES.has(contract.role) ||
      !CALLBACK_OUTPUT_VALUE_SHAPES.has(contract.valueShape) ||
      !Array.isArray(contract.sourceRefs) ||
      contract.sourceRefs.length === 0 ||
      contract.sourceRefs.some(
        (sourceRef) =>
          typeof sourceRef !== "string" ||
          sourceRef.length === 0 ||
          !sourceEvidence.has(sourceRef),
      ) ||
      canonicalJson(contract.sourceRefs) !==
        canonicalJson([...new Set(contract.sourceRefs)].sort(compareText))
    ) {
      throw new Error(`${label}: malformed callback output contract`);
    }
    const key = `${contract.selector}\0${contract.returnVariant}`;
    if (keys.has(key)) {
      throw new Error(
        `${surface.observedKey}: duplicate callback output ${contract.selector}:${contract.returnVariant}`,
      );
    }
    keys.add(key);
    return structuredClone(contract);
  });
}

function structuralReasonCode(surface, sourceAssertedContract) {
  const metadata = surface.metadata ?? {};
  if (sourceAssertedContract) {
    if (surface.kind !== "native-op") {
      throw new Error(
        `${surface.observedKey}: source-asserted native structural contract has the wrong surface kind`,
      );
    }
    return sourceAssertedContract.reasonCode;
  }
  if (
    surface.kind === "builtin" &&
    metadata.importReachability === "bootstrap-internal"
  ) {
    return "bootstrap-internal-builtin";
  }
  if (surface.kind === "cli") return "cli-structural-surface";
  if (surface.kind === "loader") return "loader-structural-route";
  if (surface.kind === "startup") return "startup-structural-route";
  if (
    surface.kind === "native-op" &&
    metadata.surfaceType === "native-network-backend"
  ) {
    return "native-network-backend";
  }
  if (
    surface.kind === "callback" &&
    metadata.evidenceType === "push-runtime-callback-producer"
  ) {
    return "callback-producer-provenance";
  }
  if (
    surface.kind === "callback" &&
    metadata.callbackOutputBoundary === "none"
  ) {
    return "callback-control-plane";
  }
  return null;
}

function unresolvedReasonCode(surface) {
  if (surface.kind === "callback") return "callback-payload-contract-missing";
  if (surface.kind === "host-abi") {
    return "host-abi-signature-contract-missing";
  }
  if (surface.kind === "native-op") {
    return surface.metadata?.surfaceType === "global-api"
      ? "native-global-reachability-contract-missing"
      : "native-surface-contract-missing";
  }
  return "output-contract-missing";
}

function surfaceAccount({
  edge,
  surface,
  implementation,
  recipeSurfaceIds,
  sourceAssertedStructuralContract,
}) {
  if (surface.kind === "host-abi") {
    const signatureAccount = deriveHostAbiOutputCatalogAccount(surface);
    const membershipComplete =
      signatureAccount.status === "output-bearing" &&
      signatureAccount.membershipUnresolved.length === 0;
    const signatureRefs = (surface.metadata?.outputContracts ?? []).map(
      (contract) => contract.sourceRef,
    );
    const sourceRefs = [
      ...new Set(signatureRefs.length > 0 ? signatureRefs : surface.sourceRefs),
    ].sort(compareText);
    if (sourceRefs.length === 0) {
      throw new Error(
        `output catalog account ${edge.id} has no host ABI signature evidence`,
      );
    }
    return {
      surfaceId: edge.id,
      status: signatureAccount.status,
      reasonCode: signatureAccount.reasonCode,
      sourceRefs,
      outputKinds: membershipComplete
        ? signatureAccount.outputChannels.map((channel) => channel.selector)
        : [],
    };
  }
  const callbackContracts = callbackOutputContracts(surface);
  const generic = genericOutputContract(surface);
  const structured = recipeSurfaceIds.has(edge.id);
  const outputKinds = [
    ...callbackContracts.map((contract) => `callback-${contract.role}`),
    ...(generic ? [generic.outputKind] : []),
    ...(structured ? ["structured-output"] : []),
  ];
  const canonicalOutputKinds = [...new Set(outputKinds)].sort(compareText);
  const structuralReason =
    callbackContracts.length > 0 || generic || structured
      ? null
      : structuralReasonCode(surface, sourceAssertedStructuralContract);
  const status =
    callbackContracts.length > 0 || generic || structured
      ? "output-bearing"
      : structuralReason
        ? "structural-only"
        : "unresolved";
  const sourceRefs = [
    ...new Set([
      ...(surface.sourceRefs ?? []),
      ...implementation.sourceRefs,
      ...(sourceAssertedStructuralContract?.sourceRefs ?? []),
    ]),
  ].sort(compareText);
  if (sourceRefs.length === 0) {
    throw new Error(`output catalog account ${edge.id} has no source evidence`);
  }
  return {
    surfaceId: edge.id,
    status,
    reasonCode:
      status === "output-bearing"
        ? callbackContracts.length > 0
          ? "source-derived-callback-output"
          : structured && !generic
            ? "source-asserted-structured-output"
            : "source-derived-public-output"
        : status === "structural-only"
          ? structuralReason
          : unresolvedReasonCode(surface),
    sourceRefs,
    outputKinds: canonicalOutputKinds,
  };
}

export function validateOutputShapeCatalogAccounts({
  coverage,
  surfaceAccounts,
  rows,
  parameterizedOutputBindings = [],
  parameterizedOutputEvidence = [],
  promotionStatus = "unpromotable",
}) {
  if (
    !Array.isArray(surfaceAccounts) ||
    !Array.isArray(rows) ||
    !Array.isArray(parameterizedOutputBindings) ||
    !Array.isArray(parameterizedOutputEvidence)
  ) {
    throw new Error("output catalog accounts and rows must be arrays");
  }
  assertUniqueRows(rows, "output shape catalog rows");
  const coverageIds = coverage
    ? coverage.edges.map((edge) => edge.id)
    : surfaceAccounts.map((account) => account.surfaceId);
  if (new Set(coverageIds).size !== coverageIds.length) {
    throw new Error("output catalog coverage ids are not unique");
  }
  const parameterizedById = new Map();
  for (const [index, binding] of parameterizedOutputBindings.entries()) {
    exactKeys(
      binding,
      [
        "bindingSchema",
        "surfaceId",
        "surfaceName",
        "status",
        "reasonCode",
        "sourceRefs",
        "outputKinds",
        "accountSchema",
        "accountSetSource",
        "binding",
        "terminalSurfaces",
        "ordinaryCatalogRows",
      ],
      `parameterized output binding ${index}`,
    );
    if (
      binding.status !== "output-bearing" ||
      binding.ordinaryCatalogRows !== "forbidden" ||
      typeof binding.bindingSchema !== "string" ||
      typeof binding.surfaceId !== "string" ||
      typeof binding.surfaceName !== "string" ||
      typeof binding.reasonCode !== "string" ||
      typeof binding.accountSchema !== "string" ||
      typeof binding.accountSetSource !== "string" ||
      typeof binding.binding !== "string" ||
      binding.terminalSurfaces?.scalarRead?.name !== "__exactGetEnv" ||
      binding.terminalSurfaces?.scalarRead?.readSurface !== 0 ||
      binding.terminalSurfaces?.enumerationRead?.name !== "__exactGetAllEnv" ||
      binding.terminalSurfaces?.enumerationRead?.readSurface !== 1 ||
      binding.terminalSurfaces?.write?.name !== "__exactSetEnv" ||
      [
        binding.terminalSurfaces.scalarRead.surfaceId,
        binding.terminalSurfaces.enumerationRead.surfaceId,
        binding.terminalSurfaces.write.surfaceId,
      ].some(
        (surfaceId) =>
          typeof surfaceId !== "string" ||
          !/^surface\.[a-z0-9.]+$/u.test(surfaceId),
      ) ||
      !Array.isArray(binding.sourceRefs) ||
      binding.sourceRefs.length === 0 ||
      !Array.isArray(binding.outputKinds) ||
      binding.outputKinds.length === 0 ||
      canonicalJson(binding.sourceRefs) !==
        canonicalJson([...new Set(binding.sourceRefs)].sort(compareText)) ||
      canonicalJson(binding.outputKinds) !==
        canonicalJson([...new Set(binding.outputKinds)].sort(compareText)) ||
      parameterizedById.has(binding.surfaceId)
    ) {
      throw new Error(
        `parameterized output binding ${index}: malformed binding`,
      );
    }
    parameterizedById.set(binding.surfaceId, binding);
  }
  const accountsById = new Map();
  for (const [index, account] of surfaceAccounts.entries()) {
    exactKeys(
      account,
      ["surfaceId", "status", "reasonCode", "sourceRefs", "outputKinds"],
      `output surface account ${index}`,
    );
    if (
      typeof account.surfaceId !== "string" ||
      !/^surface\.[a-z0-9.]+$/u.test(account.surfaceId) ||
      !new Set(["output-bearing", "structural-only", "unresolved"]).has(
        account.status,
      ) ||
      typeof account.reasonCode !== "string" ||
      account.reasonCode.length === 0 ||
      !Array.isArray(account.sourceRefs) ||
      account.sourceRefs.length === 0 ||
      !Array.isArray(account.outputKinds)
    ) {
      throw new Error(`output surface account ${index}: malformed account`);
    }
    for (const [field, values] of [
      ["sourceRefs", account.sourceRefs],
      ["outputKinds", account.outputKinds],
    ]) {
      if (
        values.some(
          (value) => typeof value !== "string" || value.length === 0,
        ) ||
        canonicalJson(values) !==
          canonicalJson([...new Set(values)].sort(compareText))
      ) {
        throw new Error(
          `output surface account ${index}.${field}: expected a canonical string set`,
        );
      }
    }
    if (
      (account.status === "output-bearing") !==
      account.outputKinds.length > 0
    ) {
      throw new Error(
        `output surface account ${account.surfaceId}: output kinds disagree with status`,
      );
    }
    if (accountsById.has(account.surfaceId)) {
      throw new Error(`output surface accounts duplicate ${account.surfaceId}`);
    }
    accountsById.set(account.surfaceId, account);
  }
  const expectedIds = [...coverageIds].sort(compareText);
  const expectedIdSet = new Set(expectedIds);
  const actualIds = [...accountsById.keys()].sort(compareText);
  const missing = expectedIds.filter((id) => !accountsById.has(id));
  const unknown = actualIds.filter((id) => !expectedIdSet.has(id));
  if (
    missing.length ||
    unknown.length ||
    canonicalJson(expectedIds) !== canonicalJson(actualIds)
  ) {
    throw new Error(
      `output surface accounts are not set-equal to coverage; missing=[${missing.slice(0, 8).join(", ")}] unknown=[${unknown.slice(0, 8).join(", ")}]`,
    );
  }
  const rowsBySurface = Map.groupBy(rows, (row) => row.key.surfaceId);
  for (const [index, row] of rows.entries()) {
    if (row.requiredValueProof !== "live-value-observation") {
      throw new Error(
        `output shape catalog row ${index}: value rows require live value observation`,
      );
    }
    if (!accountsById.has(row.key.surfaceId)) {
      throw new Error(
        `output shape catalog row ${index}: unknown surface ${row.key.surfaceId}`,
      );
    }
  }
  for (const account of surfaceAccounts) {
    const rowCount = rowsBySurface.get(account.surfaceId)?.length ?? 0;
    const parameterized = parameterizedById.get(account.surfaceId);
    if (parameterized) {
      if (
        rowCount !== 0 ||
        account.status !== parameterized.status ||
        account.reasonCode !== parameterized.reasonCode ||
        canonicalJson(account.sourceRefs) !==
          canonicalJson(parameterized.sourceRefs) ||
        canonicalJson(account.outputKinds) !==
          canonicalJson(parameterized.outputKinds)
      ) {
        throw new Error(
          `parameterized output-bearing surface ${account.surfaceId} disagrees with its rowless binding`,
        );
      }
      continue;
    }
    if (account.status === "output-bearing" && rowCount === 0) {
      throw new Error(
        `output-bearing surface ${account.surfaceId} has no output rows`,
      );
    }
    if (account.status !== "output-bearing" && rowCount !== 0) {
      throw new Error(
        `${account.status} surface ${account.surfaceId} has output rows`,
      );
    }
  }
  for (const surfaceId of parameterizedById.keys()) {
    if (!accountsById.has(surfaceId)) {
      throw new Error(
        `parameterized output binding references unknown surface ${surfaceId}`,
      );
    }
  }
  const counts = Object.fromEntries(
    ["output-bearing", "structural-only", "unresolved"].map((status) => [
      status,
      surfaceAccounts.filter((account) => account.status === status).length,
    ]),
  );
  if (promotionStatus === "verified" && counts.unresolved > 0) {
    throw new Error(
      `verified output catalog has ${counts.unresolved} unresolved surface accounts`,
    );
  }
  if (promotionStatus === "verified") {
    const evidenceById = new Map();
    for (const [index, evidence] of parameterizedOutputEvidence.entries()) {
      if (
        evidence?.environmentOutputSweepObservationSchema !==
          "ibex/capsec-environment-output-sweep-observation/1" ||
        typeof evidence.surfaceId !== "string" ||
        !/^sha256-[A-Za-z0-9_-]{43}$/u.test(
          evidence.sweepBindingDigest ?? "",
        ) ||
        !/^sha256-[A-Za-z0-9_-]{43}$/u.test(evidence.observationDigest ?? "") ||
        evidenceById.has(evidence.surfaceId)
      ) {
        throw new Error(
          `parameterized output evidence ${index}: malformed or duplicated live observation`,
        );
      }
      evidenceById.set(evidence.surfaceId, evidence);
    }
    const missing = [...parameterizedById.keys()].filter(
      (surfaceId) => !evidenceById.has(surfaceId),
    );
    const unknown = [...evidenceById.keys()].filter(
      (surfaceId) => !parameterizedById.has(surfaceId),
    );
    if (missing.length || unknown.length) {
      throw new Error(
        `verified output catalog requires set-equal live exact-name evidence; missing=[${missing.join(", ")}] unknown=[${unknown.join(", ")}]`,
      );
    }
  }
  if (!new Set(["unpromotable", "verified"]).has(promotionStatus)) {
    throw new Error(
      `unknown output catalog promotion status ${promotionStatus}`,
    );
  }
  return counts;
}

export function buildOutputShapeCatalog({
  coverage,
  implementationRows,
  surfaces,
  repoRoot,
  liveEvidence,
}) {
  if (
    !liveEvidence ||
    liveEvidence.requiredExecutor !== OUTPUT_DISPOSITION_EVIDENCE_EXECUTOR ||
    !["unpromotable", "verified"].includes(liveEvidence.status)
  ) {
    throw new Error("output shape discovery has malformed live-evidence state");
  }
  const edgeByName = new Map();
  for (const edge of coverage.edges) {
    const rows = edgeByName.get(edge.surface.name) ?? [];
    rows.push(edge);
    edgeByName.set(edge.surface.name, rows);
  }
  const implementationByEdge = implementationEvidenceByEdge(implementationRows);
  const sourcesByObservedKey = sourceSurfaceMap(surfaces);
  const inspectorCdpSourceAudit = auditInspectorCdpStructuralClosure(
    inspectorCdpAuditSources(repoRoot),
  );
  const inspectorCdpContracts = inspectorCdpStructuralAccountBindings(
    inspectorCdpSourceAudit,
  ).map((binding) => ({
    surfaceName: binding.surfaceName,
    reasonCode: binding.reasonCode,
    sourceRefs: binding.sourceRefs,
  }));
  const debuggerNativeAliasSourceAudit = auditDebuggerNativeAliasClosure({
    ...debuggerNativeAliasAuditSources(repoRoot),
    surfaces,
    coverage,
  });
  const debuggerNativeAliasContracts =
    debuggerNativeAliasStructuralAccountBindings(
      debuggerNativeAliasSourceAudit,
    ).map((binding) => ({
      surfaceName: binding.surfaceName,
      reasonCode: binding.reasonCode,
      sourceRefs: binding.sourceRefs,
    }));
  const nativeGlobalMarkerSourceAudit = auditNativeGlobalMarkerAliasClosure({
    repoRoot,
    surfaces,
    coverage,
  });
  const contextObserverOutputBinding =
    capsecContextObserverOutputCatalogBinding(nativeGlobalMarkerSourceAudit);
  const contextObserverEdges =
    edgeByName.get(contextObserverOutputBinding.surfaceName) ?? [];
  if (
    contextObserverEdges.length !== 1 ||
    contextObserverEdges[0].id !==
      contextObserverOutputBinding.account.surfaceId ||
    contextObserverOutputBinding.rows.some(
      (row) =>
        row.key?.surfaceId !== contextObserverOutputBinding.account.surfaceId,
    )
  ) {
    throw new Error(
      "context observer output binding disagrees with the coverage edge",
    );
  }
  const sourceAssertedOutputBindingsById = new Map([
    [
      contextObserverOutputBinding.account.surfaceId,
      contextObserverOutputBinding,
    ],
  ]);
  const nativeGlobalMarkerContracts =
    nativeGlobalMarkerStructuralAccountBindings(
      nativeGlobalMarkerSourceAudit,
    ).map((binding) => ({
      surfaceName: binding.surfaceName,
      reasonCode: binding.reasonCode,
      sourceRefs: binding.sourceRefs,
    }));
  const environmentSourceAudit = auditCanonicalEnvironmentOutputSources(
    environmentOutputAuditSources(repoRoot),
  );
  const environmentContract = canonicalEnvironmentOutputContract({
    coverageEdges: coverage.edges,
    sourceAudit: environmentSourceAudit,
    surfaces,
  });
  const environmentContracts = environmentStructuralAccountBindings(
    environmentSourceAudit,
  ).map((binding) => ({
    surfaceName: binding.surfaceName,
    reasonCode: binding.reasonCode,
    sourceRefs: binding.sourceRefs,
  }));
  const parameterizedOutputBindings =
    environmentParameterizedOutputCatalogBindings(environmentContract);
  const parameterizedBindingsById = new Map(
    parameterizedOutputBindings.map((binding) => [binding.surfaceId, binding]),
  );
  const structuralContracts = [
    ...SOURCE_ASSERTED_STRUCTURAL_CONTRACTS,
    ...inspectorCdpContracts,
    ...debuggerNativeAliasContracts,
    ...nativeGlobalMarkerContracts,
    ...environmentContracts,
  ];
  const sourceAssertedStructuralContracts = new Map();
  for (const [contractIndex, contract] of structuralContracts.entries()) {
    const edges = edgeByName.get(contract.surfaceName) ?? [];
    if (edges.length !== 1) {
      throw new Error(
        `source-asserted structural contract ${contractIndex}: expected one ${contract.surfaceName} surface, got ${edges.length}`,
      );
    }
    const edge = edges[0];
    const sourceSurface = sourcesByObservedKey.get(
      `${edge.surface.kind}:${edge.surface.name}`,
    );
    if (!sourceSurface || sourceSurface.kind !== "native-op") {
      throw new Error(
        `source-asserted structural contract ${contractIndex}: missing native-op source surface ${contract.surfaceName}`,
      );
    }
    const sourceRefs = contract.sourceRefs
      ? [...contract.sourceRefs].sort(compareText)
      : contract.assertions
          .map((assertion, assertionIndex) =>
            sourceAssertion(
              repoRoot,
              assertion,
              `source-asserted structural contract ${contractIndex} assertion ${assertionIndex}`,
            ),
          )
          .sort(compareText);
    if (
      sourceRefs.length === 0 ||
      sourceRefs.some(
        (sourceRef) => typeof sourceRef !== "string" || sourceRef.length === 0,
      ) ||
      new Set(sourceRefs).size !== sourceRefs.length ||
      sourceAssertedStructuralContracts.has(edge.id)
    ) {
      throw new Error(
        `source-asserted structural contract ${contractIndex}: malformed or duplicate evidence for ${contract.surfaceName}`,
      );
    }
    sourceAssertedStructuralContracts.set(edge.id, {
      reasonCode: contract.reasonCode,
      sourceRefs,
    });
  }
  const replacementIds = new Set();
  const recipeSurfaceIds = new Set();
  const recipeRows = [];
  for (const [recipeIndex, recipe] of STRUCTURED_OUTPUT_RECIPES.entries()) {
    const edges = edgeByName.get(recipe.surfaceName) ?? [];
    if (edges.length !== 1) {
      throw new Error(
        `output shape recipe ${recipeIndex}: expected one ${recipe.surfaceName} surface, got ${edges.length}`,
      );
    }
    const edge = edges[0];
    const sourceSurface = sourcesByObservedKey.get(
      `${edge.surface.kind}:${edge.surface.name}`,
    );
    if (!sourceSurface) {
      throw new Error(
        `output shape recipe ${recipeIndex}: missing source surface ${edge.surface.kind}:${edge.surface.name}`,
      );
    }
    recipeSurfaceIds.add(edge.id);
    if (recipe.replaceDefault) replacementIds.add(edge.id);
    const sourceRefs = recipe.assertions
      .map((assertion, assertionIndex) =>
        sourceAssertion(
          repoRoot,
          assertion,
          `output shape recipe ${recipeIndex} assertion ${assertionIndex}`,
        ),
      )
      .sort(compareText);
    for (const recipeShape of recipe.shapes) {
      const partialKey = {
        surfaceId: edge.id,
        output: recipeShape.output,
        alias: recipeShape.alias,
        mode: recipeShape.mode,
        sourceKind: recipeShape.sourceKind,
        returnVariant: recipeShape.returnVariant,
      };
      recipeRows.push({
        key: {
          ...partialKey,
          contextId:
            recipe.contextId ??
            defaultContextIdForCatalogRow(partialKey, sourceSurface),
        },
        discovery: {
          kind: "source-asserted-structured-output",
          sourceRefs,
        },
        requiredValueProof: "live-value-observation",
      });
    }
  }
  recipeSurfaceIds.add(contextObserverOutputBinding.account.surfaceId);
  for (const row of contextObserverOutputBinding.rows) recipeRows.push(row);

  const baselineRows = coverage.edges.flatMap((edge) => {
    const sourceSurface = sourcesByObservedKey.get(
      `${edge.surface.kind}:${edge.surface.name}`,
    );
    if (!sourceSurface) {
      throw new Error(
        `output catalog surface ${edge.id} lacks source inventory metadata`,
      );
    }
    const implementation = implementationByEdge.get(edge.id);
    if (!implementation) {
      throw new Error(
        `output catalog surface ${edge.id} lacks source inventory evidence`,
      );
    }
    if (parameterizedBindingsById.has(edge.id)) return [];

    if (sourceSurface.kind === "host-abi") {
      if (replacementIds.has(edge.id)) return [];
      const signatureAccount = deriveHostAbiOutputCatalogAccount(sourceSurface);
      if (
        signatureAccount.status !== "output-bearing" ||
        signatureAccount.membershipUnresolved.length > 0
      ) {
        return [];
      }
      return signatureAccount.outputChannels.map((channel) => {
        const partialKey = {
          surfaceId: edge.id,
          output: channel.selector,
          alias: edge.surface.name,
          mode: "all",
          sourceKind: "host-abi",
          returnVariant: "default",
        };
        return {
          key: {
            ...partialKey,
            contextId: defaultContextIdForCatalogRow(partialKey, sourceSurface),
          },
          discovery: {
            kind: "source-inventory-surface",
            observedKeys: [sourceSurface.observedKey],
            sourceRefs: [...channel.sourceRefs],
          },
          requiredValueProof: "live-value-observation",
        };
      });
    }

    const callbackContracts = callbackOutputContracts(sourceSurface);
    if (callbackContracts.length > 0) {
      return callbackContracts.map((contract) => {
        const partialKey = {
          surfaceId: edge.id,
          output: contract.selector,
          alias: edge.surface.name,
          mode: "all",
          sourceKind: "callback",
          returnVariant: contract.returnVariant,
        };
        return {
          key: {
            ...partialKey,
            contextId: defaultContextIdForCatalogRow(partialKey, sourceSurface),
          },
          discovery: {
            kind: "source-inventory-surface",
            observedKeys: [...implementation.observedKeys].sort(compareText),
            sourceRefs: [...contract.sourceRefs],
          },
          requiredValueProof: "live-value-observation",
        };
      });
    }

    const outputContract = genericOutputContract(sourceSurface);
    if (outputContract === null || replacementIds.has(edge.id)) return [];
    const partialKey = {
      surfaceId: edge.id,
      output: outputContract.output,
      alias: outputContract.alias ?? edge.surface.name,
      mode: "all",
      sourceKind: edge.surface.kind,
      returnVariant: "default",
    };
    return [
      {
        key: {
          ...partialKey,
          contextId: defaultContextIdForCatalogRow(partialKey, sourceSurface),
        },
        discovery: {
          kind: "source-inventory-surface",
          observedKeys: [...implementation.observedKeys].sort(compareText),
          sourceRefs: [...implementation.sourceRefs].sort(compareText),
        },
        requiredValueProof: "live-value-observation",
      },
    ];
  });
  const rows = sortRows([...baselineRows, ...recipeRows]);
  assertUniqueRows(rows, "output shape catalog rows");
  const surfaceAccounts = coverage.edges
    .map((edge) => {
      const implementation = implementationByEdge.get(edge.id);
      if (!implementation) {
        throw new Error(
          `output catalog account ${edge.id} lacks source inventory evidence`,
        );
      }
      const sourceSurface = sourcesByObservedKey.get(
        `${edge.surface.kind}:${edge.surface.name}`,
      );
      if (!sourceSurface) {
        throw new Error(
          `output catalog account ${edge.id} lacks source inventory metadata`,
        );
      }
      const sourceAssertedOutputBinding = sourceAssertedOutputBindingsById.get(
        edge.id,
      );
      if (sourceAssertedOutputBinding) {
        return structuredClone(sourceAssertedOutputBinding.account);
      }
      const parameterizedBinding = parameterizedBindingsById.get(edge.id);
      if (parameterizedBinding) {
        return {
          surfaceId: edge.id,
          status: parameterizedBinding.status,
          reasonCode: parameterizedBinding.reasonCode,
          sourceRefs: [...parameterizedBinding.sourceRefs],
          outputKinds: [...parameterizedBinding.outputKinds],
        };
      }
      return surfaceAccount({
        edge,
        surface: sourceSurface,
        implementation,
        recipeSurfaceIds,
        sourceAssertedStructuralContract: sourceAssertedStructuralContracts.get(
          edge.id,
        ),
      });
    })
    .sort((left, right) => compareText(left.surfaceId, right.surfaceId));
  const accountCounts = validateOutputShapeCatalogAccounts({
    coverage,
    surfaceAccounts,
    rows,
    parameterizedOutputBindings,
    parameterizedOutputEvidence:
      liveEvidence.sweepArtifact?.parameterizedObservations ?? [],
    promotionStatus: liveEvidence.status,
  });
  const contexts = outputExecutionContextsForRows(rows);
  const catalog = {
    outputShapeCatalogSchema: "ibex/capsec-output-shape-catalog/2",
    profile: PROFILE,
    discovery: {
      status: liveEvidence.status,
      method:
        "source-inventory-surface-accounting-plus-source-asserted-structured-outputs",
      requiredExecutor: liveEvidence.requiredExecutor,
      ...(liveEvidence.status === "unpromotable"
        ? { reason: liveEvidence.reason }
        : {
            sourceRevision: liveEvidence.sourceRevision,
            sourceTreeDigest: liveEvidence.sourceTreeDigest,
            target: structuredClone(liveEvidence.target),
            engine: structuredClone(liveEvidence.engine),
          }),
    },
    contexts,
    surfaceAccounts,
    [ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD]:
      parameterizedOutputBindings,
    parameterizedBindingDigest: outputParameterizedBindingDigest(
      parameterizedOutputBindings,
    ),
    catalogKeyDigest: outputShapeCatalogKeyDigest(rows),
    counts: {
      coverageSurfaces: coverage.edges.length,
      outputBearingSurfaces: accountCounts["output-bearing"],
      structuralOnlySurfaces: accountCounts["structural-only"],
      unresolvedSurfaces: accountCounts.unresolved,
      catalogRows: rows.length,
      parameterizedBindings: parameterizedOutputBindings.length,
      sourceInventoryRows: baselineRows.length,
      structuredRows: recipeRows.length,
    },
    rows,
  };
  validateInspectorCdpStructuralCatalog({
    catalog,
    coverage,
    sourceAudit: inspectorCdpSourceAudit,
  });
  validateDebuggerNativeAliasStructuralCatalog({
    catalog,
    coverage,
    sourceAudit: debuggerNativeAliasSourceAudit,
  });
  validateNativeGlobalMarkerAliasCatalog({
    catalog,
    coverage,
    sourceAudit: nativeGlobalMarkerSourceAudit,
  });
  validateEnvironmentOutputCatalog({
    catalog,
    contract: environmentContract,
    coverage,
    sourceAudit: environmentSourceAudit,
  });
  return catalog;
}

export function validateOutputDispositionJoin(catalogRows, dispositionRows) {
  assertUniqueRows(catalogRows, "output shape catalog rows");
  assertUniqueRows(dispositionRows, "output disposition rows");
  const catalogKeys = new Set(
    catalogRows.map((row) => canonicalOutputDispositionKey(row.key)),
  );
  const dispositionKeys = new Set(
    dispositionRows.map((row) => canonicalOutputDispositionKey(row.key)),
  );
  const uncovered = [...catalogKeys].filter((key) => !dispositionKeys.has(key));
  const unknown = [...dispositionKeys].filter((key) => !catalogKeys.has(key));
  if (uncovered.length || unknown.length) {
    throw new Error(
      `output disposition join is not bidirectional; uncovered=[${uncovered.slice(0, 8).join(", ")}] unknown=[${unknown.slice(0, 8).join(", ")}]`,
    );
  }
}

function validateOutputShapeCatalogDocument(catalog, evidence) {
  if (
    catalog?.outputShapeCatalogSchema !==
      "ibex/capsec-output-shape-catalog/2" ||
    catalog.profile !== PROFILE ||
    !Array.isArray(catalog.contexts) ||
    !Array.isArray(catalog.surfaceAccounts) ||
    !Array.isArray(catalog[ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD]) ||
    !Array.isArray(catalog.rows)
  ) {
    throw new Error("output shape catalog is not a complete v2 document");
  }
  const discovery = catalog.discovery;
  if (
    !discovery ||
    typeof discovery !== "object" ||
    discovery.method !==
      "source-inventory-surface-accounting-plus-source-asserted-structured-outputs" ||
    !evidence ||
    typeof evidence !== "object" ||
    discovery.status !== evidence.status ||
    discovery.requiredExecutor !== evidence.requiredExecutor
  ) {
    throw new Error(
      "output shape catalog discovery does not bind the loaded-engine evidence state",
    );
  }
  if (
    discovery.status === "unpromotable" &&
    discovery.reason !== evidence.reason
  ) {
    throw new Error(
      "output shape catalog discovery does not bind the unpromotable evidence reason",
    );
  }
  if (
    discovery.status === "verified" &&
    (discovery.sourceRevision !== evidence.sourceRevision ||
      discovery.sourceTreeDigest !== evidence.sourceTreeDigest ||
      canonicalJson(discovery.target) !== canonicalJson(evidence.target) ||
      canonicalJson(discovery.engine) !== canonicalJson(evidence.engine))
  ) {
    throw new Error(
      "output shape catalog discovery does not bind the verified engine identity",
    );
  }
  if (catalog.catalogKeyDigest !== outputShapeCatalogKeyDigest(catalog.rows)) {
    throw new Error("output shape catalog key digest does not match its rows");
  }
  if (
    catalog.parameterizedBindingDigest !==
    outputParameterizedBindingDigest(
      catalog[ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD],
    )
  ) {
    throw new Error(
      "output shape catalog parameterized binding digest does not match its bindings",
    );
  }
  const expectedContexts = outputExecutionContextsForRows(catalog.rows);
  if (canonicalJson(catalog.contexts) !== canonicalJson(expectedContexts)) {
    throw new Error(
      "output shape catalog execution contexts do not match its rows",
    );
  }
  const accountCounts = validateOutputShapeCatalogAccounts({
    surfaceAccounts: catalog.surfaceAccounts,
    rows: catalog.rows,
    parameterizedOutputBindings:
      catalog[ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD],
    parameterizedOutputEvidence:
      evidence.sweepArtifact?.parameterizedObservations ?? [],
    promotionStatus: evidence.status,
  });
  const expectedCounts = {
    coverageSurfaces: catalog.surfaceAccounts.length,
    outputBearingSurfaces: accountCounts["output-bearing"],
    structuralOnlySurfaces: accountCounts["structural-only"],
    unresolvedSurfaces: accountCounts.unresolved,
    catalogRows: catalog.rows.length,
    parameterizedBindings:
      catalog[ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD].length,
    sourceInventoryRows: catalog.rows.filter(
      (row) => row.discovery.kind === "source-inventory-surface",
    ).length,
    structuredRows: catalog.rows.filter(
      (row) => row.discovery.kind === "source-asserted-structured-output",
    ).length,
  };
  if (canonicalJson(catalog.counts) !== canonicalJson(expectedCounts)) {
    throw new Error(
      "output shape catalog counts do not match its accounts and rows",
    );
  }
  return accountCounts;
}

function validateReviewedDispositionOverride(row, index) {
  const label = `output disposition policy override ${index}`;
  exactKeys(row, ["key", "disposition", "expectation", "rationale"], label);
  canonicalOutputDispositionKey(row.key, `${label}.key`);
  if (!OUTPUT_DISPOSITIONS.includes(row.disposition)) {
    throw new Error(`${label}.disposition: unknown output disposition`);
  }
  if (typeof row.rationale !== "string" || row.rationale.length === 0) {
    throw new Error(`${label}.rationale: expected non-empty string`);
  }
  exactKeys(
    row.expectation,
    ["outcome", "normalizedValue"],
    `${label}.expectation`,
  );
  if (
    !new Set(["absent", "return", "throw", "typed-return"]).has(
      row.expectation.outcome,
    ) ||
    typeof row.expectation.normalizedValue !== "string" ||
    row.expectation.normalizedValue.length === 0
  ) {
    throw new Error(`${label}.expectation: malformed normalized observation`);
  }

  const privateNativeMarker = "private-native-path";
  if (row.disposition === privateNativeMarker) {
    if (
      row.key.sourceKind !== "host-abi" ||
      row.key.contextId !== "host.private-native-call-initialized" ||
      canonicalJson(row.expectation) !==
        canonicalJson({
          outcome: "return",
          normalizedValue: privateNativeMarker,
        })
    ) {
      throw new Error(
        `${label}: private-native-path requires an authenticated Host-ABI return marker`,
      );
    }
  } else if (row.expectation.normalizedValue === privateNativeMarker) {
    throw new Error(
      `${label}: private-native-path marker requires the matching disposition`,
    );
  }
}

function buildDispositionRows(catalog, policy) {
  if (
    policy?.outputDispositionPolicySchema !==
      "ibex/capsec-output-disposition-policy/2" ||
    policy.profile !== PROFILE
  ) {
    throw new Error("output disposition policy is not a complete v2 document");
  }
  if (policy.catalogKeyDigest !== catalog.catalogKeyDigest) {
    throw new Error(
      `output disposition policy has unreviewed catalog fields: expected ${policy.catalogKeyDigest}, discovered ${catalog.catalogKeyDigest}`,
    );
  }
  if (policy.defaultDisposition !== "non-path") {
    throw new Error(
      "output disposition policy default must be explicit non-path",
    );
  }
  policy.overrides.forEach(validateReviewedDispositionOverride);
  assertUniqueRows(policy.overrides, "output disposition policy overrides");
  const overrides = new Map(
    policy.overrides.map((row) => [
      canonicalOutputDispositionKey(row.key),
      row,
    ]),
  );
  const rows = catalog.rows.map((catalogRow) => {
    const key = canonicalOutputDispositionKey(catalogRow.key);
    const override = overrides.get(key);
    if (override) {
      overrides.delete(key);
      return {
        key: structuredClone(catalogRow.key),
        disposition: override.disposition,
        expectation: structuredClone(override.expectation),
        rationale: override.rationale,
      };
    }
    return {
      key: structuredClone(catalogRow.key),
      disposition: "non-path",
      expectation: {
        outcome: "return",
        normalizedValue: "non-path",
      },
      rationale: policy.defaultRationale,
    };
  });
  if (overrides.size) {
    throw new Error(
      `output disposition policy references unknown catalog keys: ${[...overrides.keys()].slice(0, 8).join(", ")}`,
    );
  }
  validateOutputDispositionJoin(catalog.rows, rows);
  return sortRows(rows);
}

export function validateOutputDispositionEvidence(dispositionRows, evidence) {
  if (
    evidence?.outputDispositionEvidenceSchema !==
      "ibex/capsec-output-disposition-evidence/3" ||
    evidence.profile !== PROFILE ||
    evidence.requiredExecutor !== OUTPUT_DISPOSITION_EVIDENCE_EXECUTOR ||
    !Array.isArray(evidence.observations)
  ) {
    throw new Error(
      "output disposition evidence is not a complete v3 document",
    );
  }
  assertUniqueRows(evidence.observations, "output disposition observations");
  if (evidence.status === "unpromotable") {
    exactKeys(
      evidence,
      [
        "outputDispositionEvidenceSchema",
        "profile",
        "status",
        "requiredExecutor",
        "reason",
        "observations",
      ],
      "unpromotable output disposition evidence",
    );
    if (typeof evidence.reason !== "string" || evidence.reason.length === 0) {
      throw new Error(
        "unpromotable output evidence requires an explicit reason",
      );
    }
    if (evidence.observations.length !== 0) {
      throw new Error(
        "unpromotable output evidence must not carry observations",
      );
    }
    return { status: "unpromotable", reason: evidence.reason };
  }
  exactKeys(
    evidence,
    [
      "outputDispositionEvidenceSchema",
      "profile",
      "status",
      "requiredExecutor",
      "sourceRevision",
      "sourceTreeDigest",
      "conformanceRunner",
      "target",
      "engine",
      "sweepPlan",
      "sweepArtifact",
      "observations",
    ],
    "verified output disposition evidence",
  );
  if (
    evidence.status !== "verified" ||
    !REVISION_PATTERN.test(evidence.sourceRevision ?? "") ||
    !DIGEST_PATTERN.test(evidence.sourceTreeDigest ?? "") ||
    !evidence.sweepPlan ||
    typeof evidence.sweepPlan !== "object" ||
    Array.isArray(evidence.sweepPlan) ||
    !evidence.sweepArtifact ||
    typeof evidence.sweepArtifact !== "object" ||
    Array.isArray(evidence.sweepArtifact)
  ) {
    throw new Error(
      "verified output evidence lacks exact source and engine identity",
    );
  }
  validateExactOutputTarget(evidence.target, "verified output evidence.target");
  validateExactOutputEngine(
    evidence.engine,
    evidence.target,
    "verified output evidence.engine",
  );
  validateConformanceRunnerBinding(evidence.conformanceRunner, {
    sourceRevision: evidence.sourceRevision,
    sourceTreeDigest: evidence.sourceTreeDigest,
  });
  const expectedByKey = new Map(
    dispositionRows.map((row) => [canonicalOutputDispositionKey(row.key), row]),
  );
  const observationsByKey = new Map(
    evidence.observations.map((row) => [
      canonicalOutputDispositionKey(row.key),
      row,
    ]),
  );
  const uncovered = [...expectedByKey.keys()].filter(
    (key) => !observationsByKey.has(key),
  );
  const unknown = [...observationsByKey.keys()].filter(
    (key) => !expectedByKey.has(key),
  );
  if (uncovered.length || unknown.length) {
    throw new Error(
      `loaded-engine output evidence is incomplete; uncovered=[${uncovered.slice(0, 8).join(", ")}] unknown=[${unknown.slice(0, 8).join(", ")}]`,
    );
  }
  for (const [key, expected] of expectedByKey) {
    const actual = observationsByKey.get(key);
    validateOutputValueProofKind(
      actual.proofKind,
      `loaded-engine output evidence ${key}`,
    );
    if (
      actual.disposition !== expected.disposition ||
      canonicalJson(actual.observation) !== canonicalJson(expected.expectation)
    ) {
      throw new Error(`loaded-engine output value mismatch for ${key}`);
    }
  }
  return {
    status: "verified",
    sourceRevision: evidence.sourceRevision,
    sourceTreeDigest: evidence.sourceTreeDigest,
    conformanceRunner: structuredClone(evidence.conformanceRunner),
    target: structuredClone(evidence.target),
    engine: structuredClone(evidence.engine),
  };
}

export function validateTrackedOutputDispositionEvidenceSentinel(evidence) {
  const state = validateOutputDispositionEvidence([], evidence);
  if (state.status !== "unpromotable") {
    throw new Error(
      "the tracked output-disposition evidence document must remain an unpromotable source sentinel",
    );
  }
  return state;
}

export function buildOutputDispositionDataset({ catalog, policy, evidence }) {
  validateOutputShapeCatalogDocument(catalog, evidence);
  const rows = buildDispositionRows(catalog, policy);
  const evidenceState = validateOutputDispositionEvidence(rows, evidence);
  const dispositionCounts = Object.fromEntries(
    OUTPUT_DISPOSITIONS.map((disposition) => [
      disposition,
      rows.filter((row) => row.disposition === disposition).length,
    ]),
  );
  const absentDispositions = OUTPUT_DISPOSITIONS.filter(
    (disposition) => dispositionCounts[disposition] === 0,
  );
  if (absentDispositions.length) {
    throw new Error(
      `output disposition dataset does not exercise the closed disposition set: ${absentDispositions.join(", ")}`,
    );
  }
  return {
    outputDispositionDatasetSchema: "ibex/capsec-output-dispositions/2",
    profile: PROFILE,
    catalogKeyDigest: catalog.catalogKeyDigest,
    evidence: evidenceState,
    dispositions: OUTPUT_DISPOSITIONS,
    rows,
    counts: {
      catalogRows: catalog.rows.length,
      dispositionRows: rows.length,
      byDisposition: dispositionCounts,
    },
  };
}

function markdownCell(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}

export function renderOutputDispositionMarkdown(dataset) {
  const materialRows = dataset.rows.filter(
    (row) => row.disposition !== "non-path",
  );
  const lines = [
    "# Output dispositions",
    "",
    "<!-- @generated by packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs; do not edit -->",
    "",
    `Evidence status: **${dataset.evidence.status}**.`,
    "",
    ...(dataset.evidence.status === "unpromotable"
      ? [`Reason: ${dataset.evidence.reason}`, ""]
      : []),
    `The machine dataset contains ${dataset.counts.dispositionRows} canonical rows; ${dataset.counts.byDisposition["non-path"]} are explicit \`non-path\` decisions pinned by catalog digest \`${dataset.catalogKeyDigest}\`.`,
    "",
    "The table below projects every material (non-`non-path`) decision. The JSON artifact is normative and total.",
    "",
    "| Surface ID | Output | Alias | Mode | Source kind | Variant | Execution context | Disposition | Expected observation |",
    "|---|---|---|---|---|---|---|---|---|",
  ];
  for (const row of materialRows) {
    lines.push(
      `| \`${markdownCell(row.key.surfaceId)}\` | \`${markdownCell(row.key.output)}\` | \`${markdownCell(row.key.alias)}\` | \`${markdownCell(row.key.mode)}\` | \`${markdownCell(row.key.sourceKind)}\` | \`${markdownCell(row.key.returnVariant)}\` | \`${markdownCell(row.key.contextId)}\` | \`${markdownCell(row.disposition)}\` | \`${markdownCell(canonicalJson(row.expectation))}\` |`,
    );
  }
  return `${lines.join("\n")}\n`;
}
