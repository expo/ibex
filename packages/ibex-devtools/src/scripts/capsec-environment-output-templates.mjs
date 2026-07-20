/**
 * Source-bound output accounts for the armed process environment facade.
 *
 * The shared JavaScript proxy is caller-sensitive because all armed state is
 * held by the native current-principal overlay. The armed snapshot base is
 * explicitly empty; neither exact-name reads nor enumeration can fall through
 * to the host process environment. Exact.env and Bun.env are identity aliases
 * of the pinned process.env proxy, not independent environment namespaces.
 *
 * @ref LLP 0022#7-capabilities-principals-and-affordance-parity — armed
 * environment state belongs to the authenticated current principal.
 * @ref LLP 0022#11-delegated-obligations — OBL-ENV-BASE requires an explicit empty
 * armed base, with values admitted only through typed principal overlays.
 * @ref LLP 0021#typed-resources-and-initial-vocabulary — env:read and env:write
 * independently bind one exact principal-overlay name at requested and commit.
 * @ref LLP 0025#2-startup-configuration-is-captured-before-arming — ambient
 * process-environment enumeration remains a diagnostic-only, post-gate helper.
 */

import crypto from "node:crypto";

export const ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA =
  "ibex/capsec-environment-output-source-audit/1";
export const ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA =
  "ibex/capsec-environment-output-contract/1";
export const ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA =
  "ibex/capsec-environment-output-account/1";
export const ENVIRONMENT_PARAMETERIZED_CATALOG_BINDING_SCHEMA =
  "ibex/capsec-environment-parameterized-catalog-binding/1";
export const ENVIRONMENT_OUTPUT_SWEEP_BINDING_SCHEMA =
  "ibex/capsec-environment-output-sweep-binding/1";
export const ENVIRONMENT_OUTPUT_SWEEP_ACCOUNT_SCHEMA =
  "ibex/capsec-environment-output-sweep-account/1";
export const ENVIRONMENT_OUTPUT_SWEEP_OBSERVATION_SCHEMA =
  "ibex/capsec-environment-output-sweep-observation/1";
export const ENVIRONMENT_OUTPUT_SWEEP_EXECUTOR_RESULT_SCHEMA =
  "ibex/capsec-environment-output-executor-result/1";
export const ENVIRONMENT_OUTPUT_SWEEP_PROBE_KIND =
  "loaded-engine-parameterized-environment";

/**
 * The exact finite policy used only by the loaded-engine output executor.
 * These are real selectors in the authenticated sweep snapshot, not sample
 * names standing in for an open-ended environment table.
 */
export const ENVIRONMENT_OUTPUT_SWEEP_NAMES = Object.freeze([
  "IBEX_CAPSEC_OUTPUT_ALPHA",
  "IBEX_CAPSEC_OUTPUT_OMEGA",
]);

export const CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY =
  "global:process.env.[[dynamic-table:principal-environment-overlay-properties]]";
export const LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY =
  "global:process.env.[[dynamic-table:env-obj-properties]]";
export const ENVIRONMENT_LEGACY_STRUCTURAL_REASON_CODE =
  "armed-legacy-environment-object-unreachable";
export const ENVIRONMENT_PARAMETERIZED_REASON_CODE =
  "authenticated-exact-environment-output-accounts";
export const ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD =
  "parameterizedOutputBindings";

const ENVIRONMENT_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/u;
const OPAQUE_ALIAS_FAMILY_PATTERN =
  /^global:(?:Bun|Exact)\.env\.\[\[dynamic-table:call-result-[a-f0-9]+-properties\]\]$/u;
const OUTPUT_KEY_FIELDS = Object.freeze([
  "surfaceId",
  "output",
  "alias",
  "mode",
  "sourceKind",
  "returnVariant",
  "contextId",
]);
const ENVIRONMENT_SWEEP_BINDING_DIGEST_DOMAIN =
  "ibex:capsec:environment-output-sweep-binding:1";
const ENVIRONMENT_SWEEP_VALUE_DIGEST_DOMAIN =
  "ibex:capsec:environment-output-sweep-value:1";
const CAPSEC_DIGEST_PATTERN = /^sha256-[A-Za-z0-9_-]{43}$/u;
const ENVIRONMENT_SWEEP_PHASES = Object.freeze([
  "scalar-before",
  "write-setup",
  "scalar-after",
  "enumeration",
]);

const COMPATIBILITY_READER_SOURCE_PATHS = Object.freeze([
  "packages/ibex-runtime-js/src/fetch/Headers.ts",
  "packages/ibex-runtime-js/src/fetch/Request.ts",
  "packages/ibex-runtime-js/src/fetch/Response.ts",
  "packages/ibex-runtime-js/src/fetch/body.ts",
  "packages/ibex-runtime-js/src/fetch/fetch.ts",
  "packages/ibex-runtime-js/src/streams/ReadableStream.ts",
]);

const SOURCE_REFS = Object.freeze({
  armedBunAliasPreload: "src/bin/ibex/runtime.rs#load_runtime_once:Bun=Exact",
  armedSharedRuntimeGuard:
    "src/engine/hermes_runtime.cc#installGlobals:armed-shared-runtime-required",
  builtinCanonicalIdentity:
    "src/builtins/process.js#process.env:canonical-proxy-marker",
  canonicalFacade:
    "packages/ibex-runtime-js/src/node/process.ts#createEnvProxy",
  compatibilityControl:
    "packages/ibex-runtime-js/src/core/host-inputs.ts#bootstrapCompatibilityControl",
  compatibilityFetchBodyReader:
    "packages/ibex-runtime-js/src/fetch/body.ts#readRuntimeEnv",
  compatibilityFetchHeadersReader:
    "packages/ibex-runtime-js/src/fetch/Headers.ts#readRuntimeEnv",
  compatibilityFetchReader:
    "packages/ibex-runtime-js/src/fetch/fetch.ts#readRuntimeEnv",
  compatibilityFetchRequestReader:
    "packages/ibex-runtime-js/src/fetch/Request.ts#readRuntimeEnv",
  compatibilityFetchResponseReader:
    "packages/ibex-runtime-js/src/fetch/Response.ts#readRuntimeEnv",
  compatibilityReadableStreamReader:
    "packages/ibex-runtime-js/src/streams/ReadableStream.ts#readRuntimeEnv",
  exactAliases: "src/engine/bootstrap/exact-global.js#Exact.env",
  hostEnvironmentAbi:
    "src/host/abi.rs#ex_host_authorize_typed_environment_read_stack",
  hostTypedOverlay: "src/host/mod.rs#authorize_typed_environment_overlay_stage",
  legacyEnvironment:
    "src/engine/hermes_runtime_process_setup.cc#jsi-global:process.env.[[dynamic-table:env-obj-properties]]",
  nativeAuthorization:
    "src/engine/hermes_runtime_internal.h#typedEnvironmentOverlayAccessAllowed",
  nativeEnumeration: "src/engine/hermes_runtime.cc#__exactGetAllEnv",
  nativeScalarRead: "src/engine/hermes_runtime.cc#__exactGetEnv",
  nativeScalarWrite: "src/engine/hermes_runtime.cc#__exactSetEnv",
  sharedRuntimeAliases:
    "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:Exact.env",
  snapshotBaseFactory: "src/bin/ibex/runtime.rs#environmentBase",
  snapshotBaseSchema:
    "capsec/schema/armed-snapshot.schema.json#environmentBase",
});

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

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function requireSource(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label}: expected non-empty source text`);
  }
  return value;
}

function requireMatch(source, pattern, message) {
  if (!pattern.test(source)) throw new Error(message);
}

function sourceRegion(source, startMarker, endMarker, label) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error(`${label}: source region unavailable`);
  }
  return source.slice(start, end);
}

function requireOrdered(source, tokens, message) {
  let offset = 0;
  for (const token of tokens) {
    const found = source.indexOf(token, offset);
    if (found < 0) throw new Error(`${message}: missing ${token}`);
    offset = found + token.length;
  }
}

function parseJsonSource(source, label) {
  try {
    return JSON.parse(requireSource(source, label));
  } catch (error) {
    throw new Error(`${label}: invalid JSON: ${error.message}`);
  }
}

function validateSourceAudit(sourceAudit) {
  requireCondition(
    sourceAudit?.auditSchema === ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA &&
      sourceAudit.canonicalDynamicFamily ===
        CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY &&
      sourceAudit.legacyUnarmedDynamicFamily ===
        LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY &&
      Object.values(sourceAudit.proofs ?? {}).every(
        (proof) => proof === true,
      ) &&
      Object.keys(sourceAudit.proofs ?? {}).length === 17 &&
      Array.isArray(sourceAudit.sourceRefs) &&
      canonicalJson(sourceAudit.sourceRefs) ===
        canonicalJson(Object.values(SOURCE_REFS).sort(compareText)),
    "canonical environment source audit is missing or invalid",
  );
  return sourceAudit;
}

/**
 * Prove the complete armed environment chain from the authenticated snapshot
 * through native authorization and storage to the shared JavaScript facade.
 */
export function auditCanonicalEnvironmentOutputSources({
  armedRuntimeSource,
  builtinProcessSource,
  compatibilityReaderSources,
  exactGlobalSource,
  hostInputsSource,
  hostEnvironmentAbiSource,
  hostEnvironmentSource,
  nativeAuthorizationSource,
  nativeEnvironmentSource,
  processSetupSource,
  processFacadeSource,
  runtimeInstallSource,
  sharedBootstrapSource,
  snapshotFactorySource,
  snapshotSchemaSource,
}) {
  const armedRuntime = requireSource(
    armedRuntimeSource,
    "armed runtime preload",
  );
  const builtinProcess = requireSource(builtinProcessSource, "builtin process");
  requireCondition(
    compatibilityReaderSources !== null &&
      typeof compatibilityReaderSources === "object" &&
      canonicalJson(
        Object.keys(compatibilityReaderSources).sort(compareText),
      ) ===
        canonicalJson([...COMPATIBILITY_READER_SOURCE_PATHS].sort(compareText)),
    "bootstrap compatibility readers must provide the complete fixed source set",
  );
  const compatibilityReaders = Object.fromEntries(
    COMPATIBILITY_READER_SOURCE_PATHS.map((sourcePath) => [
      sourcePath,
      requireSource(
        compatibilityReaderSources[sourcePath],
        `bootstrap compatibility reader ${sourcePath}`,
      ),
    ]),
  );
  const exactGlobal = requireSource(exactGlobalSource, "exact global");
  const hostInputs = requireSource(
    hostInputsSource,
    "private bootstrap host inputs",
  );
  const hostEnvironmentAbi = requireSource(
    hostEnvironmentAbiSource,
    "host environment ABI",
  );
  const hostEnvironment = requireSource(
    hostEnvironmentSource,
    "host environment authorization",
  );
  const nativeAuthorization = requireSource(
    nativeAuthorizationSource,
    "native environment authorization",
  );
  const nativeEnvironment = requireSource(
    nativeEnvironmentSource,
    "native environment",
  );
  const processSetup = requireSource(
    processSetupSource,
    "native process setup",
  );
  const processFacade = requireSource(processFacadeSource, "process facade");
  const runtimeInstall = requireSource(runtimeInstallSource, "runtime install");
  const sharedBootstrap = requireSource(
    sharedBootstrapSource,
    "shared runtime bootstrap",
  );
  const snapshotFactory = requireSource(
    snapshotFactorySource,
    "armed snapshot factory",
  );
  const snapshotSchema = parseJsonSource(
    snapshotSchemaSource,
    "armed snapshot schema",
  );

  requireCondition(
    snapshotSchema?.required?.includes("environmentBase") &&
      snapshotSchema?.properties?.environmentBase?.type === "array" &&
      snapshotSchema.properties.environmentBase.maxItems === 0,
    "armed snapshot must require an explicitly empty environmentBase",
  );
  requireMatch(
    snapshotFactory,
    /value\["environmentBase"\]\s*=\s*serde_json::json!\(\[\]\);/u,
    "production snapshot factory must emit an explicitly empty environmentBase",
  );

  const compatibilityControl = sourceRegion(
    hostInputs,
    "const bootstrapCompatibilityControl: BootstrapCompatibilityControl = (() => {",
    "export function captureHostNavigatorInput",
    "fixed bootstrap compatibility control",
  );
  requireOrdered(
    compatibilityControl,
    [
      "const fixed =",
      "__exactSetEnv",
      '"function"',
      "const disabled = Object.freeze({",
      "fixed,",
      "const value =",
      ".__exactCompatModes",
      "if (!Array.isArray(value)) return disabled;",
      'new Set(["bun", "fixture", "fixture:bun"])',
      "return Object.freeze({ ...disabled, fixed });",
      "return Object.freeze({",
      'bun: modes.has("bun")',
      'fixture: modes.has("fixture")',
      'fixtureBun: modes.has("fixture:bun")',
      "fixed,",
      "return disabled;",
    ],
    "armed compatibility controls must be captured once and fail closed",
  );
  requireMatch(
    hostInputs,
    /const BOOTSTRAP_COMPATIBILITY_ENVIRONMENT_NAMES = new Set\(\[\s*"EXACT_COMPAT_BUN",\s*"EXACT_COMPAT_TEST",\s*"EXACT_TEST_SECTION",\s*\]\);/u,
    "fixed compatibility controls must remain a closed three-name set",
  );
  requireMatch(
    hostInputs,
    /export function isBootstrapCompatibilityControlFixed\(key: string\): boolean \{\s*return \(\s*bootstrapCompatibilityControl\.fixed &&\s*BOOTSTRAP_COMPATIBILITY_ENVIRONMENT_NAMES\.has\(key\)\s*\);\s*\}/u,
    "compatibility false values must remain authoritative in armed runtimes",
  );

  for (const [sourcePath, source] of Object.entries(compatibilityReaders)) {
    requireCondition(
      (
        source.match(
          /function readRuntimeEnv\(key: string\): string \| undefined/gu,
        ) ?? []
      ).length === 1,
      `${sourcePath}: expected exactly one compatibility environment reader`,
    );
    const reader = source.slice(source.indexOf("function readRuntimeEnv("));
    const fixedGuard =
      /const bootstrapValue = readBootstrapCompatibilityControl\(key\);\s*if \(\s*bootstrapValue !== undefined \|\|\s*isBootstrapCompatibilityControlFixed\(key\)\s*\) return bootstrapValue;/u.exec(
        reader,
      );
    requireCondition(
      fixedGuard !== null,
      `${sourcePath}: compatibility reader must make fixed false authoritative`,
    );
    const fallbackOffsets = [
      reader.indexOf("__exactHostEnv"),
      reader.indexOf("getRuntimeEnvObject()"),
      reader.indexOf("process.env"),
    ].filter((offset) => offset >= 0);
    requireCondition(
      fixedGuard !== null &&
        fallbackOffsets.length > 0 &&
        Math.min(...fallbackOffsets) > fixedGuard.index + fixedGuard[0].length,
      `${sourcePath}: mutable environment fallback must follow the fixed compatibility decision`,
    );
  }

  const hostOverlayAuthorization = sourceRegion(
    hostEnvironment,
    "fn authorize_typed_environment_overlay_stage(",
    "pub fn authorize_typed_environment_read_stage(",
    "host typed environment overlay authorization",
  );
  requireOrdered(
    hostOverlayAuthorization,
    [
      "Stage::Requested | capsec_semantics::model::Stage::Commit",
      "let requested = SelectorResource::EnvironmentName",
      "target: EnvironmentTarget::PrincipalOverlay",
      "let expected_surface_name = if write",
      '"__exactSetEnv"',
      'coverage_surface_name == "__exactGetAllEnv"',
      '"__exactGetEnv"',
      'generated_coverage_edge_id("native-op", coverage_surface_name)',
      'ActionId::new(if write { "env:write" } else { "env:read" })',
      "value_origin: EnvironmentValueOrigin::PrincipalOverlay",
    ],
    "host must independently type exact principal-overlay reads and writes",
  );
  if (
    /EnvironmentTarget::BrokerBase|EnvironmentValueOrigin::BrokerBase/u.test(
      hostOverlayAuthorization,
    )
  ) {
    throw new Error(
      "armed environment authorization must not select broker-base",
    );
  }
  requireMatch(
    hostEnvironment,
    /authorize_typed_environment_read_stage\([\s\S]*?false,\s*"__exactGetEnv",[\s\S]*?authorize_typed_environment_enumeration_stage\([\s\S]*?false,\s*"__exactGetAllEnv",[\s\S]*?authorize_typed_environment_write_stage\([\s\S]*?true,\s*"__exactSetEnv",/u,
    "host environment operations must retain distinct generated terminal edges",
  );

  const readAbi = sourceRegion(
    hostEnvironmentAbi,
    'pub unsafe extern "C" fn ex_host_authorize_typed_environment_read_stack(',
    'pub unsafe extern "C" fn ex_host_authorize_typed_environment_write_stack(',
    "host environment read ABI",
  );
  requireOrdered(
    readAbi,
    [
      "read_surface: u32",
      "stage > 1",
      "read_surface > 1",
      "let stage = if stage == 0",
      "Stage::Requested",
      "Stage::Commit",
      "if read_surface == 0",
      "host.authorize_typed_environment_read_stage(",
      "host.authorize_typed_environment_enumeration_stage(",
    ],
    "host read ABI must distinguish scalar and nonempty-enumeration edges",
  );
  const writeAbi = sourceRegion(
    hostEnvironmentAbi,
    'pub unsafe extern "C" fn ex_host_authorize_typed_environment_write_stack(',
    'pub unsafe extern "C" fn ex_host_authorize_typed_print_stack(',
    "host environment write ABI",
  );
  requireOrdered(
    writeAbi,
    [
      "stage > 1",
      "let stage = if stage == 0",
      "Stage::Requested",
      "Stage::Commit",
      "host.authorize_typed_environment_write_stage(",
    ],
    "host write ABI must preserve requested and commit terminal decisions",
  );

  requireMatch(
    nativeAuthorization,
    /std::unordered_map<\s*uint64_t,\s*std::unordered_map<std::string, std::string>>\s*environment_principal_overlays;/u,
    "runtime must store one native environment overlay per principal",
  );
  requireMatch(
    nativeAuthorization,
    /enum class ExactEnvironmentOverlayAccess : uint32_t \{\s*ScalarRead = 0,\s*EnumerationRead = 1,\s*Write = 2,\s*\};/u,
    "native environment access must distinguish scalar, enumeration, and write terminals",
  );
  const typedAccess = sourceRegion(
    nativeAuthorization,
    "inline bool typedEnvironmentOverlayAccessAllowed(",
    "inline void authorizeTypedEnvironmentRead(",
    "native typed environment authorization",
  );
  requireOrdered(
    typedAccess,
    [
      "auto principal = currentPrincipalId();",
      "auto principals = exactCollectTypedPrincipalStack();",
      "for (uint32_t stage = 0; stage <= 1; ++stage)",
      "access == ExactEnvironmentOverlayAccess::Write",
      "ex_host_authorize_typed_environment_write_stack(",
      "reinterpret_cast<const uint8_t*>(name.data())",
      "name.size()",
      "ex_host_authorize_typed_environment_read_stack(",
      "access == ExactEnvironmentOverlayAccess::EnumerationRead ? 1u : 0u",
      "reinterpret_cast<const uint8_t*>(name.data())",
      "name.size()",
    ],
    "native authorization must bind read and write independently for both stages",
  );
  requireMatch(
    nativeAuthorization,
    /authorizeTypedEnvironmentRead\([\s\S]*?ExactEnvironmentOverlayAccess::ScalarRead[\s\S]*?authorizeTypedEnvironmentWrite\([\s\S]*?ExactEnvironmentOverlayAccess::Write/u,
    "native scalar reads and writes must select their distinct terminal routes",
  );

  const scalarRead = sourceRegion(
    nativeEnvironment,
    "auto getEnvFn =",
    "auto getAllEnvFn =",
    "native scalar environment operations",
  );
  requireOrdered(
    scalarRead,
    [
      "authorizeTypedEnvironmentRead(runtime, key);",
      "if (handle->armed)",
      "auto principal = currentPrincipalId();",
      "handle->environment_principal_overlays.find(principal)",
      "auto value = principalOverlay->second.find(key);",
      "auto value = getEnvValue(key);",
    ],
    "armed scalar reads must resolve only the current principal overlay",
  );
  requireMatch(
    scalarRead,
    /if \(handle->armed\) \{[\s\S]*?return facebook::jsi::Value::undefined\(\);[\s\S]*?\}\s*auto value = getEnvValue\(key\);/u,
    "armed scalar reads must return before the unarmed host environment reader",
  );
  const unarmedScalarRead = scalarRead.indexOf(
    "auto value = getEnvValue(key);",
  );
  requireCondition(
    unarmedScalarRead >= 0 &&
      !scalarRead.slice(0, unarmedScalarRead).includes("getEnvValue("),
    "armed scalar read branch must contain no host environment reader",
  );

  const scalarWrite = sourceRegion(
    nativeEnvironment,
    "if (handle->armed) {\n    auto setEnvFn =",
    "auto getAllEnvFn =",
    "native scalar environment write",
  );
  requireOrdered(
    scalarWrite,
    [
      'PropNameID::forAscii(rt, "__exactSetEnv")',
      "authorizeTypedEnvironmentWrite(runtime, key);",
      "auto principal = currentPrincipalId();",
      "handle->environment_principal_overlays.find(principal)",
      "principalOverlay->second.erase(key);",
      "handle->environment_principal_overlays[principal][key]",
      'rt.global().setProperty(rt, "__exactSetEnv"',
    ],
    "armed setter must mutate only the authorized current-principal overlay",
  );
  if (/\bsetenv\s*\(|\bunsetenv\s*\(/u.test(scalarWrite)) {
    throw new Error(
      "armed environment setter must not mutate the host process",
    );
  }
  requireCondition(
    (nativeEnvironment.match(/"__exactSetEnv"/gu) ?? []).length === 2,
    "__exactSetEnv must be installed only by the armed setter branch",
  );

  const eagerProcessEnvironment = sourceRegion(
    processSetup,
    'auto hasShared = rt.global().getProperty(rt, "__exactHasSharedRuntimeBundle");',
    'std::string exact_platform = "unknown";',
    "native eager process environment",
  );
  requireOrdered(
    eagerProcessEnvironment,
    [
      "if (handle->armed)",
      'processObj.setProperty(rt, "env", facebook::jsi::Object(rt));',
      "else if (!skipEnvCopy)",
      "*_NSGetEnviron()",
      "::environ",
      'processObj.setProperty(rt, "env", std::move(envObj));',
    ],
    "armed process setup must install an empty temporary environment before the unarmed host snapshot branch",
  );
  const armedEmptyEnvironment = eagerProcessEnvironment.indexOf(
    'processObj.setProperty(rt, "env", facebook::jsi::Object(rt));',
  );
  requireCondition(
    armedEmptyEnvironment >= 0 &&
      !eagerProcessEnvironment
        .slice(0, armedEmptyEnvironment)
        .includes("GetEnviron"),
    "armed temporary process setup must not read the host environment",
  );

  const enumeration = sourceRegion(
    nativeEnvironment,
    "auto getAllEnvFn =",
    "auto setActiveModuleIdFn =",
    "native environment enumeration",
  );
  requireOrdered(
    enumeration,
    [
      "if (handle->armed)",
      "handle->environment_principal_overlays.find(",
      "currentPrincipalId()",
      "std::sort(keys.begin(), keys.end());",
      "for (const auto& key : keys)",
      "typedEnvironmentOverlayAccessAllowed(",
      "key, ExactEnvironmentOverlayAccess::EnumerationRead",
      "env.setProperty(",
      "return env;",
      'if (!checkCapability("env:read:*"))',
      "populateDiagnosticProcessEnvironment(runtime, env);",
      "return env;",
    ],
    "armed enumeration must authorize every current-principal overlay name",
  );
  requireMatch(
    enumeration,
    /\n[ \t]*return env;\r?\n[ \t]*\}\r?\n[ \t]*if \(!checkCapability\("env:read:\*"\)\)/u,
    "armed enumeration must return before the diagnostic environment gate",
  );
  requireMatch(
    enumeration,
    /if \(!checkCapability\("env:read:\*"\)\) \{\s*return env;\s*\}\s*populateDiagnosticProcessEnvironment\(runtime, env\);\s*return env;/u,
    "diagnostic environment helper must remain behind the unarmed wildcard gate",
  );

  const diagnosticEnvironmentHelper = sourceRegion(
    nativeEnvironment,
    "void populateDiagnosticProcessEnvironment(",
    "\nvoid installGlobals(",
    "diagnostic process environment helper",
  );
  requireCondition(
    (
      nativeEnvironment.match(
        /\bpopulateDiagnosticProcessEnvironment\s*\(/gu,
      ) ?? []
    ).length === 2,
    "diagnostic environment helper must have exactly one definition and one guarded call",
  );
  requireOrdered(
    diagnosticEnvironmentHelper,
    [
      "#if defined(_WIN32)",
      "GetEnvironmentStringsW()",
      "#if defined(__APPLE__)",
      "*_NSGetEnviron()",
      "::environ",
    ],
    "diagnostic environment helper must retain every platform host reader",
  );
  const nativeEnvironmentWithoutDiagnosticHelper = nativeEnvironment.replace(
    diagnosticEnvironmentHelper,
    "",
  );
  for (const hostReader of [
    "GetEnvironmentStringsW()",
    "*_NSGetEnviron()",
    "::environ",
  ]) {
    requireCondition(
      diagnosticEnvironmentHelper.includes(hostReader) &&
        !nativeEnvironmentWithoutDiagnosticHelper.includes(hostReader),
      `ambient host reader ${hostReader} must be confined to the guarded diagnostic helper`,
    );
  }

  const envProxy = sourceRegion(
    processFacade,
    "export function createEnvProxy",
    "/**\n * Process object providing Node.js-like environment info.",
    "canonical environment proxy",
  );
  requireOrdered(
    envProxy,
    [
      "typeof __exactSetEnv === 'function' ? __exactSetEnv : null",
      "const jsEnv: Record<string, string | undefined> = setPrincipalOverlay",
      "? {}",
      "value = __exactGetEnv(key);",
      "catch (_error)",
      "return undefined;",
      "if (prop === '__exactEnvProxy')",
      "setPrincipalOverlay(key, normalized);",
      "return true;",
      "setPrincipalOverlay(key, undefined);",
      "Object.keys(refreshNativeCache())",
      "preventExtensions(): boolean",
      "setPrototypeOf(): boolean",
    ],
    "canonical proxy must preserve the caller-sensitive native overlay",
  );
  requireMatch(
    envProxy,
    /preventExtensions\(\): boolean \{\s*return false;\s*\}[\s\S]*?setPrototypeOf\(\): boolean \{\s*return false;/u,
    "canonical proxy must refuse shared hardening and prototype mutation",
  );
  const armedProxyWrite = sourceRegion(
    envProxy,
    "if (setPrincipalOverlay) {",
    "target[key] = normalized;",
    "armed proxy write",
  );
  if (/jsOverrides|jsDeleted|target\s*\[/u.test(armedProxyWrite)) {
    throw new Error(
      "armed proxy writes must not retain shared JavaScript state",
    );
  }
  requireMatch(
    processFacade,
    /readonly env: Record<string, string \| undefined> = createEnvProxy\(\);/u,
    "process.env must be the canonical createEnvProxy instance",
  );

  requireMatch(
    builtinProcess,
    /!_rawEnv\.__exactEnvProxy[\s\S]*?if \(!_rawEnv\.__exactEnvProxy\) \{[\s\S]*?new Proxy\(_rawEnv/u,
    "builtin process must preserve a marked canonical environment proxy",
  );

  requireMatch(
    sharedBootstrap,
    /g\.process = exactProcess;[\s\S]*?if \(typeof g\.__exactSetEnv === 'function'\) \{[\s\S]*?Object\.defineProperty\(exactProcess, 'env', \{\s*value: exactProcess\.env,\s*writable: false,\s*configurable: false,\s*enumerable: true,\s*\}\);/u,
    "armed shared runtime must pin process.env to the canonical proxy",
  );
  requireMatch(
    sharedBootstrap,
    /const fixedBunCompat = readBootstrapCompatibilityControl\('EXACT_COMPAT_BUN'\);\s*const bunCompatEnabled =\s*fixedBunCompat === '1' \|\|\s*\(!isBootstrapCompatibilityControlFixed\('EXACT_COMPAT_BUN'\) &&\s*g\.process\?\.env\?\.EXACT_COMPAT_BUN === '1'\);\s*if \(bunCompatEnabled && g\.Exact\) \{\s*Object\.defineProperty\(g, 'Bun', \{\s*value: g\.Exact,\s*writable: false,\s*configurable: false,\s*enumerable: true,\s*\}\);\s*\}/u,
    "shared Bun facade must use fixed compatibility state before any unarmed environment fallback",
  );
  requireOrdered(
    armedRuntime,
    [
      "let compat_modes_json =",
      "globalThis.__exactCompatModes = {}",
      "Array.isArray(globalThis.__exactCompatModes)",
      "globalThis.__exactCompatModes.indexOf('bun') !== -1",
      "globalThis.Exact) {",
      "Object.defineProperty(globalThis, 'Bun'",
      "value: globalThis.Exact",
      "writable: false",
      "configurable: false",
      "enumerable: true",
      "self.engine.eval_immediate(&preload_bootstrap).await?",
    ],
    "armed runtime preload must install and pin Bun as the Exact identity alias",
  );
  requireMatch(
    sharedBootstrap,
    /Object\.defineProperty\(g\.Exact, 'env', \{[\s\S]*?get\(\) \{ return g\.process\?\.env; \},[\s\S]*?configurable: typeof g\.__exactSetEnv !== 'function'/u,
    "shared Exact.env must resolve and pin the canonical armed process.env",
  );

  requireMatch(
    exactGlobal,
    /var nativePrincipalEnvironmentOverlay =\s*typeof g\.__exactSetEnv === 'function';/u,
    "legacy Exact bootstrap must detect the armed native overlay",
  );
  requireMatch(
    exactGlobal,
    /Object\.defineProperty\(E, 'env', \{[\s\S]*?configurable: !nativePrincipalEnvironmentOverlay,[\s\S]*?get: function\(\) \{ return g\.process && g\.process\.env; \}/u,
    "legacy Exact.env must resolve and pin the canonical armed process.env",
  );
  requireMatch(
    exactGlobal,
    /catch \(err\) \{\s*if \(nativePrincipalEnvironmentOverlay\) throw err;/u,
    "armed legacy alias installation must fail closed",
  );
  requireMatch(
    exactGlobal,
    /g\.Exact = E;\s*g\.Bun = E;/u,
    "legacy Exact and Bun facades must share one object",
  );
  if (
    /E\.env\s*=\s*\(function/u.test(exactGlobal) ||
    /__exactGet(?:All)?Env/u.test(exactGlobal)
  ) {
    throw new Error(
      "exact-global must not create or directly populate an environment proxy",
    );
  }

  requireMatch(
    runtimeInstall,
    /if \(handle->armed && !sharedRuntimeInstalled\) \{[\s\S]*?Armed startup requires the capability-mediated shared runtime bundle/u,
    "armed startup must refuse the eager legacy process environment",
  );

  return deepFreeze({
    auditSchema: ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA,
    canonicalDynamicFamily: CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
    legacyUnarmedDynamicFamily: LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
    namespaceRoots: [
      "global:process.env",
      "global:Exact.env",
      "global:Bun.env",
    ],
    proofs: {
      aliasesShareCanonicalObject: true,
      armedHostEnvironmentBypassed: true,
      armedLegacyEnvironmentUnreachable: true,
      armedSetterNativeOnly: true,
      builtinPreservesCanonicalIdentity: true,
      currentPrincipalOverlayIsolation: true,
      deniedReadBecomesAbsent: true,
      enumerationAuthorizesEveryExactName: true,
      exactNameReadWriteIndependent: true,
      explicitEmptySnapshotBase: true,
      fixedCompatibilityControlsCaptured: true,
      fixedCompatibilityFalseBlocksEnvironmentFallback: true,
      processEnvironmentDescriptorPinned: true,
      proxyHardeningMutationRefused: true,
      proxyMarkerPresent: true,
      requestedAndCommitAuthorized: true,
      typedPrincipalOverlayOccurrence: true,
    },
    sourceRefs: Object.values(SOURCE_REFS).sort(compareText),
  });
}

function exactNativeOperationEdge(edge, label) {
  requireCondition(
    edge?.surface?.kind === "native-op" &&
      typeof edge?.id === "string" &&
      edge.id.length > 0,
    `${edge?.surface?.name ?? label}: ${label} identity drift`,
  );
  return edge;
}

function uniqueNamedRow(rows, name, label) {
  const matches = rows.filter((row) => row?.surface?.name === name);
  requireCondition(
    matches.length === 1,
    `${label}: expected exactly one ${name}`,
  );
  return matches[0];
}

/**
 * Bind the source proof to the source-derived principal-overlay family and the
 * separate eager native legacy sentinel. The removed ambient-host projection
 * must not be recreated merely to preserve its former inventory spelling.
 */
export function canonicalEnvironmentOutputContract({
  coverageEdges,
  sourceAudit,
  surfaces,
}) {
  validateSourceAudit(sourceAudit);
  requireCondition(
    Array.isArray(surfaces) && Array.isArray(coverageEdges),
    "environment contract requires surfaces and coverage edges",
  );

  const opaqueAliases = surfaces.filter(({ name }) =>
    OPAQUE_ALIAS_FAMILY_PATTERN.test(name),
  );
  if (opaqueAliases.length !== 0) {
    throw new Error(
      `opaque Exact/Bun environment families remain: ${opaqueAliases
        .map(({ name }) => name)
        .sort(compareText)
        .join(", ")}`,
    );
  }
  const canonicalSurface = surfaces.filter(
    ({ name }) => name === CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
  );
  const canonicalInventoryContract =
    canonicalSurface[0]?.metadata?.principalEnvironmentOverlaySourceContract;
  requireCondition(
    canonicalSurface.length === 1 &&
      canonicalSurface[0].kind === "native-op" &&
      canonicalSurface[0].observedKey ===
        `native-op:${CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY}` &&
      canonicalSurface[0].metadata?.memberKinds?.includes("dynamic-table") &&
      canonicalSurface[0].metadata?.semanticRoles?.includes(
        "principal-environment-overlay",
      ) &&
      canonicalInventoryContract?.schema ===
        "ibex/principal-environment-overlay-source-contract/1" &&
      canonicalInventoryContract.surfaceName ===
        CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY &&
      canonicalInventoryContract.binding?.factory === "createEnvProxy" &&
      canonicalInventoryContract.binding?.member === "Process.prototype.env" &&
      canonicalJson(canonicalInventoryContract.nativeBridges) ===
        canonicalJson(["__exactGetAllEnv", "__exactGetEnv", "__exactSetEnv"]) &&
      canonicalJson(
        canonicalInventoryContract.proxyTraps?.map(
          ({ name, nativeBridges }) => ({ name, nativeBridges }),
        ),
      ) ===
        canonicalJson([
          { name: "deleteProperty", nativeBridges: ["__exactSetEnv"] },
          {
            name: "get",
            nativeBridges: ["__exactGetAllEnv", "__exactGetEnv"],
          },
          {
            name: "ownKeys",
            nativeBridges: ["__exactGetAllEnv", "__exactGetEnv"],
          },
          { name: "set", nativeBridges: ["__exactSetEnv"] },
        ]),
    "canonical principal-overlay environment inventory family is missing or malformed",
  );

  const legacySurface = surfaces.filter(
    ({ name }) => name === LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
  );
  requireCondition(
    legacySurface.length === 1 &&
      legacySurface[0].kind === "native-op" &&
      legacySurface[0].observedKey ===
        `native-op:${LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY}` &&
      legacySurface[0].metadata?.memberKinds?.includes("dynamic-table"),
    "guarded legacy environment inventory family is missing or malformed",
  );
  for (const alias of ["global:Exact.env", "global:Bun.env"]) {
    requireCondition(
      surfaces.filter(({ name }) => name === alias).length === 1,
      `${alias}: namespace alias surface is missing or duplicated`,
    );
  }

  const canonicalEdge = uniqueNamedRow(
    coverageEdges,
    CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
    "canonical environment coverage",
  );
  const legacyEdge = uniqueNamedRow(
    coverageEdges,
    LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
    "legacy environment coverage",
  );
  exactNativeOperationEdge(canonicalEdge, "canonical environment family");
  exactNativeOperationEdge(legacyEdge, "legacy environment family");
  const scalarReadEdge = exactNativeOperationEdge(
    uniqueNamedRow(
      coverageEdges,
      "__exactGetEnv",
      "scalar environment read coverage",
    ),
    "scalar environment terminal",
  );
  const enumerationReadEdge = exactNativeOperationEdge(
    uniqueNamedRow(
      coverageEdges,
      "__exactGetAllEnv",
      "environment enumeration coverage",
    ),
    "enumeration environment terminal",
  );
  const writeEdge = exactNativeOperationEdge(
    uniqueNamedRow(
      coverageEdges,
      "__exactSetEnv",
      "scalar environment write coverage",
    ),
    "write environment terminal",
  );
  requireCondition(
    canonicalEdge.surface?.kind === "native-op" &&
      legacyEdge.surface?.kind === "native-op",
    "environment coverage families must remain native operations",
  );

  return deepFreeze({
    contractSchema: ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA,
    accountKind: "parameterized-exact-principal-overlay-read",
    surfaceId: canonicalEdge.id,
    surfaceObservedKey: `native-op:${CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY}`,
    aliases: [
      { availability: "always", root: "global:process.env" },
      { availability: "always", root: "global:Exact.env" },
      { availability: "bun-compat-or-legacy", root: "global:Bun.env" },
    ],
    authorization: {
      independence: "read-does-not-imply-write-and-write-does-not-imply-read",
      read: {
        capability: "env:read",
        stages: ["requested", "commit"],
        target: "principal-overlay",
      },
      write: {
        capability: "env:write",
        stages: ["requested", "commit"],
        target: "principal-overlay",
      },
    },
    base: {
      armedSnapshot: "explicit-empty-array",
      hostFallback: false,
    },
    enumeration: {
      membership: "current-principal-overlay-only",
      authorization: "independent-env:read-per-exact-name",
      ordering: "canonical-name-sort",
    },
    legacyNativeFamily: {
      armedReachability: "refused-before-package-evaluation",
      reasonCode: ENVIRONMENT_LEGACY_STRUCTURAL_REASON_CODE,
      surfaceId: legacyEdge.id,
      observedKey: legacySurface[0].observedKey,
      outputRows: "none",
    },
    mutation: {
      hostProcessMutation: false,
      capability: "env:write",
      deleteEffect: "current-principal-overlay-delete",
      nativeSetter: "armed-only",
      setEffect: "current-principal-overlay-string-write",
    },
    output: {
      channel: "exact-property-read-return",
      dispositionClaim: "none",
      valueVariants: ["string", "undefined"],
    },
    parameter: {
      accountSetSource: "authenticated-policy-exact-name-selectors",
      binding: "one-concrete-name-per-account",
      maximumUtf8Bytes: 32768,
      name: "environmentName",
      normalizer: "environment.name.v1",
      pattern: ENVIRONMENT_NAME_PATTERN.source,
      wildcardAllowed: false,
    },
    proofMode: "source-bound-parameterized-occurrence",
    terminalSurfaces: {
      enumerationRead: {
        name: "__exactGetAllEnv",
        readSurface: 1,
        surfaceId: enumerationReadEdge.id,
        authorization: "nonempty-per-exact-name",
      },
      scalarRead: {
        name: "__exactGetEnv",
        readSurface: 0,
        surfaceId: scalarReadEdge.id,
      },
      write: {
        name: "__exactSetEnv",
        surfaceId: writeEdge.id,
      },
    },
    sourceRefs: [
      ...new Set([
        ...sourceAudit.sourceRefs,
        ...canonicalSurface[0].sourceRefs,
      ]),
    ].sort(compareText),
  });
}

function validateContract(contract) {
  requireCondition(
    contract?.contractSchema === ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA &&
      contract.accountKind === "parameterized-exact-principal-overlay-read" &&
      contract.parameter?.wildcardAllowed === false &&
      contract.authorization?.read?.target === "principal-overlay" &&
      contract.authorization?.write?.target === "principal-overlay" &&
      contract.base?.hostFallback === false &&
      contract.terminalSurfaces?.scalarRead?.name === "__exactGetEnv" &&
      contract.terminalSurfaces?.enumerationRead?.name === "__exactGetAllEnv" &&
      contract.terminalSurfaces?.write?.name === "__exactSetEnv",
    "invalid canonical environment output contract",
  );
  return contract;
}

function canonicalEnvironmentName(value) {
  if (
    typeof value !== "string" ||
    !ENVIRONMENT_NAME_PATTERN.test(value) ||
    Buffer.byteLength(value, "utf8") > 32768
  ) {
    throw new Error(`invalid exact environment name ${JSON.stringify(value)}`);
  }
  return value;
}

/** Instantiate one finite read account without probing or enumerating a host. */
export function instantiateEnvironmentOutputAccount(contract, environmentName) {
  validateContract(contract);
  const name = canonicalEnvironmentName(environmentName);
  const memberAliases = contract.aliases.map(({ availability, root }) => ({
    availability,
    member: `${root}.${name}`,
  }));
  return deepFreeze({
    accountSchema: ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA,
    accountId: `principal-overlay-environment-read:${name}`,
    evidenceMode: "parameterized-exact-occurrence",
    memberAliases,
    operation: {
      capability: "env:read",
      occurrence: {
        kind: "environment-occurrence",
        requested: {
          kind: "environment-name",
          name,
          target: "principal-overlay",
        },
        valueOrigin: "principal-overlay",
      },
      stages: ["requested", "commit"],
      terminalSurface: {
        name: contract.terminalSurfaces.scalarRead.name,
        surfaceId: contract.terminalSurfaces.scalarRead.surfaceId,
      },
    },
    output: {
      channel: "exact-property-read-return",
      dispositionClaim: "none",
      valueVariants: ["string", "undefined"],
    },
    surfaceId: contract.surfaceId,
    surfaceObservedKey: contract.surfaceObservedKey,
  });
}

/**
 * Expand the finite exact-name set supplied by authenticated policy. This
 * never consults process.env, ownKeys, or a representative fixture value.
 */
export function instantiateAuthorizedEnvironmentOutputAccounts(
  contract,
  authorizedNames,
) {
  validateContract(contract);
  requireCondition(
    Array.isArray(authorizedNames) && authorizedNames.length > 0,
    "authorized environment account set must be non-empty",
  );
  const names = authorizedNames.map(canonicalEnvironmentName);
  const canonicalNames = [...new Set(names)].sort(compareText);
  if (canonicalJson(names) !== canonicalJson(canonicalNames)) {
    throw new Error(
      new Set(names).size !== names.length
        ? "authorized environment names must be unique"
        : "authorized environment names must be canonically sorted",
    );
  }
  const accounts = canonicalNames.map((name) =>
    instantiateEnvironmentOutputAccount(contract, name),
  );
  requireCondition(
    new Set(accounts.map(({ accountId }) => accountId)).size ===
      accounts.length,
    "environment output account ids must be unique",
  );
  return Object.freeze(accounts);
}

export function validateEnvironmentOutputAccount(account, contract) {
  validateContract(contract);
  requireCondition(
    account?.accountSchema === ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA &&
      account.surfaceId === contract.surfaceId &&
      account.surfaceObservedKey === contract.surfaceObservedKey &&
      account.evidenceMode === "parameterized-exact-occurrence" &&
      account.operation?.capability === "env:read" &&
      account.operation?.occurrence?.requested?.target ===
        "principal-overlay" &&
      account.operation?.occurrence?.valueOrigin === "principal-overlay" &&
      account.output?.dispositionClaim === "none" &&
      canonicalJson(account.output?.valueVariants) ===
        canonicalJson(["string", "undefined"]),
    "invalid environment output account",
  );
  const name = canonicalEnvironmentName(
    account.operation.occurrence.requested.name,
  );
  const expected = instantiateEnvironmentOutputAccount(contract, name);
  requireCondition(
    canonicalJson(account) === canonicalJson(expected),
    "environment output account binding drift",
  );
  return account;
}

/** Rowless integration binding for the unreachable eager native env object. */
export function environmentStructuralAccountBindings(sourceAudit) {
  validateSourceAudit(sourceAudit);
  return deepFreeze([
    {
      surfaceName: LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
      status: "structural-only",
      reasonCode: ENVIRONMENT_LEGACY_STRUCTURAL_REASON_CODE,
      sourceRefs: [
        SOURCE_REFS.armedSharedRuntimeGuard,
        SOURCE_REFS.legacyEnvironment,
      ].sort(compareText),
      outputKinds: [],
    },
  ]);
}

/**
 * Catalog integration binding for a coverage-only, parameterized output
 * family. Ordinary catalog rows are forbidden because no unauthenticated name
 * or representative host value can stand in for the finite policy name set.
 */
export function environmentParameterizedOutputCatalogBindings(contract) {
  validateContract(contract);
  return deepFreeze([
    {
      bindingSchema: ENVIRONMENT_PARAMETERIZED_CATALOG_BINDING_SCHEMA,
      surfaceId: contract.surfaceId,
      surfaceName: CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
      status: "output-bearing",
      reasonCode: ENVIRONMENT_PARAMETERIZED_REASON_CODE,
      sourceRefs: [...contract.sourceRefs].sort(compareText),
      outputKinds: ["exact-property-read-return"],
      accountSchema: ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA,
      accountSetSource: contract.parameter.accountSetSource,
      binding: contract.parameter.binding,
      terminalSurfaces: contract.terminalSurfaces,
      ordinaryCatalogRows: "forbidden",
    },
  ]);
}

function exactObjectKeys(value, expected, label) {
  requireCondition(
    value && typeof value === "object" && !Array.isArray(value),
    `${label}: expected object`,
  );
  requireCondition(
    canonicalJson(Object.keys(value).sort(compareText)) ===
      canonicalJson([...expected].sort(compareText)),
    `${label}: unexpected fields`,
  );
}

function requireNonEmptyString(value, label) {
  requireCondition(
    typeof value === "string" && value.length > 0,
    `${label}: expected non-empty string`,
  );
  return value;
}

function projectObservedPrincipal(principal, label) {
  requireCondition(
    principal && typeof principal === "object" && !Array.isArray(principal),
    `${label}: expected principal`,
  );
  switch (principal.kind) {
    case "package":
      exactObjectKeys(
        principal,
        ["kind", "name", "integrity", "locator"],
        label,
      );
      requireNonEmptyString(principal.name, `${label}.name`);
      requireCondition(
        CAPSEC_DIGEST_PATTERN.test(principal.integrity),
        `${label}.integrity: expected CapSec digest`,
      );
      requireNonEmptyString(principal.locator, `${label}.locator`);
      return {
        kind: principal.kind,
        name: principal.name,
        integrity: principal.integrity,
        locator: principal.locator,
      };
    case "root":
    case "runtime":
    case "module-loader":
    case "quarantine":
      exactObjectKeys(principal, ["kind", "identity"], label);
      requireNonEmptyString(principal.identity, `${label}.identity`);
      return { kind: principal.kind, identity: principal.identity };
    default:
      throw new Error(`${label}: unsupported principal kind`);
  }
}

function projectObservedPrincipalArray(principals, label) {
  requireCondition(Array.isArray(principals), `${label}: expected array`);
  return principals.map((principal, index) =>
    projectObservedPrincipal(principal, `${label}[${index}]`),
  );
}

function projectObservedDecisionEvidenceEntry(entry, label) {
  exactObjectKeys(
    entry,
    ["effectIndex", "principal", "stratum", "reason", "sourceId"],
    label,
  );
  requireCondition(
    Number.isSafeInteger(entry.effectIndex) && entry.effectIndex >= 0,
    `${label}.effectIndex: expected safe unsigned integer`,
  );
  requireCondition(
    entry.stratum === "static-floor" && entry.reason === "static-floor",
    `${label}: environment sweep evidence must name the static floor exactly`,
  );
  requireNonEmptyString(entry.sourceId, `${label}.sourceId`);
  return {
    effectIndex: entry.effectIndex,
    principal: projectObservedPrincipal(entry.principal, `${label}.principal`),
    stratum: entry.stratum,
    reason: entry.reason,
    sourceId: entry.sourceId,
  };
}

function projectObservedSemanticIdentity(identity, label) {
  exactObjectKeys(
    identity,
    [
      "profile",
      "semanticCore",
      "vocabDigest",
      "registryDigest",
      "policyDigest",
      "armedSnapshotDigest",
    ],
    label,
  );
  requireCondition(
    identity.profile === "ibex/capsec/1" &&
      identity.semanticCore === "capsec/semantics/1",
    `${label}: unsupported semantic contract identity`,
  );
  for (const field of [
    "vocabDigest",
    "registryDigest",
    "policyDigest",
    "armedSnapshotDigest",
  ]) {
    requireCondition(
      CAPSEC_DIGEST_PATTERN.test(identity[field]),
      `${label}.${field}: expected CapSec digest`,
    );
  }
  return {
    profile: identity.profile,
    semanticCore: identity.semanticCore,
    vocabDigest: identity.vocabDigest,
    registryDigest: identity.registryDigest,
    policyDigest: identity.policyDigest,
    armedSnapshotDigest: identity.armedSnapshotDigest,
  };
}

/**
 * Validate and project the complete Rust `ObservedTypedDecision` serializer
 * shape. Nothing executor-owned is retained merely because it happened to be
 * nested under a recognized decision envelope.
 */
function projectObservedEnvironmentDecision(
  decision,
  expectedBranchId,
  expectedFloorSourceIds,
  label,
) {
  exactObjectKeys(
    decision,
    ["terminalBranchId", "decisionSet", "gates", "evidence"],
    label,
  );
  requireCondition(
    decision.terminalBranchId === expectedBranchId,
    `${label}: typed decision escaped its exact executor branch`,
  );

  const set = decision.decisionSet;
  exactObjectKeys(
    set,
    [
      "decisionSetSchema",
      "operationId",
      "atomicityGroup",
      "combination",
      "context",
      "effects",
    ],
    `${label}.decisionSet`,
  );
  requireCondition(
    set.decisionSetSchema === "ibex/capsec-decision-set/1" &&
      set.combination === "conjunction",
    `${label}.decisionSet: unsupported decision-set contract`,
  );
  requireNonEmptyString(set.operationId, `${label}.decisionSet.operationId`);
  requireNonEmptyString(
    set.atomicityGroup,
    `${label}.decisionSet.atomicityGroup`,
  );

  exactObjectKeys(
    set.context,
    ["stage", "actor", "constrainedPrincipals", "presentedHandleIds"],
    `${label}.decisionSet.context`,
  );
  requireCondition(
    ["requested", "commit"].includes(set.context.stage),
    `${label}.decisionSet.context.stage: unsupported environment stage`,
  );
  const actor = projectObservedPrincipal(
    set.context.actor,
    `${label}.decisionSet.context.actor`,
  );
  const constrainedPrincipals = projectObservedPrincipalArray(
    set.context.constrainedPrincipals,
    `${label}.decisionSet.context.constrainedPrincipals`,
  );
  requireCondition(
    canonicalJson(actor) ===
      canonicalJson({ kind: "root", identity: "project-root" }) &&
      canonicalJson(constrainedPrincipals) === canonicalJson([actor]),
    `${label}.decisionSet.context: environment evidence is not constrained to the fixture root`,
  );
  requireCondition(
    Array.isArray(set.context.presentedHandleIds) &&
      set.context.presentedHandleIds.length === 0,
    `${label}.decisionSet.context: environment sweep presented handles`,
  );

  requireCondition(
    Array.isArray(set.effects) && set.effects.length === 1,
    `${label}.decisionSet.effects: expected one environment effect`,
  );
  const effect = set.effects[0];
  exactObjectKeys(
    effect,
    ["cap", "effectOwner", "resource"],
    `${label}.decisionSet.effects[0]`,
  );
  requireCondition(
    effect.cap === "env:read" || effect.cap === "env:write",
    `${label}.decisionSet.effects[0].cap: unsupported capability`,
  );
  const effectOwner = projectObservedPrincipal(
    effect.effectOwner,
    `${label}.decisionSet.effects[0].effectOwner`,
  );
  requireCondition(
    canonicalJson(effectOwner) === canonicalJson(actor),
    `${label}.decisionSet.effects[0]: effect owner disagrees with actor`,
  );
  exactObjectKeys(
    effect.resource,
    ["kind", "requested", "valueOrigin"],
    `${label}.decisionSet.effects[0].resource`,
  );
  exactObjectKeys(
    effect.resource.requested,
    ["kind", "target", "name"],
    `${label}.decisionSet.effects[0].resource.requested`,
  );
  requireCondition(
    effect.resource.kind === "environment-occurrence" &&
      effect.resource.requested.kind === "environment-name" &&
      effect.resource.requested.target === "principal-overlay" &&
      effect.resource.valueOrigin === "principal-overlay",
    `${label}.decisionSet.effects[0].resource: invalid environment occurrence`,
  );
  canonicalEnvironmentName(effect.resource.requested.name);

  requireCondition(
    Array.isArray(decision.gates) && decision.gates.length === 1,
    `${label}.gates: expected one effect gate`,
  );
  const gate = decision.gates[0];
  exactObjectKeys(
    gate,
    [
      "coverageEdgeId",
      "targetCell",
      "definitionAndEdgePredicatesSatisfied",
    ],
    `${label}.gates[0]`,
  );
  requireNonEmptyString(gate.coverageEdgeId, `${label}.gates[0].coverageEdgeId`);
  requireCondition(
    gate.targetCell === "complete" &&
      gate.definitionAndEdgePredicatesSatisfied === true &&
      set.atomicityGroup === `${gate.coverageEdgeId}.decision`,
    `${label}: gate and atomicity-group binding drift`,
  );

  const evidence = decision.evidence;
  exactObjectKeys(
    evidence,
    [
      "identity",
      "generations",
      "operationId",
      "stage",
      "actor",
      "effectOwners",
      "constrainedPrincipals",
      "outcome",
      "evidence",
    ],
    `${label}.evidence`,
  );
  const identity = projectObservedSemanticIdentity(
    evidence.identity,
    `${label}.evidence.identity`,
  );
  exactObjectKeys(
    evidence.generations,
    ["negative", "dynamic", "handle"],
    `${label}.evidence.generations`,
  );
  for (const field of ["negative", "dynamic", "handle"]) {
    requireCondition(
      evidence.generations[field] === 0,
      `${label}.evidence.generations.${field}: fixture generation must be zero`,
    );
  }
  const evidenceActor = projectObservedPrincipal(
    evidence.actor,
    `${label}.evidence.actor`,
  );
  const evidenceOwners = projectObservedPrincipalArray(
    evidence.effectOwners,
    `${label}.evidence.effectOwners`,
  );
  const evidenceConstrained = projectObservedPrincipalArray(
    evidence.constrainedPrincipals,
    `${label}.evidence.constrainedPrincipals`,
  );
  requireCondition(
    evidence.operationId === set.operationId &&
      evidence.stage === set.context.stage &&
      canonicalJson(evidenceActor) === canonicalJson(actor) &&
      canonicalJson(evidenceOwners) === canonicalJson([effectOwner]) &&
      canonicalJson(evidenceConstrained) ===
        canonicalJson(constrainedPrincipals) &&
      evidence.outcome === "allow" &&
      Array.isArray(evidence.evidence),
    `${label}.evidence: structured evidence lost its decision binding`,
  );
  const evidenceEntries = evidence.evidence.map((entry, index) =>
    projectObservedDecisionEvidenceEntry(
      entry,
      `${label}.evidence.evidence[${index}]`,
    ),
  );
  const expectedFloorSourceId = expectedFloorSourceIds.get(
    canonicalJson(
      environmentSweepSelector(
        effect.cap,
        effect.resource.requested.name,
      ),
    ),
  );
  requireCondition(
    typeof expectedFloorSourceId === "string" &&
      evidenceEntries.length === 1 &&
      evidenceEntries[0].effectIndex === 0 &&
      canonicalJson(evidenceEntries[0].principal) === canonicalJson(actor) &&
      evidenceEntries[0].sourceId === expectedFloorSourceId,
    `${label}.evidence: evidence escaped the exact authenticated environment floor`,
  );

  return {
    terminalBranchId: decision.terminalBranchId,
    decisionSet: {
      decisionSetSchema: set.decisionSetSchema,
      operationId: set.operationId,
      atomicityGroup: set.atomicityGroup,
      combination: set.combination,
      context: {
        stage: set.context.stage,
        actor,
        constrainedPrincipals,
        presentedHandleIds: [],
      },
      effects: [
        {
          cap: effect.cap,
          effectOwner,
          resource: {
            kind: effect.resource.kind,
            requested: {
              kind: effect.resource.requested.kind,
              target: effect.resource.requested.target,
              name: effect.resource.requested.name,
            },
            valueOrigin: effect.resource.valueOrigin,
          },
        },
      ],
    },
    gates: [
      {
        coverageEdgeId: gate.coverageEdgeId,
        targetCell: gate.targetCell,
        definitionAndEdgePredicatesSatisfied:
          gate.definitionAndEdgePredicatesSatisfied,
      },
    ],
    evidence: {
      identity,
      generations: {
        negative: evidence.generations.negative,
        dynamic: evidence.generations.dynamic,
        handle: evidence.generations.handle,
      },
      operationId: evidence.operationId,
      stage: evidence.stage,
      actor: evidenceActor,
      effectOwners: evidenceOwners,
      constrainedPrincipals: evidenceConstrained,
      outcome: evidence.outcome,
      evidence: evidenceEntries,
    },
  };
}

function environmentSweepSelector(capability, name) {
  return {
    cap: capability,
    resource: {
      kind: "environment-name",
      target: "principal-overlay",
      name,
    },
  };
}

function environmentSweepBindingDigest(binding) {
  const projected = structuredClone(binding);
  delete projected.sweepBindingDigest;
  return taggedDigest(ENVIRONMENT_SWEEP_BINDING_DIGEST_DOMAIN, projected);
}

function environmentSweepFloorSourceIds(binding) {
  const selectors = binding.accounts
    .flatMap(({ readSelector, writeSetupSelector }) => [
      structuredClone(readSelector),
      structuredClone(writeSetupSelector),
    ])
    .sort((left, right) =>
      compareText(canonicalJson(left), canonicalJson(right)),
    );
  return new Map(
    selectors.map((selector, index) => [
      canonicalJson(selector),
      `principal.000000.floor.${String(index).padStart(6, "0")}`,
    ]),
  );
}

/**
 * Expand a rowless catalog family into the finite exact-name authority that
 * the loaded-engine sweep will actually authenticate. The account names are
 * fixed executor policy, not inferred from process.env or the host.
 */
export function buildEnvironmentOutputSweepBindings(
  parameterizedBindings,
  names = ENVIRONMENT_OUTPUT_SWEEP_NAMES,
) {
  requireCondition(
    Array.isArray(parameterizedBindings),
    "environment sweep requires parameterized catalog bindings",
  );
  const canonicalNames = names.map(canonicalEnvironmentName);
  requireCondition(
    canonicalJson(canonicalNames) ===
      canonicalJson([...new Set(canonicalNames)].sort(compareText)) &&
      canonicalNames.length > 0,
    "environment sweep names must be a non-empty canonical exact-name set",
  );
  const bindings = parameterizedBindings.map((catalogBinding, index) => {
    requireCondition(
      catalogBinding?.bindingSchema ===
        ENVIRONMENT_PARAMETERIZED_CATALOG_BINDING_SCHEMA &&
        catalogBinding.accountSetSource ===
          "authenticated-policy-exact-name-selectors" &&
        catalogBinding.ordinaryCatalogRows === "forbidden",
      `environment sweep catalog binding ${index}: unsupported binding`,
    );
    const binding = {
      environmentOutputSweepBindingSchema:
        ENVIRONMENT_OUTPUT_SWEEP_BINDING_SCHEMA,
      surfaceId: catalogBinding.surfaceId,
      surfaceName: catalogBinding.surfaceName,
      catalogBindingDigest: taggedDigest(
        ENVIRONMENT_SWEEP_BINDING_DIGEST_DOMAIN,
        catalogBinding,
      ),
      accounts: canonicalNames.map((environmentName) => ({
        environmentOutputSweepAccountSchema:
          ENVIRONMENT_OUTPUT_SWEEP_ACCOUNT_SCHEMA,
        accountId: `principal-overlay-environment-read:${environmentName}`,
        environmentName,
        readSelector: environmentSweepSelector("env:read", environmentName),
        writeSetupSelector: environmentSweepSelector(
          "env:write",
          environmentName,
        ),
      })),
      terminalSurfaces: structuredClone(catalogBinding.terminalSurfaces),
      phases: [...ENVIRONMENT_SWEEP_PHASES],
    };
    binding.sweepBindingDigest = environmentSweepBindingDigest(binding);
    return binding;
  });
  return deepFreeze(bindings);
}

export function validateEnvironmentOutputSweepBindings(
  bindings,
  parameterizedBindings,
) {
  requireCondition(
    Array.isArray(bindings),
    "environment sweep bindings must be an array",
  );
  const expected = parameterizedBindings
    ? buildEnvironmentOutputSweepBindings(parameterizedBindings)
    : null;
  const surfaceIds = new Set();
  for (const [index, binding] of bindings.entries()) {
    const label = `environment sweep binding ${index}`;
    exactObjectKeys(
      binding,
      [
        "environmentOutputSweepBindingSchema",
        "surfaceId",
        "surfaceName",
        "catalogBindingDigest",
        "accounts",
        "terminalSurfaces",
        "phases",
        "sweepBindingDigest",
      ],
      label,
    );
    requireCondition(
      binding.environmentOutputSweepBindingSchema ===
        ENVIRONMENT_OUTPUT_SWEEP_BINDING_SCHEMA &&
        typeof binding.surfaceId === "string" &&
        !surfaceIds.has(binding.surfaceId) &&
        typeof binding.surfaceName === "string" &&
        /^sha256-[A-Za-z0-9_-]{43}$/u.test(binding.catalogBindingDigest) &&
        binding.sweepBindingDigest === environmentSweepBindingDigest(binding) &&
        canonicalJson(binding.phases) ===
          canonicalJson(ENVIRONMENT_SWEEP_PHASES) &&
        binding.terminalSurfaces?.scalarRead?.name === "__exactGetEnv" &&
        binding.terminalSurfaces?.enumerationRead?.name ===
          "__exactGetAllEnv" &&
        binding.terminalSurfaces?.write?.name === "__exactSetEnv" &&
        Array.isArray(binding.accounts) &&
        binding.accounts.length > 0,
      `${label}: malformed or drifted binding`,
    );
    surfaceIds.add(binding.surfaceId);
    const names = [];
    for (const [accountIndex, account] of binding.accounts.entries()) {
      const accountLabel = `${label}.accounts[${accountIndex}]`;
      exactObjectKeys(
        account,
        [
          "environmentOutputSweepAccountSchema",
          "accountId",
          "environmentName",
          "readSelector",
          "writeSetupSelector",
        ],
        accountLabel,
      );
      const name = canonicalEnvironmentName(account.environmentName);
      requireCondition(
        account.environmentOutputSweepAccountSchema ===
          ENVIRONMENT_OUTPUT_SWEEP_ACCOUNT_SCHEMA &&
          account.accountId === `principal-overlay-environment-read:${name}` &&
          canonicalJson(account.readSelector) ===
            canonicalJson(environmentSweepSelector("env:read", name)) &&
          canonicalJson(account.writeSetupSelector) ===
            canonicalJson(environmentSweepSelector("env:write", name)),
        `${accountLabel}: selector binding drift`,
      );
      names.push(name);
    }
    requireCondition(
      canonicalJson(names) ===
        canonicalJson([...new Set(names)].sort(compareText)),
      `${label}: account names must be a canonical exact-name set`,
    );
  }
  if (expected) {
    requireCondition(
      canonicalJson(bindings) === canonicalJson(expected),
      "environment sweep bindings do not match the parameterized catalog",
    );
  }
  return bindings;
}

/** Exact selectors that must be present in the sweep's authenticated floor. */
export function environmentOutputSweepAuthoritySelectors(bindings) {
  validateEnvironmentOutputSweepBindings(bindings);
  return deepFreeze(
    bindings.flatMap(({ accounts }) =>
      accounts.flatMap(({ readSelector, writeSetupSelector }) => [
        structuredClone(readSelector),
        structuredClone(writeSetupSelector),
      ]),
    ),
  );
}

function validateEnvironmentDecisionPhase(binding, phase, label) {
  exactObjectKeys(
    phase,
    ["phase", "legacyObservationCount", "typedDecisions"],
    label,
  );
  requireCondition(
    ENVIRONMENT_SWEEP_PHASES.includes(phase.phase) &&
      phase.legacyObservationCount === 0 &&
      Array.isArray(phase.typedDecisions),
    `${label}: malformed or legacy observation`,
  );
  const primary =
    phase.phase === "write-setup"
      ? {
          cap: "env:write",
          operation: "environment-write",
          surfaceId: binding.terminalSurfaces.write.surfaceId,
        }
      : phase.phase === "enumeration"
        ? {
            cap: "env:read",
            operation: "environment-enumerate",
            surfaceId: binding.terminalSurfaces.enumerationRead.surfaceId,
          }
        : {
            cap: "env:read",
            operation: "environment-read",
            surfaceId: binding.terminalSurfaces.scalarRead.surfaceId,
          };
  const primaryStagesByName = new Map(
    binding.accounts.map(({ environmentName }) => [environmentName, []]),
  );
  const scalarStagesByName = new Map(
    binding.accounts.map(({ environmentName }) => [environmentName, []]),
  );
  const expectedFloorSourceIds = environmentSweepFloorSourceIds(binding);
  const expectedBranchId = `output-shape-environment:${binding.sweepBindingDigest}:${phase.phase}`;
  const projectedDecisions = phase.typedDecisions.map((decision, index) =>
    projectObservedEnvironmentDecision(
      decision,
      expectedBranchId,
      expectedFloorSourceIds,
      `${label}.typedDecisions[${index}]`,
    ),
  );
  requireCondition(
    projectedDecisions.length ===
      binding.accounts.length * (phase.phase === "enumeration" ? 8 : 2),
    `${label}: typed decision cardinality does not match the exact executor calls`,
  );
  const authenticatedStates = new Set(
    projectedDecisions.map((decision) =>
      canonicalJson({
        identity: decision.evidence.identity,
        generations: decision.evidence.generations,
      }),
    ),
  );
  requireCondition(
    authenticatedStates.size === 1,
    `${label}: typed decisions disagree on authenticated semantic state`,
  );
  for (const decision of projectedDecisions) {
    const effects = decision?.decisionSet?.effects;
    const gates = decision?.gates;
    requireCondition(
      decision?.evidence?.outcome === "allow" &&
        Array.isArray(effects) &&
        effects.length === 1 &&
        Array.isArray(gates) &&
        gates.length === 1 &&
        gates[0]?.targetCell === "complete" &&
        gates[0]?.definitionAndEdgePredicatesSatisfied === true,
      `${label}: typed decision is not one complete authenticated allow`,
    );
    const effect = effects[0];
    const requested = effect?.resource?.requested;
    const operation = String(decision?.decisionSet?.operationId ?? "");
    const expectedOperation = `${primary.operation}:0:${JSON.stringify({
      kind: "environment-name",
      target: "principal-overlay",
      name: requested?.name,
    })}`;
    const isPrimary =
      effect?.cap === primary.cap &&
      operation === expectedOperation &&
      gates[0]?.coverageEdgeId === primary.surfaceId;
    const expectedScalarOperation = `environment-read:0:${JSON.stringify({
      kind: "environment-name",
      target: "principal-overlay",
      name: requested?.name,
    })}`;
    const isEnumerationScalarRead =
      phase.phase === "enumeration" &&
      effect?.cap === "env:read" &&
      operation === expectedScalarOperation &&
      gates[0]?.coverageEdgeId ===
        binding.terminalSurfaces.scalarRead.surfaceId;
    requireCondition(
      (isPrimary || isEnumerationScalarRead) &&
        requested?.kind === "environment-name" &&
        requested?.target === "principal-overlay" &&
        effect.resource?.valueOrigin === "principal-overlay" &&
        primaryStagesByName.has(requested.name) &&
        ["requested", "commit"].includes(decision?.decisionSet?.context?.stage),
      `${label}: typed decision escaped the finite exact-name route`,
    );
    if (isPrimary) {
      primaryStagesByName
        .get(requested.name)
        .push(decision.decisionSet.context.stage);
    } else {
      scalarStagesByName
        .get(requested.name)
        .push(decision.decisionSet.context.stage);
    }
  }
  for (const [name, stages] of primaryStagesByName) {
    requireCondition(
      canonicalJson(stages) === canonicalJson(["requested", "commit"]),
      `${label}: ${name} lacks one requested/commit ${primary.operation} pair`,
    );
    const scalarStages = scalarStagesByName.get(name);
    const expectedScalarStages =
      phase.phase === "enumeration"
        ? [
            "requested",
            "commit",
            "requested",
            "commit",
            "requested",
            "commit",
          ]
        : [];
    requireCondition(
      canonicalJson(scalarStages) === canonicalJson(expectedScalarStages),
      `${label}: ${name} lacks the exact scalar reads caused by ${phase.phase}`,
    );
  }
  return {
    phase: phase.phase,
    legacyObservationCount: phase.legacyObservationCount,
    typedDecisions: projectedDecisions,
  };
}

function validateEnvironmentExecutorIdentity(executorIdentity, label) {
  exactObjectKeys(
    executorIdentity,
    ["executor", "loadedEngineBinaryDigest"],
    label,
  );
  requireNonEmptyString(executorIdentity.executor, `${label}.executor`);
  requireCondition(
    CAPSEC_DIGEST_PATTERN.test(executorIdentity.loadedEngineBinaryDigest),
    `${label}.loadedEngineBinaryDigest: expected loaded engine digest`,
  );
  return executorIdentity;
}

function validateEnvironmentExecutorResult(
  binding,
  result,
  executorIdentity,
  label,
) {
  exactObjectKeys(
    result,
    [
      "environmentOutputExecutorResultSchema",
      "executor",
      "loadedEngineBinaryDigest",
      "surfaceId",
      "sweepBindingDigest",
      "accounts",
      "enumerationNames",
      "facadeAliases",
      "sealedRawBridges",
      "hostEnvironmentCanary",
      "phases",
    ],
    label,
  );
  requireCondition(
    result.environmentOutputExecutorResultSchema ===
      ENVIRONMENT_OUTPUT_SWEEP_EXECUTOR_RESULT_SCHEMA &&
      result.executor === executorIdentity.executor &&
      result.loadedEngineBinaryDigest ===
        executorIdentity.loadedEngineBinaryDigest &&
      result.surfaceId === binding.surfaceId &&
      result.sweepBindingDigest === binding.sweepBindingDigest &&
      canonicalJson(result.enumerationNames) ===
        canonicalJson(
          binding.accounts.map(({ environmentName }) => environmentName),
        ) &&
      canonicalJson(result.facadeAliases) ===
        canonicalJson({ bun: true, exact: true }) &&
      canonicalJson(result.sealedRawBridges) ===
        canonicalJson({
          enumeration: "undefined",
          scalar: "undefined",
          write: "undefined",
        }) &&
      Array.isArray(result.accounts) &&
      result.accounts.length === binding.accounts.length &&
      Array.isArray(result.phases) &&
      result.phases.length === ENVIRONMENT_SWEEP_PHASES.length,
    `${label}: stale, incomplete, or unsealed executor result`,
  );
  exactObjectKeys(
    result.hostEnvironmentCanary,
    ["fixedNamesSeeded", "scalarBeforeHidden", "unchangedAfterOverlayWrites"],
    `${label}.hostEnvironmentCanary`,
  );
  requireCondition(
    result.hostEnvironmentCanary.fixedNamesSeeded === true &&
      result.hostEnvironmentCanary.scalarBeforeHidden === true &&
      result.hostEnvironmentCanary.unchangedAfterOverlayWrites === true,
    `${label}: host-environment positive control failed`,
  );
  for (const [index, expected] of binding.accounts.entries()) {
    const account = result.accounts[index];
    exactObjectKeys(
      account,
      [
        "accountId",
        "environmentName",
        "scalarBefore",
        "scalarAfter",
        "enumerated",
      ],
      `${label}.accounts[${index}]`,
    );
    for (const field of ["scalarBefore", "scalarAfter", "enumerated"]) {
      exactObjectKeys(
        account[field],
        ["valueShape", "value"],
        `${label}.accounts[${index}].${field}`,
      );
    }
    requireCondition(
      account.accountId === expected.accountId &&
        account.environmentName === expected.environmentName &&
        account.scalarBefore.valueShape === "undefined" &&
        account.scalarBefore.value === null &&
        account.scalarAfter.valueShape === "string" &&
        typeof account.scalarAfter.value === "string" &&
        account.scalarAfter.value.length > 0 &&
        account.enumerated.valueShape === "string" &&
        account.enumerated.value === account.scalarAfter.value,
      `${label}.accounts[${index}]: scalar/enumeration value mismatch`,
    );
  }
  const projectedPhases = [];
  for (const [index, phase] of result.phases.entries()) {
    requireCondition(
      phase?.phase === ENVIRONMENT_SWEEP_PHASES[index],
      `${label}: phases are missing, duplicated, or reordered`,
    );
    projectedPhases.push(
      validateEnvironmentDecisionPhase(
        binding,
        phase,
        `${label}.phases[${index}]`,
      ),
    );
  }
  const authenticatedStates = new Set(
    projectedPhases.flatMap((phase) =>
      phase.typedDecisions.map((decision) =>
        canonicalJson({
          identity: decision.evidence.identity,
          generations: decision.evidence.generations,
        }),
      ),
    ),
  );
  requireCondition(
    authenticatedStates.size === 1,
    `${label}: phases disagree on authenticated semantic state`,
  );
  return projectedPhases;
}

function environmentObservationDigest(observation) {
  const projected = structuredClone(observation);
  delete projected.observationDigest;
  return taggedDigest(ENVIRONMENT_SWEEP_VALUE_DIGEST_DOMAIN, projected);
}

/** Normalize live values without retaining their executor-owned raw strings. */
export function buildEnvironmentOutputSweepObservations(
  bindings,
  results,
  executorIdentity,
) {
  validateEnvironmentOutputSweepBindings(bindings);
  validateEnvironmentExecutorIdentity(
    executorIdentity,
    "environment executor identity",
  );
  requireCondition(
    Array.isArray(results) && results.length === bindings.length,
    "environment executor results must be set-equal to sweep bindings",
  );
  let authenticatedSemanticState = null;
  return deepFreeze(
    bindings.map((binding, index) => {
      const result = results[index];
      const projectedPhases = validateEnvironmentExecutorResult(
        binding,
        result,
        executorIdentity,
        `environment executor result ${index}`,
      );
      const firstEvidence = projectedPhases[0].typedDecisions[0].evidence;
      const resultSemanticState = canonicalJson({
        identity: firstEvidence.identity,
        generations: firstEvidence.generations,
      });
      requireCondition(
        authenticatedSemanticState === null ||
          authenticatedSemanticState === resultSemanticState,
        `environment executor result ${index}: mixed authenticated semantic state`,
      );
      authenticatedSemanticState = resultSemanticState;
      const observation = {
        environmentOutputSweepObservationSchema:
          ENVIRONMENT_OUTPUT_SWEEP_OBSERVATION_SCHEMA,
        surfaceId: binding.surfaceId,
        sweepBindingDigest: binding.sweepBindingDigest,
        probeKind: ENVIRONMENT_OUTPUT_SWEEP_PROBE_KIND,
        executor: result.executor,
        loadedEngineBinaryDigest: result.loadedEngineBinaryDigest,
        accounts: result.accounts.map((account) => ({
          accountId: account.accountId,
          environmentName: account.environmentName,
          scalarBeforeShape: account.scalarBefore.valueShape,
          scalarAfterShape: account.scalarAfter.valueShape,
          enumerationShape: account.enumerated.valueShape,
          valueDigest: taggedDigest(ENVIRONMENT_SWEEP_VALUE_DIGEST_DOMAIN, {
            accountId: account.accountId,
            value: account.scalarAfter.value,
          }),
        })),
        enumerationNames: structuredClone(result.enumerationNames),
        facadeAliases: structuredClone(result.facadeAliases),
        sealedRawBridges: structuredClone(result.sealedRawBridges),
        hostEnvironmentCanary: {
          fixedNamesSeeded: result.hostEnvironmentCanary.fixedNamesSeeded,
          scalarBeforeHidden: result.hostEnvironmentCanary.scalarBeforeHidden,
          unchangedAfterOverlayWrites:
            result.hostEnvironmentCanary.unchangedAfterOverlayWrites,
        },
        phases: projectedPhases,
      };
      observation.observationDigest = environmentObservationDigest(observation);
      return observation;
    }),
  );
}

export function validateEnvironmentOutputSweepObservations(
  bindings,
  observations,
  executorIdentity,
) {
  validateEnvironmentOutputSweepBindings(bindings);
  validateEnvironmentExecutorIdentity(
    executorIdentity,
    "environment observation executor identity",
  );
  requireCondition(
    Array.isArray(observations) && observations.length === bindings.length,
    "environment observations must be set-equal to sweep bindings",
  );
  const authenticatedSemanticStates = new Set();
  for (const [index, binding] of bindings.entries()) {
    const observation = observations[index];
    const label = `environment observation ${index}`;
    exactObjectKeys(
      observation,
      [
        "environmentOutputSweepObservationSchema",
        "surfaceId",
        "sweepBindingDigest",
        "probeKind",
        "executor",
        "loadedEngineBinaryDigest",
        "accounts",
        "enumerationNames",
        "facadeAliases",
        "sealedRawBridges",
        "hostEnvironmentCanary",
        "phases",
        "observationDigest",
      ],
      label,
    );
    requireCondition(
      observation.environmentOutputSweepObservationSchema ===
        ENVIRONMENT_OUTPUT_SWEEP_OBSERVATION_SCHEMA &&
        observation.surfaceId === binding.surfaceId &&
        observation.sweepBindingDigest === binding.sweepBindingDigest &&
        observation.probeKind === ENVIRONMENT_OUTPUT_SWEEP_PROBE_KIND &&
        observation.executor === executorIdentity.executor &&
        observation.loadedEngineBinaryDigest ===
          executorIdentity.loadedEngineBinaryDigest &&
        observation.observationDigest ===
          environmentObservationDigest(observation) &&
        canonicalJson(observation.enumerationNames) ===
          canonicalJson(
            binding.accounts.map(({ environmentName }) => environmentName),
          ) &&
        canonicalJson(observation.facadeAliases) ===
          canonicalJson({ bun: true, exact: true }) &&
        canonicalJson(observation.sealedRawBridges) ===
          canonicalJson({
            enumeration: "undefined",
            scalar: "undefined",
            write: "undefined",
          }) &&
        Array.isArray(observation.accounts) &&
        observation.accounts.length === binding.accounts.length &&
        Array.isArray(observation.phases) &&
        observation.phases.length === ENVIRONMENT_SWEEP_PHASES.length,
      `${label}: malformed or drifted observation`,
    );
    exactObjectKeys(
      observation.hostEnvironmentCanary,
      ["fixedNamesSeeded", "scalarBeforeHidden", "unchangedAfterOverlayWrites"],
      `${label}.hostEnvironmentCanary`,
    );
    requireCondition(
      observation.hostEnvironmentCanary.fixedNamesSeeded === true &&
        observation.hostEnvironmentCanary.scalarBeforeHidden === true &&
        observation.hostEnvironmentCanary.unchangedAfterOverlayWrites === true,
      `${label}: host-environment positive control is absent`,
    );
    for (const [accountIndex, expected] of binding.accounts.entries()) {
      const account = observation.accounts[accountIndex];
      exactObjectKeys(
        account,
        [
          "accountId",
          "environmentName",
          "scalarBeforeShape",
          "scalarAfterShape",
          "enumerationShape",
          "valueDigest",
        ],
        `${label}.accounts[${accountIndex}]`,
      );
      requireCondition(
        account.accountId === expected.accountId &&
          account.environmentName === expected.environmentName &&
          account.scalarBeforeShape === "undefined" &&
          account.scalarAfterShape === "string" &&
          account.enumerationShape === "string" &&
          /^sha256-[A-Za-z0-9_-]{43}$/u.test(account.valueDigest),
        `${label}.accounts[${accountIndex}]: account proof drift`,
      );
    }
    for (const [phaseIndex, phase] of observation.phases.entries()) {
      requireCondition(
        phase?.phase === ENVIRONMENT_SWEEP_PHASES[phaseIndex],
        `${label}: phases are missing, duplicated, or reordered`,
      );
      const projectedPhase = validateEnvironmentDecisionPhase(
        binding,
        phase,
        `${label}.phases[${phaseIndex}]`,
      );
      const firstEvidence = projectedPhase.typedDecisions[0].evidence;
      authenticatedSemanticStates.add(
        canonicalJson({
          identity: firstEvidence.identity,
          generations: firstEvidence.generations,
        }),
      );
    }
  }
  requireCondition(
    authenticatedSemanticStates.size <= 1,
    "environment observations mix authenticated semantic states",
  );
  return observations;
}

function assertUniqueCatalogKeys(rows) {
  const seen = new Set();
  for (const [index, row] of rows.entries()) {
    const key = row?.key;
    requireCondition(
      key && OUTPUT_KEY_FIELDS.every((field) => typeof key[field] === "string"),
      `environment catalog row ${index}: malformed canonical output key`,
    );
    const canonical = canonicalJson(
      OUTPUT_KEY_FIELDS.map((field) => key[field]),
    );
    requireCondition(
      !seen.has(canonical),
      `environment catalog rows duplicate key ${canonical}`,
    );
    seen.add(canonical);
  }
}

/**
 * Verify the standard catalog projection plus its parameterized extension.
 * The canonical family is source-discovered from the shared proxy and native
 * bridges, never from an ambient-host object projection.
 */
export function validateEnvironmentOutputCatalog({
  catalog,
  contract,
  coverage,
  sourceAudit,
}) {
  validateSourceAudit(sourceAudit);
  validateContract(contract);
  const coverageEdges = coverage?.edges ?? coverage;
  requireCondition(
    Array.isArray(coverageEdges) &&
      Array.isArray(catalog?.surfaceAccounts) &&
      Array.isArray(catalog?.rows),
    "environment output catalog inputs are malformed",
  );
  const canonicalEdge = uniqueNamedRow(
    coverageEdges,
    CANONICAL_ENVIRONMENT_DYNAMIC_FAMILY,
    "canonical environment catalog coverage",
  );
  const legacyEdge = uniqueNamedRow(
    coverageEdges,
    LEGACY_UNARMED_ENVIRONMENT_DYNAMIC_FAMILY,
    "legacy environment catalog coverage",
  );
  requireCondition(
    canonicalEdge.id === contract.surfaceId &&
      legacyEdge.id === contract.legacyNativeFamily.surfaceId,
    "environment catalog coverage does not match the source-bound contract",
  );
  for (const terminalKey of ["scalarRead", "enumerationRead", "write"]) {
    const terminalContract = contract.terminalSurfaces[terminalKey];
    const terminalEdge = exactNativeOperationEdge(
      uniqueNamedRow(
        coverageEdges,
        terminalContract.name,
        `${terminalKey} environment catalog coverage`,
      ),
      `${terminalKey} environment catalog terminal`,
    );
    requireCondition(
      terminalEdge.id === terminalContract.surfaceId,
      `${terminalContract.name}: catalog terminal surface id drift`,
    );
  }

  const accountIds = new Set();
  for (const account of catalog.surfaceAccounts) {
    requireCondition(
      typeof account?.surfaceId === "string" &&
        !accountIds.has(account.surfaceId),
      `environment catalog duplicates surface account ${account?.surfaceId}`,
    );
    accountIds.add(account.surfaceId);
  }
  assertUniqueCatalogKeys(catalog.rows);

  const structuralBinding =
    environmentStructuralAccountBindings(sourceAudit)[0];
  const legacyAccount = catalog.surfaceAccounts.find(
    ({ surfaceId }) => surfaceId === legacyEdge.id,
  );
  const legacyRows = catalog.rows.filter(
    ({ key }) => key.surfaceId === legacyEdge.id,
  );
  requireCondition(
    legacyAccount?.status === "structural-only" &&
      legacyAccount.reasonCode === structuralBinding.reasonCode &&
      canonicalJson(legacyAccount.outputKinds) === canonicalJson([]) &&
      structuralBinding.sourceRefs.every((sourceRef) =>
        legacyAccount.sourceRefs?.includes(sourceRef),
      ) &&
      legacyRows.length === 0,
    "legacy environment family must remain a source-bound rowless structural account",
  );

  const expectedParameterized =
    environmentParameterizedOutputCatalogBindings(contract);
  const parameterized =
    catalog[ENVIRONMENT_PARAMETERIZED_OUTPUT_BINDINGS_FIELD];
  requireCondition(
    canonicalJson(parameterized) === canonicalJson(expectedParameterized),
    "canonical environment parameterized catalog binding is missing or drifted",
  );
  const canonicalAccount = catalog.surfaceAccounts.find(
    ({ surfaceId }) => surfaceId === canonicalEdge.id,
  );
  const canonicalRows = catalog.rows.filter(
    ({ key }) => key.surfaceId === canonicalEdge.id,
  );
  const binding = expectedParameterized[0];
  requireCondition(
    canonicalAccount?.status === binding.status &&
      canonicalAccount.reasonCode === binding.reasonCode &&
      canonicalJson(canonicalAccount.outputKinds) ===
        canonicalJson(binding.outputKinds) &&
      binding.sourceRefs.every((sourceRef) =>
        canonicalAccount.sourceRefs?.includes(sourceRef),
      ) &&
      canonicalRows.length === 0,
    "canonical environment family must use parameterized accounts without ordinary catalog rows",
  );
  return true;
}
