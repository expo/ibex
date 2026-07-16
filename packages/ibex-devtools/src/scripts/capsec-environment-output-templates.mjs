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

export const ENVIRONMENT_OUTPUT_SOURCE_AUDIT_SCHEMA =
  "ibex/capsec-environment-output-source-audit/1";
export const ENVIRONMENT_OUTPUT_CONTRACT_SCHEMA =
  "ibex/capsec-environment-output-contract/1";
export const ENVIRONMENT_OUTPUT_ACCOUNT_SCHEMA =
  "ibex/capsec-environment-output-account/1";
export const ENVIRONMENT_PARAMETERIZED_CATALOG_BINDING_SCHEMA =
  "ibex/capsec-environment-parameterized-catalog-binding/1";

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
      canonicalJson(Object.keys(compatibilityReaderSources).sort(compareText)) ===
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
      (source.match(/function readRuntimeEnv\(key: string\): string \| undefined/gu) ?? [])
        .length === 1,
      `${sourcePath}: expected exactly one compatibility environment reader`,
    );
    const reader = source.slice(source.indexOf("function readRuntimeEnv("));
    const fixedGuard = /const bootstrapValue = readBootstrapCompatibilityControl\(key\);\s*if \(\s*bootstrapValue !== undefined \|\|\s*isBootstrapCompatibilityControlFixed\(key\)\s*\) return bootstrapValue;/u.exec(
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
        Math.min(...fallbackOffsets) >
          fixedGuard.index + fixedGuard[0].length,
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
    "auto hasShared = rt.global().getProperty(rt, \"__exactHasSharedRuntimeBundle\");",
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
