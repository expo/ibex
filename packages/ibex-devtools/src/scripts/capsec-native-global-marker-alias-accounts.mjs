/**
 * Structural alias account for the native dynamic-global-name marker.
 *
 * Recursive C++ discovery must find exactly one such marker. Its sole writer
 * is the conformance-only, armed-only, unpredictable-name context observer.
 * The marker names that writer and carries no value itself; the abstract
 * observer remains output-bearing through its exact three structured rows.
 *
 * @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence — the
 * observer is bounded evidence plumbing, not an authorization mechanism.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — the
 * structural alias is bound to recursive source discovery and exact outputs.
 * @ref LLP 0023#6-path-bearing-observables — a registrar-name marker is not a
 * duplicate value boundary for the registered callable's return record.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJson } from "./capsec-contract.mjs";
import { scanCppGlobalPropertySurfaces } from "./capsec-surface-inventory.mjs";

export const NATIVE_GLOBAL_MARKER_STRUCTURAL_ACCOUNT_SCHEMA =
  "ibex/capsec-native-global-marker-structural-account/1";
export const NATIVE_GLOBAL_MARKER_STRUCTURAL_REASON_CODE =
  "conformance-observer-dynamic-name-alias";
export const NATIVE_GLOBAL_MARKER_OUTPUT_CATALOG_BINDINGS = Object.freeze([]);

export const NATIVE_GLOBAL_MARKER_SURFACE =
  "global:[[dynamic-table:native-global-name]]";
export const CAPSEC_CONTEXT_OBSERVER_SURFACE = "__ibexCapsecContextObserver_";

const MARKER_OBSERVED_KEY = `native-op:${NATIVE_GLOBAL_MARKER_SURFACE}`;
const OBSERVER_OBSERVED_KEY = `native-op:${CAPSEC_CONTEXT_OBSERVER_SURFACE}`;
const ENGINE_PATH = "src/engine/hermes_runtime.cc";
const HERMES_RUST_PATH = "src/bin/ibex/engine/hermes.rs";
const FIXTURE_RUST_PATH =
  "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs";
const BUILD_PATH = "build.rs";
const CARGO_PATH = "Cargo.toml";
const OBSERVER_PREFIX = "__ibexCapsecContextObserver_";

const OUTPUT_SHAPES = Object.freeze([
  Object.freeze({
    alias: "__ibexCapsecContextObserver_.context",
    output: "[[return]]",
    returnVariant: "context-record",
  }),
  Object.freeze({
    alias: "__ibexCapsecContextObserver_.principalId",
    output: "field:principalId",
    returnVariant: "u64-tagged-string",
  }),
  Object.freeze({
    alias: "__ibexCapsecContextObserver_.runtimeNonce",
    output: "field:runtimeNonce",
    returnVariant: "u64-tagged-string",
  }),
]);

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

function count(source, token) {
  let total = 0;
  let offset = 0;
  while (true) {
    const next = source.indexOf(token, offset);
    if (next === -1) return total;
    total += 1;
    offset = next + token.length;
  }
}

function requireTokens(source, tokens, label) {
  let offset = 0;
  for (const token of tokens) {
    const next = source.indexOf(token, offset);
    requireCondition(next !== -1, `${label}: missing source token ${token}`);
    offset = next + token.length;
  }
}

function repositoryPath(value) {
  return value.split(path.sep).join("/");
}

function recursiveEngineCppPaths(repoRoot) {
  const engineRoot = path.join(repoRoot, "src/engine");
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && entry.name.endsWith(".cc")) {
        files.push(repositoryPath(path.relative(repoRoot, absolute)));
      }
    }
  };
  visit(engineRoot);
  return files.sort(compareText);
}

function recursiveRustPaths(repoRoot) {
  const rustRoot = path.join(repoRoot, "src/bin/ibex");
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && entry.name.endsWith(".rs")) {
        files.push(repositoryPath(path.relative(repoRoot, absolute)));
      }
    }
  };
  visit(rustRoot);
  return files.sort(compareText);
}

function sourceReader(repoRoot, readSource) {
  return (relativePath) => {
    const absolutePath = path.join(repoRoot, relativePath);
    const source = readSource
      ? readSource(absolutePath, relativePath)
      : fs.readFileSync(absolutePath, "utf8");
    requireCondition(
      typeof source === "string",
      `${relativePath}: expected source text`,
    );
    return source;
  };
}

function exactSurfaceMap(surfaces) {
  const result = new Map();
  for (const surface of surfaces ?? []) {
    requireCondition(
      !result.has(surface.observedKey),
      `${surface.observedKey}: duplicate inventory surface`,
    );
    result.set(surface.observedKey, surface);
  }
  return result;
}

function exactCoverageMap(coverage) {
  const result = new Map();
  for (const edge of coverage?.edges ?? []) {
    const observedKey = `${edge.surface?.kind}:${edge.surface?.name}`;
    requireCondition(
      !result.has(observedKey),
      `${observedKey}: duplicate coverage edge`,
    );
    result.set(observedKey, edge);
  }
  return result;
}

function observerRows(observerEdge, sourceRefs) {
  return OUTPUT_SHAPES.map((shape) => ({
    key: {
      surfaceId: observerEdge.id,
      output: shape.output,
      alias: shape.alias,
      mode: "ephemeral-one-shot",
      sourceKind: "native-op",
      returnVariant: shape.returnVariant,
      contextId: "javascript.package-call-loaded",
    },
    discovery: {
      kind: "source-asserted-structured-output",
      sourceRefs: [...sourceRefs],
    },
    requiredValueProof: "live-value-observation",
  }));
}

function validateAudit(sourceAudit) {
  requireCondition(
    sourceAudit?.structuralAccountSchema ===
      NATIVE_GLOBAL_MARKER_STRUCTURAL_ACCOUNT_SCHEMA &&
      sourceAudit.reasonCode === NATIVE_GLOBAL_MARKER_STRUCTURAL_REASON_CODE &&
      sourceAudit.marker?.observedKey === MARKER_OBSERVED_KEY &&
      sourceAudit.observer?.observedKey === OBSERVER_OBSERVED_KEY &&
      sourceAudit.observer?.catalogRows?.length === 3,
    "invalid native-global marker structural audit",
  );
  return sourceAudit;
}

/**
 * Recursively discover the engine C++ corpus and bind its only dynamic global
 * writer to the bounded context observer and its Rust capture lifecycle.
 */
export function auditNativeGlobalMarkerAliasClosure({
  repoRoot,
  surfaces,
  coverage,
  readSource,
}) {
  requireCondition(
    typeof repoRoot === "string" && path.isAbsolute(repoRoot),
    "native-global marker audit requires an absolute repository root",
  );
  const read = sourceReader(repoRoot, readSource);
  const enginePaths = recursiveEngineCppPaths(repoRoot);
  requireCondition(
    enginePaths.length > 0,
    "native-global marker audit found no engine C++ corpus",
  );

  const engineSources = new Map(
    enginePaths.map((relativePath) => [relativePath, read(relativePath)]),
  );
  const writerDiscoveries = [];
  for (const [relativePath, source] of engineSources) {
    for (const surface of scanCppGlobalPropertySurfaces(source, relativePath)) {
      if (surface.name === NATIVE_GLOBAL_MARKER_SURFACE) {
        writerDiscoveries.push({ relativePath, surface });
      }
    }
  }
  requireCondition(
    writerDiscoveries.length === 1 &&
      writerDiscoveries[0].relativePath === ENGINE_PATH,
    `recursive engine discovery expected one native dynamic-global writer in ${ENGINE_PATH}, got ${writerDiscoveries
      .map(({ relativePath }) => relativePath)
      .join(", ")}`,
  );

  const engineSource = engineSources.get(ENGINE_PATH);
  const functionStart = engineSource.indexOf(
    'extern "C" int ibex_test_install_capsec_context_observer(',
  );
  const functionEnd = engineSource.indexOf("\n#endif", functionStart);
  requireCondition(
    functionStart !== -1 && functionEnd !== -1,
    "context observer C++ region is unavailable",
  );
  const observerRegion = engineSource.slice(functionStart, functionEnd);
  const precedingGuard = engineSource.slice(
    Math.max(0, functionStart - 800),
    functionStart,
  );
  requireCondition(
    precedingGuard.includes("#ifdef IBEX_CAPSEC_CONFORMANCE_OBSERVER"),
    "context observer must remain conformance-feature-only",
  );
  requireTokens(
    observerRegion,
    [
      `constexpr const char* kPrefix = "${OBSERVER_PREFIX}"`,
      "std::strncmp(global_name, kPrefix, std::strlen(kPrefix)) != 0",
      "ExactRuntimeDriveGuard drive(runtime);",
      "!drive || !runtime->armed || runtime->restricted",
      "std::string name(global_name)",
      "facebook::jsi::PropNameID::forUtf8(rt, name)",
      "rt.global().hasProperty(rt, property)",
      "std::make_shared<std::atomic<bool>>(false)",
      "facebook::jsi::Function::createFromHostFunction(",
      "if (count != 0)",
      "called->exchange(true)",
      '"principalId"',
      '"u64:" + std::to_string(currentPrincipalId())',
      '"runtimeNonce"',
      '"u64:" + std::to_string(runtime->runtime_nonce)',
      "return context;",
      "rt.global().setProperty(rt, property, std::move(observer));",
      "return 1;",
    ],
    "context observer C++ proof",
  );
  requireCondition(
    count(
      observerRegion,
      "rt.global().setProperty(rt, property, std::move(observer));",
    ) === 1 &&
      count(observerRegion, "called->exchange(true)") === 1 &&
      count(observerRegion, "context.setProperty(\n              rt,") === 2,
    "context observer must retain one writer, one-shot gate, and two fields",
  );

  const buildSource = read(BUILD_PATH);
  const cargoSource = read(CARGO_PATH);
  const observerBuildBinding = `if std::env::var_os("CARGO_FEATURE_CAPSEC_CONFORMANCE_OBSERVER").is_some() {
        build.define("IBEX_CAPSEC_CONFORMANCE_OBSERVER", None);
        build.file("src/engine/hermes_session_conformance.cc");
    }`;
  requireCondition(
    count(buildSource, observerBuildBinding) === 1 &&
      /^capsec-conformance-observer\s*=\s*\[\]\s*$/mu.test(cargoSource),
    "context observer build feature binding drifted",
  );

  const rustPaths = recursiveRustPaths(repoRoot);
  const rustSources = new Map(
    rustPaths.map((relativePath) => [relativePath, read(relativePath)]),
  );
  const hermesRust = rustSources.get(HERMES_RUST_PATH);
  const fixtureRust = rustSources.get(FIXTURE_RUST_PATH);
  requireCondition(
    typeof hermesRust === "string" && typeof fixtureRust === "string",
    "context observer Rust sources are missing",
  );
  const methodStart = hermesRust.indexOf(
    "async fn install_capsec_context_test_observer(&self) -> Result<String>",
  );
  const methodEnd = hermesRust.indexOf(
    "async fn maybe_enable_debugger",
    methodStart,
  );
  const methodGuard = hermesRust.slice(
    Math.max(0, methodStart - 100),
    methodStart,
  );
  const method = hermesRust.slice(methodStart, methodEnd);
  requireCondition(
    methodStart !== -1 &&
      methodEnd !== -1 &&
      methodGuard.includes(
        '#[cfg(all(test, feature = "capsec-conformance-observer"))]',
      ),
    "Rust context observer installer must remain test-and-feature-only",
  );
  requireTokens(
    method,
    [
      "let mut nonce = [0u8; 16]",
      "getrandom::getrandom(&mut nonce)",
      '.map(|byte| format!("{byte:02x}"))',
      `format!("${OBSERVER_PREFIX}{suffix}")`,
      "CString::new(name.as_str())",
      "ibex_test_install_capsec_context_observer(raw, name_c.as_ptr(), std::ptr::null())",
      "if installed != 1",
      "Ok(name)",
    ],
    "Rust context observer name proof",
  );

  const callToken = ".install_capsec_context_test_observer()";
  const callFiles = [];
  for (const [relativePath, source] of rustSources) {
    for (let index = 0; index < count(source, callToken); index += 1) {
      callFiles.push(relativePath);
    }
  }
  requireCondition(
    callFiles.length === 7 &&
      callFiles.every((relativePath) => relativePath === FIXTURE_RUST_PATH),
    `context observer must have exactly seven conformance fixture installs, got ${callFiles.join(", ")}`,
  );
  const callOffsets = [];
  const captureOffsets = [];
  const deleteOffsets = [];
  for (const [token, offsets] of [
    [callToken, callOffsets],
    ["var observer = globalThis", captureOffsets],
    ["var removed = delete globalThis", deleteOffsets],
  ]) {
    let offset = 0;
    while (true) {
      const next = fixtureRust.indexOf(token, offset);
      if (next === -1) break;
      offsets.push(next);
      offset = next + token.length;
    }
  }
  requireCondition(
    callOffsets.length === 7 &&
      captureOffsets.length === 7 &&
      deleteOffsets.length === 7 &&
      callOffsets.every(
        (callOffset, index) =>
          callOffset < captureOffsets[index] &&
          captureOffsets[index] < deleteOffsets[index] &&
          (index === 6 || deleteOffsets[index] < callOffsets[index + 1]),
      ) &&
      count(fixtureRust, "CapSec context observer was project-reachable") === 7,
    "every context observer must be captured and deleted before use",
  );

  const surfaceByObservedKey = exactSurfaceMap(surfaces);
  const edgeByObservedKey = exactCoverageMap(coverage);
  const markerSurface = surfaceByObservedKey.get(MARKER_OBSERVED_KEY);
  const observerSurface = surfaceByObservedKey.get(OBSERVER_OBSERVED_KEY);
  const markerEdge = edgeByObservedKey.get(MARKER_OBSERVED_KEY);
  const observerEdge = edgeByObservedKey.get(OBSERVER_OBSERVED_KEY);
  requireCondition(
    markerSurface?.sourceRefs?.length === 1 &&
      markerSurface.sourceRefs[0] ===
        `${ENGINE_PATH}#jsi-global:[[dynamic-table:native-global-name]]` &&
      typeof markerEdge?.id === "string" &&
      markerEdge.id.length > 0,
    "native dynamic-global marker inventory or coverage drifted",
  );
  requireCondition(
    observerSurface?.sourceRefs?.length === 1 &&
      observerSurface.sourceRefs[0] ===
        `${ENGINE_PATH}#${CAPSEC_CONTEXT_OBSERVER_SURFACE}` &&
      typeof observerEdge?.id === "string" &&
      observerEdge.id.length > 0,
    "abstract context observer inventory or coverage drifted",
  );

  const observerSourceRefs = [
    ...observerSurface.sourceRefs,
    `${ENGINE_PATH}#ibex_test_install_capsec_context_observer`,
    `${HERMES_RUST_PATH}#install_capsec_context_test_observer`,
    `${FIXTURE_RUST_PATH}#context-observer:capture-delete-before-use`,
    `${BUILD_PATH}#IBEX_CAPSEC_CONFORMANCE_OBSERVER`,
  ].sort(compareText);
  const catalogRows = observerRows(observerEdge, observerSourceRefs);
  const observerCatalogAccount = {
    surfaceId: observerEdge.id,
    status: "output-bearing",
    reasonCode: "source-asserted-structured-output",
    sourceRefs: [...observerSourceRefs],
    outputKinds: ["structured-output"],
  };
  const markerSourceRefs = [
    ...markerSurface.sourceRefs,
    ...observerSourceRefs,
  ].sort(compareText);
  const outputDependencies = OUTPUT_SHAPES.map(({ output }) => ({
    surfaceObservedKey: OBSERVER_OBSERVED_KEY,
    selector: output,
  }));

  const proof = {
    engineCppFiles: enginePaths.length,
    engineCppPathsDigest: taggedDigest(enginePaths),
    dynamicWriterPath: ENGINE_PATH,
    buildFeature: "capsec-conformance-observer",
    armedOnly: true,
    restrictedRuntimeRefused: true,
    unpredictableNamePrefix: OBSERVER_PREFIX,
    unpredictableSuffixBits: 128,
    oneShot: true,
    captureDeletePairs: 7,
  };
  const proofDigest = taggedDigest({
    proof,
    markerSourceRefs,
    observerCatalogAccount,
    catalogRows,
  });

  return deepFreeze({
    structuralAccountSchema: NATIVE_GLOBAL_MARKER_STRUCTURAL_ACCOUNT_SCHEMA,
    reasonCode: NATIVE_GLOBAL_MARKER_STRUCTURAL_REASON_CODE,
    proof,
    marker: {
      surfaceId: markerEdge.id,
      observedKey: MARKER_OBSERVED_KEY,
      sourceRefs: markerSourceRefs,
      proofDigest,
      outputDependencies,
    },
    observer: {
      surfaceId: observerEdge.id,
      observedKey: OBSERVER_OBSERVED_KEY,
      sourceRefs: observerSourceRefs,
      catalogAccount: observerCatalogAccount,
      catalogRows,
    },
  });
}

/** Catalog-builder integration row for the rowless marker. */
export function nativeGlobalMarkerStructuralAccountBindings(sourceAudit) {
  validateAudit(sourceAudit);
  return [
    {
      surfaceName: NATIVE_GLOBAL_MARKER_SURFACE,
      status: "structural-only",
      reasonCode: NATIVE_GLOBAL_MARKER_STRUCTURAL_REASON_CODE,
      sourceRefs: [...sourceAudit.marker.sourceRefs],
      proofDigest: sourceAudit.marker.proofDigest,
      outputKinds: [],
      outputDependencies: structuredClone(
        sourceAudit.marker.outputDependencies,
      ),
    },
  ];
}

/** Exact output-bearing companion account and its three structured rows. */
export function capsecContextObserverOutputCatalogBinding(sourceAudit) {
  validateAudit(sourceAudit);
  return structuredClone({
    surfaceName: CAPSEC_CONTEXT_OBSERVER_SURFACE,
    account: sourceAudit.observer.catalogAccount,
    rows: sourceAudit.observer.catalogRows,
  });
}

export function validateNativeGlobalMarkerStructuralAccount(
  account,
  { surface, coverageEdge, sourceAudit },
) {
  validateAudit(sourceAudit);
  const expected = {
    structuralAccountSchema: NATIVE_GLOBAL_MARKER_STRUCTURAL_ACCOUNT_SCHEMA,
    surfaceId: sourceAudit.marker.surfaceId,
    surfaceObservedKey: MARKER_OBSERVED_KEY,
    status: "structural-only",
    reasonCode: NATIVE_GLOBAL_MARKER_STRUCTURAL_REASON_CODE,
    sourceRefs: [...sourceAudit.marker.sourceRefs],
    proofDigest: sourceAudit.marker.proofDigest,
    outputKinds: [],
    outputDependencies: structuredClone(sourceAudit.marker.outputDependencies),
  };
  requireCondition(
    surface?.kind === "native-op" &&
      surface.observedKey === MARKER_OBSERVED_KEY &&
      coverageEdge?.id === sourceAudit.marker.surfaceId &&
      canonicalJson(account) === canonicalJson(expected),
    "invalid native-global marker structural account",
  );
  return account;
}

export function authoredNativeGlobalMarkerStructuralAccount({
  surface,
  coverageEdge,
  sourceAudit,
}) {
  if (surface?.name !== NATIVE_GLOBAL_MARKER_SURFACE) return null;
  validateAudit(sourceAudit);
  return validateNativeGlobalMarkerStructuralAccount(
    {
      structuralAccountSchema: NATIVE_GLOBAL_MARKER_STRUCTURAL_ACCOUNT_SCHEMA,
      surfaceId: sourceAudit.marker.surfaceId,
      surfaceObservedKey: MARKER_OBSERVED_KEY,
      status: "structural-only",
      reasonCode: NATIVE_GLOBAL_MARKER_STRUCTURAL_REASON_CODE,
      sourceRefs: [...sourceAudit.marker.sourceRefs],
      proofDigest: sourceAudit.marker.proofDigest,
      outputKinds: [],
      outputDependencies: structuredClone(
        sourceAudit.marker.outputDependencies,
      ),
    },
    { surface, coverageEdge, sourceAudit },
  );
}

/** Marker must be rowless; the observer must retain exactly three rows. */
export function validateNativeGlobalMarkerAliasCatalog({
  catalog,
  coverage,
  sourceAudit,
}) {
  validateAudit(sourceAudit);
  requireCondition(
    Array.isArray(catalog?.surfaceAccounts) && Array.isArray(catalog?.rows),
    "native-global marker catalog lacks accounts or rows",
  );
  const relevantIds = [
    sourceAudit.marker.surfaceId,
    sourceAudit.observer.surfaceId,
  ];
  const accounts = catalog.surfaceAccounts.filter((account) =>
    relevantIds.includes(account.surfaceId),
  );
  const rows = catalog.rows.filter((row) =>
    relevantIds.includes(row.key?.surfaceId),
  );
  requireCondition(
    accounts.length === 2,
    "native-global marker catalog must contain exactly two bound accounts",
  );
  const accountById = new Map(
    accounts.map((account) => [account.surfaceId, account]),
  );
  const expectedMarkerAccount = {
    surfaceId: sourceAudit.marker.surfaceId,
    status: "structural-only",
    reasonCode: NATIVE_GLOBAL_MARKER_STRUCTURAL_REASON_CODE,
    sourceRefs: [...sourceAudit.marker.sourceRefs],
    outputKinds: [],
  };
  requireCondition(
    canonicalJson(accountById.get(sourceAudit.marker.surfaceId)) ===
      canonicalJson(expectedMarkerAccount),
    "native dynamic-global marker catalog account drifted",
  );
  requireCondition(
    canonicalJson(accountById.get(sourceAudit.observer.surfaceId)) ===
      canonicalJson(sourceAudit.observer.catalogAccount),
    "context observer output-bearing catalog account drifted",
  );
  requireCondition(
    rows.filter((row) => row.key?.surfaceId === sourceAudit.marker.surfaceId)
      .length === 0,
    "native dynamic-global marker must remain rowless",
  );
  const observerRowsInCatalog = rows.filter(
    (row) => row.key?.surfaceId === sourceAudit.observer.surfaceId,
  );
  requireCondition(
    canonicalJson(observerRowsInCatalog) ===
      canonicalJson(sourceAudit.observer.catalogRows),
    "context observer must retain exactly three structured output rows",
  );

  const edgeByObservedKey = exactCoverageMap(coverage);
  requireCondition(
    edgeByObservedKey.get(MARKER_OBSERVED_KEY)?.id ===
      sourceAudit.marker.surfaceId &&
      edgeByObservedKey.get(OBSERVER_OBSERVED_KEY)?.id ===
        sourceAudit.observer.surfaceId,
    "native-global marker catalog coverage binding drifted",
  );
  return true;
}
