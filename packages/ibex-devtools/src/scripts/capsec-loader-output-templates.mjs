/**
 * Expectation-free recipes for output rows discovered in the production
 * module loader. Executable routes name only loader entrypoints that already
 * exist in the loaded public/legacy surface. Lexical helpers are never exposed
 * for conformance, and every residual states why no bounded public traversal is
 * available.
 *
 * @ref LLP 0023#6-path-bearing-observables — loader evidence must retain the
 * real loaded completion without projecting host paths or policy expectations.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const INVOCATION_SCHEMA = "ibex/capsec-loader-output-invocation/1";
const MODULE_LOADER_REF = "src/engine/bootstrap/module-loader.js";

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const PROJECT_PACKAGE_JSON_READ = Object.freeze({
  kind: "typed-effect",
  cap: "fs:read",
  resourceKind: "path-occurrence",
  requested: Object.freeze({
    root: "project",
    components: Object.freeze(["package.json"]),
  }),
});

const PUBLIC_ENTRYPOINTS = new Set([
  "exact-require",
  "global-import",
  "global-require",
  "import-module",
  "require-resolve",
]);

function invoke(entrypoint, specifier, options = {}) {
  if (!PUBLIC_ENTRYPOINTS.has(entrypoint)) {
    throw new TypeError(`unsupported public loader entrypoint ${entrypoint}`);
  }
  return {
    operation: "invoke-public-loader",
    entrypoint,
    specifier,
    ...(options.authority ? { authority: options.authority } : {}),
  };
}

const unavailable = (reasonCode, reason) => ({
  operation: "unexercisable",
  reasonCode,
  reason,
});

const requireBuiltin = () => invoke("global-require", "node:path");
const exactRequireBuiltin = () => invoke("exact-require", "node:path");
const importBuiltin = (entrypoint = "import-module") =>
  invoke(entrypoint, "node:path");
const resolveBuiltin = () => invoke("require-resolve", "node:path");
const requireInternal = (specifier = "internal/errors") =>
  invoke("global-require", specifier);

const BASE_ROUTES = Object.freeze({
  "builtin-module": exactRequireBuiltin,
  "dynamic-import": importBuiltin,
  "import-needs": importBuiltin,
  "import-policy-bare": requireBuiltin,
  "internal-module": requireInternal,
  "json-module": () =>
    invoke("exact-require", "./package.json", {
      authority: [PROJECT_PACKAGE_JSON_READ],
    }),
  "native-resolve": exactRequireBuiltin,
  "require-resolve": resolveBuiltin,
});

const BASE_RESIDUALS = Object.freeze({
  "commonjs-module": [
    "project-module-body-required",
    "the CommonJS branch requires evaluating a project-authored module body",
  ],
  "import-policy-resolved-path": [
    "cross-package-fixture-required",
    "the resolved-target gate requires a real cross-package path edge",
  ],
  "package-compile": [
    "project-module-body-required",
    "package compilation has no public traversal without a project module body",
  ],
  "package-principal": [
    "project-module-body-required",
    "package-principal output requires a resolved project package record",
  ],
});

const ENTRY_ROUTES = Object.freeze({
  "entry:dynamic-import": importBuiltin,
  "entry:exact-require": exactRequireBuiltin,
  "entry:global-import": () => importBuiltin("global-import"),
  "entry:global-require": requireBuiltin,
  "entry:import-module": importBuiltin,
  "entry:load": exactRequireBuiltin,
  "entry:load-internal": requireInternal,
  "entry:require-resolve": resolveBuiltin,
  "entry:resolve-path": resolveBuiltin,
});

const ENTRY_RESIDUALS = Object.freeze({
  "entry:local-require": [
    "module-local-entry-not-public",
    "localRequire exists only inside an evaluated module wrapper",
  ],
  "entry:module-dynamic-import": [
    "module-local-entry-not-public",
    "moduleDynamicImport exists only inside an evaluated module wrapper",
  ],
});

// These helpers are entered deterministically before cache-sensitive module
// body evaluation. The traversal observes the outer public loader completion;
// it does not expose or call the helper itself.
const FUNCTION_ROUTES = Object.freeze({
  __exactResolvePath: resolveBuiltin,
  __exactResolvedPath: resolveBuiltin,
  _loadNamedStreamInternal: () => requireInternal("internal/streams/readable"),
  checkImportGate: requireBuiltin,
  idToModuleId: exactRequireBuiltin,
  importImpl: importBuiltin,
  load: exactRequireBuiltin,
  loadInternal: requireInternal,
  privateBridgesForBuiltin: exactRequireBuiltin,
  privateResolverPath: resolveBuiltin,
  publicImport: importBuiltin,
  rejectRuntimeLoaderOptions: requireBuiltin,
  resolverVirtualPath: resolveBuiltin,
  stripViteImportQuery: exactRequireBuiltin,
});

function functionResidual(functionName) {
  if (
    functionName === "__exactResolveSessionPath" ||
    functionName === "__sessionStaticImport"
  ) {
    return unavailable(
      "authenticated-session-only",
      `${functionName} is entered only through a native-authenticated session record`,
    );
  }
  if (functionName === "makeWindowsCryptoModule") {
    return unavailable(
      "target-variant-only",
      "makeWindowsCryptoModule is not a loaded macOS target branch",
    );
  }
  if (functionName === "builtinCacheKeyFor") {
    return unavailable(
      "armed-runtime-bypasses-legacy-helper",
      "authenticated builtin SourceIds bypass the legacy source-text cache key helper",
    );
  }
  if (
    new Set([
      "createOriginalModuleRegistry",
      "originalModuleRegistryForRecord",
      "principalForOriginal",
    ]).has(functionName)
  ) {
    return unavailable(
      "generated-module-only",
      `${functionName} requires a native-authenticated generated-module record`,
    );
  }
  if (
    new Set([
      "compileFallbackSource",
      "compileModuleBody",
      "invokeModuleBody",
      "isCompleteStaticImportStatement",
      "looksLikeCompleteModuleStatement",
      "looksLikeModuleSyntax",
      "moduleDynamicImport",
      "restoreModuleId",
      "runFallbackModule",
      "splitInlineModuleStatements",
      "stripModuleStatementComments",
      "transformDynamicImport",
      "transformImportMeta",
      "wrapAsyncModule",
    ]).has(functionName)
  ) {
    return unavailable(
      "project-module-body-required",
      `${functionName} requires compiling or invoking a project-authored module body`,
    );
  }
  return unavailable(
    "no-bounded-public-loader-route",
    `${functionName} has no cache-independent public loader traversal`,
  );
}

function routeFor(surface) {
  const evidenceType = surface.metadata?.evidenceType ?? null;
  if (evidenceType === "internal-loader-route") {
    return requireInternal(surface.metadata.specifier);
  }
  if (evidenceType === "lazy-loader-installer-route") {
    // __exactRequire is an already-exposed legacy entry. Unlike global require,
    // it goes directly through load(), so aliases such as dns/promises cannot
    // be intercepted by loadInternal before the lazy installer branch runs.
    return invoke("exact-require", surface.metadata.specifier);
  }
  if (evidenceType === "loader-entry-route") {
    const author = ENTRY_ROUTES[surface.name];
    if (author) return author();
    const residual = ENTRY_RESIDUALS[surface.name];
    if (residual) return unavailable(residual[0], residual[1]);
  }
  if (evidenceType === "loader-kind-branch") {
    if (surface.metadata.loaderKind === "builtin") return exactRequireBuiltin();
    return unavailable(
      "project-module-body-required",
      "the CommonJS kind branch requires a real project-authored module body",
    );
  }
  if (evidenceType === "loader-function") {
    const functionName = surface.name.slice("function:javascript:".length);
    const author = FUNCTION_ROUTES[functionName];
    return author ? author() : functionResidual(functionName);
  }
  const author = BASE_ROUTES[surface.name];
  if (author) return author();
  const residual = BASE_RESIDUALS[surface.name];
  if (residual) return unavailable(residual[0], residual[1]);
  return unavailable(
    "no-bounded-public-loader-route",
    `${surface.name} has no authored public loader traversal`,
  );
}

export function authoredModuleLoaderOutputInvocation({ surface, coverageEdge }) {
  if (
    !coverageEdge ||
    surface?.kind !== "loader" ||
    surface.observedKey !== `loader:${surface.name}` ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length === 0 ||
    !surface.sourceRefs.some((sourceRef) =>
      sourceRef.startsWith(MODULE_LOADER_REF),
    ) ||
    !surface.sourceRefs.every(
      (sourceRef) => typeof sourceRef === "string" && sourceRef.length > 0,
    )
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "module-loader-surface",
    surfaceName: surface.name,
    evidenceType: surface.metadata?.evidenceType ?? null,
    sourceRefs: [...surface.sourceRefs],
  };
  const route = routeFor(surface);
  const asynchronous =
    route.operation === "invoke-public-loader" &&
    new Set(["global-import", "import-module"]).has(route.entrypoint);
  return {
    invocationSchema: INVOCATION_SCHEMA,
    kind: "loader-output",
    coverageEdgeId: coverageEdge.id,
    coverageClassification: coverageEdge.classification,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    route,
    completion: asynchronous
      ? { kind: "event-loop-quiescence", timeoutMilliseconds: 1_000 }
      : { kind: "synchronous-loaded-runtime" },
  };
}

export const moduleLoaderPublicEntrypoints = Object.freeze(
  [...PUBLIC_ENTRYPOINTS].sort(),
);
