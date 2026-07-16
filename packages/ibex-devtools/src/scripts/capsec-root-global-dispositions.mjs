/**
 * Build and validate the root-realm reachability contract for native/runtime
 * installation sites. Capability classification and reachability are distinct
 * axes: the CapSec registry says what an operation means, while this manifest
 * says whether the property which installs it survives armed bootstrap.
 *
 * @ref LLP 0022#7-capabilities-principals-and-affordance-parity — every native
 * install branch has a stable disposition, and the live descriptor-only sweep
 * must equal the permitted post-bootstrap surface.
 */

import crypto from "node:crypto";

export const ROOT_GLOBAL_DISPOSITION_SCHEMA =
  "ibex/root-global-disposition-manifest/1";
export const ROOT_GLOBAL_DISPOSITION_PROFILE = "ibex/capsec/1";

export const ROOT_GLOBAL_SWEEP_BUDGET = Object.freeze({
  maxDepth: 12,
  maxDescriptors: 65_536,
  maxObjects: 4_096,
});

const DISPOSITIONS = new Set(["converted", "exposed", "private", "sealed"]);
const LIVE_DISPOSITIONS = new Set(["converted", "exposed"]);
const DYNAMIC_SENTINEL = /\[\[dynamic-table:[^\]]+\]\]/u;
const EFFECTFUL_PROXY_ROOTS = new Set(["localStorage", "sessionStorage"]);

const PRIVATE_CONSUMERS = new Map([
  ["__exactCaptureSessionStaticImport", "trusted-module-loader"],
  ["__exactCheckImport", "trusted-module-loader"],
  ["__exactExit", "runtime-process-lifecycle-adapter"],
  ["__exactFsMutationGuard", "trusted-fs-builtin"],
  ["__exactGetCwd", "trusted-path-process-builtins"],
  ["__exactGeneratedImportGrantKeys", "trusted-module-loader"],
  ["__exactGrantCapability", "trusted-capability-bootstrap"],
  ["__exactModuleResolve", "trusted-module-loader"],
  ["__exactModuleResolveMeta", "trusted-module-loader"],
  ["__exactNativeModuleResolve", "trusted-module-loader"],
  ["__exactNativeModuleResolveMeta", "trusted-module-loader"],
  ["__exactNativeFreeze", "native-lockdown-bootstrap"],
  ["__exactOnRejectionHandled", "native-promise-rejection-checkpoint"],
  ["__exactOnUnhandledRejection", "native-promise-rejection-checkpoint"],
  ["__exactDeepFreeze", "native-lockdown-bootstrap"],
  ["__exactRegisterPackage", "trusted-module-loader"],
  ["__exactResolveManifestBuiltinInternal", "trusted-module-loader"],
  ["__exactSetActiveModuleId", "trusted-module-loader"],
  ["__exactSetCompartmentFor", "trusted-module-loader"],
  ["__exactSetCwd", "trusted-path-process-builtins"],
  ["__exactSetPendingPackageId", "trusted-module-loader"],
  ["__exactStdinRead", "runtime-process-stdin-adapter"],
  ["__ibexBarePackageName", "trusted-module-loader"],
  ["__ibexEndowRaw", "compartment-registry-bootstrap"],
  ["__ibexEndowments", "compartment-registry-bootstrap"],
  ["__ibexRefreshCompartmentBaseline", "armed-runtime-finalizer"],
]);

const SEALED_ROOTS = new Set([
  "__ex_p",
  "__dirname",
  // Native installs this digest-bound compatibility tuple only long enough
  // for the shared runtime to capture it in module-private state. It is not a
  // project-visible compatibility or environment surface.
  "__exactCompatModes",
  "__exactEnsureChildProcess",
  "__exactEnsureDns",
  "__exactEnsureFormData",
  "__exactEnsureFs",
  "__exactEnsureHttp",
  "__exactEnsureNet",
  "__exactEnsureSqlite",
  "__exactEnsureStreamEnhance",
  "__exactEnsureWebCrypto",
  "__exactEnsureWebStorage",
  // Diagnostic POSIX child IPC is captured from this frozen, one-shot root
  // during trusted bootstrap. It is never an armed or project-visible channel.
  "__exactProcessIpcBootstrap",
  "__hostCall",
  "__hostCallAsync",
  "__filename",
]);

const SEALED_PATHS = new Set([
  "Exact.setModuleCapabilities",
  "Ibex.authority",
  "Ibex.permissions",
]);

const ROOT_ALIASES = new Map([
  ["global", ["globalThis", "self", "window"]],
  ["self", ["global", "globalThis", "window"]],
  ["window", ["global", "globalThis", "self"]],
]);

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(compareText);
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value)
    .sort(compareText)
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

function stableDigest(value) {
  return crypto
    .createHash("sha256")
    .update(canonical(value), "utf8")
    .digest("hex");
}

function stableSlug(value) {
  const slug = value
    .replace(/^global:/u, "")
    .replace(/\[\[[^\]]+\]\]/gu, "dynamic")
    .replace(/[^A-Za-z0-9]+/gu, ".")
    .replace(/^\.|\.$/gu, "")
    .toLowerCase();
  return (slug || "root").slice(0, 48);
}

function stableInstallId(surface, branch) {
  const identity = {
    observedKey: surface.observedKey,
    routes: uniqueSorted(branch.routes ?? [branch.route]),
    targetVariant: branch.targetVariant,
  };
  return `root-global.${stableSlug(surface.name)}.${stableDigest(identity).slice(0, 16)}`;
}

function splitLogicalPath(metadata) {
  const root = metadata.globalName;
  if (typeof root !== "string" || root.length === 0) {
    throw new Error("root-global installation lacks a globalName");
  }
  const member = metadata.memberName;
  return {
    root,
    segments:
      member === null || member === undefined || member === ""
        ? []
        : member.split("."),
  };
}

function keyShape(segment) {
  const symbol = segment.match(/^\[\[Symbol\.([A-Za-z0-9_$]+)\]\]$/u);
  if (symbol) return { kind: "well-known-symbol", value: symbol[1] };
  const dynamic = segment.match(/^\[\[dynamic-table:([^\]]+)\]\]$/u);
  if (dynamic) return { kind: "dynamic-table", value: dynamic[1] };
  const returned = segment === "[[return]]";
  if (returned) return { kind: "return-value", value: "return" };
  return { kind: "string", value: segment };
}

function logicalPath(metadata) {
  const split = splitLogicalPath(metadata);
  return {
    root: keyShape(split.root),
    path: split.segments.map(keyShape),
  };
}

function sourceKeys(metadata) {
  return new Set([
    ...(metadata.sourceKeys ?? []),
    ...[metadata.sourceKey].filter(Boolean),
  ]);
}

function privateConsumerFor(surface) {
  const { root } = splitLogicalPath(surface.metadata);
  return PRIVATE_CONSUMERS.get(root) ?? null;
}

function pathText(surface) {
  const { root, segments } = splitLogicalPath(surface.metadata);
  return [root, ...segments].join(".");
}

function dispositionFor(surface, edge) {
  const { root } = splitLogicalPath(surface.metadata);
  if (root === "[[dynamic-table:native-global-name]]") return "sealed";
  if (PRIVATE_CONSUMERS.has(root)) return "private";
  if (SEALED_ROOTS.has(root) || SEALED_PATHS.has(pathText(surface))) {
    return "sealed";
  }
  if (edge.classification === "effects" || edge.classification === "closed") {
    return "converted";
  }
  if (/^__(?:exact|host|native)/u.test(root)) return "converted";
  return "exposed";
}

function traversalFor(surface) {
  const { root } = splitLogicalPath(surface.metadata);
  // Web Storage deliberately implements named-property enumeration through a
  // Proxy whose ownKeys/getOwnPropertyDescriptor traps read SQLite. Invoking
  // those traps during a security audit would itself exercise authority. The
  // root descriptor remains checked exactly; its JS façade is a leaf, while
  // the separately installed native SQLite roots remain fully traversed.
  return EFFECTFUL_PROXY_ROOTS.has(root) ? "descriptor-leaf" : "descend";
}

function installPhase(branch) {
  const routes = new Set(branch.routes ?? [branch.route]);
  if (routes.has("hermes-intrinsic")) return "engine-create";
  if (
    routes.has("native-jsi-global") ||
    routes.has("native-env-enumeration") ||
    routes.has("windows-native-shim")
  ) {
    return "native-install";
  }
  if (routes.has("evaluated-native-script")) return "native-evaluated-script";
  if (routes.has("shared-runtime")) return "shared-runtime";
  if ([...routes].some((route) => route.startsWith("legacy-bootstrap"))) {
    return "bootstrap-script";
  }
  return "source-derived";
}

const LEGACY_RUNTIME_FALLBACK_FILES = new Set([
  "src/engine/bootstrap/bootstrap-globals.js",
  "src/engine/bootstrap/process-compat-fix.js",
  "src/engine/bootstrap/compat-polyfills.js",
  "src/engine/bootstrap/exact-global.js",
]);

const ANDROID_PLATFORM_STATE_ROOTS = new Set([
  "__exactAccessibilitySnapshot",
  "__exactAppState",
  "__exactInitialURL",
  "__exactLocaleSnapshot",
]);

const OPENSSL_CRYPTO_ROOTS = new Set([
  "__exactEcdhDeriveBits",
  "__exactEcdsaSign",
  "__exactEcdsaVerify",
  "__exactEd25519Sign",
  "__exactEd25519Verify",
  "__exactEvpCipherDecrypt",
  "__exactEvpCipherEncrypt",
  "__exactExportKeyPkcs8",
  "__exactExportKeySpki",
  "__exactImportKeyPkcs8",
  "__exactImportKeySpki",
  "__exactRsaOaepDecrypt",
  "__exactRsaOaepEncrypt",
  "__exactX25519DeriveBits",
]);

const POST_BOOTSTRAP_LAZY_ROOTS = new Set([
  "__exactDebugModuleSource",
  "__exactDebugModuleSources",
  "__exactEntryFileConsumed",
  "__exactNativeWrapState",
  "__exactStreamWrapReadBytesOrErrorIndex",
  "__exactStreamWrapState",
  "__exactUvEOFValue",
]);

const POST_BOOTSTRAP_EMBEDDER_ENDOWMENT_PATHS = new Set([
  // The native registrar predeclares the stable `exact` facade, but this
  // method is added only after ex_hermes_set_exact_host_call_async validates
  // one immutable app/agent operation endowment and refreshes the compartment
  // baseline. It is deliberately absent at the armed bootstrap seal.
  "exact.invokeHostAsync",
]);

const IPC_BOOTSTRAP_ROOTS = new Set([
  "__exactInstallAsyncIpcListenerPatch",
  "__exactProcessIpcBootstrap",
  "__exactSyncTrackedIpcListenersAfterDispatch",
]);

function branchActivation(surface, routes, sourceRefs, targetVariant) {
  const { root } = splitLogicalPath(surface.metadata);
  const routeSet = new Set(routes);
  const logicalPath = pathText(surface);

  // Native process setup installs concrete stream/memory helpers before the
  // shared runtime replaces those objects with lazy JavaScript façades. The
  // native descriptors remain live only on the legacy fallback path.
  if (
    routeSet.has("native-jsi-global") &&
    (/^process\.(?:stdin|stdout|stderr)\./u.test(logicalPath) ||
      logicalPath === "process.memoryUsage.rss")
  ) {
    return "legacy-runtime-fallback";
  }

  // Source discovery records constructors reached through lockdown's
  // prototype reflection as global surfaces. They are engine intrinsics, not
  // root own-properties, so an own global with either spelling remains an
  // unexpected post-bootstrap addition.
  if (root === "AsyncFunction" || root === "GeneratorFunction") {
    return "intrinsic-reference-only";
  }

  // These compatibility cells are deliberately created only after project
  // code requires the corresponding builtin or begins loading its entry
  // module. They are covered by the install/registry join, but must not exist
  // at the armed bootstrap seal.
  if (POST_BOOTSTRAP_LAZY_ROOTS.has(root)) return "post-bootstrap-lazy";
  if (POST_BOOTSTRAP_EMBEDDER_ENDOWMENT_PATHS.has(logicalPath)) {
    return "post-bootstrap-embedder-endowment";
  }

  if (IPC_BOOTSTRAP_ROOTS.has(root)) return "ipc-channel-bootstrap";
  if (
    root === "WebStreamsPolyfill" ||
    root === "__exactWebStreamsPolyfillLoaded"
  ) {
    return "web-streams-polyfill";
  }
  if (OPENSSL_CRYPTO_ROOTS.has(root)) return "openssl-crypto";
  if (root === "__nativeFetchSync") return "windows-native";

  if (ANDROID_PLATFORM_STATE_ROOTS.has(root)) {
    if (
      targetVariant === "android" &&
      (routeSet.has("native-jsi-global") ||
        routeSet.has("native-env-enumeration"))
    ) {
      return "always";
    }
    return "android-platform-state";
  }

  // These shared-runtime references consume an already installed host input;
  // neither line is itself an unconditional root installation.
  if (root === "__exactHostNavigator") return "host-navigator-copy";
  if (root === "__exactLoadTimings") return "baseline-input";

  // The Promise tracker exposes this root only on its userland compatibility
  // fallback. Armed runtimes install the native rejection hooks first, so the
  // shared bundle returns before creating either the root or its descendants.
  if (root === "__OriginalPromise") {
    return "diagnostic-unarmed-promise-fallback";
  }

  if (root === "Bun") {
    const shared = routeSet.has("shared-runtime");
    const legacy = routeSet.has("legacy-bootstrap");
    if (shared && legacy) {
      return "bun-compat-shared-or-legacy-fallback";
    }
    if (shared) return "bun-compat-shared-runtime";
    // The legacy fallback predates the opt-in facade and installs Bun
    // together with Exact. Keep that behavior explicit rather than pretending
    // the shared bundle's compat predicate applies to it.
    if (legacy) return "legacy-runtime-fallback";
  }

  if (
    routeSet.has("native-jsi-global") ||
    routeSet.has("native-env-enumeration") ||
    routeSet.has("windows-native-shim")
  ) {
    return "always";
  }
  if (routeSet.has("shared-runtime")) return "shared-runtime-bundle";
  if (
    routeSet.has("legacy-bootstrap") &&
    sourceRefs.every((sourceRef) => {
      const separator = sourceRef.lastIndexOf("#");
      const sourcePath =
        separator === -1 ? sourceRef : sourceRef.slice(0, separator);
      return LEGACY_RUNTIME_FALLBACK_FILES.has(sourcePath);
    })
  ) {
    return "legacy-runtime-fallback";
  }
  return "always";
}

function dynamicResolution(surface, branch, disposition) {
  if (!DYNAMIC_SENTINEL.test(surface.name)) return "static";
  if (!LIVE_DISPOSITIONS.has(disposition)) return "sealed-before-live-sweep";
  const roles = new Set(surface.metadata?.semanticRoles ?? []);
  if (
    roles.has("host-object-overlay") ||
    roles.has("runtime-property-overlay")
  ) {
    // These tables have a typed owner which bounds their keys. The descriptor
    // sweep still enumerates their concrete live keys and never invokes a
    // getter; the sentinel does not survive into a live key comparison.
    return "typed-bounded-live-keys";
  }
  if (
    roles.has("inherited-global-shape") &&
    typeof surface.metadata?.inheritedShapeReviewId === "string"
  ) {
    return "reviewed-inherited-descriptor-shape";
  }
  if (surface.metadata?.dynamicNamespaceEvidence) {
    return "digest-bound-live-descriptor-shape";
  }
  if (
    /^global:process\.\[\[dynamic-table:(?:channel-handle-key|exact-channel-handle-key|k-channel-handle)\]\](?:\.|$)/u.test(
      surface.name,
    )
  ) {
    return "closed-ipc-symbol-key";
  }
  const sourceRefs = branch.sourceRefs ?? [];
  if (
    surface.metadata?.globalName === "[[dynamic-table:native-global-name]]" &&
    sourceRefs.every((sourceRef) =>
      /#jsi-global:\[\[dynamic-table:native-global-name\]\]$/u.test(sourceRef),
    )
  ) {
    // Source discovery also sees helpers which accept a runtime/user-selected
    // property. They are not bootstrap install sites. They remain recorded so
    // the join is exact, but a conformant target may not select them as a live
    // bootstrap property.
    return "non-bootstrap-dynamic-writer";
  }
  return "unresolved";
}

function aliasesFor(surface) {
  const { root } = splitLogicalPath(surface.metadata);
  const aliases = ROOT_ALIASES.get(root) ?? [];
  return aliases.map((alias) => ({
    root: { kind: "string", value: alias },
    path: [],
  }));
}

function registryEdgesByObservedKey(coverage) {
  if (
    !coverage ||
    coverage.coverageSchema !== "ibex/capsec-coverage/1" ||
    !Array.isArray(coverage.edges)
  ) {
    throw new Error("root-global disposition join requires CapSec coverage/1");
  }
  const result = new Map();
  for (const edge of coverage.edges) {
    const observedKey = `${edge.surface?.kind}:${edge.surface?.name}`;
    if (result.has(observedKey)) {
      throw new Error(`duplicate CapSec edge for ${observedKey}`);
    }
    result.set(observedKey, edge);
  }
  return result;
}

function validateBranch(branch, observedKey) {
  if (!branch || typeof branch !== "object") {
    throw new Error(`${observedKey}: installation branch is absent`);
  }
  if (
    typeof branch.targetVariant !== "string" ||
    branch.targetVariant.length === 0
  ) {
    throw new Error(`${observedKey}: installation branch target is absent`);
  }
  const routes = uniqueSorted(branch.routes ?? [branch.route]);
  if (routes.length === 0 || routes.some((route) => !route)) {
    throw new Error(`${observedKey}: installation branch route is absent`);
  }
  const sourceRefs = uniqueSorted(branch.sourceRefs ?? []);
  if (sourceRefs.length === 0) {
    throw new Error(`${observedKey}: installation branch source refs are absent`);
  }
  return { routes, sourceRefs };
}

function applicableConformantBranch(branch) {
  // Only the default desktop profile is currently eligible for conformance.
  // Platform rows stay in the generated manifest but never inherit a target
  // advertisement from source discovery.
  return new Set(["all", "default"]).has(branch.targetVariant);
}

export function buildRootGlobalDispositionManifest({
  globals,
  coverage,
  sourceDigest = null,
}) {
  if (!Array.isArray(globals) || globals.length === 0) {
    throw new Error("root-global disposition source inventory is empty");
  }
  const edges = registryEdgesByObservedKey(coverage);
  const globalKeys = new Set();
  const rows = [];
  const installIds = new Set();

  for (const surface of [...globals].sort((left, right) =>
    compareText(left.observedKey, right.observedKey),
  )) {
    if (surface.metadata?.surfaceType !== "global-api") {
      throw new Error(`${surface.observedKey}: non-global row in global inventory`);
    }
    if (globalKeys.has(surface.observedKey)) {
      throw new Error(`duplicate root-global surface ${surface.observedKey}`);
    }
    globalKeys.add(surface.observedKey);
    const edge = edges.get(surface.observedKey);
    if (!edge) {
      throw new Error(
        `${surface.observedKey}: missing CapSec registry classification`,
      );
    }
    const branches = surface.metadata?.installationBranches;
    if (!Array.isArray(branches) || branches.length === 0) {
      throw new Error(`${surface.observedKey}: installation branches are absent`);
    }
    const disposition = dispositionFor(surface, edge);
    if (!DISPOSITIONS.has(disposition)) {
      throw new Error(`${surface.observedKey}: invalid disposition`);
    }
    const privateConsumer = privateConsumerFor(surface);
    if ((disposition === "private") !== (privateConsumer !== null)) {
      throw new Error(
        `${surface.observedKey}: private disposition/consumer mismatch`,
      );
    }
    for (const branch of branches) {
      const { routes, sourceRefs } = validateBranch(
        branch,
        surface.observedKey,
      );
      const installId = stableInstallId(surface, branch);
      if (installIds.has(installId)) {
        throw new Error(`duplicate stable root-global install id ${installId}`);
      }
      installIds.add(installId);
      const resolution = dynamicResolution(surface, branch, disposition);
      if (
        resolution === "unresolved" &&
        LIVE_DISPOSITIONS.has(disposition) &&
        applicableConformantBranch(branch)
      ) {
        throw new Error(
          `${surface.observedKey}: unresolved dynamic sentinel is root-reachable on ${branch.targetVariant}`,
        );
      }
      rows.push({
        installId,
        observedKey: surface.observedKey,
        registryEdgeId: edge.id,
        branch: {
          id: branch.id,
          routes,
          sourceRefs,
          targetVariant: branch.targetVariant,
          activation: branchActivation(
            surface,
            routes,
            sourceRefs,
            branch.targetVariant,
          ),
        },
        property: logicalPath(surface.metadata),
        aliases: aliasesFor(surface),
        installPhase: installPhase(branch),
        privateConsumer,
        disposition,
        traversal: traversalFor(surface),
        liveExpectation: LIVE_DISPOSITIONS.has(disposition)
          ? "reachable"
          : "absent",
        resolution,
        // A logical surface may have both a shared-runtime implementation and
        // a native implementation on another target. Native-ness belongs to
        // this concrete install branch, not to the merged logical surface.
        // Otherwise a JS-only default branch is incorrectly required by the
        // live native sweep merely because (for example) iOS also installs the
        // same spelling from C++.
        nativeImplementation:
          routes.includes("native-jsi-global") ||
          routes.includes("native-env-enumeration") ||
          routes.includes("windows-native-shim"),
      });
    }
  }

  const registryGlobalKeys = [...edges.keys()]
    .filter((key) => key.startsWith("native-op:"))
    .filter((key) => {
      const edge = edges.get(key);
      return (
        edge.surface.name.startsWith("global:") ||
        globals.some((surface) => surface.observedKey === key)
      );
    });
  const extraRegistryRows = registryGlobalKeys.filter(
    (key) => !globalKeys.has(key),
  );
  if (extraRegistryRows.length > 0) {
    throw new Error(
      `CapSec registry has extra root-global rows: ${extraRegistryRows.sort(compareText).join(", ")}`,
    );
  }

  rows.sort((left, right) => compareText(left.installId, right.installId));
  const registryEdgeIds = uniqueSorted(rows.map((row) => row.registryEdgeId));
  return {
    rootGlobalDispositionManifestSchema: ROOT_GLOBAL_DISPOSITION_SCHEMA,
    profile: ROOT_GLOBAL_DISPOSITION_PROFILE,
    status: "enforced-by-armed-live-sweep",
    sourceDigest,
    sweep: {
      roots: ["globalThis"],
      descriptorOnly: true,
      invokeGetters: false,
      includeNonEnumerable: true,
      includePrototypes: true,
      includeSymbols: true,
      cyclePolicy: "object-identity-once-per-root",
      descriptorLeafRoots: [...EFFECTFUL_PROXY_ROOTS].sort(compareText),
      ...ROOT_GLOBAL_SWEEP_BUDGET,
    },
    registryJoin: {
      coverageSchema: coverage.coverageSchema,
      edgeIds: registryEdgeIds,
    },
    rows,
    counts: {
      installBranches: rows.length,
      logicalGlobals: globalKeys.size,
      registryEdges: registryEdgeIds.length,
      sealedOrPrivate: rows.filter((row) => row.liveExpectation === "absent")
        .length,
      permittedReachable: rows.filter(
        (row) => row.liveExpectation === "reachable",
      ).length,
    },
  };
}

export function assertExactRootGlobalDispositionJoin(manifest, globals, coverage) {
  const rebuilt = buildRootGlobalDispositionManifest({
    globals,
    coverage,
    sourceDigest: manifest.sourceDigest ?? null,
  });
  if (canonical(manifest) !== canonical(rebuilt)) {
    throw new Error("root-global disposition manifest is stale or non-canonical");
  }
  return true;
}

/**
 * Test/reference implementation of the live traversal. It performs no property
 * read on the traversed objects: all edges come from own descriptors, accessor
 * functions are recorded as values but never invoked, and prototype traversal
 * uses the captured intrinsic supplied by the caller.
 */
export function sweepReachableOwnDescriptors(
  roots,
  {
    getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor,
    getOwnPropertyNames = Object.getOwnPropertyNames,
    getOwnPropertySymbols = Object.getOwnPropertySymbols,
    getPrototypeOf = Object.getPrototypeOf,
    maxDepth = ROOT_GLOBAL_SWEEP_BUDGET.maxDepth,
    maxDescriptors = ROOT_GLOBAL_SWEEP_BUDGET.maxDescriptors,
    maxObjects = ROOT_GLOBAL_SWEEP_BUDGET.maxObjects,
    descriptorLeafPaths = new Set(),
  } = {},
) {
  const queue = Object.entries(roots).map(([path, value]) => ({
    depth: 0,
    path,
    value,
  }));
  const visited = new WeakSet();
  const descriptors = [];
  let objectCount = 0;
  const enqueue = (path, value, depth) => {
    if ((typeof value === "object" && value !== null) || typeof value === "function") {
      queue.push({ depth, path, value });
    }
  };
  while (queue.length > 0) {
    const current = queue.shift();
    if (
      (typeof current.value !== "object" || current.value === null) &&
      typeof current.value !== "function"
    ) {
      continue;
    }
    if (visited.has(current.value)) continue;
    visited.add(current.value);
    objectCount += 1;
    if (objectCount > maxObjects) throw new Error("root-global sweep object budget exceeded");
    if (current.depth > maxDepth) throw new Error("root-global sweep depth budget exceeded");
    if (descriptorLeafPaths.has(current.path)) continue;
    const keys = [
      ...getOwnPropertyNames(current.value),
      ...getOwnPropertySymbols(current.value),
    ];
    for (const key of keys) {
      const descriptor = getOwnPropertyDescriptor(current.value, key);
      if (!descriptor) throw new Error("root-global sweep descriptor disappeared");
      const keyText =
        typeof key === "symbol"
          ? `[${String(key)}]`
          : /^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(key)
            ? `.${key}`
            : `[${JSON.stringify(key)}]`;
      const path = `${current.path}${keyText}`;
      descriptors.push({
        path,
        kind: Object.hasOwn(descriptor, "value") ? "data" : "accessor",
      });
      if (descriptors.length > maxDescriptors) {
        throw new Error("root-global sweep descriptor budget exceeded");
      }
      if (Object.hasOwn(descriptor, "value")) {
        enqueue(path, descriptor.value, current.depth + 1);
      } else {
        enqueue(`${path}[[Get]]`, descriptor.get, current.depth + 1);
        enqueue(`${path}[[Set]]`, descriptor.set, current.depth + 1);
      }
    }
    const prototype = getPrototypeOf(current.value);
    if (prototype !== null) {
      enqueue(`${current.path}[[Prototype]]`, prototype, current.depth + 1);
    }
  }
  descriptors.sort((left, right) => compareText(left.path, right.path));
  return { descriptors, objectCount };
}

export function dispositionConstantsForTests() {
  return {
    privateConsumers: new Map(PRIVATE_CONSUMERS),
    sealedPaths: new Set(SEALED_PATHS),
    sealedRoots: new Set(SEALED_ROOTS),
  };
}
