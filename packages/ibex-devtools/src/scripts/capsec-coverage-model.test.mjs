// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
// semantic classifier is closed over observed surfaces and produces stable,
// reproducible coverage and implementation joins.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertReviewedSurfaceInventory,
  buildCoverageModel,
  classifyObservedSurface,
  deriveEffectTemplate,
  derivePositiveSources,
  logicalBranchConditionsOverlap,
  reviewedBuiltinExportNames,
  reviewedBuiltinRootNames,
  reviewedCallbackIngressNames,
  reviewedCallbackProducerNames,
  reviewedCliNames,
  reviewedClosedFsMutationObservedKeys,
  reviewedGlobalApiNames,
  reviewedHostAbiNames,
  reviewedInspectorNativeNames,
  reviewedLoaderNames,
  reviewedNativeOperationNames,
  reviewedStartupNames,
  stableIdForSurface,
} from "./capsec-coverage-model.mjs";
import {
  discoverRepositorySurfaces,
  HERMES_EVALUATOR_REVIEW_ID,
} from "./capsec-surface-inventory.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..", "..", "..", "..");
const definitions = JSON.parse(
  fs.readFileSync(
    path.join(repoRoot, "capsec/registry/capability-definitions.json"),
    "utf8",
  ),
);
const rules = JSON.parse(
  fs.readFileSync(
    path.join(repoRoot, "capsec/registry/policy-rules.json"),
    "utf8",
  ),
);
const context = { definitions, rules };
const REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST =
  "sha256-9f79a77fc45cb8d2d163928f0f834d35ec121a7cdb4dc553463a77961ed0124f";
const REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID =
  "sha256-161c4e4bf9027d0d3e4f9427954c18529f7ef0bd727be9064fc8f79270a75c75";

function surface(kind, name, metadata = undefined, sourceRefs = undefined) {
  return {
    kind,
    name,
    observedKey: `${kind}:${name}`,
    sourceRefs: sourceRefs ?? [
      `src/engine/example.cc#${name.replace(/[^A-Za-z0-9_$.-]/gu, "_")}`,
    ],
    ...(metadata ? { metadata } : {}),
  };
}

function builtinExport(sourceKey, exportName, metadata = {}) {
  return surface(
    "builtin",
    `export:${sourceKey}:${exportName}`,
    { surfaceType: "export", sourceKey, exportName, ...metadata },
    [`modules.ts#${sourceKey}.${exportName}`],
  );
}

function reviewedDnsProjectionExport(sourceKey, exportName) {
  if (sourceKey === "node_dns_promises") {
    return builtinExport(sourceKey, exportName, {
      crossSourceExportProjection: {
        carrierBinding: "module.exports=dns.promises",
        carrierSourceKey: "node_dns_promises",
        kind: "immutable-commonjs-member-object",
        memberPath: exportName,
        providerBinding: "module.exports.promises",
        providerSourceKey: "node_dns",
      },
      dnsPromiseExportShapeReviewId:
        REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID,
    });
  }
  return builtinExport(sourceKey, exportName, {
    constructorInstanceProjection: {
      constructorExport: "Resolver",
      instancePath: exportName.slice("Resolver.".length),
      kind: "constructor-installed-nested-object",
    },
    dnsPromiseExportShapeReviewId:
      REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID,
  });
}

function globalApi(globalName, memberName = null) {
  const exportName = memberName ? `${globalName}.${memberName}` : globalName;
  return surface("native-op", `global:${exportName}`, {
    surfaceType: "global-api",
    sourceKey: "synthetic_global_audit",
    globalName,
    memberName,
    exportName,
  });
}

function principalEnvironmentOverlayGlobal() {
  const dynamicMember =
    "[[dynamic-table:principal-environment-overlay-properties]]";
  const name = `global:process.env.${dynamicMember}`;
  const sourcePath = "packages/ibex-runtime-js/src/node/process.ts";
  const sourceRefs = [
    `${sourcePath}#Process.prototype.env`,
    `${sourcePath}#createEnvProxy`,
    `${sourcePath}#createEnvProxy:Proxy.deleteProperty`,
    `${sourcePath}#createEnvProxy:Proxy.get`,
    `${sourcePath}#createEnvProxy:Proxy.ownKeys`,
    `${sourcePath}#createEnvProxy:Proxy.set`,
  ];
  return surface(
    "native-op",
    name,
    {
      exportName: `process.env.${dynamicMember}`,
      globalName: "process",
      memberKinds: ["dynamic-table"],
      memberName: `env.${dynamicMember}`,
      principalEnvironmentOverlaySourceContract: {
        schema: "ibex/principal-environment-overlay-source-contract/1",
        surfaceName: name,
        dynamicMember,
        globalPath: "process.env",
        binding: {
          factory: "createEnvProxy",
          member: "Process.prototype.env",
          sourceRef: sourceRefs[0],
        },
        factory: { name: "createEnvProxy", sourceRef: sourceRefs[1] },
        nativeBridges: ["__exactGetAllEnv", "__exactGetEnv", "__exactSetEnv"],
        proxyTraps: [
          {
            name: "deleteProperty",
            nativeBridges: ["__exactSetEnv"],
            sourceRef: sourceRefs[2],
          },
          {
            name: "get",
            nativeBridges: ["__exactGetAllEnv", "__exactGetEnv"],
            sourceRef: sourceRefs[3],
          },
          {
            name: "ownKeys",
            nativeBridges: ["__exactGetAllEnv", "__exactGetEnv"],
            sourceRef: sourceRefs[4],
          },
          {
            name: "set",
            nativeBridges: ["__exactSetEnv"],
            sourceRef: sourceRefs[5],
          },
        ],
        sourceRefs,
      },
      semanticRoles: [
        "principal-environment-overlay",
        "runtime-property-overlay",
      ],
      sourceKey: "shared_runtime",
      surfaceType: "global-api",
    },
    sourceRefs,
  );
}

function hermesEvaluatorGlobal(globalName, metadata = {}) {
  const reachability =
    globalName === "eval" || globalName === "Function"
      ? "inherited-global"
      : "intrinsic-constructor";
  const mergedEvalSources =
    globalName === "eval"
      ? [
          "global_compat_polyfills",
          "global_process_compat_fix",
          "hermes_intrinsic_evaluators",
        ]
      : null;
  const lockdownRef = `src/engine/hermes_runtime.cc#lockdown-taming:${REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST}`;
  const branches = [
    {
      authorityRef: "scripts/hermes-version.sh#IBEX_HERMES_ANDROID_VERSION",
      profileId: "android-maven",
      targetVariant: "android",
    },
    {
      authorityRef: "scripts/apply-hermes-patches.sh#patches",
      profileId: "source-patched",
      targetVariant: "default",
    },
    {
      authorityRef: "scripts/build-hermes-windows.ps1#apply-hermes-patches.sh",
      profileId: "windows-source-patched",
      targetVariant: "windows",
    },
  ].map(({ authorityRef, profileId, targetVariant }) => {
    const route = `hermes-intrinsic-${profileId}-reviewed`;
    return {
      branchKind: "alternative",
      id: `${targetVariant}-reviewed`,
      kind: "alternative",
      route,
      routes: [route],
      sourceRefs: [authorityRef, lockdownRef].sort(),
      stubDisposition: "not-structurally-proven",
      targetVariant,
    };
  });
  return surface(
    "native-op",
    `global:${globalName}`,
    {
      surfaceType: "global-api",
      sourceKey:
        globalName === "eval"
          ? "global_compat_polyfills"
          : "hermes_intrinsic_evaluators",
      ...(mergedEvalSources ? { sourceKeys: mergedEvalSources } : {}),
      globalName,
      memberName: null,
      exportName: globalName,
      branches,
      evidenceType: "hermes-evaluator-reachability",
      engineIdentityReviewId: HERMES_EVALUATOR_REVIEW_ID,
      engineProfileIds: [
        "android-maven",
        "source-patched",
        "windows-source-patched",
      ],
      installationBranches: branches,
      lockdownTamingDigest: REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST,
      tamingEvidence: "lockdownJS",
      reachability,
      moduleSpecifiers: [],
      ...metadata,
    },
    branches.flatMap((branch) => branch.sourceRefs),
  );
}

function dualRoleGlobalNative(name, globalName, memberName = null) {
  const exportName = memberName ? `${globalName}.${memberName}` : globalName;
  return surface("native-op", name, {
    surfaceType: "global-api",
    surfaceTypes: ["global-api", "private-native-operation"],
    semanticRoles: ["global-api-installation", "private-native-operation"],
    sourceKey: "synthetic_dual_role_audit",
    globalName,
    memberName,
    exportName,
  });
}

function edgeActions(classification) {
  return classification.edge.classification === "effects"
    ? classification.edge.effects.map((effect) => effect.cap)
    : classification.edge.classification === "closed"
      ? [classification.edge.cap]
      : [];
}

describe("LLP 0021 WP1 semantic coverage classifier", () => {
  test("logical branches reject subset and cross-fact overlap", () => {
    const base = [{ fact: "mode", equals: "path" }];
    expect(logicalBranchConditionsOverlap(base, base)).toBe(true);
    expect(
      logicalBranchConditionsOverlap(base, [
        ...base,
        { fact: "ownership", equals: "caller" },
      ]),
    ).toBe(true);
    expect(
      logicalBranchConditionsOverlap(base, [
        { fact: "ownership", equals: "caller" },
      ]),
    ).toBe(true);
    expect(
      logicalBranchConditionsOverlap(base, [
        { fact: "mode", equals: "descriptor" },
      ]),
    ).toBe(false);
  });
  const cases = [
    [
      "filesystem open",
      surface("native-op", "__exactFsOpen"),
      "effects",
      ["fs:list", "fs:read", "fs:write"],
    ],
    [
      "async filesystem read",
      surface("native-op", "__exactFsReadAsync"),
      "effects",
      ["fs:read"],
    ],
    [
      "sync filesystem stat",
      surface("native-op", "__exactFsFstatSync"),
      "effects",
      ["fs:list"],
    ],
    [
      "filesystem mutation enforcement seam",
      surface("native-op", "__exactFsMutationGuard"),
      "non-capability",
      [],
    ],
    [
      "fetch",
      surface("native-op", "__nativeFetch"),
      "effects",
      ["network:fetch"],
    ],
    [
      "DNS",
      surface("native-op", "__exactDnsResolve"),
      "effects",
      ["network:resolve"],
    ],
    [
      "raw socket",
      surface("native-op", "__exactTcpConnect"),
      "effects",
      ["network:connect"],
    ],
    [
      "Unix socket connect",
      surface("native-op", "__exactUnixConnect"),
      "effects",
      ["fs:read", "network:connect"],
    ],
    [
      "Unix socket listen",
      surface("native-op", "__exactUnixListen"),
      "effects",
      ["fs:write", "network:listen"],
    ],
    [
      "HTTP listener",
      surface("native-op", "__exactHttpServe"),
      "effects",
      ["network:listen"],
    ],
    [
      "process spawn",
      surface("native-op", "__exactSpawn"),
      "effects",
      [
        "env:read",
        "env:write",
        "fs:list",
        "process:spawn",
        "stdio:read",
        "stdio:write",
      ],
    ],
    [
      "stdio read",
      surface("native-op", "__exactStdinRead"),
      "effects",
      ["stdio:read"],
    ],
    [
      "environment read",
      surface("host-abi", "ex_host_env_get"),
      "effects",
      ["env:read"],
    ],
    [
      "principal environment overlay write",
      surface("native-op", "__exactSetEnv"),
      "effects",
      ["env:write"],
    ],
    [
      "system information",
      surface("native-op", "__exactGetCpuCount"),
      "effects",
      ["sys:read"],
    ],
    [
      "network-interface information",
      surface("native-op", "__exactGetNetworkInterfaces"),
      "effects",
      ["sys:read"],
    ],
    [
      "Android location",
      surface("native-op", "__exactAndroidLocation"),
      "effects",
      ["device:location"],
    ],
    [
      "Android camera/microphone bridge",
      surface("native-op", "__exactAndroidCameraHostCall"),
      "effects",
      ["device:camera", "device:microphone"],
    ],
    [
      "Android camera metadata",
      surface("native-op", "__exactAndroidCameraMetadata"),
      "non-capability",
      [],
    ],
    [
      "clipboard read",
      surface("native-op", "__exactClipboardRead"),
      "effects",
      ["clipboard:read"],
    ],
    [
      "clipboard write",
      surface("native-op", "__exactClipboardWrite"),
      "effects",
      ["clipboard:write"],
    ],
    [
      "SQLite decomposition",
      surface("native-op", "__exactSqliteOpen"),
      "effects",
      ["fs:list", "fs:read", "fs:write"],
    ],
    [
      "shared worklet value closed",
      surface("native-op", "__svGet"),
      "closed",
      ["ipc:channel"],
    ],
    [
      "application-runtime worklet helper closed",
      globalApi("worklet", "clamp"),
      "closed",
      ["worker:create"],
    ],
    [
      "heap inspection closed",
      surface("native-op", "__exactGetHeapInfo"),
      "closed",
      ["runtime:inspect"],
    ],
    [
      "application state closed",
      surface("native-op", "__exactAppState"),
      "closed",
      ["ipc:channel"],
    ],
    [
      "OS version",
      surface("native-op", "__exactOSVersion", {
        exportName: "process.__exactOSVersion",
        globalName: "process",
        memberName: "__exactOSVersion",
        publicOutputAccess: {
          alias: "process.__exactOSVersion",
          kind: "property-read",
        },
        publicReadAccessSourceProven: true,
        sourceKey: "native_jsi_global",
        surfaceType: "global-api",
      }),
      "effects",
      ["sys:read"],
    ],
    [
      "unbound copy mutation closed",
      surface("native-op", "__exactCopyFile"),
      "closed",
      ["fs:unbound-mutation"],
    ],
    [
      "readlink reads link bytes",
      surface("native-op", "__exactReadlink"),
      "effects",
      ["fs:read"],
    ],
    [
      "unbound hard-link mutation closed",
      surface("native-op", "__exactLink"),
      "closed",
      ["fs:unbound-mutation"],
    ],
    [
      "module resolution metadata lists only",
      surface("native-op", "__exactModuleResolveMeta"),
      "effects",
      ["fs:list"],
    ],
    [
      "inspector closed",
      surface("native-op", "inspector.debugger-enable"),
      "closed",
      ["inspector:activate"],
    ],
    ["VM closed", surface("startup", "script:eval"), "closed", ["vm:evaluate"]],
    [
      "worker closed",
      surface("host-abi", "ex_worklet_create"),
      "closed",
      ["worker:create"],
    ],
    [
      "WASI closed",
      surface("loader", "wasm-module"),
      "closed",
      ["wasi:instantiate"],
    ],
    [
      "IPC closed",
      surface("native-op", "__exactIpcSendMsg"),
      "closed",
      ["ipc:channel"],
    ],
    [
      "raw descriptor adoption closed",
      surface("native-op", "__exactTcpFromFd"),
      "closed",
      ["ipc:channel"],
    ],
    [
      "unbound UDP allocation",
      surface("native-op", "__exactUdpSocket"),
      "non-capability",
      [],
    ],
    [
      "TCP reset release",
      surface("native-op", "__exactTcpReset"),
      "non-capability",
      [],
    ],
    [
      "crypto compute",
      surface("native-op", "__exactHashSync"),
      "non-capability",
      [],
    ],
    [
      "clock",
      surface("native-op", "__exactPerformanceNow"),
      "non-capability",
      [],
    ],
    [
      "randomness",
      surface("host-abi", "ex_host_random_fill"),
      "non-capability",
      [],
    ],
    [
      "byte transform",
      surface("native-op", "__exactDeflateSync"),
      "non-capability",
      [],
    ],
    [
      "security control",
      surface("native-op", "__exactCapabilityCheck"),
      "non-capability",
      [],
    ],
    [
      "callback plumbing",
      surface("callback", "callback.queue-enqueue"),
      "non-capability",
      [],
    ],
    [
      "worklet measure channel closed",
      surface("callback", "worklet-measure"),
      "closed",
      ["ipc:channel"],
    ],
    [
      "builtin fs watch export",
      surface("builtin", "export:node_fs:watch", {
        surfaceType: "export",
        sourceKey: "node_fs",
        exportName: "watch",
      }),
      "closed",
      ["fs:unbound-mutation"],
    ],
    [
      "builtin process kill export",
      surface("builtin", "export:exact_process:kill", {
        surfaceType: "export",
        sourceKey: "exact_process",
        exportName: "kill",
      }),
      "closed",
      ["process:signal"],
    ],
    [
      "builtin TTY raw-mode method",
      surface("builtin", "export:node_tty:ReadStream.setRawMode", {
        surfaceType: "export",
        sourceKey: "node_tty",
        exportName: "ReadStream.setRawMode",
      }),
      "effects",
      ["stdio:raw"],
    ],
    [
      "global storage read",
      surface("native-op", "global:localStorage.getItem", {
        surfaceType: "global-api",
        sourceKey: "global_web_storage",
        globalName: "localStorage",
        memberName: "getItem",
        exportName: "localStorage.getItem",
      }),
      "closed",
      ["storage:read"],
    ],
    [
      "global storage write",
      surface("native-op", "global:sessionStorage.setItem", {
        surfaceType: "global-api",
        sourceKey: "global_web_storage",
        globalName: "sessionStorage",
        memberName: "setItem",
        exportName: "sessionStorage.setItem",
      }),
      "closed",
      ["storage:write"],
    ],
    [
      "global eval",
      hermesEvaluatorGlobal("eval"),
      "closed",
      ["vm:evaluate"],
      3,
    ],
    [
      "embedder eval ABI",
      surface("host-abi", "ex_hermes_eval"),
      "closed",
      ["vm:evaluate"],
    ],
    [
      "worklet create ABI",
      surface("host-abi", "ex_worklet_create"),
      "closed",
      ["worker:create"],
    ],
    [
      "builtin alias with import-time system read",
      surface("builtin", "node:fs", {
        sourceKey: "node_fs",
        bundleExternal: true,
        moduleBuiltin: true,
      }),
      "effects",
      ["sys:read"],
    ],
    [
      "closed builtin root",
      surface("builtin", "node:vm", {
        sourceKey: "node_vm",
        bundleExternal: true,
        moduleBuiltin: true,
      }),
      "closed",
      ["vm:evaluate"],
    ],
    [
      "loader disk branch",
      surface("loader", "native-resolve"),
      "effects",
      ["fs:list", "fs:read"],
    ],
    [
      "loader policy branch",
      surface("loader", "import-policy-bare"),
      "non-capability",
      [],
    ],
    ["startup", surface("startup", "runtime-create"), "non-capability", []],
    ["CLI", surface("cli", "run"), "non-capability", []],
  ];

  for (const [
    label,
    observed,
    expectedClass,
    expectedActions,
    expectedImplementationRows = 1,
  ] of cases) {
    test(`classifies ${label}`, () => {
      const classified = classifyObservedSurface(observed, context);
      expect(classified.edge.classification).toBe(expectedClass);
      expect(edgeActions(classified)).toEqual(expectedActions);
      expect(classified.implementationRows).toHaveLength(
        expectedImplementationRows,
      );
      expect(
        classified.implementationRows.every(
          (row) => row.observedKey === observed.observedKey,
        ),
      ).toBe(true);
    });
  }

  test("filesystem mutation guard is authority control rather than an effect", () => {
    const classified = classifyObservedSurface(
      surface("native-op", "__exactFsMutationGuard"),
      context,
    );
    expect(classified.edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "authority-control-plane",
    });
    expect(classified.implementationRows[0].implementationOwner).toBe("WP5");
  });

  test("cancellation consistency script is terminal-session control", () => {
    const classified = classifyObservedSurface(
      surface("startup", "script:ibex-cancellation-consistency"),
      context,
    );
    expect(classified.edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "terminal-session-control",
    });
    expect(classified.implementationRows[0].implementationOwner).toBe("WP7");
  });

  test("structured settlement resume is control, not fresh code ingress", () => {
    const classified = classifyObservedSurface(
      surface("host-abi", "ex_hermes_resume_structured_session"),
      context,
    );
    expect(classified.edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "terminal-session-control",
    });
    expect(classified.implementationRows[0].implementationOwner).toBe("WP7");
  });

  test("worker-private safe throw metadata is pure in-memory inspection", () => {
    const classified = classifyObservedSurface(
      surface("host-abi", "ex_hermes_value_safe_throw_metadata"),
      context,
    );
    expect(classified.edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "pure-in-memory-compute",
    });
    expect(classified.implementationRows[0].implementationOwner).toBe("WP7");
  });

  test("native Promise rejection hooks only register checkpoint callbacks", () => {
    for (const name of [
      "__exactOnRejectionHandled",
      "__exactOnUnhandledRejection",
    ]) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(classified.edge, name).toMatchObject({
        classification: "non-capability",
        rationaleId: "callback-attribution-carrier",
      });
      expect(classified.implementationRows[0].implementationOwner, name).toBe(
        "WP8",
      );
    }
  });

  test("runtime VFS ABIs are private session-scoped virtual namespace control", () => {
    for (const name of [
      "ex_host_vfs_bind_runtime",
      "ex_host_vfs_chdir",
      "ex_host_vfs_get_cwd",
      "ex_host_vfs_resolve_path",
      "ex_host_vfs_unbind_runtime",
    ]) {
      const classified = classifyObservedSurface(
        surface("host-abi", name),
        context,
      );
      expect(classified.edge, name).toMatchObject({
        classification: "non-capability",
        rationaleId: "terminal-session-control",
      });
      expect(classified.implementationRows[0].implementationOwner, name).toBe(
        "WP7",
      );
    }
  });

  test("typed listener authorization is authority control-plane like sibling typed authorization ABIs", () => {
    for (const name of [
      "ex_host_authorize_typed_listen_stack",
      "ex_host_authorize_typed_network_stack",
      "ex_host_authorize_typed_udp_datagram_stack",
    ]) {
      const classified = classifyObservedSurface(
        surface("host-abi", name),
        context,
      );
      expect(classified.edge, name).toMatchObject({
        classification: "non-capability",
        rationaleId: "authority-control-plane",
      });
      expect(classified.implementationRows[0].implementationOwner, name).toBe(
        "WP8",
      );
    }
  });

  test("authenticated session-root resolve separates metadata from source reads", () => {
    const full = classifyObservedSurface(
      surface("host-abi", "ex_host_session_static_import_resolve"),
      context,
    );
    expect(full.edge.classification).toBe("effects");
    expect(edgeActions(full)).toEqual(["fs:list", "fs:read"]);

    const metadata = classifyObservedSurface(
      surface("host-abi", "ex_host_session_static_import_resolve_meta"),
      context,
    );
    expect(metadata.edge.classification).toBe("effects");
    expect(edgeActions(metadata)).toEqual(["fs:list"]);
  });

  test("module runner separates edge authorization from trusted access", () => {
    const gate = classifyObservedSurface(
      surface("loader", "module-runner-edge-authorization"),
      context,
    );
    expect(gate.edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "authority-control-plane",
    });
    for (const name of [
      "module-runner-cache-access",
      "module-runner-prepared-carrier-access",
      "module-runner-trusted-source-acquisition",
    ]) {
      expect(
        classifyObservedSurface(surface("loader", name), context).edge,
      ).toMatchObject({
        classification: "non-capability",
        rationaleId: "trusted-loader-source-acquisition",
      });
    }
  });

  test("escape matching does not treat identifier substrings as escape surfaces", () => {
    const diffieHellmanNames = reviewedBuiltinExportNames()
      .filter((name) =>
        /^export:exact_crypto:(?:.*DiffieHellman|diffieHellman)/u.test(name),
      )
      .map((name) => name.slice("export:exact_crypto:".length));
    expect(diffieHellmanNames.length).toBeGreaterThan(10);

    for (const exportName of diffieHellmanNames) {
      const classified = classifyObservedSurface(
        builtinExport("exact_crypto", exportName),
        context,
      );
      expect(classified.edge.classification, exportName).toBe("non-capability");
      expect(edgeActions(classified), exportName).toEqual([]);
    }

    for (const [sourceKey, exportName] of [
      ["internal_fs_utils", "toPathIfFileURL"],
      ["node_zlib", "ZSTD_c_nbWorkers"],
    ]) {
      const classified = classifyObservedSurface(
        builtinExport(sourceKey, exportName),
        context,
      );
      expect(classified.edge.classification, `${sourceKey}:${exportName}`).toBe(
        "non-capability",
      );
      expect(edgeActions(classified), `${sourceKey}:${exportName}`).toEqual([]);
    }

    const sqliteValues = classifyObservedSurface(
      surface("host-abi", "ex_host_sqlite_values"),
      context,
    );
    expect(sqliteValues.edge.classification).toBe("effects");
    expect(edgeActions(sqliteValues)).toEqual(["fs:read"]);
    expect(sqliteValues.edge.effectMode).toBe("conditional");
    expect(
      sqliteValues.edge.logicalBranches.map((branch) => branch.id),
    ).toEqual(["file", "memory"]);
  });

  test("exact escape families remain closed after boundary hardening", () => {
    for (const [observed, expectedAction] of [
      [builtinExport("node_worker_threads", "Worker"), "worker:create"],
      [builtinExport("node_vm", "Script"), "vm:evaluate"],
      [builtinExport("node_wasi", "WASI"), "wasi:instantiate"],
      [builtinExport("exact_crypto", "setEngine"), "ffi:load"],
      [builtinExport("exact_process", "binding"), "ffi:load"],
      [builtinExport("exact_sqlite", "Database.loadExtension"), "ffi:load"],
      [surface("host-abi", "ex_hermes_eval"), "vm:evaluate"],
      [surface("host-abi", "ex_hermes_debugger_eval"), "runtime:inspect"],
      [surface("host-abi", "ex_hermes_debugger_next_event"), "runtime:inspect"],
    ]) {
      const classified = classifyObservedSurface(observed, context);
      expect(classified.edge.classification, observed.name).toBe("closed");
      expect(edgeActions(classified), observed.name).toEqual([expectedAction]);
    }
  });

  test("console ABI assigns writes to the caller and treats flush as queue drain", () => {
    const log = classifyObservedSurface(
      surface("host-abi", "ex_host_console_log"),
      context,
    );
    expect(log.edge.classification).toBe("effects");
    expect(edgeActions(log)).toEqual(["stdio:write"]);
    expect(log.edge.principalSources).toEqual(["frame-set", "schedule-time"]);
    expect(log.edge.effectOwnerSource).toBe("innermost-nontransparent-frame");
    expect(log.edge.principalSources).not.toContain("descriptor-owner");

    const flush = classifyObservedSurface(
      surface("host-abi", "ex_host_console_flush"),
      context,
    );
    expect(flush.edge.classification).toBe("non-capability");
    expect(flush.edge.rationaleId).toBe("callback-attribution-carrier");
    expect(edgeActions(flush)).toEqual([]);
  });

  test("watchdog generation ABI classifies nonce capture and callback attribution", () => {
    const nonce = classifyObservedSurface(
      surface("host-abi", "ex_hermes_runtime_nonce"),
      context,
    );
    expect(nonce.edge.classification).toBe("non-capability");
    expect(nonce.edge.rationaleId).toBe("authority-control-plane");

    const schedule = classifyObservedSurface(
      surface(
        "host-abi",
        "ex_hermes_schedule_watchdog_heartbeat_for_generation",
      ),
      context,
    );
    expect(schedule.edge.classification).toBe("non-capability");
    expect(schedule.edge.rationaleId).toBe("callback-attribution-carrier");
  });

  test("newly discovered builtin instance members have reviewed retained-resource semantics", () => {
    for (const [exportName, expectedActions] of [
      ["ReadStream._read", ["fs:list", "fs:read"]],
      ["ReadStream.open", ["fs:list", "fs:read"]],
      ["WriteStream._final", ["fs:list", "fs:write"]],
      ["WriteStream._write", ["fs:list", "fs:write"]],
      ["WriteStream._writev", ["fs:list", "fs:write"]],
      ["WriteStream.open", ["fs:list", "fs:write"]],
    ]) {
      const classified = classifyObservedSurface(
        builtinExport("node_fs", exportName),
        context,
      );
      expect(classified.edge.classification, exportName).toBe("effects");
      expect(edgeActions(classified), exportName).toEqual(expectedActions);
      expect(classified.edge.effectMode, exportName).toBe("conditional");
      expect(
        classified.edge.logicalBranches.map((branch) => branch.id),
        exportName,
      ).toEqual(["descriptor", "path"]);
      expect(classified.edge.lifetimeContract, exportName).toBe("file-handle");
    }
    for (const exportName of [
      "ReadStream.close",
      "ReadStream.destroy",
      "WriteStream._emitClose",
      "WriteStream.close",
      "WriteStream.destroy",
    ]) {
      const classified = classifyObservedSurface(
        builtinExport("node_fs", exportName),
        context,
      );
      expect(classified.edge.classification, exportName).toBe("non-capability");
      expect(classified.edge.rationaleId, exportName).toBe("authority-release");
    }

    const socketMetadata = [
      "_connecting",
      "bufferSize",
      "bytesWritten",
      "readableHighWaterMark",
      "writableCorked",
      "writableEnded",
      "writableHighWaterMark",
      "writableLength",
      "writableNeedDrain",
    ];
    for (const owner of ["Socket", "Stream"]) {
      const abortListener = classifyObservedSurface(
        builtinExport("node_net", `${owner}._abortListener`),
        context,
      );
      expect(abortListener.edge.classification, owner).toBe("non-capability");
      expect(abortListener.edge.rationaleId, owner).toBe("authority-release");
      for (const member of socketMetadata) {
        const exportName = `${owner}.${member}`;
        const classified = classifyObservedSurface(
          builtinExport("node_net", exportName),
          context,
        );
        expect(classified.edge.classification, exportName).toBe("effects");
        expect(edgeActions(classified), exportName).toEqual([
          "network:connect",
          "network:listen",
        ]);
        expect(classified.edge.effectMode, exportName).toBe("conditional");
        expect(classified.edge.effectOwnerSource, exportName).toBe(
          "descriptor-owner",
        );
        expect(classified.edge.principalSources, exportName).toContain(
          "descriptor-owner",
        );
      }
    }

    const httpAbort = classifyObservedSurface(
      builtinExport("node_http", "ClientRequest._abortSignalListener"),
      context,
    );
    expect(httpAbort.edge.classification).toBe("non-capability");
    expect(httpAbort.edge.rationaleId).toBe("authority-release");

    for (const [member, expectedClassification] of [
      ["_onAbortSignal", "non-capability"],
      ["_onClose", "non-capability"],
      ["_onData", "effects"],
      ["_onEnd", "effects"],
      ["_onError", "non-capability"],
      ["_onKeypress", "effects"],
    ]) {
      const classified = classifyObservedSurface(
        builtinExport("node_readline", `Interface.${member}`),
        context,
      );
      expect(classified.edge.classification, member).toBe(
        expectedClassification,
      );
      if (expectedClassification === "effects") {
        expect(edgeActions(classified), member).toEqual([
          "stdio:read",
          "stdio:write",
        ]);
      } else {
        expect(classified.edge.rationaleId, member).toBe("authority-release");
      }
    }

    for (const exportName of [
      "Readable.readableState",
      "Stream.closed",
      "Writable.writableState",
      "default.closed",
    ]) {
      const classified = classifyObservedSurface(
        builtinExport("node_stream", exportName),
        context,
      );
      expect(classified.edge.classification, exportName).toBe("non-capability");
      expect(classified.edge.rationaleId, exportName).toBe(
        "retained-object-wrapper",
      );
    }

    for (const member of [
      "connecting",
      "destroyed",
      "localAddress",
      "localFamily",
      "localPort",
      "readable",
      "remoteAddress",
      "remoteFamily",
      "remotePort",
      "writable",
    ]) {
      const exportName = `TLSSocket.${member}`;
      const classified = classifyObservedSurface(
        builtinExport("node_tls", exportName),
        context,
      );
      expect(classified.edge.classification, exportName).toBe("effects");
      expect(edgeActions(classified), exportName).toEqual([
        "network:connect",
        "network:listen",
      ]);
      expect(classified.edge.effectMode, exportName).toBe("conditional");
      expect(classified.edge.effectOwnerSource, exportName).toBe(
        "descriptor-owner",
      );
    }
  });

  test("returned handle and media/stream members retain exact object semantics", () => {
    for (const memberName of [
      "fs.readHandle.[[return]].readFileSync",
      "fs.readHandle.[[return]].readTextSync",
    ]) {
      const classified = classifyObservedSurface(
        globalApi("Ibex", memberName),
        context,
      );
      expect(classified.edge.classification, memberName).toBe("effects");
      expect(edgeActions(classified), memberName).toEqual(["fs:read"]);
      expect(classified.edge.effectMode, memberName).toBe("conjunctive");
      expect(classified.edge.lifetimeContract, memberName).toBe("file-handle");
      expect(classified.edge.effectOwnerSource, memberName).toBe(
        "descriptor-owner",
      );
      expect(classified.edge.principalSources, memberName).toEqual([
        "descriptor-owner",
        "frame-set",
        "schedule-time",
      ]);
    }

    for (const [memberName, rationaleId] of [
      ["fs.readHandle.[[return]].scoped", "authority-control-plane"],
      ["fs.readHandle.[[return]].revoke", "authority-release"],
    ]) {
      const classified = classifyObservedSurface(
        globalApi("Ibex", memberName),
        context,
      );
      expect(classified.edge.classification, memberName).toBe("non-capability");
      expect(classified.edge.rationaleId, memberName).toBe(rationaleId);
    }

    const iteratorMarker = classifyObservedSurface(
      globalApi(
        "ReadableStream",
        "[[return]].__exactReadableStreamIteratorPatched",
      ),
      context,
    );
    expect(iteratorMarker.edge.classification).toBe("non-capability");
    expect(iteratorMarker.edge.rationaleId).toBe("runtime-bootstrap-state");

    for (const memberName of [
      "[[return]].getReader",
      "[[return]].tee",
      "[[return]].values",
    ]) {
      const classified = classifyObservedSurface(
        globalApi("ReadableStream", memberName),
        context,
      );
      expect(classified.edge.classification, memberName).toBe("non-capability");
      expect(classified.edge.rationaleId, memberName).toBe(
        "retained-object-wrapper",
      );
    }

    const videoClose = classifyObservedSurface(
      globalApi("VideoFrame", "[[return]].close"),
      context,
    );
    expect(videoClose.edge.classification).toBe("non-capability");
    expect(videoClose.edge.rationaleId).toBe("authority-release");
  });

  test("Android public ABI rows retain exact platform-boundary semantics", () => {
    const javaPrefix = "java:dev.ibex.runtime.IbexNetworking.";
    const classifiedNames = new Set();
    const classify = (name) => {
      classifiedNames.add(name);
      return classifyObservedSurface(surface("host-abi", name), context);
    };
    const classifyJava = (operation) => classify(`${javaPrefix}${operation}`);

    for (const name of [
      "ex_android_initialize",
      `${javaPrefix}getApplicationContext`,
      `${javaPrefix}initialize`,
    ]) {
      const classified = classify(name);
      expect(classified.edge.classification, name).toBe("non-capability");
      expect(classified.edge.rationaleId, name).toBe("runtime-bootstrap-state");
    }

    for (const operation of [
      "CameraHostProvider.cameraHostCall",
      "cameraHostCall",
    ]) {
      const classified = classifyJava(operation);
      expect(classified.edge.classification, operation).toBe("effects");
      expect(edgeActions(classified), operation).toEqual([
        "device:camera",
        "device:microphone",
      ]);
      expect(classified.edge.effectMode, operation).toBe("conditional");
      expect(
        classified.edge.logicalBranches.map((branch) => branch.id),
        operation,
      ).toEqual(["camera", "microphone"]);
    }

    for (const operation of [
      "DialogHostProvider.dialog",
      "accessibilityFlags",
      "appState",
      "dialog",
      "drainPlatformEvents",
      "initialURL",
      "notifyActivityPaused",
      "notifyActivityResumed",
      "notifyActivityStarted",
      "notifyActivityStopped",
      "notifyDeepLink",
      "notifyNewIntent",
      "postAnimationFrame",
    ]) {
      const classified = classifyJava(operation);
      expect(classified.edge.classification, operation).toBe("closed");
      expect(edgeActions(classified), operation).toEqual(["ipc:channel"]);
    }

    const fetch = classifyJava("fetch");
    expect(fetch.edge.classification).toBe("effects");
    expect(edgeActions(fetch)).toEqual(["network:fetch"]);
    expect(fetch.edge.lifetimeContract).toBe("socket-stream");

    const cancelFetch = classifyJava("cancelFetch");
    expect(cancelFetch.edge.classification).toBe("non-capability");
    expect(cancelFetch.edge.rationaleId).toBe("authority-release");

    for (const operation of ["connectWebSocket", "sendWebSocket"]) {
      const classified = classifyJava(operation);
      expect(classified.edge.classification, operation).toBe("effects");
      expect(edgeActions(classified), operation).toEqual(["network:connect"]);
      expect(classified.edge.lifetimeContract, operation).toBe("socket-stream");
    }
    const sendWebSocket = classifyObservedSurface(
      surface("host-abi", `${javaPrefix}sendWebSocket`),
      context,
    );
    expect(sendWebSocket.edge.effectOwnerSource).toBe("descriptor-owner");

    const closeWebSocket = classifyJava("closeWebSocket");
    expect(closeWebSocket.edge.classification).toBe("effects");
    expect(edgeActions(closeWebSocket)).toEqual(["network:connect"]);
    expect(closeWebSocket.edge.effectMode).toBe("conditional");
    expect(closeWebSocket.edge.effectOwnerSource).toBe("descriptor-owner");

    for (const operation of [
      "pauseWebSocket",
      "resumeWebSocket",
      "setWebSocketFlowControlled",
    ]) {
      const classified = classifyJava(operation);
      expect(classified.edge.classification, operation).toBe("non-capability");
      expect(classified.edge.rationaleId, operation).toBe(
        "authority-control-plane",
      );
    }

    const dns = classifyJava("dnsQuery");
    expect(dns.edge.classification).toBe("effects");
    expect(edgeActions(dns)).toEqual(["network:resolve"]);

    for (const [operation, action] of [
      ["clipboardReadText", "clipboard:read"],
      ["clipboardWriteText", "clipboard:write"],
    ]) {
      const classified = classifyJava(operation);
      expect(classified.edge.classification, operation).toBe("effects");
      expect(edgeActions(classified), operation).toEqual([action]);
    }

    for (const operation of [
      "getCurrentLocation",
      "isLocationServicesEnabled",
      "locationPermissionStatus",
    ]) {
      const classified = classifyJava(operation);
      expect(classified.edge.classification, operation).toBe("effects");
      expect(edgeActions(classified), operation).toEqual(["device:location"]);
    }

    for (const operation of [
      "localeTags",
      "platformVersion",
      "screenInfo",
      "storagePaths",
      "uses24HourClock",
    ]) {
      const classified = classifyJava(operation);
      expect(classified.edge.classification, operation).toBe("effects");
      expect(edgeActions(classified), operation).toEqual(["sys:read"]);
    }

    for (const operation of [
      "setCameraHostProvider",
      "setClient",
      "setDialogHostProvider",
    ]) {
      const classified = classifyJava(operation);
      expect(classified.edge.classification, operation).toBe("non-capability");
      expect(classified.edge.rationaleId, operation).toBe(
        "authority-control-plane",
      );
    }

    for (const operation of [
      "nativeAnimationFrame",
      "nativeFetchDidComplete",
      "nativePlatformEventAvailable",
      "nativeWebSocketDidBytesSent",
      "nativeWebSocketDidClose",
      "nativeWebSocketDidError",
      "nativeWebSocketDidMessage",
      "nativeWebSocketDidOpen",
    ]) {
      const name = `jni:dev.ibex.runtime.IbexNetworking.${operation}`;
      const classified = classify(name);
      expect(classified.edge.classification, operation).toBe("non-capability");
      expect(classified.edge.rationaleId, operation).toBe(
        "callback-attribution-carrier",
      );
    }

    expect(classifiedNames.size).toBe(48);
  });

  test("environment enumeration selects empty or per-key authorized branches", () => {
    const classified = classifyObservedSurface(
      surface("native-op", "__exactGetAllEnv"),
      context,
    );
    expect(classified.edge.classification).toBe("effects");
    expect(edgeActions(classified)).toEqual(["env:read"]);
    expect(classified.edge.effectMode).toBe("conditional");
    expect(classified.edge.logicalBranches.map((branch) => branch.id)).toEqual([
      "empty",
      "nonempty",
    ]);
  });

  test("normalizers and positive sources come only from capability definitions", () => {
    const classified = classifyObservedSurface(
      surface("native-op", "__exactReadFile"),
      context,
    );
    expect(edgeActions(classified)).toEqual(["fs:list", "fs:read"]);
    const effect = classified.edge.effects.find((row) => row.cap === "fs:read");
    const definition = definitions.definitions.find(
      (row) => row.id === "fs:read",
    );
    const normalization = rules.normalizationProfiles.find(
      (row) => row.id === definition.normalizationProfile,
    );
    expect(effect.selectorNormalizer).toBe(normalization.selector);
    expect(effect.occurrenceNormalizer).toBe(normalization.occurrence);
    expect(effect.positiveSources).toEqual(derivePositiveSources(definition));
    expect(effect.positiveSources).toEqual([
      "ambient-root",
      "handle",
      "implicit-self",
      "session",
      "static-floor",
    ]);
    const cwdMutation = definitions.definitions.find(
      (row) => row.id === "path:cwd-mutate",
    );
    expect(derivePositiveSources(cwdMutation)).toEqual(["ambient-root"]);
  });

  test("virtual cwd surfaces use explicit session-state actions", () => {
    for (const observed of [
      builtinExport("exact_process", "cwd"),
      surface("native-op", "__exactGetCwd"),
      globalApi("process", "cwd"),
    ]) {
      const classified = classifyObservedSurface(observed, context);
      expect(edgeActions(classified), observed.name).toEqual([
        "path:cwd-observe",
      ]);
      expect(classified.edge.effects[0].positiveSources, observed.name).toEqual(
        ["ambient-root", "static-floor"],
      );
    }

    for (const observed of [
      builtinExport("exact_process", "chdir"),
      surface("native-op", "__exactSetCwd"),
      globalApi("process", "chdir"),
    ]) {
      const classified = classifyObservedSurface(observed, context);
      expect(edgeActions(classified), observed.name).toEqual([
        "fs:list",
        "path:cwd-mutate",
      ]);
      expect(
        classified.edge.effects.find((row) => row.cap === "path:cwd-mutate")
          .positiveSources,
        observed.name,
      ).toEqual(["ambient-root"]);
      expect(classified.edge.effectMode, observed.name).toBe("conjunctive");
    }

    for (const observed of [
      builtinExport("node_path", "resolve"),
      builtinExport("node_path", "relative"),
      builtinExport("node_path", "toNamespacedPath"),
      builtinExport("node_url", "pathToFileURL"),
      globalApi("Exact", "resolve"),
      globalApi("Exact", "resolveSync"),
      globalApi("Exact", "pathToFileURL"),
      globalApi("Bun", "resolve"),
      globalApi("Bun", "resolveSync"),
      globalApi("Bun", "pathToFileURL"),
    ]) {
      const classified = classifyObservedSurface(observed, context);
      expect(edgeActions(classified), observed.name).toEqual([
        "path:cwd-observe",
      ]);
      expect(classified.edge.effectMode, observed.name).toBe("conditional");
      expect(
        classified.edge.logicalBranches.map((branch) => [
          branch.id,
          branch.effects.map((effect) => effect.cap),
        ]),
        observed.name,
      ).toEqual([
        ["explicit-base", []],
        ["session-base", ["path:cwd-observe"]],
      ]);
    }
  });

  test("process launch selects exact executable, environment, and stdio branches", () => {
    const classified = classifyObservedSurface(
      surface("native-op", "__exactSpawn"),
      context,
    );
    expect(classified.edge.effectMode).toBe("conditional");
    expect(classified.edge.logicalBranches.map((branch) => branch.id)).toEqual([
      "direct-isolated",
      "explicit-environment",
      "inherited-descriptors",
      "searched-isolated",
    ]);
  });

  test("SQLite storage and statement state select exact retained-resource branches", () => {
    const cases = [
      ["__exactSqliteOpen", ["file-read", "file-read-write", "memory"]],
      ["__exactSqliteAll", ["file", "memory"]],
      ["__exactSqliteRun", ["file-read", "file-read-write", "memory"]],
    ];
    for (const [name, branchIds] of cases) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(classified.edge.effectMode, name).toBe("conditional");
      expect(
        classified.edge.logicalBranches.map((branch) => branch.id),
        name,
      ).toEqual(branchIds);
      const memory = classified.edge.logicalBranches.find(
        (branch) => branch.id === "memory",
      );
      expect(memory.effects, name).toEqual([]);
    }

    const checkedDescriptorOpen = classifyObservedSurface(
      surface("host-abi", "ex_host_sqlite_open_checked_fd"),
      context,
    );
    expect(checkedDescriptorOpen.edge.effectMode).toBe("conditional");
    expect(
      checkedDescriptorOpen.edge.logicalBranches.map((branch) => branch.id),
    ).toEqual(["file-read", "file-read-write"]);
    expect(edgeActions(checkedDescriptorOpen)).toEqual([
      "fs:list",
      "fs:read",
      "fs:write",
    ]);
    expect(checkedDescriptorOpen.edge.effectOwnerSource).toBe(
      "descriptor-owner",
    );
    expect(checkedDescriptorOpen.edge.principalSources).toEqual([
      "descriptor-owner",
      "frame-set",
      "schedule-time",
    ]);
    expect(checkedDescriptorOpen.edge.lifetimeContract).toBe("file-handle");

    expect(
      classifyObservedSurface(
        surface("host-abi", "ex_host_sqlite_open_isolated_memory"),
        context,
      ).edge,
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "pure-in-memory-compute",
    });
  });

  test("filesystem open selects an exact normalized access branch", () => {
    const classified = classifyObservedSurface(
      surface("native-op", "__exactFsOpen"),
      context,
    );
    expect(classified.edge.effectMode).toBe("conditional");
    expect(classified.edge.logicalBranches).toEqual([
      expect.objectContaining({
        id: "read",
        when: [{ fact: "filesystem.open.access", equals: "read" }],
        effects: expect.arrayContaining([
          expect.objectContaining({ cap: "fs:read" }),
        ]),
      }),
      expect.objectContaining({
        id: "read-write",
        when: [{ fact: "filesystem.open.access", equals: "read-write" }],
        effects: expect.arrayContaining([
          expect.objectContaining({ cap: "fs:read" }),
          expect.objectContaining({ cap: "fs:write" }),
        ]),
      }),
      expect.objectContaining({
        id: "write",
        when: [{ fact: "filesystem.open.access", equals: "write" }],
        effects: expect.arrayContaining([
          expect.objectContaining({ cap: "fs:write" }),
        ]),
      }),
    ]);
    const enforcementBranchId =
      classified.implementationRows[0].enforcementBranchId;
    expect(classified.implementationRows[0].fixtureObligations).toContain(
      `${enforcementBranchId}.logical.read.branch-selection`,
    );
    expect(classified.implementationRows[0].fixtureObligations).not.toContain(
      `${enforcementBranchId}.conditional-refinement`,
    );
  });

  test("filesystem dispatchers and path-or-descriptor inputs expose exact branches", () => {
    const pathDispatcher = classifyObservedSurface(
      surface("native-op", "__exactFsPathAsync"),
      context,
    );
    expect(pathDispatcher.edge.effectMode).toBe("conditional");
    expect(pathDispatcher.edge.logicalBranches).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "copyfile",
          disposition: "closed",
          cap: "fs:unbound-mutation",
        }),
        expect.objectContaining({ id: "readlink" }),
        expect.objectContaining({ id: "access-write" }),
        expect.objectContaining({
          id: "mkdir-recursive",
          disposition: "closed",
        }),
        expect.objectContaining({
          id: "chmod",
          when: expect.arrayContaining([
            { fact: "runtime.target.os", equals: "apple" },
          ]),
        }),
        expect.objectContaining({
          id: "chmod-windows",
          disposition: "closed",
          when: expect.arrayContaining([
            { fact: "runtime.target.os", equals: "windows" },
          ]),
        }),
      ]),
    );

    const fdDispatcher = classifyObservedSurface(
      surface("native-op", "__exactFsFdAsync"),
      context,
    );
    expect(fdDispatcher.edge.logicalBranches).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "durability-write",
          effectOwnerSource: "descriptor-owner",
        }),
        expect.objectContaining({ id: "truncate" }),
        expect.objectContaining({
          id: "fchmod",
          disposition: "closed",
          cap: "fs:unbound-mutation",
        }),
      ]),
    );
    expect(fdDispatcher.edge.logicalBranches).toHaveLength(5);

    const mkdir = classifyObservedSurface(
      surface("native-op", "__exactMkdir"),
      context,
    );
    expect(mkdir.edge.effectMode).toBe("conditional");
    expect(mkdir.edge.logicalBranches).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "non-recursive",
          effects: expect.arrayContaining([
            expect.objectContaining({ cap: "fs:list" }),
            expect.objectContaining({ cap: "fs:write" }),
          ]),
        }),
        expect.objectContaining({
          id: "recursive",
          disposition: "closed",
          cap: "fs:unbound-mutation",
        }),
      ]),
    );

    for (const name of [
      "__exactFsReadFileAsync",
      "__exactFsStatAsync",
      "__exactFsWriteFileAsync",
    ]) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(classified.edge.effectMode, name).toBe("conditional");
      expect(
        classified.edge.logicalBranches.map((branch) => branch.id),
        name,
      ).toEqual(["descriptor", "path"]);
      expect(classified.edge.logicalBranches[0].effectOwnerSource, name).toBe(
        "descriptor-owner",
      );
      expect(classified.edge.logicalBranches[1].effectOwnerSource, name).toBe(
        "innermost-nontransparent-frame",
      );
    }
  });

  test("classifies authority-bearing builtin prototypes without a pure fallback", () => {
    const cases = [
      [
        "node_child_process",
        "ChildProcess.spawn",
        "effects",
        [
          "env:read",
          "env:write",
          "fs:list",
          "process:spawn",
          "stdio:read",
          "stdio:write",
        ],
        "conditional",
      ],
      ["node_child_process", "ChildProcess.kill", "closed", ["process:signal"]],
      ["node_child_process", "ChildProcess.send", "closed", ["ipc:channel"]],
      [
        "node_dns",
        "Resolver.resolveTxt",
        "effects",
        ["network:connect", "network:listen", "network:resolve"],
        "conditional",
      ],
      ["node_dns", "Resolver.cancel", "non-capability", []],
      [
        "node_dgram",
        "Socket.bind",
        "effects",
        ["network:listen"],
        "conjunctive",
      ],
      [
        "node_dgram",
        "Socket.send",
        "effects",
        ["network:connect", "network:listen"],
        "conditional",
      ],
      ["node_dgram", "Socket._fromFd", "closed", ["ipc:channel"]],
      ["node_dgram", "Socket.close", "non-capability", []],
      [
        "node_dgram",
        "Socket.addMembership",
        "effects",
        ["network:listen"],
        "conjunctive",
      ],
      [
        "node_dgram",
        "Socket.addSourceSpecificMembership",
        "non-capability",
        [],
      ],
      ["node_dgram", "Socket.dropMembership", "non-capability", []],
      [
        "node_dgram",
        "Socket.dropSourceSpecificMembership",
        "non-capability",
        [],
      ],
      ["node_net", "Socket", "closed", ["ipc:channel"]],
      ["node_net", "Stream", "closed", ["ipc:channel"]],
      [
        "node_net",
        "Socket.connect",
        "effects",
        ["fs:read", "network:connect"],
        "conditional",
      ],
      [
        "node_net",
        "Server.listen",
        "effects",
        ["fs:write", "network:listen"],
        "conditional",
      ],
      [
        "node_fs_promises",
        "FileHandle.read",
        "effects",
        ["fs:read"],
        "conjunctive",
      ],
      ["node_fs_promises", "FileHandle.fd", "closed", ["ipc:channel"]],
      [
        "node_fs",
        "ReadStream",
        "effects",
        ["fs:list", "fs:read"],
        "conditional",
      ],
      [
        "node_fs",
        "ReadStream.constructor",
        "effects",
        ["fs:list", "fs:read"],
        "conditional",
      ],
      [
        "node_fs",
        "WriteStream",
        "effects",
        ["fs:list", "fs:write"],
        "conditional",
      ],
      [
        "node_fs",
        "WriteStream.constructor",
        "effects",
        ["fs:list", "fs:write"],
        "conditional",
      ],
      ["node_fs", "Dir", "effects", ["fs:list"], "conjunctive"],
      ["node_fs", "Dir.read", "effects", ["fs:list"], "conjunctive"],
      [
        "node_http",
        "ClientRequest.write",
        "effects",
        ["network:connect"],
        "conditional",
      ],
      [
        "node_http",
        "IncomingMessage.read",
        "effects",
        ["network:connect", "network:listen"],
        "conditional",
      ],
      [
        "node_http",
        "Server.listen",
        "effects",
        ["network:listen"],
        "conjunctive",
      ],
      [
        "node_tls",
        "TLSSocket.connect",
        "effects",
        ["network:connect"],
        "conjunctive",
      ],
      [
        "node_tls",
        "TLSSocket.write",
        "effects",
        ["network:connect", "network:listen"],
        "conditional",
      ],
      [
        "ws",
        "WebSocket.send",
        "effects",
        ["network:connect", "network:listen"],
        "conditional",
      ],
      ["ws", "WebSocket.terminate", "non-capability", []],
      [
        "exact_sqlite",
        "Database",
        "effects",
        ["fs:list", "fs:read", "fs:write"],
        "conditional",
      ],
      [
        "exact_sqlite",
        "default",
        "effects",
        ["fs:list", "fs:read", "fs:write"],
        "conditional",
      ],
      [
        "exact_sqlite",
        "Database.close",
        "effects",
        ["fs:write"],
        "conditional",
      ],
      ["exact_sqlite", "default.close", "effects", ["fs:write"], "conditional"],
      ["exact_sqlite", "Database.enableCrSqlite", "closed", ["ffi:load"]],
      ["exact_sqlite", "Database.loadExtension", "closed", ["ffi:load"]],
      ["exact_sqlite", "Database.handle", "closed", ["ffi:load"]],
      ["exact_sqlite", "Statement.all", "effects", ["fs:read"], "conditional"],
      [
        "exact_sqlite",
        "Statement.run",
        "effects",
        ["fs:read", "fs:write"],
        "conditional",
      ],
      ["exact_sqlite", "deserialize", "non-capability", []],
      [
        "node_readline",
        "Interface",
        "effects",
        ["stdio:raw", "stdio:read", "stdio:write"],
        "conditional",
      ],
      [
        "node_readline",
        "createInterface",
        "effects",
        ["stdio:raw", "stdio:read", "stdio:write"],
        "conditional",
      ],
      [
        "node_readline",
        "Interface.resume",
        "effects",
        ["stdio:read"],
        "conditional",
      ],
    ];

    for (const [
      sourceKey,
      exportName,
      expectedClass,
      expectedActions,
      expectedMode,
    ] of cases) {
      const classified = classifyObservedSurface(
        builtinExport(sourceKey, exportName),
        context,
      );
      expect(classified.edge.classification, `${sourceKey}:${exportName}`).toBe(
        expectedClass,
      );
      expect(edgeActions(classified), `${sourceKey}:${exportName}`).toEqual(
        expectedActions,
      );
      if (expectedMode) {
        expect(classified.edge.effectMode, `${sourceKey}:${exportName}`).toBe(
          expectedMode,
        );
      }
    }
  });

  test("DNS builtin roots and defaults are module-reachability-only", () => {
    for (const [alias, sourceKey] of [
      ["dns", "node_dns"],
      ["node:dns", "node_dns"],
      ["dns/promises", "node_dns_promises"],
      ["node:dns/promises", "node_dns_promises"],
    ]) {
      const classified = classifyObservedSurface(
        surface("builtin", alias, {
          sourceKey,
          bundleExternal: true,
          moduleBuiltin: true,
        }),
        context,
      );
      expect(classified.edge.classification, alias).toBe("non-capability");
      expect(classified.edge.rationaleId, alias).toBe(
        "module-reachability-only",
      );
      expect(edgeActions(classified), alias).toEqual([]);
    }

    for (const sourceKey of ["node_dns", "node_dns_promises"]) {
      const classified = classifyObservedSurface(
        builtinExport(sourceKey, "default"),
        context,
      );
      expect(classified.edge.classification, sourceKey).toBe(
        "non-capability",
      );
      expect(classified.edge.rationaleId, sourceKey).toBe(
        "module-reachability-only",
      );
      expect(edgeActions(classified), sourceKey).toEqual([]);
    }

    for (const sourceKey of ["node_dns", "node_dns_promises"]) {
      for (const exportName of ["getServers", "Resolver"]) {
        const edge = classifyObservedSurface(
          sourceKey === "node_dns_promises"
            ? reviewedDnsProjectionExport(sourceKey, exportName)
            : builtinExport(sourceKey, exportName),
          context,
        ).edge;
        expect(edge.classification, `${sourceKey}:${exportName}`).toBe(
          "effects",
        );
        expect(edge.effectMode, `${sourceKey}:${exportName}`).toBe(
          "conditional",
        );
        expect(edgeActions({ edge }), `${sourceKey}:${exportName}`).toEqual([
          "fs:list",
          "fs:read",
          "network:resolve",
        ]);
        expect(
          edge.logicalBranches.map((branch) => ({
            id: branch.id,
            when: branch.when,
            actions: branch.effects.map((effect) => effect.cap),
          })),
          `${sourceKey}:${exportName}`,
        ).toEqual([
        {
          id: "cached-or-custom",
          when: [
            {
              fact: "network.dns.system-servers-state",
              equals: "cached-or-custom",
            },
          ],
          actions: [],
        },
        {
          id: "filesystem-only",
          when: [
            {
              fact: "network.dns.system-servers-state",
              equals: "filesystem-only",
            },
          ],
          actions: ["fs:list", "fs:read"],
        },
        {
          id: "native-fallback",
          when: [
            {
              fact: "network.dns.system-servers-state",
              equals: "native-fallback",
            },
          ],
          actions: ["fs:list", "fs:read", "network:resolve"],
        },
        {
          id: "native-success",
          when: [
            {
              fact: "network.dns.system-servers-state",
              equals: "native-success",
            },
          ],
          actions: ["network:resolve"],
        },
        ]);
      }
    }
  });

  test("classifies all 42 projected dns/promises operations without promoting their routes", () => {
    const resolverEffects = [
      "resolve",
      "resolve4",
      "resolve6",
      "resolveAny",
      "resolveCaa",
      "resolveCname",
      "resolveMx",
      "resolveNaptr",
      "resolveNs",
      "resolvePtr",
      "resolveSoa",
      "resolveSrv",
      "resolveTxt",
      "reverse",
    ];
    const expected = new Map([
      ...[
        "Resolver",
        "getServers",
        "lookup",
        "lookupService",
        ...resolverEffects,
        ...resolverEffects.map((name) => `Resolver.${name}`),
      ].map((name) => [name, "effects"]),
      ...["setDefaultResultOrder", "setServers"].map((name) => [
        name,
        "closed",
      ]),
      ...[
        "getDefaultResultOrder",
        "Resolver.cancel",
        "Resolver.getServers",
        "Resolver._handle.cancel",
        "Resolver._handle.getServers",
        "Resolver._handle.setServers",
        "Resolver.setLocalAddress",
        "Resolver.setServers",
      ].map((name) => [name, "non-capability"]),
    ]);
    expect(expected.size).toBe(42);
    const counts = new Map();
    for (const [exportName, classification] of expected) {
      const surface = reviewedDnsProjectionExport(
        "node_dns_promises",
        exportName,
      );
      const edge = classifyObservedSurface(
        surface,
        context,
      ).edge;
      expect(edge.classification, exportName).toBe(classification);
      const unreviewed = structuredClone(surface);
      delete unreviewed.metadata.dnsPromiseExportShapeReviewId;
      expect(
        () => classifyObservedSurface(unreviewed, context),
        `${exportName} must require the independent classifier review pin`,
      ).toThrow(/unclassified observed surface/);
      counts.set(classification, (counts.get(classification) ?? 0) + 1);
      if (resolverEffects.includes(exportName.replace(/^Resolver\./u, ""))) {
        expect(edge.effectMode, exportName).toBe("conditional");
        expect(edgeActions({ edge }), exportName).toEqual([
          "network:connect",
          "network:listen",
          "network:resolve",
        ]);
      }
    }
    expect(Object.fromEntries(counts)).toEqual({
      effects: 32,
      closed: 2,
      "non-capability": 8,
    });
  });

  test("classifies six reviewed Resolver handle projections and rejects metadata drift", () => {
    for (const sourceKey of ["node_dns", "node_dns_promises"]) {
      for (const [exportName, rationaleId] of [
        ["Resolver._handle.cancel", "authority-release"],
        ["Resolver._handle.getServers", "authority-control-plane"],
        ["Resolver._handle.setServers", "authority-control-plane"],
      ]) {
        const surface = reviewedDnsProjectionExport(sourceKey, exportName);
        const edge = classifyObservedSurface(surface, context).edge;
        expect(edge.classification, `${sourceKey}:${exportName}`).toBe(
          "non-capability",
        );
        expect(edge.rationaleId, `${sourceKey}:${exportName}`).toBe(
          rationaleId,
        );

        const unreviewed = structuredClone(surface);
        delete unreviewed.metadata.dnsPromiseExportShapeReviewId;
        expect(
          () => classifyObservedSurface(unreviewed, context),
          `${sourceKey}:${exportName} must require the independent classifier review pin`,
        ).toThrow(/unclassified observed surface/);
      }
    }

    const carrierDrift = reviewedDnsProjectionExport(
      "node_dns_promises",
      "lookup",
    );
    carrierDrift.metadata.crossSourceExportProjection.memberPath = "resolve";
    expect(() => classifyObservedSurface(carrierDrift, context)).toThrow(
      /unclassified observed surface/,
    );

    const providerDrift = reviewedDnsProjectionExport(
      "node_dns",
      "Resolver._handle.cancel",
    );
    providerDrift.metadata.constructorInstanceProjection.instancePath =
      "_handle.getServers";
    expect(() => classifyObservedSurface(providerDrift, context)).toThrow(
      /unclassified observed surface/,
    );
  });

  test("source-specific dgram membership compatibility stubs stay explicit", () => {
    for (const exportName of [
      "Socket.addSourceSpecificMembership",
      "Socket.dropSourceSpecificMembership",
    ]) {
      const classified = classifyObservedSurface(
        builtinExport("node_dgram", exportName),
        context,
      );
      expect(classified.edge.classification, exportName).toBe("non-capability");
      expect(classified.edge.rationaleId, exportName).toBe(
        "pure-in-memory-compute",
      );
    }
  });

  test("process warnings remain closed across the shared warning registry", () => {
    const classified = classifyObservedSurface(
      builtinExport("exact_process", "emitWarning"),
      context,
    );
    expect(classified.edge.classification).toBe("closed");
    expect(edgeActions(classified)).toEqual(["ipc:channel"]);
  });

  test("all spawn families account for inherited environment reads", () => {
    for (const [sourceKey, exportName] of [
      ["exact_process", "execve"],
      ["node_child_process", "spawn"],
      ["node_child_process", "spawnSync"],
      ["node_child_process", "exec"],
      ["node_child_process", "execFile"],
      ["node_child_process", "fork"],
      ["node_cluster", "fork"],
    ]) {
      const classified = classifyObservedSurface(
        builtinExport(sourceKey, exportName),
        context,
      );
      expect(classified.edge.classification, `${sourceKey}:${exportName}`).toBe(
        "effects",
      );
      expect(edgeActions(classified), `${sourceKey}:${exportName}`).toContain(
        "env:read",
      );
      expect(classified.edge.effectMode, `${sourceKey}:${exportName}`).toBe(
        "conditional",
      );
    }

    for (const name of [
      "__exactSpawn",
      "__exactSpawnSync",
      "__exactExecSync",
    ]) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(edgeActions(classified), name).toContain("env:read");
      expect(classified.edge.effectMode, name).toBe("conditional");
    }
  });

  test("native process exit is an exact cooperative lifecycle effect", () => {
    const classified = classifyObservedSurface(
      surface("native-op", "__exactExit"),
      context,
    );
    expect(classified.edge.classification).toBe("effects");
    expect(edgeActions(classified)).toEqual(["lifecycle:exit"]);
  });

  test("process listener aliases retain closed default with exit no-effect branches", () => {
    const aliases = [
      "addListener",
      "listenerCount",
      "listeners",
      "off",
      "on",
      "once",
      "prependListener",
      "prependOnceListener",
      "rawListeners",
      "removeAllListeners",
      "removeListener",
    ];
    for (const alias of aliases) {
      const classified = classifyObservedSurface(
        globalApi("process", alias),
        context,
      );
      expect(classified.edge.classification, alias).toBe("closed");
      expect(classified.edge.cap, alias).toBe("runtime:inspect");
      expect(classified.edge.logicalBranches, alias).toEqual([
        {
          id: "before-exit",
          when: [
            {
              fact: "process.listener.event",
              equals: "before-exit",
            },
          ],
          disposition: "no-effect",
        },
        {
          id: "exit",
          when: [{ fact: "process.listener.event", equals: "exit" }],
          disposition: "no-effect",
        },
      ]);
    }

    const emit = classifyObservedSurface(globalApi("process", "emit"), context);
    expect(emit.edge).toMatchObject({
      classification: "closed",
      cap: "ipc:channel",
    });
    expect(emit.edge.logicalBranches).toBeUndefined();
    const eventNames = classifyObservedSurface(
      globalApi("process", "eventNames"),
      context,
    );
    expect(eventNames.edge).toMatchObject({
      classification: "closed",
      cap: "runtime:inspect",
    });
    expect(eventNames.edge.logicalBranches).toBeUndefined();
  });

  test("private session worker bootstrap is classified without public reachability", () => {
    const name = "private:ibex:session-worker-bootstrap:v1";
    expect(reviewedStartupNames()).toContain(name);
    const classified = classifyObservedSurface(
      surface("startup", name, {
        argument: "__ibex-session-worker-v1",
        evidenceType: "private-session-worker-bootstrap",
        javascriptReachability: "none",
        visibility: "private-supervisor-worker",
      }),
      context,
    );
    expect(classified.edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "terminal-session-control",
    });

    for (const mutate of [
      (metadata) => {
        metadata.argument = "--session-worker";
      },
      (metadata) => {
        metadata.javascriptReachability = "global";
      },
      (metadata) => {
        metadata.visibility = "public-cli";
      },
    ]) {
      const metadata = {
        argument: "__ibex-session-worker-v1",
        evidenceType: "private-session-worker-bootstrap",
        javascriptReachability: "none",
        visibility: "private-supervisor-worker",
      };
      mutate(metadata);
      expect(() =>
        classifyObservedSurface(surface("startup", name, metadata), context),
      ).toThrow(/unclassified observed surface/u);
    }
  });

  test("public filesystem watchers remain closed before polling begins", () => {
    for (const exportName of ["watch", "watchFile"]) {
      const classified = classifyObservedSurface(
        builtinExport("node_fs", exportName),
        context,
      );
      expect(classified.edge, exportName).toMatchObject({
        classification: "closed",
        cap: "fs:unbound-mutation",
      });
    }
  });

  test("opendir is a list-only retained directory operation, not flag-selected open", () => {
    for (const name of ["opendir", "opendirSync"]) {
      const classified = classifyObservedSurface(
        builtinExport("node_fs", name),
        context,
      );
      expect(edgeActions(classified), name).toEqual(["fs:list"]);
      expect(classified.edge.effectMode, name).toBe("conjunctive");
      expect(classified.edge.lifetimeContract, name).toBe("file-handle");
    }
  });

  test("Bun.file and Exact.file allocate lazy wrappers; native use remains gated", () => {
    for (const root of ["Bun", "Exact"]) {
      const classified = classifyObservedSurface(
        globalApi(root, "file"),
        context,
      );
      expect(classified.edge.classification, root).toBe("non-capability");
      expect(classified.edge.rationaleId, root).toBe("pure-in-memory-compute");
    }
  });

  test("shared registries and unowned numeric handles remain closed", () => {
    for (const [sourceKey, exportName, expectedAction] of [
      ["node_cluster", "disconnect", "ipc:channel"],
      ["node_fs", "unwatchFile", "runtime:inspect"],
      ["node_module", "Module", "runtime:inspect"],
      ["node_module", "createRequire", "runtime:inspect"],
      ["node_timers", "clearImmediate", "runtime:inspect"],
    ]) {
      const classified = classifyObservedSurface(
        builtinExport(sourceKey, exportName),
        context,
      );
      expect(classified.edge.classification, `${sourceKey}:${exportName}`).toBe(
        "closed",
      );
      expect(edgeActions(classified), `${sourceKey}:${exportName}`).toEqual([
        expectedAction,
      ]);
    }

    for (const name of ["__exactUncaughtExceptionHandler"]) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(classified.edge.classification, name).toBe("closed");
      expect(edgeActions(classified), name).toEqual(["runtime:inspect"]);
    }

    for (const [name, rationaleId] of [
      ["__exactTlsEngineNew", "internal-data-transform"],
      ["__exactTlsEngineWriteTls", "internal-data-transform"],
      ["__exactTlsEngineReadPlain", "internal-data-transform"],
      ["__exactTlsEnginePeerCerts", "internal-data-transform"],
      ["__exactTlsEngineClose", "authority-release"],
      ["__exactTlsOwnerToken", "authority-control-plane"],
      ["__exactZlibCreate", "internal-data-transform"],
      ["__exactZlibWrite", "internal-data-transform"],
      ["__exactZlibParams", "internal-data-transform"],
      ["__exactZlibClose", "authority-release"],
      ["__exactZlibCheckOwner", "authority-control-plane"],
      ["__exactTimerRef", "authority-control-plane"],
      ["__exactTimerUnref", "authority-control-plane"],
    ]) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(classified.edge.classification, name).toBe("non-capability");
      expect(classified.edge.rationaleId, name).toBe(rationaleId);
    }

    const spawnPoll = classifyObservedSurface(
      surface("native-op", "__exactSpawnPoll"),
      context,
    );
    expect(edgeActions(spawnPoll)).toEqual(["process:spawn"]);
    expect(spawnPoll.edge.lifetimeContract).toBe("child-process");
    expect(spawnPoll.edge.effectOwnerSource).toBe("descriptor-owner");
    expect(
      classifyObservedSurface(
        surface("native-op", "__exactSpawnSetReferenced"),
        context,
      ).edge,
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "authority-control-plane",
    });

    for (const globalName of ["clearImmediate"]) {
      const classified = classifyObservedSurface(
        globalApi(globalName),
        context,
      );
      expect(classified.edge.classification, globalName).toBe("closed");
      expect(edgeActions(classified), globalName).toEqual(["runtime:inspect"]);
    }

    for (const globalName of ["clearTimeout", "clearInterval"]) {
      const global = classifyObservedSurface(globalApi(globalName), context);
      expect(global.edge.classification, globalName).toBe("non-capability");
      expect(global.edge.rationaleId, globalName).toBe("authority-release");

      const builtin = classifyObservedSurface(
        builtinExport("node_timers", globalName),
        context,
      );
      expect(builtin.edge.classification, globalName).toBe("non-capability");
      expect(builtin.edge.rationaleId, globalName).toBe("authority-release");
    }
  });

  test("owner-authenticated timer controls are authority-reducing", () => {
    const timerRuntime = fs.readFileSync(
      path.join(repoRoot, "src/engine/hermes_runtime_timers.cc"),
      "utf8",
    );
    expect(
      timerRuntime.match(/it->second\.principal == currentPrincipalId\(\)/gu),
    ).toHaveLength(4);

    for (const name of ["__exactTimerRef", "__exactTimerUnref"]) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(classified.edge).toMatchObject({
        classification: "non-capability",
        rationaleId: "authority-control-plane",
      });
    }
  });

  test("implicit bind and stream-constructor wrappers retain every possible effect", () => {
    for (const exportName of [
      "Socket.connect",
      "Socket.send",
      "Socket.sendto",
    ]) {
      const classified = classifyObservedSurface(
        builtinExport("node_dgram", exportName),
        context,
      );
      expect(edgeActions(classified), exportName).toEqual([
        "network:connect",
        "network:listen",
      ]);
      expect(classified.edge.effectMode, exportName).toBe("conditional");
    }

    for (const exportName of ["resolve", "resolve4", "reverse"]) {
      const classified = classifyObservedSurface(
        builtinExport("node_dns", exportName),
        context,
      );
      expect(edgeActions(classified), exportName).toEqual([
        "network:connect",
        "network:listen",
        "network:resolve",
      ]);
      expect(classified.edge.effectMode).toBe("conditional");
    }

    for (const [exportName, expectedActions] of [
      ["createReadStream", ["fs:list", "fs:read"]],
      ["createWriteStream", ["fs:list", "fs:write"]],
    ]) {
      const classified = classifyObservedSurface(
        builtinExport("node_fs", exportName),
        context,
      );
      expect(edgeActions(classified), exportName).toEqual(expectedActions);
      expect(classified.edge.effectMode, exportName).toBe("conditional");
      expect(classified.edge.logicalBranches[0].effects, exportName).toEqual(
        [],
      );
    }
  });

  test("transpile loader functions include cache, environment, and subprocess effects", () => {
    for (const name of [
      "function:rust:module_cache_key",
      "function:rust:resolve_transpile_cache_dir",
    ]) {
      const classified = classifyObservedSurface(
        surface("loader", name),
        context,
      );
      expect(edgeActions(classified), name).toEqual([
        "env:read",
        "fs:list",
        "fs:read",
        "fs:write",
      ]);
      expect(classified.edge.effectMode, name).toBe("conditional");
    }

    const transpile = classifyObservedSurface(
      surface("loader", "function:rust:transpile_module"),
      context,
    );
    expect(edgeActions(transpile)).toEqual([
      "env:read",
      "fs:list",
      "fs:read",
      "fs:write",
      "process:spawn",
      "stdio:read",
      "stdio:write",
    ]);
    expect(transpile.edge.effectMode).toBe("conditional");
    expect(transpile.edge.lifetimeContract).toBe("child-process");

    expect(
      classifyObservedSurface(
        surface("loader", "function:rust:transpile_module_to_cjs"),
        context,
      ).edge,
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "internal-data-transform",
    });

    for (const name of [
      "function:javascript:importImpl",
      "function:javascript:load",
      "function:javascript:moduleDynamicImport",
      "function:rust:load_module_source",
      "function:rust:load_source",
      "function:rust:resolve",
    ]) {
      const classified = classifyObservedSurface(
        surface("loader", name),
        context,
      );
      expect(edgeActions(classified), name).toEqual([
        "env:read",
        "fs:list",
        "fs:read",
        "fs:write",
        "process:spawn",
        "stdio:read",
        "stdio:write",
      ]);
      expect(classified.edge.effectMode, name).toBe("conditional");
    }

    const normalizedTarget = classifyObservedSurface(
      surface("loader", "function:rust:normalize_import_target"),
      context,
    );
    expect(edgeActions(normalizedTarget)).toEqual(["fs:list"]);

    for (const name of ["entry:dynamic-import", "entry:global-require"]) {
      const classified = classifyObservedSurface(
        surface("loader", name),
        context,
      );
      expect(edgeActions(classified), name).toEqual([
        "env:read",
        "fs:list",
        "fs:read",
        "fs:write",
        "process:spawn",
        "stdio:read",
        "stdio:write",
      ]);
    }

    expect(
      classifyObservedSurface(
        surface("loader", "route:load:rust:scan_balanced_region"),
        context,
      ).edge,
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "internal-data-transform",
    });
    expect(
      edgeActions(
        classifyObservedSurface(
          surface("loader", "operation:load:write"),
          context,
        ),
      ),
    ).toEqual(["fs:list", "fs:write"]);
    expect(
      classifyObservedSurface(
        surface("loader", "internal-route:internal/streams/readable"),
        context,
      ).edge.rationaleId,
    ).toBe("module-reachability-only");
  });

  test("loader external-call evidence and qualified operations retain their exact effects", () => {
    for (const category of [
      "cache",
      "load",
      "resolution",
      "subprocess",
      "transform",
    ]) {
      const classified = classifyObservedSurface(
        surface("loader", `external-calls:${category}`),
        context,
      );
      expect(classified.edge, category).toMatchObject({
        classification: "non-capability",
        rationaleId: "module-reachability-only",
      });
    }

    for (const category of ["cache", "load", "resolution", "transform"]) {
      const name = `operation:${category}:create_dir_all`;
      expect(
        edgeActions(classifyObservedSurface(surface("loader", name), context)),
        name,
      ).toEqual(["fs:list", "fs:write"]);
      for (const operation of [
        "from_raw_fd",
        "from_raw_handle",
        "last_os_error",
      ]) {
        expect(() =>
          classifyObservedSurface(
            surface("loader", `operation:${category}:${operation}`),
            context,
          ),
        ).toThrow(/unclassified observed surface/u);
      }
      expect(
        edgeActions(
          classifyObservedSurface(
            surface("loader", `operation:${category}:symlink_metadata`),
            context,
          ),
        ),
      ).toEqual(["fs:list"]);
    }

    expect(
      edgeActions(
        classifyObservedSurface(
          surface("loader", "route:load:rust:walk_transpile_tool_directory"),
          context,
        ),
      ),
    ).toEqual(["fs:list", "fs:read"]);
    for (const category of ["cache", "load", "resolution", "transform"]) {
      for (const helper of ["directory_entries", "open_relative"]) {
        const name = `route:${category}:rust:${helper}`;
        expect(() =>
          classifyObservedSurface(surface("loader", name), context),
        ).toThrow(/unclassified observed surface/u);
      }
    }
    expect(() =>
      edgeActions(
        classifyObservedSurface(
          surface("loader", "route:load:rust:drop"),
          context,
        ),
      ),
    ).toThrow(/unclassified observed surface/u);

    for (const category of ["cache", "load", "resolution", "transform"]) {
      const parser = `route:${category}:rust:parse_replacement_expr`;
      expect(
        classifyObservedSurface(surface("loader", parser), context).edge,
        parser,
      ).toMatchObject({
        classification: "non-capability",
        rationaleId: "internal-data-transform",
      });
      for (const accessor of [
        "legacy_runtime_transform",
        "runtime_transform",
      ]) {
        const name = `route:${category}:rust:${accessor}`;
        expect(
          classifyObservedSurface(surface("loader", name), context).edge,
          name,
        ).toMatchObject({
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        });
      }
    }

    for (const category of [
      "cache",
      "load",
      "resolution",
      "subprocess",
      "transform",
    ]) {
      const name = `route:${category}:rust:configure_transpile_subprocess_environment`;
      expect(
        classifyObservedSurface(surface("loader", name), context).edge,
        name,
      ).toMatchObject({
        classification: "non-capability",
        rationaleId: "authority-control-plane",
      });
    }

    for (const name of [
      "operation:load:process-id",
      "operation:resolution:env-current_dir",
      "operation:resolution:process-id",
      "operation:transform:process-id",
    ]) {
      expect(
        edgeActions(classifyObservedSurface(surface("loader", name), context)),
        name,
      ).toEqual(["sys:read"]);
    }

    expect(
      classifyObservedSurface(
        surface("loader", "operation:load:command-new"),
        context,
      ).edge,
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "unbound-owned-resource",
    });
    const status = classifyObservedSurface(
      surface("loader", "operation:load:status"),
      context,
    );
    expect(status.edge.effectMode).toBe("conditional");
    expect(edgeActions(status)).toEqual([
      "env:read",
      "fs:list",
      "fs:read",
      "fs:write",
      "process:spawn",
      "stdio:read",
      "stdio:write",
    ]);
  });

  test("package authentication loader helpers retain effect-accurate classifications", () => {
    const categories = ["cache", "load", "resolution", "transform"];
    const expectConjunctivePackageRead = (name) => {
      const classified = classifyObservedSurface(
        surface("loader", name),
        context,
      );
      expect(classified.edge, name).toMatchObject({
        classification: "effects",
        effectMode: "conjunctive",
      });
      expect(edgeActions(classified), name).toEqual(["fs:list", "fs:read"]);
    };

    expectConjunctivePackageRead("function:rust:resolve_package_link");
    for (const category of categories) {
      expectConjunctivePackageRead(
        `route:${category}:rust:walk_transpile_tool_directory`,
      );
      for (const staleName of [
        `operation:${category}:from_raw_fd`,
        `operation:${category}:from_raw_handle`,
        `operation:${category}:last_os_error`,
        `route:${category}:rust:digest_file`,
        `route:${category}:rust:directory_entries`,
        `route:${category}:rust:directory_names`,
        `route:${category}:rust:normalize_absolute`,
        `route:${category}:rust:object_identity`,
        `route:${category}:rust:open_entry_no_follow`,
        `route:${category}:rust:open_relative`,
        `route:${category}:rust:open_path_no_follow`,
        `route:${category}:rust:read_link_at`,
        `route:${category}:rust:resolve_package_link`,
        `route:${category}:rust:retain_authenticated_object`,
        `route:${category}:rust:stable_path_link`,
        `route:${category}:rust:stamp`,
        `route:${category}:rust:target_is_package_defined`,
        `route:${category}:rust:verification_generation`,
        `route:${category}:rust:walk`,
      ]) {
        expect(() =>
          classifyObservedSurface(surface("loader", staleName), context),
        ).toThrow(/unclassified observed surface/u);
      }
      if (category !== "resolution") {
        expect(() =>
          classifyObservedSurface(
            surface("loader", `operation:${category}:read_link`),
            context,
          ),
        ).toThrow(/unclassified observed surface/u);
      }
    }
  });

  test("generated-single principal normalization is a precise pure loader helper", () => {
    const name = "function:javascript:closedGeneratedSinglePrincipal";
    expect(reviewedLoaderNames()).toContain(name);
    const classified = classifyObservedSurface(
      surface("loader", name),
      context,
    );
    expect(classified.edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "pure-in-memory-compute",
    });
    expect(classified.specification.implementationOwner).toBe("WP1");

    const registrationName =
      "function:javascript:generatedSinglePackagePrincipal";
    expect(reviewedLoaderNames()).toContain(registrationName);
    expect(
      classifyObservedSurface(surface("loader", registrationName), context)
        .edge,
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "authority-control-plane",
    });

    for (const errorHelper of [
      "function:javascript:moduleResolutionError",
      "function:javascript:stableModuleResolutionErrorCode",
    ]) {
      expect(reviewedLoaderNames()).toContain(errorHelper);
      expect(
        classifyObservedSurface(surface("loader", errorHelper), context).edge,
        errorHelper,
      ).toMatchObject({
        classification: "non-capability",
        rationaleId: "pure-in-memory-compute",
      });
    }
  });

  test("dynamic-import index recognizers are exact pure loader helpers", () => {
    for (const name of [
      "function:javascript:indexAfterDynamicImport",
      "function:javascript:indexAfterLoweredDynamicImport",
    ]) {
      expect(reviewedLoaderNames()).toContain(name);
      expect(
        classifyObservedSurface(surface("loader", name), context).edge,
        name,
      ).toMatchObject({
        classification: "non-capability",
        rationaleId: "pure-in-memory-compute",
      });
    }

    for (const name of [
      "function:javascript:indexAfterDynamicImports",
      "function:javascript:indexAfterLoweredImport",
    ]) {
      expect(reviewedLoaderNames()).not.toContain(name);
      expect(() =>
        classifyObservedSurface(surface("loader", name), context),
      ).toThrow(/unclassified observed surface/u);
    }
  });

  test("classifies late diagnostic resolver selection as an exact control plane", () => {
    for (const name of [
      "function:javascript:currentDiagnosticModuleResolve",
      "function:javascript:currentDiagnosticModuleResolveMeta",
    ]) {
      expect(reviewedLoaderNames()).toContain(name);
      const classified = classifyObservedSurface(
        surface("loader", name),
        context,
      );
      expect(classified.edge).toMatchObject({
        classification: "non-capability",
        rationaleId: "authority-control-plane",
      });
      expect(classified.specification.implementationOwner).toBe("WP3");
    }
  });

  test("classifies the source-bound current-principal environment Proxy as exact read/write effects", () => {
    const observed = principalEnvironmentOverlayGlobal();
    expect(reviewedGlobalApiNames()).toContain(observed.name);
    expect(reviewedGlobalApiNames()).not.toContain(
      "global:process.env.[[dynamic-table:host-process-env-properties]]",
    );

    const classified = classifyObservedSurface(observed, context);
    expect(classified.edge).toMatchObject({
      classification: "effects",
      effectMode: "conditional",
      effectOwnerSource: "innermost-nontransparent-frame",
      principalSources: ["frame-set", "schedule-time"],
      logicalBranches: [
        {
          id: "read",
          when: [
            {
              fact: "environment.property.operation",
              equals: "read",
            },
          ],
          effects: [{ cap: "env:read" }],
        },
        {
          id: "write",
          when: [
            {
              fact: "environment.property.operation",
              equals: "write",
            },
          ],
          effects: [{ cap: "env:write" }],
        },
      ],
    });
    expect(classified.edge.effects.map(({ cap }) => cap)).toEqual([
      "env:read",
      "env:write",
    ]);
    for (const effect of classified.edge.effects) {
      expect(effect).toMatchObject({
        selectorNormalizer: "environment.name.selector.v1",
        occurrenceNormalizer: "environment.name.occurrence.v1",
        stages: ["requested", "commit"],
      });
    }

    for (const mutate of [
      (surface) => {
        surface.metadata.principalEnvironmentOverlaySourceContract.proxyTraps.find(
          ({ name }) => name === "set",
        ).nativeBridges = [];
      },
      (surface) => {
        surface.metadata.principalEnvironmentOverlaySourceContract.sourceRefs =
          surface.metadata.principalEnvironmentOverlaySourceContract.sourceRefs.slice(
            1,
          );
      },
      (surface) => {
        surface.metadata.semanticRoles = ["runtime-property-overlay"];
      },
    ]) {
      const drifted = structuredClone(observed);
      mutate(drifted);
      expect(() => classifyObservedSurface(drifted, context)).toThrow(
        /unclassified observed surface/u,
      );
    }
  });

  test("classifies typed environment-write Host authorization as control plane", () => {
    const name = "ex_host_authorize_typed_environment_write_stack";
    expect(reviewedHostAbiNames()).toContain(name);
    const classified = classifyObservedSurface(
      surface("host-abi", name),
      context,
    );
    expect(classified.edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "authority-control-plane",
    });
    expect(classified.specification.implementationOwner).toBe("WP8");
  });

  test("shared process-global builtin mutation surfaces remain closed", () => {
    for (const [sourceKey, exportName, expectedAction] of [
      ["exact_process", "env", "env:process-write"],
      ["exact_process", "_umask", "process:umask"],
      ["exact_process", "umask", "process:umask"],
      ["exact_process", "_uncaughtCaptureCb", "runtime:inspect"],
      ["exact_process", "addListener", "runtime:inspect"],
      [
        "exact_process",
        "hasUncaughtExceptionCaptureCallback",
        "runtime:inspect",
      ],
      ["exact_process", "off", "runtime:inspect"],
      [
        "exact_process",
        "setUncaughtExceptionCaptureCallback",
        "runtime:inspect",
      ],
      ["exact_process", "setSourceMapsEnabled", "runtime:inspect"],
      ["node_dns", "setServers", "runtime:inspect"],
      ["node_dns", "setDefaultResultOrder", "runtime:inspect"],
      ["node_http", "globalAgent", "runtime:inspect"],
      ["node_http", "parsers", "runtime:inspect"],
      ["node_http", "setMaxIdleHTTPParsers", "runtime:inspect"],
      ["node_https", "globalAgent", "runtime:inspect"],
      ["node_module", "default", "runtime:inspect"],
      ["node_module", "_extensions", "runtime:inspect"],
      ["node_module", "_pathCache", "runtime:inspect"],
      ["node_module", "globalPaths", "runtime:inspect"],
      ["node_net", "setDefaultAutoSelectFamily", "runtime:inspect"],
      [
        "node_net",
        "setDefaultAutoSelectFamilyAttemptTimeout",
        "runtime:inspect",
      ],
      ["node_tls", "setDefaultCACertificates", "runtime:inspect"],
      ["exact_crypto", "fips", "runtime:inspect"],
      ["exact_crypto", "setFips", "runtime:inspect"],
      ["exact_crypto", "setEngine", "ffi:load"],
      ["node_cluster", "default", "runtime:inspect"],
      ["node_cluster", "_nextWorkerId", "runtime:inspect"],
      ["node_cluster", "schedulingPolicy", "runtime:inspect"],
      ["node_cluster", "settings", "runtime:inspect"],
      ["node_cluster", "setupMaster", "runtime:inspect"],
      ["node_cluster", "setupPrimary", "runtime:inspect"],
      ["node_cluster", "worker", "runtime:inspect"],
      ["node_cluster", "workers", "runtime:inspect"],
    ]) {
      const classified = classifyObservedSurface(
        builtinExport(sourceKey, exportName),
        context,
      );
      expect(classified.edge.classification, `${sourceKey}:${exportName}`).toBe(
        "closed",
      );
      expect(edgeActions(classified), `${sourceKey}:${exportName}`).toEqual([
        expectedAction,
      ]);
    }
  });

  test("shared hook and diagnostics builtin families are closed exactly", () => {
    for (const [sourceKey, exportName, expectedAction] of [
      ["node_async_hooks", "default", "runtime:inspect"],
      ["node_async_hooks", "createHook", "runtime:inspect"],
      ["node_async_hooks", "AsyncLocalStorage.run", "runtime:inspect"],
      ["node_async_hooks", "AsyncResource.runInAsyncScope", "runtime:inspect"],
      ["node_diagnostics_channel", "default", "ipc:channel"],
      ["node_diagnostics_channel", "channel", "ipc:channel"],
      ["node_diagnostics_channel", "Channel.publish", "ipc:channel"],
      ["node_diagnostics_channel", "Channel.subscribe", "ipc:channel"],
      ["node_domain", "default", "runtime:inspect"],
      ["node_domain", "create", "runtime:inspect"],
      ["node_domain", "Domain.run", "runtime:inspect"],
    ]) {
      const classified = classifyObservedSurface(
        builtinExport(sourceKey, exportName),
        context,
      );
      expect(classified.edge.classification, `${sourceKey}:${exportName}`).toBe(
        "closed",
      );
      expect(edgeActions(classified), `${sourceKey}:${exportName}`).toEqual([
        expectedAction,
      ]);
    }

    for (const exportName of [
      "EventEmitter.addListener",
      "EventEmitter.emit",
    ]) {
      const classified = classifyObservedSurface(
        builtinExport("node_events", exportName),
        context,
      );
      expect(classified.edge.classification, exportName).toBe("non-capability");
      expect(classified.edge.rationaleId, exportName).toBe(
        "callback-attribution-carrier",
      );
    }

    const localConstructor = classifyObservedSurface(
      builtinExport("node_events", "EventEmitter"),
      context,
    );
    expect(localConstructor.edge.classification).toBe("non-capability");
    expect(localConstructor.edge.rationaleId).toBe("unbound-owned-resource");

    for (const exportName of [
      "captureRejections",
      "defaultMaxListeners",
      "setMaxListeners",
      "EventEmitter._events",
      "EventEmitter._maxListeners",
      "EventEmitter.setMaxListeners",
      "default._events",
      "default._maxListeners",
      "default.setMaxListeners",
      "EventEmitterAsyncResource",
      "EventEmitterAsyncResource.constructor",
      "EventEmitterAsyncResource.emit",
    ]) {
      const classified = classifyObservedSurface(
        builtinExport("node_events", exportName),
        context,
      );
      expect(classified.edge.classification, exportName).toBe("closed");
      expect(edgeActions(classified), exportName).toEqual(["runtime:inspect"]);
    }
  });

  test("builtin roots account for every reviewed import-time effect", () => {
    const runtimeMutationRoots = [
      ["exact_crypto", ["crypto", "exact:crypto", "node:crypto"]],
      ["exact_process", ["exact:process", "node:process", "process"]],
      ["legacy_stream_duplex", ["_stream_duplex"]],
      ["legacy_stream_passthrough", ["_stream_passthrough"]],
      ["legacy_stream_readable", ["_stream_readable"]],
      ["legacy_stream_transform", ["_stream_transform"]],
      ["legacy_stream_writable", ["_stream_writable"]],
      [
        "node_assert",
        ["assert", "assert/strict", "node:assert", "node:assert/strict"],
      ],
      ["node_async_hooks", ["async_hooks", "node:async_hooks"]],
      ["node_child_process", ["child_process", "node:child_process"]],
      ["node_cluster", ["cluster", "node:cluster"]],
      ["node_dgram", ["dgram", "node:dgram"]],
      ["node_domain", ["domain", "node:domain"]],
      ["node_events", ["events", "node:events"]],
      [
        "node_http",
        [
          "_http_agent",
          "_http_common",
          "_http_incoming",
          "_http_outgoing",
          "_http_server",
          "http",
          "node:http",
        ],
      ],
      ["node_http2", ["http2", "node:http2"]],
      ["node_https", ["https", "node:https"]],
      ["node_net", ["net", "node:net"]],
      ["node_perf_hooks", ["node:perf_hooks", "perf_hooks"]],
      [
        "node_readline",
        [
          "node:readline",
          "node:readline/promises",
          "readline",
          "readline/promises",
        ],
      ],
      ["node_stream", ["node:stream", "stream"]],
      ["node_stream_promises", ["node:stream/promises", "stream/promises"]],
      ["node_stream_web", ["node:stream/web", "stream/web"]],
      ["node_tls", ["node:tls", "tls"]],
      ["node_tty", ["node:tty", "tty"]],
      ["node_url", ["node:url"]],
      ["node_zlib", ["node:zlib", "zlib"]],
      ["url_alias", ["url"]],
      ["ws", ["ws"]],
    ];

    for (const [sourceKey, aliases] of runtimeMutationRoots) {
      for (const alias of aliases) {
        const classified = classifyObservedSurface(
          surface("builtin", alias, {
            sourceKey,
            bundleExternal: true,
            moduleBuiltin: true,
          }),
          context,
        );
        expect(classified.edge.classification, alias).toBe("closed");
        expect(edgeActions(classified), alias).toEqual(["runtime:inspect"]);
      }
    }

    for (const [sourceKey, aliases] of [
      ["node_constants", ["constants", "node:constants"]],
      ["node_fs", ["bun:fs", "fs", "node:fs"]],
      [
        "node_fs_promises",
        [
          "bun:fs/promises",
          "fs/promises",
          "internal/fs/promises",
          "node:fs/promises",
        ],
      ],
      ["node_os", ["node:os", "os"]],
    ]) {
      for (const alias of aliases) {
        const classified = classifyObservedSurface(
          surface("builtin", alias, {
            sourceKey,
            bundleExternal: true,
            moduleBuiltin: true,
          }),
          context,
        );
        expect(classified.edge.classification, alias).toBe("effects");
        expect(edgeActions(classified), alias).toEqual(["sys:read"]);
      }
    }

    for (const [sourceKey, aliases] of [
      ["node_util", ["node:sys", "node:util", "sys", "util"]],
      ["node_util_types_alias", ["node:util/types"]],
      ["util_types_alias", ["util/types"]],
    ]) {
      for (const alias of aliases) {
        const classified = classifyObservedSurface(
          surface("builtin", alias, {
            sourceKey,
            bundleExternal: true,
            moduleBuiltin: true,
          }),
          context,
        );
        expect(classified.edge.classification, alias).toBe("effects");
        expect(edgeActions(classified), alias).toEqual(["env:read"]);
        expect(classified.edge.effectMode, alias).toBe("conjunctive");
      }
    }

    for (const alias of ["diagnostics_channel", "node:diagnostics_channel"]) {
      const classified = classifyObservedSurface(
        surface("builtin", alias, {
          sourceKey: "node_diagnostics_channel",
          bundleExternal: true,
          moduleBuiltin: true,
        }),
        context,
      );
      expect(classified.edge.classification, alias).toBe("closed");
      expect(edgeActions(classified), alias).toEqual(["ipc:channel"]);
    }
  });

  test("unknown exports in effectful builtin families fail closed", () => {
    for (const [sourceKey, exportName] of [
      ["node_dgram", "transmitSecret"],
      ["node_fs", "eraseEverything"],
      ["node_http", "openExternalChannel"],
      ["node_path", "readSecretFile"],
    ]) {
      expect(() =>
        classifyObservedSurface(builtinExport(sourceKey, exportName), context),
      ).toThrow(/unclassified observed surface/);
    }
    expect(() =>
      classifyObservedSurface(
        surface("builtin", "node:future-safe-looking", {
          sourceKey: "node_path",
          bundleExternal: true,
          moduleBuiltin: true,
        }),
        context,
      ),
    ).toThrow(/unclassified observed surface/);
  });

  test("generic stream wrappers rely on retained-object native gates, not purity", () => {
    for (const [sourceKey, exportName] of [
      ["node_stream", "Readable.read"],
      ["node_stream", "Writable.write"],
      ["node_stream", "pipeline"],
      ["node_stream_consumers", "text"],
      ["node_stream_promises", "pipeline"],
      ["node_stream_web", "toWeb"],
    ]) {
      const classified = classifyObservedSurface(
        builtinExport(sourceKey, exportName),
        context,
      );
      expect(classified.edge.classification).toBe("non-capability");
      expect(classified.edge.rationaleId).toBe("retained-object-wrapper");
    }
  });

  test("global APIs use exact reviewed keys and close shared Cache namespaces", () => {
    const layoutTree = classifyObservedSurface(
      globalApi("exact", "getLayoutTree"),
      context,
    );
    expect(layoutTree.edge).toMatchObject({
      classification: "closed",
      cap: "ipc:channel",
    });

    for (const namespace of ["Exact", "Bun"]) {
      for (const member of [
        "accessibility",
        "accessibility.addEventListener",
        "accessibility.prefersReducedMotion",
      ]) {
        expect(
          classifyObservedSurface(globalApi(namespace, member), context).edge,
          `${namespace}.${member}`,
        ).toMatchObject({ classification: "closed", cap: "ipc:channel" });
      }
    }

    for (const [globalName, memberName, expectedAction] of [
      ["Cache", null, "storage:persist"],
      ["Cache", "add", "storage:write"],
      ["Cache", "addAll", "storage:write"],
      ["Cache", "put", "storage:write"],
      ["Cache", "delete", "storage:write"],
      ["Cache", "match", "storage:read"],
      ["Cache", "matchAll", "storage:read"],
      ["Cache", "keys", "storage:read"],
      ["CacheStorage", null, "storage:persist"],
      ["CacheStorage", "open", "storage:persist"],
      ["CacheStorage", "delete", "storage:persist"],
      ["CacheStorage", "has", "storage:read"],
      ["CacheStorage", "keys", "storage:read"],
      ["CacheStorage", "match", "storage:read"],
      ["caches", null, "storage:persist"],
      ["caches", "open", "storage:persist"],
      ["caches", "delete", "storage:persist"],
      ["caches", "has", "storage:read"],
      ["caches", "keys", "storage:read"],
      ["caches", "match", "storage:read"],
    ]) {
      const classified = classifyObservedSurface(
        globalApi(globalName, memberName),
        context,
      );
      expect(
        classified.edge.classification,
        `${globalName}.${memberName}`,
      ).toBe("closed");
      expect(edgeActions(classified), `${globalName}.${memberName}`).toEqual([
        expectedAction,
      ]);
    }

    for (const [globalName, memberName, expectedAction] of [
      ["caches", "[[Symbol.toStringTag]]", "storage:persist"],
      ["localStorage", "[[Symbol.toStringTag]]", "storage:read"],
      ["sessionStorage", "[[Symbol.toStringTag]]", "storage:read"],
      ["indexedDB", "cmp", "storage:persist"],
      ["IDBKeyRange", null, "storage:persist"],
      ["IDBRequest", "onsuccess", "storage:persist"],
      ["IDBOpenDBRequest", "onupgradeneeded", "storage:persist"],
      ["IDBDatabase", "close", "storage:persist"],
      ["IDBTransaction", "abort", "storage:persist"],
    ]) {
      const classified = classifyObservedSurface(
        globalApi(globalName, memberName),
        context,
      );
      expect(
        classified.edge.classification,
        `${globalName}.${memberName}`,
      ).toBe("closed");
      expect(edgeActions(classified), `${globalName}.${memberName}`).toEqual([
        expectedAction,
      ]);
    }

    for (const observed of [
      globalApi("Bun", "spawnSecret"),
      globalApi("readSecret"),
      globalApi("candidate", "readSecret"),
      globalApi("URL", "someExternalEffect"),
      globalApi("Buffer", "readSecret"),
      globalApi("Event", "openNetwork"),
      globalApi("EventTarget", "readSecret"),
      globalApi("Date", "writeFile"),
      globalApi("Performance", "connect"),
      globalApi("ReadableStream", "openNetwork"),
    ]) {
      expect(() => classifyObservedSurface(observed, context)).toThrow(
        /unclassified observed surface/,
      );
    }

    expect(() =>
      classifyObservedSurface(
        surface("native-op", "global:Cache.add", {
          surfaceType: "global-api",
          sourceKey: "synthetic_global_audit",
          globalName: "URL",
          memberName: null,
          exportName: "URL",
        }),
        context,
      ),
    ).toThrow(/unclassified observed surface/);

    const cryptoRoot = classifyObservedSurface(globalApi("crypto"), context);
    expect(cryptoRoot.edge.classification).toBe("non-capability");
    expect(cryptoRoot.edge.rationaleId).toBe("module-reachability-only");
  });

  test("source-bound IIFE call-result namespaces remain closed and tamper-evident", () => {
    const digest = "a".repeat(64);
    const memberName =
      "CryptoHasher.[[dynamic-table:call-result-aaaaaaaaaaaa-properties]]";
    const observed = surface(
      "native-op",
      `global:Bun.${memberName}`,
      {
        dynamicNamespace: true,
        dynamicNamespaceEvidence: `sha256-${digest}`,
        dynamicNamespaceKind: "iife-call-result",
        dynamicNamespaceRoot: "Bun.CryptoHasher",
        exportName: `Bun.${memberName}`,
        globalName: "Bun",
        memberName,
        semanticRoles: ["dynamic-call-result-shape"],
        sourceKey: "global_exact_global",
        surfaceType: "global-api",
      },
      ["src/engine/bootstrap/exact-global.js#Bun.CryptoHasher"],
    );
    const classified = classifyObservedSurface(observed, context);
    expect(classified.edge.classification).toBe("closed");
    expect(edgeActions(classified)).toEqual(["runtime:inspect"]);

    expect(() =>
      classifyObservedSurface(
        {
          ...observed,
          metadata: {
            ...observed.metadata,
            dynamicNamespaceEvidence: `sha256-${"b".repeat(64)}`,
          },
        },
        context,
      ),
    ).toThrow(/unclassified observed surface/);
  });

  test("Hermes evaluator classification requires the exact reviewed identity and taming evidence", () => {
    for (const globalName of [
      "AsyncFunction",
      "Function",
      "GeneratorFunction",
      "eval",
    ]) {
      const classified = classifyObservedSurface(
        hermesEvaluatorGlobal(globalName),
        context,
      );
      expect(classified.edge.classification, globalName).toBe("closed");
      expect(edgeActions(classified), globalName).toEqual(["vm:evaluate"]);
    }

    const base = hermesEvaluatorGlobal("AsyncFunction");
    for (const [label, metadata] of [
      [
        "changed engine identity sentinel",
        {
          ...base.metadata,
          engineIdentityReviewId: `hermes-evaluators.${"0".repeat(64)}`,
        },
      ],
      [
        "missing Windows artifact profile",
        {
          ...base.metadata,
          engineProfileIds: ["android-maven", "source-patched"],
        },
      ],
      [
        "missing Windows implementation branch",
        {
          ...base.metadata,
          branches: base.metadata.branches.slice(0, 2),
          installationBranches: base.metadata.installationBranches.slice(0, 2),
        },
      ],
      [
        "unbound source-patch application branch",
        {
          ...base.metadata,
          branches: base.metadata.branches.map((branch) =>
            branch.targetVariant === "default"
              ? {
                  ...branch,
                  sourceRefs: branch.sourceRefs.filter(
                    (sourceRef) =>
                      sourceRef !== "scripts/apply-hermes-patches.sh#patches",
                  ),
                }
              : branch,
          ),
          installationBranches: base.metadata.installationBranches.map(
            (branch) =>
              branch.targetVariant === "default"
                ? {
                    ...branch,
                    sourceRefs: branch.sourceRefs.filter(
                      (sourceRef) =>
                        sourceRef !== "scripts/apply-hermes-patches.sh#patches",
                    ),
                  }
                : branch,
          ),
        },
      ],
      [
        "unreviewed evidence kind",
        { ...base.metadata, evidenceType: "runtime-probe" },
      ],
      ["missing lockdown taming", { ...base.metadata, tamingEvidence: "none" }],
      [
        "changed lockdown taming source",
        {
          ...base.metadata,
          lockdownTamingDigest: `sha256-${"0".repeat(64)}`,
        },
      ],
      [
        "incorrect evaluator reachability",
        { ...base.metadata, reachability: "inherited-global" },
      ],
      [
        "floating source key",
        { ...base.metadata, sourceKey: "synthetic_global_audit" },
      ],
    ]) {
      expect(
        () => classifyObservedSurface({ ...base, metadata }, context),
        label,
      ).toThrow(/unclassified observed surface/u);
    }

    expect(() => classifyObservedSurface(globalApi("eval"), context)).toThrow(
      /unclassified observed surface/u,
    );
    expect(() =>
      classifyObservedSurface(
        hermesEvaluatorGlobal("AsyncGeneratorFunction", {
          engineProfileIds: ["android-maven"],
        }),
        context,
      ),
    ).toThrow(/unclassified observed surface/u);
  });

  test("unknown callbacks fail while worklet drains remain closed IPC", () => {
    const drain = classifyObservedSurface(
      surface("callback", "worklet-scheduled-drain"),
      context,
    );
    expect(drain.edge.classification).toBe("closed");
    expect(edgeActions(drain)).toEqual(["ipc:channel"]);

    expect(() =>
      classifyObservedSurface(
        surface("callback", "network-secret-delivery"),
        context,
      ),
    ).toThrow(/unclassified observed surface/);

    const producerMetadata = {
      enclosingDefinition: "stealSecret",
      evidenceType: "push-runtime-callback-producer",
      occurrenceCount: 1,
      producer: "pushRuntimeCallback",
    };
    expect(() =>
      classifyObservedSurface(
        surface(
          "callback",
          "producer:src/engine/hermes_runtime.cc:stealSecret:pushRuntimeCallback",
          producerMetadata,
        ),
        context,
      ),
    ).toThrow(/unclassified observed surface/);
  });

  test("dual-role globals pass both exact approvals and reconcile native semantics", () => {
    for (const [name, globalName, memberName] of [
      ["__exactFsOpen", "__exactFsOpen", null],
      [
        "__exactAndroidLocation.getCurrentLocation",
        "__exactAndroidLocation",
        "getCurrentLocation",
      ],
      ["__exactExit", "__exactExit", null],
      ["__exactHashSync", "__exactHashSync", null],
    ]) {
      const privateClassification = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      const dualClassification = classifyObservedSurface(
        dualRoleGlobalNative(name, globalName, memberName),
        context,
      );
      expect(dualClassification.specification, name).toEqual(
        privateClassification.specification,
      );
      expect(dualClassification.edge.classification, name).toBe(
        privateClassification.edge.classification,
      );
      expect(edgeActions(dualClassification), name).toEqual(
        edgeActions(privateClassification),
      );
    }

    const missingNativeRole = dualRoleGlobalNative(
      "__exactFsOpen",
      "__exactFsOpen",
    );
    missingNativeRole.metadata.semanticRoles = ["global-api-installation"];
    expect(() => classifyObservedSurface(missingNativeRole, context)).toThrow(
      /unclassified observed surface/,
    );

    expect(() =>
      classifyObservedSurface(
        dualRoleGlobalNative("__exactFsOpenSecret", "__exactFsOpenSecret"),
        context,
      ),
    ).toThrow(/unclassified observed surface/);
  });

  test("loader semantics run only after exact function, kind, and route approval", () => {
    const expectedKinds = new Map([
      ["builtin", ["non-capability", []]],
      ["commonjs", ["non-capability", []]],
      ["esm", ["non-capability", []]],
      ["json", ["non-capability", []]],
      ["native-addon", ["closed", ["ffi:load"]]],
      ["wasm", ["closed", ["wasi:instantiate"]]],
    ]);
    for (const [kind, [expectedClass, expectedActions]] of expectedKinds) {
      const classified = classifyObservedSurface(
        surface("loader", `kind:${kind}`),
        context,
      );
      expect(classified.edge.classification, kind).toBe(expectedClass);
      expect(edgeActions(classified), kind).toEqual(expectedActions);
    }

    for (const name of [
      "function:rust:module_resolve_options",
      "function:rust:resolve_builtin_meta",
      "route:resolution:rust:module_resolve_options",
      "route:resolution:rust:parse_manifest",
      "route:resolution:rust:read",
      "route:resolution:rust:read_to_string",
      "route:resolution:rust:resolve_builtin_meta",
    ]) {
      expect(
        classifyObservedSurface(surface("loader", name), context).edge,
      ).toMatchObject({
        classification: "non-capability",
        rationaleId: "module-reachability-only",
      });
    }

    for (const name of [
      "function:rust:resolve_direct_file_meta",
      "function:rust:resolve_with_resolver_at",
      "route:resolution:rust:resolve_with_resolver_at",
    ]) {
      const classified = classifyObservedSurface(
        surface("loader", name),
        context,
      );
      expect(classified.edge.classification, name).toBe("effects");
      expect(edgeActions(classified), name).toEqual(["fs:list", "fs:read"]);
    }

    const expectResolverBranches = (
      name,
      fact,
      branches,
      lifetimeContract = "operation",
    ) => {
      const edge = classifyObservedSurface(
        surface("loader", name),
        context,
      ).edge;
      expect(edge, name).toMatchObject({
        classification: "effects",
        effectMode: "conditional",
        effectOwnerSource: "loader-referrer",
        gate: "loader-admission",
        lifetimeContract,
        principalSources: ["loader-referrer"],
      });
      expect(
        edge.logicalBranches.map((branch) => ({
          effectOwnerSource: branch.effectOwnerSource,
          effects: branch.effects.map((effect) => effect.cap),
          id: branch.id,
          lifetimeContract: branch.lifetimeContract,
          principalSources: branch.principalSources,
          when: branch.when,
        })),
        name,
      ).toEqual(
        branches.map(
          ([id, equals, effects, branchLifetime = lifetimeContract]) => ({
            effectOwnerSource: "loader-referrer",
            effects,
            id,
            lifetimeContract: branchLifetime,
            principalSources: ["loader-referrer"],
            when: [{ fact, equals }],
          }),
        ),
      );
    };

    const resolverSelectionBranches = [
      ["metadata-only", "metadata-only", ["fs:list"]],
      ["no-host-lookup", "none", []],
      ["symlink-target", "symlink-target", ["fs:list", "fs:read"]],
    ];
    for (const name of [
      "function:rust:authenticated_resolver_base_dir",
      "function:rust:resolve_meta_authenticated",
      "route:resolution:rust:authenticated_resolver_base_dir",
      "route:resolution:rust:metadata",
      "route:resolution:rust:read_link",
      "route:resolution:rust:resolve_meta_authenticated",
      "route:resolution:rust:symlink_metadata",
    ]) {
      expectResolverBranches(
        name,
        "loader.resolver.io",
        resolverSelectionBranches,
      );
    }

    const resolverTraversalBranches = [
      ["metadata-only", "metadata-only", ["fs:list"]],
      ["symlink-target", "symlink-target", ["fs:list", "fs:read"]],
    ];
    for (const name of [
      "function:rust:resolve_direct_file_meta_authenticated",
      "function:rust:resolve_meta_from_authenticated_bound_package",
      "route:resolution:rust:bounded_unix_read_link",
      "route:resolution:rust:bounded_unix_symlink_metadata",
      "route:resolution:rust:canonicalize",
      "route:resolution:rust:resolve_direct_file_meta_authenticated",
      "route:resolution:rust:resolve_meta_from_authenticated_bound_package",
    ]) {
      expectResolverBranches(
        name,
        "loader.resolver.io",
        resolverTraversalBranches,
      );
    }

    for (const name of [
      "function:rust:resolve_bounded_unix_path",
      "route:resolution:rust:bounded_unix_parent",
      "route:resolution:rust:resolve_bounded_unix_path",
    ]) {
      expectResolverBranches(
        name,
        "loader.resolver.io",
        resolverTraversalBranches,
        "file-handle",
      );
    }

    expectResolverBranches(
      "route:resolution:rust:new",
      "loader.resolver.backend",
      [
        [
          "descriptor-relative-posix",
          "descriptor-relative-posix",
          ["fs:list"],
          "file-handle",
        ],
        ["unsupported", "unsupported", [], "operation"],
      ],
      "file-handle",
    );

    for (const name of [
      "function:rust:open_resolver_boundary",
      "function:rust:resolver_open_directory_at",
      "operation:resolution:open",
      "route:resolution:rust:open_resolver_boundary",
      "route:resolution:rust:resolver_open_directory_at",
    ]) {
      const classified = classifyObservedSurface(
        surface("loader", name),
        context,
      );
      expect(edgeActions(classified), name).toEqual(["fs:list"]);
      expect(classified.edge, name).toMatchObject({
        effectOwnerSource: "loader-referrer",
        gate: "loader-admission",
        lifetimeContract: "file-handle",
        principalSources: ["loader-referrer"],
      });
    }

    for (const name of [
      "function:rust:resolver_fstat",
      "function:rust:resolver_fstatat_nofollow",
      "route:resolution:rust:resolver_fstat",
      "route:resolution:rust:resolver_fstatat_nofollow",
    ]) {
      const classified = classifyObservedSurface(
        surface("loader", name),
        context,
      );
      expect(edgeActions(classified), name).toEqual(["fs:list"]);
      expect(classified.edge, name).toMatchObject({
        effectOwnerSource: "loader-referrer",
        gate: "loader-admission",
        lifetimeContract: "operation",
        principalSources: ["loader-referrer"],
      });
    }

    for (const name of [
      "function:rust:resolver_read_link_at",
      "operation:resolution:read_link",
      "route:resolution:rust:resolver_read_link_at",
    ]) {
      const classified = classifyObservedSurface(
        surface("loader", name),
        context,
      );
      expect(edgeActions(classified), name).toEqual(["fs:read"]);
      expect(classified.edge, name).toMatchObject({
        effectOwnerSource: "loader-referrer",
        gate: "loader-admission",
        lifetimeContract: "operation",
        principalSources: ["loader-referrer"],
      });
    }

    for (const name of [
      "function:rust:authenticated_module_resolve_options",
      "function:rust:duplicate_resolver_fd",
      "function:rust:lexical_absolute_path_for_resolver",
      "function:rust:resolver_component_cstring",
      "function:rust:resolver_relative_components",
      "route:resolution:rust:authenticated_module_resolve_options",
      "route:resolution:rust:boundary_root",
      "route:resolution:rust:duplicate_resolver_fd",
      "route:resolution:rust:file_system",
      "route:resolution:rust:inputs",
      "route:resolution:rust:lexical_absolute_path_for_resolver",
      "route:resolution:rust:manifest_input",
      "route:resolution:rust:normalize_in_boundary",
      "route:resolution:rust:normalized",
      "route:resolution:rust:resolver_component_cstring",
      "route:resolution:rust:resolver_relative_components",
      "route:resolution:rust:uncaptured_package_manifest_probes",
      "route:resolution:rust:legacy_runtime_transform",
      "route:resolution:rust:runtime_transform",
    ]) {
      expect(
        classifyObservedSurface(surface("loader", name), context).edge,
        name,
      ).toMatchObject({
        classification: "non-capability",
        rationaleId: "authority-control-plane",
      });
    }

    for (const name of [
      "function:rust:resolver_boundary_refusal",
      "function:rust:resolver_canonical_path",
      "function:rust:resolver_manifest_not_found",
      "function:rust:resolver_metadata_from_stat",
      "function:rust:resolver_stat_is_dir",
      "function:rust:resolver_stat_is_symlink",
      "route:resolution:rust:resolver_boundary_refusal",
      "route:resolution:rust:resolver_canonical_path",
      "route:resolution:rust:resolver_manifest_not_found",
      "route:resolution:rust:resolver_metadata_from_stat",
      "route:resolution:rust:resolver_stat_is_dir",
      "route:resolution:rust:resolver_stat_is_symlink",
      "route:resolution:rust:selected_engine_cache_tag",
      "route:resolution:rust:selected_transform_engine",
    ]) {
      expect(
        classifyObservedSurface(surface("loader", name), context).edge,
        name,
      ).toMatchObject({
        classification: "non-capability",
        rationaleId: "internal-data-transform",
      });
    }

    expect(
      classifyObservedSurface(
        surface("loader", "operation:resolution:from-owned-fd"),
        context,
      ).edge,
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "retained-object-wrapper",
    });

    const sessionMetadata = classifyObservedSurface(
      surface("loader", "function:javascript:__exactResolveSessionPath"),
      context,
    );
    expect(sessionMetadata.edge.classification).toBe("effects");
    expect(edgeActions(sessionMetadata)).toEqual(["fs:list"]);

    for (const name of [
      "function:javascript:__exactResolvedPath",
      "function:javascript:createOriginalModuleRegistry",
      "function:javascript:originalModuleRegistryForRecord",
      "function:javascript:principalForOriginal",
      "function:javascript:privateBridgesForBuiltin",
    ]) {
      expect(
        classifyObservedSurface(surface("loader", name), context).edge,
        name,
      ).toMatchObject({
        classification: "non-capability",
        rationaleId: "authority-control-plane",
      });
    }

    expect(
      classifyObservedSurface(
        surface("loader", "function:rust:strip_file_module_decorations"),
        context,
      ).edge,
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "module-reachability-only",
    });
    expect(
      classifyObservedSurface(
        surface(
          "loader",
          "function:javascript:devServedImportGateSpecifier",
        ),
        context,
      ).edge,
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "module-reachability-only",
    });
    expect(
      classifyObservedSurface(
        surface(
          "loader",
          "route:resolution:rust:strip_file_module_decorations",
        ),
        context,
      ).edge,
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "internal-data-transform",
    });

    for (const observed of [
      surface("loader", "kind:remote"),
      surface("loader", "function:javascript:loadNativeAddon"),
      surface("loader", "function:javascript:inventedHelper"),
      surface("loader", "route:load:rust:future_secret_reader"),
      surface("loader", "import-network-secret"),
    ]) {
      expect(() => classifyObservedSurface(observed, context)).toThrow(
        /unclassified observed surface/,
      );
    }
  });

  test("CLI product ingress is authenticated while diagnostic evaluation escapes stay closed", () => {
    for (const observed of [
      surface("cli", "command:ibex%20capsec%20audit", {
        evidenceType: "cli-command-route",
        path: "ibex capsec audit",
      }),
      surface("startup", "script:eval"),
      surface("startup", "script:bytecode"),
    ]) {
      const classified = classifyObservedSurface(observed, context);
      expect(classified.edge.classification).toBe("closed");
      expect(edgeActions(classified)).toEqual(["vm:evaluate"]);
    }

    for (const observed of [
      surface("cli", "eval", { commandClass: "visibleCommands" }),
      surface("cli", "command:ibex%20eval", {
        evidenceType: "cli-command-route",
        path: "ibex eval",
      }),
    ]) {
      const classified = classifyObservedSurface(observed, context);
      expect(classified.edge.classification).toBe("non-capability");
      expect(classified.edge.rationaleId).toBe("internal-data-transform");
    }

    for (const name of [
      "authenticated-direct-file-ingress",
      "authenticated-one-shot-ingress",
      "authenticated-program-stdin-ingress",
      "authenticated-repl-ingress",
      "implicit-no-file-dispatch",
    ]) {
      const classified = classifyObservedSurface(surface("cli", name), context);
      expect(classified.edge.classification, name).toBe("non-capability");
      expect(classified.edge.rationaleId, name).toBe(
        "authenticated-code-ingress",
      );
    }

    const auditFileParser = classifyObservedSurface(
      surface("cli", "argument-parser:ibex%20capsec%20audit:file:utf8-string"),
      context,
    );
    expect(auditFileParser.edge.classification).toBe("non-capability");
    expect(auditFileParser.edge.rationaleId).toBe("runtime-bootstrap-state");

    for (const observed of [
      surface("cli", "run-external-program", {
        commandClass: "visibleCommands",
      }),
      surface("cli", "option:ibex:inspect-secret:default:true"),
      surface("cli", "option:ibex:capsec:enum:future-weakened"),
      surface("startup", "installer:installNativeAddon"),
      surface("startup", "installer:installMysteryFeature"),
      surface("startup", "script:load-secret-network"),
    ]) {
      expect(() => classifyObservedSurface(observed, context)).toThrow(
        /unclassified observed surface/,
      );
    }

    for (const [name, expectedAction] of [
      ["option-name:ibex:inspect:--inspect", "inspector:activate"],
      ["option:ibex:allow_all:default-missing:true", "runtime:inspect"],
      ["option:ibex:capsec:enum:permissive", "runtime:inspect"],
    ]) {
      const classified = classifyObservedSurface(surface("cli", name), context);
      expect(classified.edge.classification, name).toBe("closed");
      expect(edgeActions(classified), name).toEqual([expectedAction]);
    }

    const authoringControl = classifyObservedSurface(
      surface("cli", "option-name:ibex:allow:--allow"),
      context,
    );
    expect(authoringControl.edge.classification).toBe("non-capability");
    expect(authoringControl.edge.rationaleId).toBe("authority-control-plane");

    for (const name of ["export", "start"]) {
      const classified = classifyObservedSurface(
        surface("cli", name, { commandClass: "legacyProjectCommands" }),
        context,
      );
      expect(classified.edge.classification, name).toBe("non-capability");
      expect(classified.edge.rationaleId, name).toBe("runtime-bootstrap-state");
    }
  });

  test("startup structural routes and dynamic environment sentinels stay exact", () => {
    const debuggerEvaluation = classifyObservedSurface(
      surface("startup", "evaluation:ex_hermes_debugger_eval:cdp", {
        evidenceType: "startup-evaluation-route",
      }),
      context,
    );
    expect(debuggerEvaluation.edge.classification).toBe("closed");
    expect(edgeActions(debuggerEvaluation)).toEqual(["runtime:inspect"]);

    const trustedEvaluation = classifyObservedSurface(
      surface("startup", "evaluation:installProcessSetup:stream-enhance", {
        caller: "installProcessSetup",
        evidenceType: "startup-evaluation-route",
        sourceUrl: "<stream-enhance>",
      }),
      context,
    );
    expect(trustedEvaluation.edge.classification).toBe("non-capability");
    expect(trustedEvaluation.edge.rationaleId).toBe("runtime-bootstrap-state");

    const nativeFreezeObservationScript = classifyObservedSurface(
      surface("startup", "script:native-freeze-conformance-observation"),
      context,
    );
    expect(nativeFreezeObservationScript.edge.classification).toBe(
      "non-capability",
    );
    expect(nativeFreezeObservationScript.edge.rationaleId).toBe(
      "runtime-bootstrap-state",
    );

    const installRoute = classifyObservedSurface(
      surface("startup", "install-route:ex_hermes_create_impl:installGlobals", {
        evidenceType: "startup-installer-call-route",
      }),
      context,
    );
    expect(installRoute.edge.classification).toBe("non-capability");
    expect(installRoute.edge.rationaleId).toBe("authority-control-plane");

    const dynamicEnvironmentMetadata = {
      evidenceType: "dynamic-runtime-environment-sentinel",
      dynamic: true,
      accessDirections: ["read"],
    };
    const dynamicEnvironment = classifyObservedSurface(
      surface(
        "startup",
        "env:<dynamic>:javascript:process.env",
        dynamicEnvironmentMetadata,
      ),
      context,
    );
    expect(dynamicEnvironment.edge.classification).toBe("effects");
    expect(dynamicEnvironment.edge.effectMode).toBe("conjunctive");
    expect(edgeActions(dynamicEnvironment)).toEqual(["env:read"]);
    const escapedProcessEnvironment = classifyObservedSurface(
      surface(
        "startup",
        "env:<dynamic>:javascript:process-binding-flow",
        dynamicEnvironmentMetadata,
      ),
      context,
    );
    expect(escapedProcessEnvironment.edge.effectMode).toBe("conjunctive");
    expect(edgeActions(escapedProcessEnvironment)).toEqual(["env:read"]);

    for (const observed of [
      surface("startup", "evaluation:future_evaluator:remote-source", {
        evidenceType: "startup-evaluation-route",
      }),
      surface("startup", "install-route:installGlobals:futureInstaller", {
        evidenceType: "startup-installer-call-route",
      }),
      surface(
        "startup",
        "env:<dynamic>:javascript:futureEnvironmentApi",
        dynamicEnvironmentMetadata,
      ),
      surface("startup", "env:<dynamic>:javascript:process.env"),
    ]) {
      expect(() => classifyObservedSurface(observed, context)).toThrow(
        /unclassified observed surface/,
      );
    }
  });

  test("supervisor history routes are root-owned explicit effects", () => {
    const expected = new Map([
      ["supervisor-history.authenticated-project-scope", ["fs:list"]],
      ["supervisor-history.global-platform-data-root", ["env:read"]],
      ["supervisor-history.journal-append", ["fs:list", "fs:write"]],
      ["supervisor-history.journal-compact", ["fs:list", "fs:write"]],
      [
        "supervisor-history.journal-recover",
        ["fs:list", "fs:read", "fs:write"],
      ],
      ["supervisor-history.legacy-probe", ["fs:list"]],
      ["supervisor-history.project-platform-data-root", ["env:read"]],
      ["supervisor-history.sidecar-lock-acquire", ["fs:list", "fs:write"]],
      ["supervisor-history.store-open", ["fs:list", "fs:write"]],
      [
        "supervisor-history.user-key-read-create",
        ["fs:list", "fs:read", "fs:write"],
      ],
    ]);

    for (const [name, actions] of expected) {
      const classified = classifyObservedSurface(
        surface("startup", name),
        context,
      );
      expect(classified.edge.classification, name).toBe("effects");
      expect(edgeActions(classified), name).toEqual(actions);
      expect(classified.edge.principalSources, name).toEqual(["root"]);
      expect(classified.edge.effectOwnerSource, name).toBe("root");
    }

    expect(() =>
      classifyObservedSurface(
        surface("startup", "supervisor-history.future-route"),
        context,
      ),
    ).toThrow(/unclassified observed surface/);
  });

  test("native environment enumeration and explicit installGlobals routes stay exact", () => {
    for (const name of [
      "env:<dynamic>:cpp:::environ",
      "env:<dynamic>:cpp:GetEnvironmentStringsW",
      "env:<dynamic>:cpp:_NSGetEnviron",
    ]) {
      const classified = classifyObservedSurface(
        surface("startup", name, {
          evidenceType: "dynamic-runtime-environment-sentinel",
          dynamic: true,
          accessDirections: ["read"],
        }),
        context,
      );
      expect(classified.edge.classification, name).toBe("effects");
      expect(edgeActions(classified), name).toEqual(["env:read"]);
      expect(classified.edge.effectMode, name).toBe("conjunctive");
    }

    for (const [label, classification, semantic] of [
      ["capability-hardening", "non-capability", "authority-control-plane"],
      ["form-data", "non-capability", "runtime-bootstrap-state"],
      ["freeze-seal", "non-capability", "authority-control-plane"],
      ["fs-handle", "non-capability", "authority-control-plane"],
      [
        "native-freeze-conformance-observation",
        "non-capability",
        "runtime-bootstrap-state",
      ],
      ["web-crypto", "non-capability", "authority-control-plane"],
      ["web-storage", "non-capability", "authority-control-plane"],
    ]) {
      const name = `evaluation:installGlobals:${label}`;
      const classified = classifyObservedSurface(
        surface("startup", name, {
          evidenceType: "startup-evaluation-route",
          caller: "installGlobals",
          sourceUrl: `<${label}>`,
        }),
        context,
      );
      expect(classified.edge.classification, name).toBe(classification);
      if (classification === "closed") {
        expect(edgeActions(classified), name).toEqual([semantic]);
      } else {
        expect(classified.edge.rationaleId, name).toBe(semantic);
      }
    }

    const installers = [
      "installChildProcessHostFunctions",
      "installCryptoHostFunctions",
      "installDnsHostFunctions",
      "installFetchGlobals",
      "installFsHostFunctions",
      "installHttpHostFunctions",
      "installIpcListenerPatch",
      "installLegacyLazyBootstrapGetters",
      "installModuleLoader",
      "installNetHostFunctions",
      "installNetOwnerHostFunction",
      "installOsInfoGlobals",
      "installProcessSetup",
      "installSqliteHostFunctions",
      "installWebSocketGlobals",
    ];
    for (const installer of installers) {
      const name = `install-route:installGlobals:${installer}`;
      const classified = classifyObservedSurface(
        surface("startup", name, {
          evidenceType: "startup-installer-call-route",
          caller: "installGlobals",
          installer,
        }),
        context,
      );
      if (installer === "installIpcListenerPatch") {
        expect(classified.edge.classification, installer).toBe("closed");
        expect(edgeActions(classified), installer).toEqual(["ipc:channel"]);
      } else {
        expect(classified.edge.classification, installer).toBe(
          "non-capability",
        );
        expect(classified.edge.rationaleId, installer).toBe(
          "authority-control-plane",
        );
      }
    }

    expect(() =>
      classifyObservedSurface(
        surface("startup", "evaluation:installGlobals:fs-handle", {
          evidenceType: "startup-evaluation-route",
          caller: "invented-caller",
          sourceUrl: "<fs-handle>",
        }),
        context,
      ),
    ).toThrow(/unclassified observed surface/u);
  });

  test("exact inspector inventory distinguishes activation from runtime data", () => {
    for (const [name, expectedAction] of [
      ["inspector.cdp-listener", "inspector:activate"],
      ["inspector.cdp-http:/json/version", "inspector:activate"],
      [
        "inspector.cdp-request-fallback:json-rpc-error--32601",
        "inspector:activate",
      ],
      ["inspector.cdp-request:Runtime.evaluate", "runtime:inspect"],
      ["inspector.cdp-request:Network.getResponseBody", "runtime:inspect"],
      ["inspector.debugger-get-script-source", "runtime:inspect"],
      ["inspector.debugger-next-event", "runtime:inspect"],
    ]) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(classified.edge.classification, name).toBe("closed");
      expect(edgeActions(classified), name).toEqual([expectedAction]);
    }
  });

  test("startup environment controls are exact and cannot hide weakening", () => {
    for (const environmentName of [
      "IBEX_CAPSEC_ALLOW_ADVISORY",
      "IBEX_COMPARTMENTS",
      "IBEX_LOCKDOWN",
      "EX_SKIP_STARTUP_HOST_FUNCTIONS",
      "EXACT_ALLOW_INSECURE_CRYPTO",
      "EXACT_WPT_TRUST_LOOPBACK_TLS",
    ]) {
      const classified = classifyObservedSurface(
        surface("startup", `env:${environmentName}`),
        context,
      );
      expect(classified.edge.classification, environmentName).toBe("closed");
      expect(edgeActions(classified), environmentName).toEqual([
        "runtime:inspect",
      ]);
      expect(
        classified.implementationRows[0].implementationOwner,
        environmentName,
      ).toBe("WP9");
    }

    expect(() =>
      classifyObservedSurface(
        surface("startup", "env:EX_DISABLE_BYTECODE_SANITY_CHECK"),
        context,
      ),
    ).toThrow(/unclassified observed surface/u);

    expect(
      classifyObservedSurface(surface("startup", "env:EXACT_IPC_FD"), context)
        .edge,
    ).toMatchObject({ classification: "closed", cap: "ipc:channel" });
    expect(
      classifyObservedSurface(
        surface("startup", "env:NODE_CHANNEL_FD"),
        context,
      ).edge,
    ).toMatchObject({ classification: "closed", cap: "ipc:channel" });
    expect(
      classifyObservedSurface(
        surface("startup", "env:EXACT_IPC_SERIALIZATION"),
        context,
      ).edge,
    ).toMatchObject({ classification: "closed", cap: "ipc:channel" });
    for (const memberName of [null, "close", "fd", "serialization"]) {
      const name = memberName
        ? `__exactProcessIpcBootstrap.${memberName}`
        : "__exactProcessIpcBootstrap";
      const observed = memberName
        ? surface("native-op", name, {
            exportName: name,
            globalName: "__exactProcessIpcBootstrap",
            memberName,
            sourceKey: "native_jsi_global",
            surfaceType: "global-api",
          })
        : surface("native-op", name);
      const ipcBootstrap = classifyObservedSurface(observed, context);
      expect(ipcBootstrap.edge, name).toMatchObject({
        classification: "closed",
        cap: "ipc:channel",
      });
      expect(ipcBootstrap.implementationRows[0].implementationOwner, name).toBe(
        "WP7",
      );
    }

    for (const environmentName of [
      "EXACT_COMPAT_TEST",
      "EXACT_TEST_SECTION",
      "EX_BOOTSTRAP_GLOBALS_SOURCE",
      "EX_BOOTSTRAP_GLOBALS_HBC",
      "IBEX_STARTUP_TRACE",
      "IBEX_NO_BYTECODE",
      "EXACT_WATCH_SHUTDOWN_TIMEOUT_MS",
    ]) {
      const classified = classifyObservedSurface(
        surface("startup", `env:${environmentName}`),
        context,
      );
      expect(classified.edge.classification, environmentName).toBe(
        "non-capability",
      );
      expect(classified.edge.rationaleId, environmentName).toBe(
        "runtime-bootstrap-state",
      );
    }

    const fixedChildEnvironmentMetadata = {
      accessDirections: ["write"],
      accessors: ["Command::env"],
      authoredNames: ["XDG_CONFIG_HOME"],
      contexts: ["spawn-child-env"],
      dynamic: false,
      evidenceType: "static-runtime-environment-control",
      languages: ["rust"],
    };
    const fixedChildEnvironment = classifyObservedSurface(
      surface("startup", "env:XDG_CONFIG_HOME", fixedChildEnvironmentMetadata),
      context,
    );
    expect(fixedChildEnvironment.edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "authority-control-plane",
    });
    expect(
      fixedChildEnvironment.implementationRows[0].implementationOwner,
    ).toBe("WP7");
    for (const invalidMetadata of [
      { ...fixedChildEnvironmentMetadata, accessDirections: ["read"] },
      { ...fixedChildEnvironmentMetadata, contexts: ["startup-input"] },
      { ...fixedChildEnvironmentMetadata, accessors: ["env::var"] },
    ]) {
      expect(() =>
        classifyObservedSurface(
          surface("startup", "env:XDG_CONFIG_HOME", invalidMetadata),
          context,
        ),
      ).toThrow(/unclassified observed surface/u);
    }

    const callbackDelayHarness = classifyObservedSurface(
      surface("startup", "env:IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS"),
      context,
    );
    expect(callbackDelayHarness.edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "runtime-bootstrap-state",
    });

    for (const [environmentName, expectedActions, expectedMode] of [
      ["IBEX_POLICY", ["env:read", "fs:list", "fs:read"], "conditional"],
      ["IBEX_REPO_ROOT", ["env:read", "fs:list", "fs:read"], "conditional"],
      ["PATH", ["env:read", "fs:list", "process:spawn"], "conditional"],
      ["IBEX_DNS_SERVER", ["env:read", "network:resolve"], "conditional"],
      ["RES_OPTIONS", ["env:read", "network:resolve"], "conditional"],
      [
        "IBEX_HTTP_MAX_REQUEST_BODY_BYTES",
        ["env:read", "network:listen"],
        "conditional",
      ],
      ["EXACT_SECURITY_LOG", ["env:read", "stdio:write"], "conditional"],
      [
        "IBEX_SUPPRESS_CONSOLE_MIRROR",
        ["env:read", "stdio:write"],
        "conditional",
      ],
      [
        "EXACT_ANDROID_CACHE_DIR",
        ["env:read", "env:write", "fs:list", "fs:read", "fs:write"],
        "conditional",
      ],
      [
        "EXACT_ANDROID_EXTERNAL_FILES_DIR",
        ["env:read", "env:write", "fs:list", "fs:read", "fs:write"],
        "conditional",
      ],
      [
        "EXACT_TRANSPILE_SCRIPT",
        ["env:read", "fs:list", "fs:read", "process:spawn"],
        "conditional",
      ],
      [
        "EXACT_EXECUTABLE",
        ["env:read", "fs:list", "process:spawn"],
        "conditional",
      ],
      [
        "EXACT_COMPAT_EXECUTABLE",
        ["env:read", "fs:list", "process:spawn"],
        "conditional",
      ],
      ["COMSPEC", ["env:read", "fs:list", "process:spawn"], "conditional"],
      [
        "EXACT_WINHTTP_ENABLE_HTTP2",
        ["env:read", "network:fetch"],
        "conditional",
      ],
    ]) {
      const classified = classifyObservedSurface(
        surface("startup", `env:${environmentName}`),
        context,
      );
      expect(classified.edge.classification, environmentName).toBe("effects");
      expect(edgeActions(classified), environmentName).toEqual(expectedActions);
      expect(classified.edge.effectMode, environmentName).toBe(expectedMode);
    }

    for (const environmentName of [
      "NODE_ENV",
      "HOME",
      "USERPROFILE",
      "USERNAME",
      "TMPDIR",
      "TMP",
      "TEMP",
    ]) {
      const classified = classifyObservedSurface(
        surface("startup", `env:${environmentName}`),
        context,
      );
      expect(classified.edge.classification, environmentName).toBe("effects");
      expect(edgeActions(classified), environmentName).toEqual(["env:read"]);
    }

    for (const environmentName of [
      "IBEX_RUNTIME_TRANSFORM",
      "EXACT_RUNTIME_TRANSFORM",
      "IBEX_LEGACY_HERMES_BLOCK_SCOPING",
      "EXACT_CLUSTER_WORKER",
      "NODE_UNIQUE_ID",
      "EXACT_CLUSTER_ID",
    ]) {
      const classified = classifyObservedSurface(
        surface("startup", `env:${environmentName}`),
        context,
      );
      expect(classified.edge.classification, environmentName).toBe(
        "non-capability",
      );
    }

    expect(() =>
      classifyObservedSurface(
        surface("startup", "env:IBEX_FUTURE_WEAKENING"),
        context,
      ),
    ).toThrow(/unclassified observed surface/);
  });

  test("public ABI escape suffixes cannot inherit safe prefix classifications", () => {
    for (const name of [
      "ex_hermes_create_worker",
      "ex_worklet_callback_write_file",
      "ex_host_ensure_native_addon",
      "ex_host_close_and_transmit_secret",
    ]) {
      expect(() =>
        classifyObservedSurface(surface("host-abi", name), context),
      ).toThrow(/unclassified observed surface/);
    }
  });

  test("unknown native operations cannot inherit broad semantic suffixes", () => {
    for (const name of [
      "__exactEnsureNativeAddon",
      "__exactCloseAndTransmitSecret",
      "__exactCancelAndWriteFile",
      "__exactFreeStringAndConnect",
      "__exactNetworkSecret",
      "__exactCallbackWriteFile",
      "__exactSpawnAndReadSecrets",
      "__exactDnsAndWriteFile",
      "__exactCameraAndWriteFile",
      "candidateEnsure",
      "candidateClose",
      "candidateAbort",
      "candidateCallback",
      "candidateNetwork",
      "inspector.cdp-request-fallback:json-rpc-error--32000",
      "inspector.cdp-request-fallback:silent-success",
      "inspector.cdp-request:Runtime.futureEvaluate",
    ]) {
      expect(() =>
        classifyObservedSurface(surface("native-op", name), context),
      ).toThrow(/unclassified observed surface/);
    }
  });

  test("alternative implementation branches share one semantic edge", () => {
    const observed = surface("native-op", "__exactTcpConnect", {
      branches: [
        {
          id: "posix",
          targetVariant: "posix",
          sourceRefs: ["src/engine/hermes_runtime_net.cc#__exactTcpConnect"],
        },
        {
          id: "windows",
          targetVariant: "windows",
          sourceRefs: [
            "src/engine/hermes_runtime_platform_windows.cc#__exactTcpConnect",
          ],
        },
      ],
    });
    const classified = classifyObservedSurface(observed, context);
    expect(classified.edge.effects.map((row) => row.cap)).toEqual([
      "network:connect",
    ]);
    expect(classified.implementationRows).toHaveLength(2);
    expect(classified.implementationRows.map((row) => row.branchKind)).toEqual([
      "alternative",
      "alternative",
    ]);
    expect(
      new Set(classified.implementationRows.map((row) => row.edgeId)).size,
    ).toBe(1);
    expect(
      classified.implementationRows.map((row) => [
        row.targetVariant,
        row.targetApplicability,
      ]),
    ).toEqual([
      ["posix", { kind: "operating-system-family", value: "posix" }],
      ["windows", { kind: "operating-system", value: "windows" }],
    ]);
    expect(
      classified.implementationRows.every((row) =>
        row.fixtureObligations.every((fixtureId) =>
          fixtureId.startsWith(`${row.enforcementBranchId}.`),
        ),
      ),
    ).toBe(true);
    expect(classified.implementationRows[0].fixtureObligations).not.toEqual(
      classified.implementationRows[1].fixtureObligations,
    );
  });

  test("implementation branch applicability and provenance fail closed", () => {
    const observed = (branch) =>
      surface("native-op", "__exactTcpConnect", {
        branches: [
          {
            id: "candidate",
            sourceRefs: ["src/engine/backend.cc#__exactTcpConnect"],
            ...branch,
          },
        ],
      });
    expect(() =>
      classifyObservedSurface(
        observed({ targetVariant: "future-platform" }),
        context,
      ),
    ).toThrow(/unreviewed implementation target variant/);
    expect(() =>
      classifyObservedSurface(
        observed({
          targetVariant: "all",
          implementationDisposition: "probably-concrete",
        }),
        context,
      ),
    ).toThrow(/unreviewed implementation disposition/);
    expect(() =>
      classifyObservedSurface(
        observed({
          targetVariant: "all",
          fixtureObligations: ["invented.fixture"],
        }),
        context,
      ),
    ).toThrow(/authored fixture obligations disagree with semantic derivation/);
  });

  test("shared source refs alone cannot collapse distinct callable boundaries", () => {
    const sharedRef = ["src/engine/shared_network.cc#authorizeConnect"];
    const sync = classifyObservedSurface(
      surface("native-op", "__exactTcpConnect", undefined, sharedRef),
      context,
    ).implementationRows[0];
    const asynchronous = classifyObservedSurface(
      surface("native-op", "__exactTcpConnectStart", undefined, sharedRef),
      context,
    ).implementationRows[0];
    expect(sync.branchId).not.toBe(asynchronous.branchId);
    expect(sync.enforcementBranchId).not.toBe(asynchronous.enforcementBranchId);
    expect(sync.fixtureObligations).not.toEqual(
      asynchronous.fixtureObligations,
    );

    const distinctSource = classifyObservedSurface(
      surface("native-op", "__exactTcpConnectStart", undefined, [
        "src/engine/other_network.cc#authorizeConnect",
      ]),
      context,
    ).implementationRows[0];
    expect(distinctSource.enforcementBranchId).not.toBe(
      sync.enforcementBranchId,
    );
  });

  test("static builtin call routes join the exact native terminal and fail on mutation", () => {
    const terminal = surface("native-op", "__exactClipboardRead", undefined, [
      "src/engine/hermes_runtime_device.cc#__exactClipboardRead",
    ]);
    const facade = (terminalName) =>
      surface(
        "builtin",
        "export:exact_clipboard:readText",
        {
          surfaceType: "export",
          sourceKey: "exact_clipboard",
          exportName: "readText",
          enforcementRouteEvidence: {
            ambiguousCallees: [],
            kind: "static-builtin-call-graph",
            paths: [`export:readText -> readText -> ${terminalName}`],
            terminals: [terminalName],
          },
        },
        ["src/builtins/clipboard.js#exports:readText"],
      );
    const model = buildCoverageModel(
      [facade("__exactClipboardRead"), terminal],
      context,
    );
    const facadeRow = model.implementationRows.find(
      (row) => row.observedKey === "builtin:export:exact_clipboard:readText",
    );
    const terminalRow = model.implementationRows.find(
      (row) => row.observedKey === "native-op:__exactClipboardRead",
    );
    expect(facadeRow.enforcementBranchId).toBe(terminalRow.enforcementBranchId);
    expect(facadeRow.enforcementRoute).toEqual({
      kind: "static-builtin-call-graph",
      proofPaths: ["export:readText -> readText -> __exactClipboardRead"],
      proofSourceRefs: ["src/builtins/clipboard.js#exports:readText"],
      sourceRefs: ["src/engine/hermes_runtime_device.cc#__exactClipboardRead"],
      terminalObservedKey: "native-op:__exactClipboardRead",
    });

    const mutated = buildCoverageModel(
      [facade("__exactClipboardWrite"), terminal],
      context,
    ).implementationRows.find(
      (row) => row.observedKey === "builtin:export:exact_clipboard:readText",
    );
    expect(mutated.enforcementBranchId).not.toBe(
      terminalRow.enforcementBranchId,
    );
    expect(mutated.enforcementRoute.kind).toBe("exact-source-and-semantics");
  });

  test("native Fetch and WebSocket backend branches share exact network semantics", () => {
    const backendBranches = [
      ["android", "okhttp-jni", "concrete"],
      ["ios", "foundation-urlsession", "concrete"],
      ["linux:curl-cli-fallback", "curl-cli", "degraded-concrete"],
      ["linux:libcurl", "libcurl", "concrete"],
      ["macos", "foundation-urlsession", "concrete"],
      ["windows", "winhttp", "concrete"],
    ];
    const classifyBackend = (name) =>
      classifyObservedSurface(
        surface("native-op", name, {
          surfaceType: "native-network-backend",
          branches: backendBranches.map(
            ([targetVariant, backend, implementationDisposition], index) => ({
              id: `target-${index}`,
              targetVariant,
              backend,
              implementationDisposition,
              sourceRefs: [`src/engine/backend-${index}.cc#${name}`],
            }),
          ),
        }),
        context,
      );

    for (const [name, actions] of [
      ["native_fetch_perform", ["network:fetch"]],
      ["native_ws_connect", ["network:connect"]],
      ["native_ws_send", ["network:connect"]],
      ["native_ws_close", ["network:connect"]],
    ]) {
      const classified = classifyBackend(name);
      expect(edgeActions(classified), name).toEqual(actions);
      expect(classified.edge.lifetimeContract, name).toBe("socket-stream");
      expect(classified.implementationRows, name).toHaveLength(6);
      expect(
        classified.implementationRows.every(
          (row) => row.branchKind === "alternative",
        ),
        name,
      ).toBe(true);
      expect(
        new Set(classified.implementationRows.map((row) => row.edgeId)).size,
        name,
      ).toBe(1);
      expect(
        classified.implementationRows.map((row) => [
          row.targetVariant,
          row.backend,
          row.implementationDisposition,
        ]),
        name,
      ).toEqual(backendBranches);
    }

    const close = classifyBackend("native_ws_close");
    expect(close.edge.effectMode).toBe("conditional");
    expect(close.edge.effectOwnerSource).toBe("descriptor-owner");
    expect(classifyBackend("native_ws_send").edge.effectOwnerSource).toBe(
      "descriptor-owner",
    );

    for (const name of ["native_fetch_cancel", "native_ws_destroy"]) {
      expect(classifyBackend(name).edge, name).toMatchObject({
        classification: "non-capability",
        rationaleId: "authority-release",
      });
    }
    for (const name of [
      "native_ws_pause",
      "native_ws_resume",
      "native_ws_set_flow_controlled",
    ]) {
      expect(classifyBackend(name).edge, name).toMatchObject({
        classification: "non-capability",
        rationaleId: "authority-control-plane",
      });
    }
    expect(classifyBackend("native_ws_has_active").edge).toMatchObject({
      classification: "non-capability",
      rationaleId: "runtime-bootstrap-state",
    });
  });

  test("unclassified surfaces fail closed", () => {
    expect(() =>
      classifyObservedSurface(
        surface("native-op", "__exactQuantumTeleport"),
        context,
      ),
    ).toThrow(/unclassified observed surface/);
  });

  test("source filenames cannot classify an unknown surface", () => {
    expect(() =>
      classifyObservedSurface(
        surface("native-op", "__exactQuantumTeleport", undefined, [
          "src/engine/hermes_runtime_fs.cc#__exactQuantumTeleport",
        ]),
        context,
      ),
    ).toThrow(/unclassified observed surface/);
  });

  test("security and callback names are not reclassified by a crypto source file", () => {
    const grant = classifyObservedSurface(
      surface("native-op", "__exactGrantCapability", undefined, [
        "src/engine/hermes_runtime_crypto.cc#__exactGrantCapability",
      ]),
      context,
    );
    const signalDelivery = classifyObservedSurface(
      surface("native-op", "__exactDispatchPendingSignals", undefined, [
        "src/engine/hermes_runtime_crypto.cc#__exactDispatchPendingSignals",
      ]),
      context,
    );
    expect(grant.edge.classification).toBe("non-capability");
    expect(grant.edge.rationaleId).toBe("authority-control-plane");
    expect(signalDelivery.edge.classification).toBe("closed");
    expect(edgeActions(signalDelivery)).toEqual(["process:signal"]);
    expect(signalDelivery.implementationRows[0].fixtureObligations).toEqual([
      `${signalDelivery.implementationRows[0].branchId}.closed`,
    ]);
  });

  test("retained descriptor operations retain descriptor ownership", () => {
    for (const name of [
      "__exactFsRead",
      "__exactFsWrite",
      "ex_host_fs_pread",
    ]) {
      const kind = name.startsWith("ex_host_") ? "host-abi" : "native-op";
      const classified = classifyObservedSurface(surface(kind, name), context);
      expect(classified.edge.effectOwnerSource).toBe("descriptor-owner");
      expect(classified.edge.principalSources).toContain("descriptor-owner");
      expect(classified.edge.lifetimeContract).toBe("file-handle");
    }
  });

  test("listener creation belongs to the creator and retained use to the descriptor", () => {
    const create = classifyObservedSurface(
      surface("native-op", "__exactHttpServe"),
      context,
    );
    const use = classifyObservedSurface(
      surface("native-op", "__exactHttpRespondEnd"),
      context,
    );
    expect(create.edge.effectOwnerSource).toBe(
      "innermost-nontransparent-frame",
    );
    expect(use.edge.effectOwnerSource).toBe("descriptor-owner");
    expect(edgeActions(use)).toEqual(["network:listen"]);
  });

  test("unknown actions and normalizers fail closed", () => {
    expect(() => deriveEffectTemplate("future:unknown", context)).toThrow(
      /unknown action/,
    );

    const metadataOverride = surface("native-op", "__exactReadFile", {
      coverage: {
        classification: "non-capability",
        rationaleId: "pure-in-memory-compute",
      },
    });
    expect(() => classifyObservedSurface(metadataOverride, context)).toThrow(
      /source metadata cannot override semantic coverage classification/,
    );

    const brokenDefinitions = structuredClone(definitions);
    brokenDefinitions.definitions.find(
      (row) => row.id === "fs:read",
    ).normalizationProfile = "missing.normalizer.v1";
    expect(() =>
      classifyObservedSurface(surface("native-op", "__exactReadFile"), {
        definitions: brokenDefinitions,
        rules,
      }),
    ).toThrow(/unknown normalization profile/);
  });

  test("stable IDs distinguish aliases that sanitize to the same text", () => {
    const nodeAlias = surface("builtin", "node:fs", { sourceKey: "node_fs" });
    const dottedAlias = surface("builtin", "node.fs", { sourceKey: "node_fs" });
    expect(stableIdForSurface(nodeAlias)).not.toBe(
      stableIdForSurface(dottedAlias),
    );
  });

  test("coverage and implementation ordering is deterministic", () => {
    const observed = [
      surface("native-op", "__exactFsOpen"),
      surface("native-op", "__nativeFetch"),
      surface("callback", "callback.queue-enqueue"),
      surface("builtin", "node:fs", { sourceKey: "node_fs" }),
    ];
    const forward = buildCoverageModel(observed, context);
    const reverse = buildCoverageModel([...observed].reverse(), context);
    expect(JSON.stringify(forward)).toBe(JSON.stringify(reverse));
  });

  test("duplicate surfaces and explicit edge-ID collisions fail", () => {
    const one = surface("native-op", "__exactFsOpen");
    expect(() =>
      buildCoverageModel([one, structuredClone(one)], context),
    ).toThrow(/duplicate observed surface/);
    const first = surface("native-op", "__exactFsOpen", {
      edgeId: "surface.forced",
    });
    const second = surface("native-op", "__nativeFetch", {
      edgeId: "surface.forced",
    });
    expect(() => buildCoverageModel([first, second], context)).toThrow(
      /edge id collision/,
    );
  });

  test("definition coverage accounts for all 41 frozen definitions", () => {
    const model = buildCoverageModel(
      [
        surface("native-op", "__exactFsOpen"),
        surface("native-op", "__nativeFetch"),
        surface("native-op", "inspector.debugger-enable"),
      ],
      context,
    );
    expect(model.definitionCoverage).toHaveLength(41);
    expect(
      new Set(model.definitionCoverage.map((row) => row.definitionId)).size,
    ).toBe(41);
    expect(
      model.definitionCoverage.every((row) =>
        ["covered", "closed", "unsupported", "absent"].includes(
          row.disposition,
        ),
      ),
    ).toBe(true);
    expect(
      new Set(model.definitionCoverage.map((row) => row.disposition)),
    ).toEqual(new Set(["covered", "closed", "unsupported", "absent"]));
  });

  test("every currently observed repository surface joins exactly one semantic edge", async () => {
    const inventory = await discoverRepositorySurfaces(repoRoot);
    const liveBuiltinRoots = inventory.surfaces
      .filter(
        (row) =>
          row.kind === "builtin" && row.metadata?.surfaceType !== "export",
      )
      .map((row) => row.name)
      .sort();
    expect(reviewedBuiltinRootNames()).toEqual(liveBuiltinRoots);
    const liveBuiltinExportRows = inventory.surfaces.filter(
      (row) => row.kind === "builtin" && row.metadata?.surfaceType === "export",
    );
    const inheritedBuiltinExports = liveBuiltinExportRows.filter(
      (row) => row.metadata?.inheritedShape === true,
    );
    // The 22 additional rows are the reviewed zlib Transform `end`/`destroy`
    // overrides. They authenticate retained native streams before inherited
    // Transform state can commit a terminal transition. ServerResponse's
    // owner-gated appendHeader override and Duplex's materialized `_undestroy`
    // copy move two former inherited rows into the explicit export review, for
    // a net +20 inherited rows.
    expect(inheritedBuiltinExports).toHaveLength(458);
    const dnsReviewedInheritedExports = inheritedBuiltinExports.filter(
      (row) => row.metadata?.dnsPromiseExportShapeReviewId !== undefined,
    );
    expect(dnsReviewedInheritedExports).toHaveLength(4);
    expect(
      dnsReviewedInheritedExports.every(
        (row) => row.metadata.inheritedShapeReviewId === undefined,
      ),
    ).toBe(true);
    const genericallyReviewedInheritedExports = inheritedBuiltinExports.filter(
      (row) => row.metadata?.dnsPromiseExportShapeReviewId === undefined,
    );
    expect(genericallyReviewedInheritedExports).toHaveLength(454);
    expect(
      new Set(
        genericallyReviewedInheritedExports.map(
          (row) => row.metadata.inheritedShapeReviewId,
        ),
      ),
    ).toEqual(
      new Set([
        "sha256-a38490336f46e4dd2791e1e1fa14a1164d7c0da99f2670894ded67a33d8d1e2c",
      ]),
    );
    const reviewedBuiltinNames = new Set([
      ...reviewedBuiltinExportNames(),
      ...inheritedBuiltinExports.map((row) => row.name),
    ]);
    expect([...reviewedBuiltinNames].sort()).toEqual(
      liveBuiltinExportRows.map((row) => row.name).sort(),
    );
    const livePrivateNativeOperations = inventory.surfaces
      .filter(
        (row) =>
          row.kind === "native-op" &&
          (row.metadata?.surfaceType !== "global-api" ||
            row.metadata?.surfaceTypes?.includes("private-native-operation")) &&
          !row.name.startsWith("inspector."),
      )
      .map((row) => row.name)
      .sort();
    expect(reviewedNativeOperationNames()).toEqual(livePrivateNativeOperations);
    const liveDualRoleOperations = inventory.surfaces.filter(
      (row) =>
        row.kind === "native-op" &&
        row.metadata?.surfaceType === "global-api" &&
        row.metadata?.surfaceTypes?.includes("private-native-operation"),
    );
    // Session-boundary hardening added eight reviewed dual-role operations.
    // Integration may add more, but must never regress below that coverage
    // floor; the reviewed/live name equality above remains the exact check.
    expect(liveDualRoleOperations.length).toBeGreaterThanOrEqual(289);
    expect(
      liveDualRoleOperations.every(
        (row) =>
          row.metadata.semanticRoles?.includes("global-api-installation") &&
          row.metadata.semanticRoles?.includes("private-native-operation"),
      ),
    ).toBe(true);
    const liveCallbackProducers = inventory.surfaces
      .filter(
        (row) =>
          row.kind === "callback" &&
          row.metadata?.evidenceType === "push-runtime-callback-producer",
      )
      .map((row) => row.name)
      .sort();
    expect(liveCallbackProducers).toContain(
      "producer:src/engine/hermes_runtime_fs_windows.cc:startFsAsync:pushRuntimeCallback",
    );
    expect(reviewedCallbackProducerNames()).toEqual(liveCallbackProducers);
    const liveCallbackIngresses = inventory.surfaces
      .filter(
        (row) =>
          row.kind === "callback" &&
          row.metadata?.evidenceType === "versioned-callback-table-ingress",
      )
      .map((row) => row.name)
      .sort();
    expect(reviewedCallbackIngressNames()).toEqual(liveCallbackIngresses);
    assertReviewedSurfaceInventory(inventory.surfaces);

    const liveGlobalApiRows = inventory.surfaces.filter(
      (row) => row.metadata?.surfaceType === "global-api",
    );
    const inheritedGlobalApis = liveGlobalApiRows.filter(
      (row) => row.metadata?.inheritedShape === true,
    );
    expect(
      new Set(
        inheritedGlobalApis.map((row) => row.metadata.inheritedShapeReviewId),
      ),
    ).toEqual(
      new Set([
        "sha256-c9c7018e05cebdc8e26bb9d46773b3c06643cfa84cec49d86a401d30a1e7e430",
      ]),
    );
    const reviewedGlobalNames = new Set([
      ...reviewedGlobalApiNames(),
      ...inheritedGlobalApis.map((row) => row.name),
      ...liveGlobalApiRows
        .filter((row) =>
          row.metadata?.semanticRoles?.includes("dynamic-call-result-shape"),
        )
        .map((row) => row.name),
    ]);
    expect([...reviewedGlobalNames].sort()).toEqual(
      liveGlobalApiRows.map((row) => row.name).sort(),
    );
    const liveHostAbis = inventory.surfaces
      .filter((row) => row.kind === "host-abi")
      .map((row) => row.name)
      .sort();
    expect(reviewedHostAbiNames()).toEqual(liveHostAbis);
    const liveInspectorNatives = inventory.surfaces
      .filter(
        (row) => row.kind === "native-op" && row.name.startsWith("inspector."),
      )
      .map((row) => row.name)
      .sort();
    expect(reviewedInspectorNativeNames()).toEqual(liveInspectorNatives);
    const liveCliNames = inventory.surfaces
      .filter((row) => row.kind === "cli")
      .map((row) => row.name)
      .sort();
    const generatedReplCliNames = inventory.surfaces
      .filter(
        (row) =>
          row.kind === "cli" &&
          new Set([
            "repl-command-recognition",
            "repl-command-route",
            "repl-keybinding",
            "repl-load-extension",
          ]).has(row.metadata?.evidenceType),
      )
      .map((row) => row.name);
    expect(
      [...new Set([...reviewedCliNames(), ...generatedReplCliNames])].sort(),
    ).toEqual(liveCliNames);
    const liveLoaderNames = inventory.surfaces
      .filter((row) => row.kind === "loader")
      .map((row) => row.name)
      .sort();
    expect(reviewedLoaderNames()).toEqual(liveLoaderNames);
    const liveStartupNames = inventory.surfaces
      .filter((row) => row.kind === "startup")
      .map((row) => row.name)
      .sort();
    expect(reviewedStartupNames()).toEqual(liveStartupNames);
    const model = buildCoverageModel(inventory.surfaces, context);
    const observedKeys = new Set(
      inventory.surfaces.map((row) => row.observedKey),
    );
    const edgeByObservedKey = new Map(
      model.coverage.edges.map((edge) => [
        `${edge.surface.kind}:${edge.surface.name}`,
        edge,
      ]),
    );
    const liveClosedFsMutationKeys = model.coverage.edges
      .filter((edge) => edge.cap === "fs:unbound-mutation")
      .map((edge) => {
        const key = `${edge.surface.kind}:${edge.surface.name}`;
        return edge.surface.kind === "builtin" ? key.toLowerCase() : key;
      })
      .sort();
    expect(reviewedClosedFsMutationObservedKeys()).toEqual(
      liveClosedFsMutationKeys,
    );
    expect(liveClosedFsMutationKeys).toHaveLength(76);
    expect(inventory.surfaces.length).toBeGreaterThan(500);
    for (const expected of [
      "builtin:export:node_fs:watch",
      "host-abi:ex_hermes_eval",
      "host-abi:ex_worklet_create",
      "native-op:global:AsyncFunction",
      "native-op:global:Function",
      "native-op:global:GeneratorFunction",
      "native-op:global:eval",
      "native-op:global:localStorage.getItem",
      "native-op:global:sessionStorage.setItem",
    ]) {
      expect(observedKeys.has(expected)).toBe(true);
    }
    expect(model.coverage.edges).toHaveLength(inventory.surfaces.length);
    expect(model.implementationRows.length).toBeGreaterThanOrEqual(
      inventory.surfaces.length,
    );
    expect(
      new Set(model.implementationRows.map((row) => row.observedKey)).size,
    ).toBe(inventory.surfaces.length);
    expect(
      model.coverage.edges.every(
        (edge) =>
          !Object.hasOwn(edge.surface, "sourceRef") &&
          !Object.hasOwn(edge, "fixtures") &&
          !Object.hasOwn(edge, "implementationOwner"),
      ),
    ).toBe(true);
    expect(
      model.implementationRows.some((row) => row.branchKind === "alternative"),
    ).toBe(true);
    expect(edgeByObservedKey.get("native-op:__svGet")).toMatchObject({
      classification: "closed",
      cap: "ipc:channel",
    });
    expect(
      edgeByObservedKey.get("native-op:__exactGrantCapability"),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "authority-control-plane",
    });
    expect(edgeByObservedKey.get("builtin:export:node_fs:watch")).toMatchObject(
      {
        classification: "closed",
        cap: "fs:unbound-mutation",
      },
    );
    for (const evaluator of [
      "AsyncFunction",
      "Function",
      "GeneratorFunction",
      "eval",
    ]) {
      expect(
        edgeByObservedKey.get(`native-op:global:${evaluator}`),
        evaluator,
      ).toMatchObject({ classification: "closed", cap: "vm:evaluate" });
    }
    expect(
      edgeByObservedKey.get("host-abi:ex_host_sqlite_values"),
    ).toMatchObject({
      classification: "effects",
      effectMode: "conditional",
      effects: [{ cap: "fs:read" }],
    });
    expect(edgeByObservedKey.get("native-op:__exactGetAllEnv")).toMatchObject({
      classification: "effects",
      effectMode: "conditional",
      effects: [{ cap: "env:read" }],
    });
    expect(
      edgeByObservedKey.get("host-abi:ex_hermes_debugger_next_event"),
    ).toMatchObject({ classification: "closed", cap: "runtime:inspect" });
    expect(
      edgeByObservedKey.get("native-op:inspector.debugger-next-event"),
    ).toMatchObject({ classification: "closed", cap: "runtime:inspect" });
    expect(edgeByObservedKey.get("host-abi:ex_host_console_log")).toMatchObject(
      {
        classification: "effects",
        principalSources: ["frame-set", "schedule-time"],
        effectOwnerSource: "innermost-nontransparent-frame",
        effects: [{ cap: "stdio:write" }],
      },
    );
    expect(
      edgeByObservedKey.get("host-abi:ex_host_console_flush"),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "callback-attribution-carrier",
    });
    expect(
      edgeByObservedKey.get("host-abi:ex_hermes_runtime_nonce"),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "authority-control-plane",
    });
    expect(
      edgeByObservedKey.get("host-abi:ex_hermes_module_compile_factory"),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "module-reachability-only",
    });
    expect(
      edgeByObservedKey.get("host-abi:ex_hermes_module_load_carrier_factory"),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "module-reachability-only",
    });
    expect(
      edgeByObservedKey.get("host-abi:ex_hermes_module_release_handle"),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "authority-release",
    });
    expect(
      edgeByObservedKey.get("host-abi:ex_hermes_module_record_namespace_json"),
    ).toMatchObject({
      classification: "closed",
      cap: "runtime:inspect",
    });
    expect(
      edgeByObservedKey.get(
        "host-abi:ex_hermes_schedule_watchdog_heartbeat_for_generation",
      ),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "callback-attribution-carrier",
    });
    for (const [exportName, effects] of [
      ["ReadStream._read", ["fs:list", "fs:read"]],
      ["ReadStream.open", ["fs:list", "fs:read"]],
      ["WriteStream._final", ["fs:list", "fs:write"]],
      ["WriteStream._write", ["fs:list", "fs:write"]],
      ["WriteStream._writev", ["fs:list", "fs:write"]],
      ["WriteStream.open", ["fs:list", "fs:write"]],
    ]) {
      expect(
        edgeByObservedKey.get(`builtin:export:node_fs:${exportName}`),
        exportName,
      ).toMatchObject({
        classification: "effects",
        effectMode: "conditional",
        effects: effects.map((cap) => ({ cap })),
      });
    }
    for (const exportName of [
      "ReadStream.close",
      "ReadStream.destroy",
      "WriteStream._emitClose",
      "WriteStream.close",
      "WriteStream.destroy",
    ]) {
      expect(
        edgeByObservedKey.get(`builtin:export:node_fs:${exportName}`),
        exportName,
      ).toMatchObject({
        classification: "non-capability",
        rationaleId: "authority-release",
      });
    }
    for (const owner of ["Socket", "Stream"]) {
      for (const member of [
        "_connecting",
        "bufferSize",
        "bytesWritten",
        "readableHighWaterMark",
        "writableCorked",
        "writableEnded",
        "writableHighWaterMark",
        "writableLength",
        "writableNeedDrain",
      ]) {
        const exportName = `${owner}.${member}`;
        expect(
          edgeByObservedKey.get(`builtin:export:node_net:${exportName}`),
          exportName,
        ).toMatchObject({
          classification: "effects",
          effectMode: "conditional",
          effectOwnerSource: "descriptor-owner",
          effects: [{ cap: "network:connect" }, { cap: "network:listen" }],
        });
      }
    }
    for (const memberName of [
      "fs.readHandle.[[return]].readFileSync",
      "fs.readHandle.[[return]].readTextSync",
    ]) {
      expect(
        edgeByObservedKey.get(`native-op:global:Ibex.${memberName}`),
        memberName,
      ).toMatchObject({
        classification: "effects",
        effectOwnerSource: "descriptor-owner",
        lifetimeContract: "file-handle",
        effects: [{ cap: "fs:read" }],
      });
    }
    for (const [observedKey, rationaleId] of [
      [
        "native-op:global:Ibex.fs.readHandle.[[return]].scoped",
        "authority-control-plane",
      ],
      [
        "native-op:global:Ibex.fs.readHandle.[[return]].revoke",
        "authority-release",
      ],
      [
        "native-op:global:ReadableStream.[[return]].__exactReadableStreamIteratorPatched",
        "runtime-bootstrap-state",
      ],
      [
        "native-op:global:ReadableStream.[[return]].getReader",
        "retained-object-wrapper",
      ],
      [
        "native-op:global:ReadableStream.[[return]].tee",
        "retained-object-wrapper",
      ],
      [
        "native-op:global:ReadableStream.[[return]].values",
        "retained-object-wrapper",
      ],
      ["native-op:global:VideoFrame.[[return]].close", "authority-release"],
    ]) {
      expect(edgeByObservedKey.get(observedKey), observedKey).toMatchObject({
        classification: "non-capability",
        rationaleId,
      });
    }
    expect(
      edgeByObservedKey.get("host-abi:ex_android_initialize"),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "runtime-bootstrap-state",
    });
    expect(
      edgeByObservedKey.get(
        "host-abi:java:dev.ibex.runtime.IbexNetworking.fetch",
      ),
    ).toMatchObject({
      classification: "effects",
      effects: [{ cap: "network:fetch" }],
    });
    expect(
      edgeByObservedKey.get(
        "host-abi:java:dev.ibex.runtime.IbexNetworking.closeWebSocket",
      ),
    ).toMatchObject({
      classification: "effects",
      effectMode: "conditional",
      effectOwnerSource: "descriptor-owner",
      effects: [{ cap: "network:connect" }],
    });
    expect(
      edgeByObservedKey.get(
        "host-abi:java:dev.ibex.runtime.IbexNetworking.cameraHostCall",
      ),
    ).toMatchObject({
      classification: "effects",
      effectMode: "conditional",
      effects: [{ cap: "device:camera" }, { cap: "device:microphone" }],
    });
    expect(
      edgeByObservedKey.get(
        "host-abi:java:dev.ibex.runtime.IbexNetworking.dialog",
      ),
    ).toMatchObject({ classification: "closed", cap: "ipc:channel" });
    expect(
      edgeByObservedKey.get(
        "host-abi:java:dev.ibex.runtime.IbexNetworking.getCurrentLocation",
      ),
    ).toMatchObject({
      classification: "effects",
      effects: [{ cap: "device:location" }],
    });
    expect(
      edgeByObservedKey.get(
        "host-abi:java:dev.ibex.runtime.IbexNetworking.platformVersion",
      ),
    ).toMatchObject({
      classification: "effects",
      effects: [{ cap: "sys:read" }],
    });
    expect(
      edgeByObservedKey.get(
        "host-abi:java:dev.ibex.runtime.IbexNetworking.setClient",
      ),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "authority-control-plane",
    });
    expect(
      edgeByObservedKey.get(
        "host-abi:jni:dev.ibex.runtime.IbexNetworking.nativeFetchDidComplete",
      ),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "callback-attribution-carrier",
    });
    for (const name of [
      "env:<dynamic>:cpp:::environ",
      "env:<dynamic>:cpp:GetEnvironmentStringsW",
      "env:<dynamic>:cpp:_NSGetEnviron",
    ]) {
      expect(edgeByObservedKey.get(`startup:${name}`), name).toMatchObject({
        classification: "effects",
        effectMode: "conjunctive",
        effects: [{ cap: "env:read" }],
      });
    }
    for (const [label, expected] of [
      [
        "capability-hardening",
        {
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        },
      ],
      [
        "form-data",
        {
          classification: "non-capability",
          rationaleId: "runtime-bootstrap-state",
        },
      ],
      [
        "freeze-seal",
        {
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        },
      ],
      [
        "fs-handle",
        {
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        },
      ],
      [
        "native-freeze-conformance-observation",
        {
          classification: "non-capability",
          rationaleId: "runtime-bootstrap-state",
        },
      ],
      [
        "web-crypto",
        {
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        },
      ],
      [
        "web-storage",
        {
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        },
      ],
    ]) {
      const name = `evaluation:installGlobals:${label}`;
      expect(edgeByObservedKey.get(`startup:${name}`), name).toMatchObject(
        expected,
      );
    }
    expect(
      edgeByObservedKey.get(
        "startup:script:native-freeze-conformance-observation",
      ),
    ).toMatchObject({
      classification: "non-capability",
      rationaleId: "runtime-bootstrap-state",
    });
    for (const installer of [
      "installChildProcessHostFunctions",
      "installCryptoHostFunctions",
      "installDnsHostFunctions",
      "installFetchGlobals",
      "installFsHostFunctions",
      "installHttpHostFunctions",
      "installIpcListenerPatch",
      "installLegacyLazyBootstrapGetters",
      "installModuleLoader",
      "installNetHostFunctions",
      "installNetOwnerHostFunction",
      "installOsInfoGlobals",
      "installProcessSetup",
      "installSqliteHostFunctions",
      "installWebSocketGlobals",
    ]) {
      const name = `install-route:installGlobals:${installer}`;
      expect(edgeByObservedKey.get(`startup:${name}`), name).toMatchObject(
        installer === "installIpcListenerPatch"
          ? { classification: "closed", cap: "ipc:channel" }
          : {
              classification: "non-capability",
              rationaleId: "authority-control-plane",
            },
      );
    }
    for (const category of [
      "cache",
      "load",
      "resolution",
      "subprocess",
      "transform",
    ]) {
      const observedKey = `loader:external-calls:${category}`;
      expect(edgeByObservedKey.get(observedKey), observedKey).toMatchObject({
        classification: "non-capability",
        rationaleId: "module-reachability-only",
      });
    }
    for (const category of ["cache", "load", "resolution", "transform"]) {
      const observedKey = `loader:operation:${category}:write`;
      expect(edgeByObservedKey.get(observedKey), observedKey).toMatchObject({
        classification: "effects",
        effects: [{ cap: "fs:list" }, { cap: "fs:write" }],
      });
    }
    for (const category of ["cache", "load", "resolution", "transform"]) {
      for (const accessor of [
        "legacy_runtime_transform",
        "runtime_transform",
      ]) {
        const observedKey = `loader:route:${category}:rust:${accessor}`;
        expect(edgeByObservedKey.get(observedKey), observedKey).toMatchObject({
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        });
      }
    }
    for (const name of [
      "operation:load:process-id",
      "operation:resolution:env-current_dir",
      "operation:resolution:process-id",
      "operation:transform:process-id",
    ]) {
      const observedKey = `loader:${name}`;
      expect(edgeByObservedKey.get(observedKey), observedKey).toMatchObject({
        classification: "effects",
        effects: [{ cap: "sys:read" }],
      });
    }
    for (const [name, expected] of [
      [
        "native_fetch_cancel",
        { classification: "non-capability", rationaleId: "authority-release" },
      ],
      [
        "native_fetch_perform",
        { classification: "effects", effects: [{ cap: "network:fetch" }] },
      ],
      [
        "native_ws_close",
        {
          classification: "effects",
          effectMode: "conditional",
          effectOwnerSource: "descriptor-owner",
          effects: [{ cap: "network:connect" }],
        },
      ],
      [
        "native_ws_connect",
        { classification: "effects", effects: [{ cap: "network:connect" }] },
      ],
      [
        "native_ws_destroy",
        { classification: "non-capability", rationaleId: "authority-release" },
      ],
      [
        "native_ws_has_active",
        {
          classification: "non-capability",
          rationaleId: "runtime-bootstrap-state",
        },
      ],
      [
        "native_ws_pause",
        {
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        },
      ],
      [
        "native_ws_resume",
        {
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        },
      ],
      [
        "native_ws_send",
        {
          classification: "effects",
          effectOwnerSource: "descriptor-owner",
          effects: [{ cap: "network:connect" }],
        },
      ],
      [
        "native_ws_set_flow_controlled",
        {
          classification: "non-capability",
          rationaleId: "authority-control-plane",
        },
      ],
    ]) {
      const observedKey = `native-op:${name}`;
      expect(edgeByObservedKey.get(observedKey), observedKey).toMatchObject(
        expected,
      );
      const implementationRows = model.implementationRows.filter(
        (row) => row.observedKey === observedKey,
      );
      expect(implementationRows, observedKey).toHaveLength(6);
      expect(
        implementationRows.every((row) => row.branchKind === "alternative"),
        observedKey,
      ).toBe(true);
    }
    for (const [observedKey, expected] of [
      [
        "builtin:export:exact_crypto:DiffieHellman",
        { classification: "non-capability" },
      ],
      [
        "builtin:export:internal_fs_utils:toPathIfFileURL",
        { classification: "non-capability" },
      ],
      [
        "builtin:export:node_zlib:ZSTD_c_nbWorkers",
        { classification: "non-capability" },
      ],
      [
        "builtin:export:node_worker_threads:Worker",
        { classification: "closed", cap: "worker:create" },
      ],
      [
        "builtin:export:exact_crypto:setEngine",
        { classification: "closed", cap: "ffi:load" },
      ],
    ]) {
      expect(edgeByObservedKey.get(observedKey), observedKey).toMatchObject(
        expected,
      );
    }
  }, 60_000);
});
