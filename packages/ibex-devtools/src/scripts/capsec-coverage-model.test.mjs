// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — the
// semantic classifier is closed over observed surfaces and produces stable,
// reproducible coverage and implementation joins.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildCoverageModel,
  classifyObservedSurface,
  deriveEffectTemplate,
  derivePositiveSources,
  reviewedBuiltinExportNames,
  reviewedBuiltinRootNames,
  reviewedCallbackProducerNames,
  reviewedCliNames,
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
  "sha256-8e6f277ae960175a3b0d16dd2276576f3be5e17c4e5a8d9cb9da47dc239096f8";

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

function builtinExport(sourceKey, exportName) {
  return surface(
    "builtin",
    `export:${sourceKey}:${exportName}`,
    { surfaceType: "export", sourceKey, exportName },
    [`modules.ts#${sourceKey}.${exportName}`],
  );
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
      authorityRef: "scripts/install-windows-hermes.ps1#Version",
      profileId: "windows-nuget",
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
      engineProfileIds: ["android-maven", "source-patched", "windows-nuget"],
      installationBranches: branches,
      lockdownTamingDigest: REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST,
      tamingEvidence: "kLockdownJS",
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
      surface("native-op", "__exactOSVersion"),
      "effects",
      ["sys:read"],
    ],
    [
      "copy reads and writes",
      surface("native-op", "__exactCopyFile"),
      "effects",
      ["fs:read", "fs:write"],
    ],
    [
      "readlink reads link bytes",
      surface("native-op", "__exactReadlink"),
      "effects",
      ["fs:read"],
    ],
    [
      "hard link reads and writes",
      surface("native-op", "__exactLink"),
      "effects",
      ["fs:read", "fs:write"],
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
      "effects",
      ["fs:list", "fs:watch"],
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
    expect(sqliteValues.edge.effectMode).toBe("conditional-unrefined");
    expect(sqliteValues.edge.refinementOwner).toBe("WP5");
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
      expect(classified.edge.effectMode, exportName).toBe(
        "conditional-unrefined",
      );
      expect(classified.edge.refinementOwner, exportName).toBe("WP5");
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
        expect(classified.edge.effectMode, exportName).toBe(
          "conditional-unrefined",
        );
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
      expect(classified.edge.effectMode, exportName).toBe(
        "conditional-unrefined",
      );
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
      expect(classified.edge.effectMode, operation).toBe(
        "conditional-unrefined",
      );
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
    expect(closeWebSocket.edge.effectMode).toBe("conditional-unrefined");
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

  test("environment enumeration remains per-concrete-key WP7 refinement", () => {
    const classified = classifyObservedSurface(
      surface("native-op", "__exactGetAllEnv"),
      context,
    );
    expect(classified.edge.classification).toBe("effects");
    expect(edgeActions(classified)).toEqual(["env:read"]);
    expect(classified.edge.effectMode).toBe("conditional-unrefined");
    expect(classified.edge.refinementOwner).toBe("WP7");
    expect(classified.edge.rationale).toMatch(/every concrete key/u);
  });

  test("normalizers and positive sources come only from capability definitions", () => {
    const classified = classifyObservedSurface(
      surface("native-op", "__exactReadFile"),
      context,
    );
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
  });

  test("parameter-dependent effects remain explicitly unrefined and unclaimable", () => {
    for (const name of [
      "__exactFsOpen",
      "__exactSpawn",
      "__exactAndroidCameraHostCall",
      "__exactTcpRead",
      "__exactSqliteOpen",
    ]) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(classified.edge.effectMode).toBe("conditional-unrefined");
      expect(classified.edge.refinementOwner).toMatch(/^WP/);
      expect(classified.edge.rationale.length).toBeGreaterThan(20);
      expect(classified.implementationRows[0].fixtureObligations).toContain(
        `${classified.implementationRows[0].branchId}.conditional-refinement`,
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
        "conditional-unrefined",
      ],
      ["node_child_process", "ChildProcess.kill", "closed", ["process:signal"]],
      ["node_child_process", "ChildProcess.send", "closed", ["ipc:channel"]],
      [
        "node_dns",
        "Resolver.resolveTxt",
        "effects",
        ["network:connect", "network:listen", "network:resolve"],
        "conditional-unrefined",
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
        "conditional-unrefined",
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
        "conditional-unrefined",
      ],
      [
        "node_net",
        "Server.listen",
        "effects",
        ["fs:write", "network:listen"],
        "conditional-unrefined",
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
        "conditional-unrefined",
      ],
      [
        "node_fs",
        "ReadStream.constructor",
        "effects",
        ["fs:list", "fs:read"],
        "conditional-unrefined",
      ],
      [
        "node_fs",
        "WriteStream",
        "effects",
        ["fs:list", "fs:write"],
        "conditional-unrefined",
      ],
      [
        "node_fs",
        "WriteStream.constructor",
        "effects",
        ["fs:list", "fs:write"],
        "conditional-unrefined",
      ],
      ["node_fs", "Dir.read", "effects", ["fs:list"], "conjunctive"],
      [
        "node_http",
        "ClientRequest.write",
        "effects",
        ["network:connect"],
        "conditional-unrefined",
      ],
      [
        "node_http",
        "IncomingMessage.read",
        "effects",
        ["network:connect", "network:listen"],
        "conditional-unrefined",
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
        "conditional-unrefined",
      ],
      [
        "ws",
        "WebSocket.send",
        "effects",
        ["network:connect", "network:listen"],
        "conditional-unrefined",
      ],
      ["ws", "WebSocket.terminate", "non-capability", []],
      [
        "exact_sqlite",
        "Database",
        "effects",
        ["fs:list", "fs:read", "fs:write"],
        "conditional-unrefined",
      ],
      [
        "exact_sqlite",
        "default",
        "effects",
        ["fs:list", "fs:read", "fs:write"],
        "conditional-unrefined",
      ],
      [
        "exact_sqlite",
        "Database.close",
        "effects",
        ["fs:write"],
        "conditional-unrefined",
      ],
      [
        "exact_sqlite",
        "default.close",
        "effects",
        ["fs:write"],
        "conditional-unrefined",
      ],
      ["exact_sqlite", "Database.enableCrSqlite", "closed", ["ffi:load"]],
      ["exact_sqlite", "Database.loadExtension", "closed", ["ffi:load"]],
      ["exact_sqlite", "Database.handle", "closed", ["ffi:load"]],
      [
        "exact_sqlite",
        "Statement.all",
        "effects",
        ["fs:read"],
        "conditional-unrefined",
      ],
      [
        "exact_sqlite",
        "Statement.run",
        "effects",
        ["fs:read", "fs:write"],
        "conditional-unrefined",
      ],
      ["exact_sqlite", "deserialize", "non-capability", []],
      [
        "node_readline",
        "Interface",
        "effects",
        ["stdio:raw", "stdio:read", "stdio:write"],
        "conditional-unrefined",
      ],
      [
        "node_readline",
        "createInterface",
        "effects",
        ["stdio:raw", "stdio:read", "stdio:write"],
        "conditional-unrefined",
      ],
      [
        "node_readline",
        "Interface.resume",
        "effects",
        ["stdio:read"],
        "conditional-unrefined",
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

  test("DNS builtin loading accounts for synchronous resolver-file reads", () => {
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
      expect(edgeActions(classified), alias).toEqual(["fs:list", "fs:read"]);
      expect(classified.edge.effectMode, alias).toBe("conditional-unrefined");
    }

    for (const sourceKey of ["node_dns", "node_dns_promises"]) {
      const classified = classifyObservedSurface(
        builtinExport(sourceKey, "default"),
        context,
      );
      expect(edgeActions(classified), sourceKey).toEqual([
        "fs:list",
        "fs:read",
      ]);
      expect(classified.edge.effectMode, sourceKey).toBe(
        "conditional-unrefined",
      );
    }
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
        "conditional-unrefined",
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
      expect(classified.edge.effectMode, name).toBe("conditional-unrefined");
    }
  });

  test("native process termination is closed rather than authority release", () => {
    for (const name of ["__exactExit", "__exactHostExit"]) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(classified.edge.classification, name).toBe("closed");
      expect(edgeActions(classified), name).toEqual(["process:signal"]);
    }
  });

  test("filesystem watcher polling authorizes discovery and repeated watch", () => {
    for (const exportName of ["watch", "watchFile"]) {
      const classified = classifyObservedSurface(
        builtinExport("node_fs", exportName),
        context,
      );
      expect(classified.edge.classification, exportName).toBe("effects");
      expect(edgeActions(classified), exportName).toEqual([
        "fs:list",
        "fs:watch",
      ]);
      expect(classified.edge.lifetimeContract, exportName).toBe("watch");
    }
  });

  test("shared registries and unowned numeric handles remain closed", () => {
    for (const [sourceKey, exportName, expectedAction] of [
      ["node_cluster", "disconnect", "ipc:channel"],
      ["node_fs", "unwatchFile", "runtime:inspect"],
      ["node_module", "Module", "runtime:inspect"],
      ["node_module", "createRequire", "runtime:inspect"],
      ["node_timers", "clearImmediate", "runtime:inspect"],
      ["node_timers", "clearInterval", "runtime:inspect"],
      ["node_timers", "clearTimeout", "runtime:inspect"],
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

    for (const name of [
      "__exactTimerRef",
      "__exactTimerUnref",
      "__exactTlsEngineNew",
      "__exactTlsEngineWriteTls",
      "__exactTlsEngineReadPlain",
      "__exactTlsEnginePeerCerts",
      "__exactTlsEngineClose",
      "__exactZlibCreate",
      "__exactZlibWrite",
      "__exactZlibParams",
      "__exactZlibClose",
      "__exactUncaughtExceptionHandler",
    ]) {
      const classified = classifyObservedSurface(
        surface("native-op", name),
        context,
      );
      expect(classified.edge.classification, name).toBe("closed");
      expect(edgeActions(classified), name).toEqual(["runtime:inspect"]);
    }

    const spawnPoll = classifyObservedSurface(
      surface("native-op", "__exactSpawnPoll"),
      context,
    );
    expect(edgeActions(spawnPoll)).toEqual(["process:spawn"]);
    expect(spawnPoll.edge.lifetimeContract).toBe("child-process");
    expect(spawnPoll.edge.effectOwnerSource).toBe("descriptor-owner");

    for (const globalName of [
      "clearImmediate",
      "clearTimeout",
      "clearInterval",
    ]) {
      const classified = classifyObservedSurface(
        globalApi(globalName),
        context,
      );
      expect(classified.edge.classification, globalName).toBe("closed");
      expect(edgeActions(classified), globalName).toEqual(["runtime:inspect"]);
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
      expect(classified.edge.effectMode, exportName).toBe(
        "conditional-unrefined",
      );
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
      expect(classified.edge.effectMode).toBe("conditional-unrefined");
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
      expect(classified.edge.effectMode, exportName).toBe(
        "conditional-unrefined",
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
      expect(classified.edge.effectMode, name).toBe("conditional-unrefined");
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
    expect(transpile.edge.effectMode).toBe("conditional-unrefined");
    expect(transpile.edge.lifetimeContract).toBe("child-process");

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
      expect(classified.edge.effectMode, name).toBe("conditional-unrefined");
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
      const name = `operation:${category}:create`;
      expect(
        edgeActions(classifyObservedSurface(surface("loader", name), context)),
        name,
      ).toEqual(["fs:list", "fs:write"]);
    }

    for (const category of [
      "cache",
      "load",
      "resolution",
      "subprocess",
      "transform",
    ]) {
      const name = `operation:${category}:env-var`;
      expect(
        edgeActions(classifyObservedSurface(surface("loader", name), context)),
        name,
      ).toEqual(["env:read"]);
    }

    for (const name of [
      "operation:cache:env-temp_dir",
      "operation:load:env-temp_dir",
      "operation:load:process-id",
      "operation:resolution:env-current_dir",
      "operation:resolution:env-temp_dir",
      "operation:resolution:process-id",
      "operation:transform:env-temp_dir",
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
    expect(status.edge.effectMode).toBe("conditional-unrefined");
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

  test("shared process-global builtin mutation surfaces remain closed", () => {
    for (const [sourceKey, exportName, expectedAction] of [
      ["exact_process", "env", "env:process-write"],
      ["exact_process", "chdir", "process:cwd"],
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
      ["node_module", "_cache", "runtime:inspect"],
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
        expect(classified.edge.effectMode, alias).toBe("conditional-unrefined");
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

  test("CLI and startup classification is exact-key and closes evaluation escapes", () => {
    for (const observed of [
      surface("cli", "eval", { commandClass: "visibleCommands" }),
      surface("cli", "command:ibex%20eval", {
        evidenceType: "cli-command-route",
        path: "ibex eval",
      }),
      surface("startup", "script:eval"),
      surface("startup", "script:bytecode"),
    ]) {
      const classified = classifyObservedSurface(observed, context);
      expect(classified.edge.classification).toBe("closed");
      expect(edgeActions(classified)).toEqual(["vm:evaluate"]);
    }

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
      surface("startup", "evaluation:__has_include:18ool1z:stream-enhance", {
        evidenceType: "startup-evaluation-route",
      }),
      context,
    );
    expect(trustedEvaluation.edge.classification).toBe("non-capability");
    expect(trustedEvaluation.edge.rationaleId).toBe("runtime-bootstrap-state");

    const installRoute = classifyObservedSurface(
      surface("startup", "install-route:ex_hermes_create:installGlobals", {
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
    expect(dynamicEnvironment.edge.effectMode).toBe("conditional-unrefined");
    expect(edgeActions(dynamicEnvironment)).toEqual(["env:read"]);
    const escapedProcessEnvironment = classifyObservedSurface(
      surface(
        "startup",
        "env:<dynamic>:javascript:process-binding-flow",
        dynamicEnvironmentMetadata,
      ),
      context,
    );
    expect(escapedProcessEnvironment.edge.effectMode).toBe(
      "conditional-unrefined",
    );
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

  test("native environment enumeration and translation-unit fallback routes stay exact", () => {
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
      expect(classified.edge.effectMode, name).toBe("conditional-unrefined");
      expect(classified.edge.refinementOwner, name).toBe("WP7");
    }

    for (const [label, classification, semantic] of [
      ["capability-hardening", "non-capability", "authority-control-plane"],
      ["cdp", "closed", "inspector:activate"],
      ["form-data", "non-capability", "runtime-bootstrap-state"],
      ["freeze-seal", "non-capability", "authority-control-plane"],
      ["fs-handle", "non-capability", "authority-control-plane"],
      ["web-crypto", "non-capability", "authority-control-plane"],
      ["web-storage", "non-capability", "authority-control-plane"],
    ]) {
      const name = `evaluation:translation-unit-fallback:${label}`;
      const classified = classifyObservedSurface(
        surface("startup", name, {
          evidenceType: "startup-evaluation-route",
          structuralFallback: "translation-unit",
          caller: "translation-unit-fallback",
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
      "installOsInfoGlobals",
      "installProcessSetup",
      "installSqliteHostFunctions",
      "installWebSocketGlobals",
    ];
    for (const installer of installers) {
      const name = `install-route:translation-unit-fallback:${installer}`;
      const classified = classifyObservedSurface(
        surface("startup", name, {
          evidenceType: "startup-installer-call-route",
          structuralFallback: "translation-unit",
          caller: "translation-unit-fallback",
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
        surface("startup", "evaluation:translation-unit-fallback:fs-handle", {
          evidenceType: "startup-evaluation-route",
          structuralFallback: "translation-unit",
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
      "IBEX_ENDOW",
      "IBEX_PER_PACKAGE_CHUNKS",
      "IBEX_CAPSEC_ALLOW_ADVISORY",
      "EX_SKIP_STARTUP_HOST_FUNCTIONS",
      "EX_DISABLE_BYTECODE_SANITY_CHECK",
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

    for (const [environmentName, expectedActions] of [
      ["IBEX_POLICY", ["env:read", "fs:list", "fs:read"]],
      ["IBEX_REPO_ROOT", ["env:read", "fs:list", "fs:read"]],
      ["PATH", ["env:read", "fs:list", "process:spawn"]],
      ["IBEX_DNS_SERVER", ["env:read", "network:resolve"]],
      ["RES_OPTIONS", ["env:read", "network:resolve"]],
      ["IBEX_HTTP_MAX_REQUEST_BODY_BYTES", ["env:read", "network:listen"]],
      ["EXACT_SECURITY_LOG", ["env:read", "stdio:write"]],
      ["IBEX_SUPPRESS_CONSOLE_MIRROR", ["env:read", "stdio:write"]],
      [
        "EXACT_ANDROID_CACHE_DIR",
        ["env:read", "env:write", "fs:list", "fs:read", "fs:write"],
      ],
      [
        "EXACT_ANDROID_EXTERNAL_FILES_DIR",
        ["env:read", "env:write", "fs:list", "fs:read", "fs:write"],
      ],
      [
        "EXACT_TRANSPILE_SCRIPT",
        ["env:read", "fs:list", "fs:read", "process:spawn"],
      ],
      ["EXACT_EXECUTABLE", ["env:read", "fs:list", "process:spawn"]],
      ["EXACT_COMPAT_EXECUTABLE", ["env:read", "fs:list", "process:spawn"]],
      ["COMSPEC", ["env:read", "fs:list", "process:spawn"]],
      ["EXACT_WINHTTP_ENABLE_HTTP2", ["env:read", "network:fetch"]],
    ]) {
      const classified = classifyObservedSurface(
        surface("startup", `env:${environmentName}`),
        context,
      );
      expect(classified.edge.classification, environmentName).toBe("effects");
      expect(edgeActions(classified), environmentName).toEqual(expectedActions);
      expect(classified.edge.effectMode, environmentName).toBe(
        "conditional-unrefined",
      );
    }

    for (const environmentName of [
      "NODE_ENV",
      "HOME",
      "USERPROFILE",
      "USERNAME",
      "TMPDIR",
      "TMP",
      "TEMP",
      "HOSTNAME",
      "HOST",
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
          fixtureId.startsWith(`${row.branchId}.`),
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
    expect(close.edge.effectMode).toBe("conditional-unrefined");
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

  test("definition coverage accounts for all 38 frozen definitions", () => {
    const model = buildCoverageModel(
      [
        surface("native-op", "__exactFsOpen"),
        surface("native-op", "__nativeFetch"),
        surface("native-op", "inspector.debugger-enable"),
      ],
      context,
    );
    expect(model.definitionCoverage).toHaveLength(38);
    expect(
      new Set(model.definitionCoverage.map((row) => row.definitionId)).size,
    ).toBe(38);
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
    expect(inheritedBuiltinExports).toHaveLength(504);
    expect(
      new Set(
        inheritedBuiltinExports.map(
          (row) => row.metadata.inheritedShapeReviewId,
        ),
      ),
    ).toEqual(
      new Set([
        "sha256-93cea4f43ae03d6bd8594c30d94af07b2c1c415793947f2aec25fca93af0de72",
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
    expect(liveDualRoleOperations).toHaveLength(281);
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
    expect(reviewedCliNames()).toEqual(liveCliNames);
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
    expect(inventory.surfaces.length).toBeGreaterThan(500);
    for (const expected of [
      "builtin:export:node_fs:watch",
      "host-abi:ex_hermes_eval",
      "host-abi:ex_worklet_create",
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
        classification: "effects",
        effectMode: "conjunctive",
      },
    );
    expect(edgeByObservedKey.get("native-op:global:eval")).toMatchObject({
      classification: "closed",
      cap: "vm:evaluate",
    });
    expect(
      edgeByObservedKey.get("host-abi:ex_host_sqlite_values"),
    ).toMatchObject({
      classification: "effects",
      effectMode: "conditional-unrefined",
      effects: [{ cap: "fs:read" }],
    });
    expect(edgeByObservedKey.get("native-op:__exactGetAllEnv")).toMatchObject({
      classification: "effects",
      effectMode: "conditional-unrefined",
      refinementOwner: "WP7",
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
        effectMode: "conditional-unrefined",
        refinementOwner: "WP5",
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
          effectMode: "conditional-unrefined",
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
      effectMode: "conditional-unrefined",
      effectOwnerSource: "descriptor-owner",
      effects: [{ cap: "network:connect" }],
    });
    expect(
      edgeByObservedKey.get(
        "host-abi:java:dev.ibex.runtime.IbexNetworking.cameraHostCall",
      ),
    ).toMatchObject({
      classification: "effects",
      effectMode: "conditional-unrefined",
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
        effectMode: "conditional-unrefined",
        refinementOwner: "WP7",
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
      ["cdp", { classification: "closed", cap: "inspector:activate" }],
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
      const name = `evaluation:translation-unit-fallback:${label}`;
      expect(edgeByObservedKey.get(`startup:${name}`), name).toMatchObject(
        expected,
      );
    }
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
      "installOsInfoGlobals",
      "installProcessSetup",
      "installSqliteHostFunctions",
      "installWebSocketGlobals",
    ]) {
      const name = `install-route:translation-unit-fallback:${installer}`;
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
      const observedKey = `loader:operation:${category}:create`;
      expect(edgeByObservedKey.get(observedKey), observedKey).toMatchObject({
        classification: "effects",
        effects: [{ cap: "fs:list" }, { cap: "fs:write" }],
      });
    }
    for (const category of [
      "cache",
      "load",
      "resolution",
      "subprocess",
      "transform",
    ]) {
      const observedKey = `loader:operation:${category}:env-var`;
      expect(edgeByObservedKey.get(observedKey), observedKey).toMatchObject({
        classification: "effects",
        effects: [{ cap: "env:read" }],
      });
    }
    for (const name of [
      "operation:cache:env-temp_dir",
      "operation:load:env-temp_dir",
      "operation:load:process-id",
      "operation:resolution:env-current_dir",
      "operation:resolution:env-temp_dir",
      "operation:resolution:process-id",
      "operation:transform:env-temp_dir",
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
          effectMode: "conditional-unrefined",
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
  }, 30_000);
});
