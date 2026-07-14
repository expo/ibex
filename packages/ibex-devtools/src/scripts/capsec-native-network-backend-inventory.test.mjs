import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";
import { scanAndroidCppBridgeBindings } from "./capsec-android-bridge-inventory.mjs";
import {
  discoverNativeNetworkingBackendSurfaces,
  scanNativeNetworkingBackendDefinitions,
  scanNativeNetworkingBackendInventory,
} from "./capsec-native-network-backend-inventory.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

const BACKEND_PATHS = [
  "src/engine/native_android_networking.cc",
  "src/engine/native_fetch_linux.cc",
  "src/engine/native_fetch_macos.mm",
  "src/engine/native_fetch_windows.cc",
  "src/engine/native_websocket_linux.cc",
  "src/engine/native_websocket_macos.mm",
  "src/engine/native_websocket_windows.cc",
];

const DECLARATION_PATHS = [
  "src/engine/hermes_runtime.cc",
  "src/engine/hermes_runtime_fetch.cc",
  "src/engine/hermes_runtime_websocket.cc",
];

const OPERATION_NAMES = [
  "native_fetch_cancel",
  "native_fetch_perform",
  "native_ws_close",
  "native_ws_connect",
  "native_ws_destroy",
  "native_ws_has_active",
  "native_ws_pause",
  "native_ws_resume",
  "native_ws_send",
  "native_ws_set_flow_controlled",
];

const BRANCH_IDS = [
  "android-okhttp-jni",
  "ios-foundation",
  "linux-curl-cli-fallback",
  "linux-libcurl",
  "macos-foundation",
  "windows-winhttp",
];

const TARGET_VARIANTS = [
  "android",
  "ios",
  "linux:curl-cli-fallback",
  "linux:libcurl",
  "macos",
  "windows",
];

function readSource(sourcePath) {
  return fs.readFileSync(path.join(repoRoot, sourcePath), "utf8");
}

function liveInputs() {
  const backendSources = BACKEND_PATHS.map((sourcePath) => ({
    sourcePath,
    text: readSource(sourcePath),
  }));
  const androidPath = "src/engine/native_android_networking.cc";
  return {
    backendSources,
    declarationSources: DECLARATION_PATHS.map((sourcePath) => ({
      sourcePath,
      text: readSource(sourcePath),
    })),
    buildSource: { sourcePath: "build.rs", text: readSource("build.rs") },
    androidBindings: scanAndroidCppBridgeBindings(
      backendSources.find((entry) => entry.sourcePath === androidPath).text,
      androidPath,
    ),
  };
}

function branch(row, branchId) {
  return row.metadata.branches.find((candidate) => candidate.id === branchId);
}

describe("native networking backend lexical discovery", () => {
  test("recognizes definitions while excluding comments, strings, raw strings, and calls", () => {
    const scan = scanNativeNetworkingBackendDefinitions(
      String.raw`
        // extern "C" void native_ws_comment() {}
        const char* ordinary = "extern \"C\" void native_ws_string() {}";
        const char* raw = R"tag(extern "C" void native_ws_raw() {})tag";
        extern "C" void native_ws_send(int id);
        extern "C" void native_ws_send(int id) {
          native_ws_send(id);
        }
      `,
      "synthetic.cc",
    );

    expect(scan.referencedNames).toEqual(["native_ws_send"]);
    expect(
      scan.occurrences.map(({ kind, linkage, name }) => ({
        kind,
        linkage,
        name,
      })),
    ).toEqual([
      { kind: "declaration", linkage: "extern-c", name: "native_ws_send" },
      { kind: "definition", linkage: "extern-c", name: "native_ws_send" },
    ]);
  });

  test("rejects malformed lexical input instead of scanning a partial file", () => {
    expect(() =>
      scanNativeNetworkingBackendDefinitions("/* no close", "broken.cc"),
    ).toThrow(/unterminated block comment/u);
    expect(() =>
      scanNativeNetworkingBackendDefinitions(
        'const char* s = "no close',
        "broken.cc",
      ),
    ).toThrow(/unterminated literal/u);
  });
});

describe("native networking backend repository inventory", () => {
  test("groups the exact ABI operations into deterministic target alternatives", () => {
    const rows = discoverNativeNetworkingBackendSurfaces(repoRoot);

    expect(rows.map((row) => row.name)).toEqual(OPERATION_NAMES);
    expect(rows.map((row) => row.observedKey)).toEqual(
      OPERATION_NAMES.map((name) => `native-op:${name}`),
    );
    for (const row of rows) {
      expect(row.kind).toBe("native-op");
      expect(row.metadata.surfaceType).toBe("native-network-backend");
      expect(row.metadata.branches.map((candidate) => candidate.id)).toEqual(
        BRANCH_IDS,
      );
      expect(
        row.metadata.branches.map((candidate) => candidate.targetVariant),
      ).toEqual(TARGET_VARIANTS);
      expect(
        row.metadata.branches.every(
          (candidate) =>
            candidate.kind === "alternative" &&
            candidate.branchKind === "alternative" &&
            candidate.sourceRefs.length > 0,
        ),
      ).toBe(true);
      expect(row.sourceRefs).toEqual([...row.sourceRefs].sort());
    }
  });

  test("retains Linux, Foundation, WinHTTP, and Android OkHttp/JNI provenance", () => {
    const rows = discoverNativeNetworkingBackendSurfaces(repoRoot);
    const fetch = rows.find((row) => row.name === "native_fetch_perform");
    const connect = rows.find((row) => row.name === "native_ws_connect");
    const send = rows.find((row) => row.name === "native_ws_send");

    expect(branch(fetch, "linux-libcurl").sourceRefs).toEqual(
      expect.arrayContaining([
        "src/engine/native_fetch_linux.cc#definition:native_fetch_perform",
        "src/engine/native_fetch_linux.cc#definition:native_fetch_perform_async",
        "src/engine/native_fetch_linux.cc#preprocessor:EXACT_HAS_CURL:defined",
      ]),
    );
    expect(branch(fetch, "linux-curl-cli-fallback")).toMatchObject({
      backend: "curl-cli",
      implementationDisposition: "degraded-concrete",
    });
    expect(branch(connect, "linux-curl-cli-fallback")).toMatchObject({
      backend: "unavailable-websocket-stub",
      implementationDisposition: "unsupported-stub",
    });
    expect(branch(fetch, "macos-foundation").sourceRefs).toContain(
      "src/engine/native_fetch_macos.mm#definition:native_fetch_perform",
    );
    expect(branch(fetch, "ios-foundation").sourceRefs).toContain(
      "build.rs#backend-selection:ios:native_fetch_macos.mm",
    );
    expect(branch(fetch, "windows-winhttp").sourceRefs).toContain(
      "src/engine/native_fetch_windows.cc#definition:native_fetch_perform",
    );
    expect(branch(fetch, "android-okhttp-jni").sourceRefs).toEqual(
      expect.arrayContaining([
        "src/engine/native_android_networking.cc#java-call:fetch:fetch",
        "src/engine/native_android_networking.cc#jni-callback:" +
          "nativeFetchDidComplete:android_fetch_did_complete",
      ]),
    );
    expect(branch(connect, "android-okhttp-jni").sourceRefs).toEqual(
      expect.arrayContaining([
        "src/engine/native_android_networking.cc#java-call:connectWebSocket:connectWebSocket",
        "src/engine/native_android_networking.cc#jni-callback:nativeWebSocketDidOpen:android_ws_did_open",
        "src/engine/native_android_networking.cc#jni-callback:" +
          "nativeWebSocketDidMessage:android_ws_did_message",
      ]),
    );
    expect(branch(send, "android-okhttp-jni").sourceRefs).toContain(
      "src/engine/native_android_networking.cc#jni-callback:" +
        "nativeWebSocketDidBytesSent:android_ws_did_send_bytes",
    );
    expect(rows.some((row) => /^(?:java|jni):/u.test(row.name))).toBe(false);
  });

  test("joins the shared ABI declarations without treating context helpers as backends", () => {
    const rows = discoverNativeNetworkingBackendSurfaces(repoRoot);
    expect(
      rows.find((row) => row.name === "native_fetch_perform").metadata
        .declarations,
    ).toEqual([
      "src/engine/hermes_runtime.cc#declaration:native_fetch_perform",
      "src/engine/hermes_runtime_fetch.cc#declaration:native_fetch_perform",
    ]);
    expect(
      rows.find((row) => row.name === "native_ws_destroy").metadata
        .declarations,
    ).toEqual([
      "src/engine/hermes_runtime.cc#declaration:native_ws_destroy",
      "src/engine/hermes_runtime_websocket.cc#declaration:native_ws_destroy",
    ]);
    expect(rows.some((row) => row.name.includes("context"))).toBe(false);
  });
});

describe("native networking backend fail-closed gates", () => {
  test("repository discovery rejects a newly added backend file", () => {
    const tempRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "ibex-native-backend-inventory-"),
    );
    try {
      for (const sourcePath of BACKEND_PATHS) {
        const absolutePath = path.join(tempRoot, sourcePath);
        fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
        fs.writeFileSync(absolutePath, "", "utf8");
      }
      fs.writeFileSync(
        path.join(tempRoot, "src/engine/native_fetch_freebsd.cc"),
        "",
        "utf8",
      );
      expect(() => discoverNativeNetworkingBackendSurfaces(tempRoot)).toThrow(
        /native backend file inventory drift.*native_fetch_freebsd/u,
      );
    } finally {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  });

  test("rejects an unknown backend source file", () => {
    const inputs = liveInputs();
    inputs.backendSources.push({
      sourcePath: "src/engine/native_fetch_freebsd.cc",
      text: 'extern "C" void native_fetch_perform() {}',
    });
    expect(() => scanNativeNetworkingBackendInventory(inputs)).toThrow(
      /source set drift.*native_fetch_freebsd/u,
    );
  });

  test("rejects unknown or missing backend functions", () => {
    const unknown = liveInputs();
    const linux = unknown.backendSources.find(
      (entry) => entry.sourcePath === "src/engine/native_fetch_linux.cc",
    );
    linux.text += "\nstatic void native_fetch_surprise() {}\n";
    expect(() => scanNativeNetworkingBackendInventory(unknown)).toThrow(
      /unknown native networking symbol.*native_fetch_surprise/u,
    );

    const missing = liveInputs();
    const windows = missing.backendSources.find(
      (entry) => entry.sourcePath === "src/engine/native_fetch_windows.cc",
    );
    windows.text = windows.text.replace(
      'extern "C" void native_fetch_cancel(uint32_t request_id, uint64_t runtime_nonce)',
      'extern "C" void reviewed_cancel(uint32_t request_id, uint64_t runtime_nonce)',
    );
    expect(() => scanNativeNetworkingBackendInventory(missing)).toThrow(
      /definition set drift.*native_fetch_cancel/u,
    );
  });

  test("rejects declaration and build-selection drift", () => {
    const declaration = liveInputs();
    declaration.declarationSources.find(
      (entry) => entry.sourcePath === "src/engine/hermes_runtime_websocket.cc",
    ).text += '\nextern "C" void native_ws_ping(void);\n';
    expect(() => scanNativeNetworkingBackendInventory(declaration)).toThrow(
      /unknown native networking declaration symbol.*native_ws_ping/u,
    );

    const build = liveInputs();
    build.buildSource.text = build.buildSource.text.replace(
      '.file("src/engine/native_fetch_windows.cc")',
      '.file("src/engine/native_fetch_win32.cc")',
    );
    expect(() => scanNativeNetworkingBackendInventory(build)).toThrow(
      /native backend \.file selection set drift/u,
    );
  });

  test("rejects missing Android JNI evidence", () => {
    const inputs = liveInputs();
    inputs.androidBindings.staticMethods.delete("connectWebSocket");
    expect(() => scanNativeNetworkingBackendInventory(inputs)).toThrow(
      /Android backend binding connectWebSocket is absent/u,
    );
  });
});
