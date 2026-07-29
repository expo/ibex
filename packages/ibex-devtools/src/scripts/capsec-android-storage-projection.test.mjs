import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
function readSource(sourcePath) {
  return fs.readFileSync(path.join(repoRoot, sourcePath), "utf8");
}

const androidSource = readSource("src/engine/hermes_runtime_android.cc");
const runtimeSource = readSource("src/engine/hermes_runtime.cc");
const runtimeHeaderSource = readSource("src/engine/hermes_runtime_internal.h");
const bootstrapSource = readSource(
  "packages/ibex-runtime-js/src/bootstrap.ts",
);
const indexedDbSource = readSource(
  "packages/ibex-runtime-js/src/indexeddb/IDBFactory.ts",
);

function sourceBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end).replace(/\s+/gu, " ");
}

describe("armed Android storage-path projection", () => {
  test("neutralizes every storage field while preserving unarmed values", () => {
    const projection = sourceBetween(
      androidSource,
      "facebook::jsi::Object makeStoragePathsObject(",
      "bool prepareAndroidStoragePathsProjection(",
    );
    const fields = [
      ["filesDir", "files_dir"],
      ["cacheDir", "cache_dir"],
      ["noBackupFilesDir", "no_backup_files_dir"],
      ["codeCacheDir", "code_cache_dir"],
      ["externalFilesDir", "external_files_dir"],
    ];

    for (const [property, member] of fields) {
      expect(projection).toContain(
        `"${property}", facebook::jsi::String::createFromUtf8( runtime, androidStoragePathForJavaScript(armed, paths.${member}))`,
      );
    }

    expect(androidSource).toContain(
      'return armed || host_path == nullptr ? "" : host_path;',
    );
    expect(androidSource).toContain(
      "androidStoragePathForJavaScript(true, \"/data/user/0/dev.ibex/files\")",
    );
    expect(androidSource).toContain(
      "androidStoragePathForJavaScript(false, \"/data/user/0/dev.ibex/files\")",
    );
  });

  test(
    "does not fetch host roots and threads armed state through every JS projection",
    () => {
      const preparation = sourceBetween(
        androidSource,
        "bool prepareAndroidStoragePathsProjection(",
        "facebook::jsi::Object makeAndroidPlatformState(",
      );
      expect(preparation).toContain(
        "paths = AndroidStoragePaths{}; if (armed) {",
      );
      expect(preparation.indexOf("return true;")).toBeLessThan(
        preparation.indexOf("android_get_storage_paths("),
      );

      expect(
        androidSource.match(
          /makeAndroidPlatformState\([^;]*handle->armed\)/gs,
        ),
      ).toHaveLength(2);
      expect(androidSource).toContain(
        "makeStoragePathsObject(runtime, storage_paths, armed)",
      );
      expect(androidSource).toContain(
        "makeStoragePathsObject(rt, storage_paths, handle->armed)",
      );
      const globalInstall = sourceBetween(
        androidSource,
        "void installStoragePathsGlobal(",
        "bool prepareAndroidStoragePathsProjection(",
      );
      expect(globalInstall).toContain("freeze.call(runtime, installed)");
      expect(globalInstall).toContain(
        'descriptor.setProperty(runtime, "writable", false)',
      );
      expect(globalInstall).toContain(
        'descriptor.setProperty(runtime, "configurable", false)',
      );
      expect(androidSource).toContain(
        "installStoragePathsGlobal(rt, std::move(storage), handle->armed)",
      );
      expect(androidSource).toContain(
        "installAndroidEnvironmentGlobals(handle)",
      );
    },
  );

  test("closes every Android storage environment alias before native lookup", () => {
    const guard = sourceBetween(
      runtimeSource,
      "bool isAndroidStorageHostPathEnvironmentKey(",
      "std::optional<std::string> getEnvValue(",
    );
    for (const key of [
      "HOME",
      "TMPDIR",
      "TEMP",
      "TMP",
      "EXACT_ANDROID_FILES_DIR",
      "EXACT_ANDROID_CACHE_DIR",
      "EXACT_ANDROID_NO_BACKUP_FILES_DIR",
      "EXACT_ANDROID_CODE_CACHE_DIR",
      "EXACT_ANDROID_EXTERNAL_FILES_DIR",
    ]) {
      expect(guard).toContain(`key == "${key}"`);
    }

    const getEnv = sourceBetween(
      runtimeSource,
      "auto getEnvFn = facebook::jsi::Function::createFromHostFunction(",
      'rt.global().setProperty(rt, "__exactGetEnv"',
    );
    const closed = getEnv.indexOf(
      "handle->armed && isAndroidStorageHostPathEnvironmentKey(key)",
    );
    expect(closed).toBeGreaterThanOrEqual(0);
    expect(closed).toBeLessThan(
      getEnv.indexOf("authorizeTypedEnvironmentRead(runtime, key)"),
    );
    expect(closed).toBeLessThan(getEnv.indexOf("getEnvValue(key)"));
  });

  test("Web Storage and IndexedDB treat the empty projection as closed", () => {
    const webStorageInstall = sourceBetween(
      bootstrapSource,
      "function installSQLiteStorageModule(g: any): boolean",
      "function ensureFetchInitialized(",
    );
    expect(webStorageInstall).toContain("captureAndroidStorageRoot(g)");
    expect(webStorageInstall).toContain("resolveNativeStorageRoot(");
    expect(webStorageInstall).toContain("if (storageRoot === null)");
    expect(webStorageInstall).not.toContain("g.process?.env");
    expect(webStorageInstall).not.toContain("return '/tmp'");

    const indexedDbPath = sourceBetween(
      indexedDbSource,
      "function indexedDbPath(name: string): string",
      "function readStoredVersion(",
    );
    expect(indexedDbSource).toContain(
      "captureAndroidStorageRoot(globalThis as any)",
    );
    expect(indexedDbSource).not.toContain("g.process?.env");
    expect(indexedDbSource).not.toContain("return '/tmp'");
    expect(indexedDbPath.indexOf("if (root === null)")).toBeLessThan(
      indexedDbPath.indexOf("ensureIndexedDbDirectory(directory)"),
    );
    expect(indexedDbPath).toContain("'NotAllowedError'");
  });
});

describe("armed Android platform-event delivery", () => {
  test("retains the trusted consumer and removes its forgeable global", () => {
    const capture = sourceBetween(
      runtimeSource,
      "static bool capturePrivateBridgeConsumers(",
      "static bool sealRootGlobalSessionBridges(",
    );
    const seal = sourceBetween(
      runtimeSource,
      "static bool sealRootGlobalSessionBridges(",
      "static bool injectRootGlobalDispositionTestAccessor(",
    );
    const dispatch = sourceBetween(
      androidSource,
      "bool dispatchAndroidPlatformEvents(",
      "void registerAndroidRuntime(",
    );

    expect(runtimeHeaderSource).toContain(
      "android_platform_event_handler;",
    );
    expect(capture).toContain(
      'ownDataFunction("__exactAndroidDispatchPlatformEvent")',
    );
    expect(seal).toContain('"__exactAndroidDispatchPlatformEvent"');
    expect(dispatch).toContain(
      "auto* handler = handle->android_platform_event_handler.get()",
    );
    expect(dispatch).toContain(
      "if (handle->armed && !handle->armed_bootstrap_eval_open)",
    );
    expect(dispatch).toContain("if (handler == nullptr) { return false;");
    expect(dispatch).toContain("} else if (handler == nullptr) {");
    expect(dispatch).toContain(
      'rt.global().getProperty(rt, "__exactAndroidDispatchPlatformEvent")',
    );
    expect(dispatch.indexOf("if (handle->armed)")).toBeLessThan(
      dispatch.indexOf(
        'rt.global().getProperty(rt, "__exactAndroidDispatchPlatformEvent")',
      ),
    );
    expect(dispatch).toContain("handler->call(");
  });
});
