// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — source
// discovery is deterministic, comment-aware, and fail-closed on duplicate keys.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  discoverRepositorySurfaces,
  discoverHermesEvaluatorIdentityProfiles,
  fixedRuntimeSurfaceInventory,
  HERMES_EVALUATOR_REVIEW_ID,
  isRuntimeEnvironmentSourceAllowed,
  scanBuiltinSurfaces,
  scanCdpSurfaces,
  scanCppGlobalPropertySurfaces,
  scanCppPublicAbiDefinitions,
  scanEvaluatedCppGlobalScripts,
  scanFixedRuntimeEvidenceCandidates,
  scanHermesEvaluatorIdentityProfiles,
  scanJavaScriptLoaderSurfaces,
  scanJavaScriptLoaderRoutes,
  scanLegacyEvaluatorBootstrapInstallations,
  scanLockdownEvaluatorSurfaces,
  scanModuleSpecifierEntries,
  scanNativeLifecycleSurfaces,
  scanPrivateNativeIdentifiers,
  scanRuntimeCliSurfaces,
  scanRuntimeCommandClasses,
  scanRuntimeEnvironmentSurfaces,
  scanRustHostExterns,
  scanRustLoaderSurfaces,
  scanRustLoaderRoutes,
  scanRustPublicAbiDefinitions,
  scanSharedRuntimeGlobalSurfaces,
  scanStaticBuiltinExports,
  scanStaticGlobalApiSurfaces,
  validateRuntimeBundleEntry,
  validateFixedRuntimeSurfaceRefs,
} from "./capsec-surface-inventory.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..", "..");

const REVIEWED_TEST_EVALUATORS = [
  "AsyncFunction",
  "Function",
  "GeneratorFunction",
  "eval",
];

const LOCKDOWN_EVALUATOR_SOURCE = String.raw`
  std::string lockdownJS = std::string(R"JS((function () {
    var failClosed = )JS") + (handle->armed ? "true" : "false") + R"JS(;
    tameCtor(Function.prototype, 'Function');
    tameCtor(getProto(function*(){}), 'GeneratorFunction');
    tameCtor(getProto(async function(){}), 'AsyncFunction');
    makeTamed('eval');
  })())JS";
  auto buffer = std::make_shared<facebook::jsi::StringBuffer>(lockdownJS.c_str());
  runtime.evaluateJavaScript(buffer, "<lockdown>");
`;

function syntheticHermesEvaluatorProfiles() {
  return [
    {
      id: "synthetic-android",
      targetVariant: "android",
      identity: { artifact: "synthetic/android", version: "1" },
      reachableEvaluators: REVIEWED_TEST_EVALUATORS,
      sourceRefs: ["synthetic/android.pin#version"],
    },
    {
      id: "synthetic-default",
      targetVariant: "default",
      identity: { artifact: "synthetic/source", version: "1" },
      reachableEvaluators: REVIEWED_TEST_EVALUATORS,
      sourceRefs: ["synthetic/source.pin#version"],
    },
  ];
}

function liveHermesEvaluatorIdentityInputs() {
  const patchRoot = path.join(repoRoot, "patches", "hermes");
  return {
    hermesVersionText: fs.readFileSync(
      path.join(repoRoot, "scripts", "hermes-version.sh"),
      "utf8",
    ),
    androidInstallerText: fs.readFileSync(
      path.join(repoRoot, "scripts", "install-android-hermes.sh"),
      "utf8",
    ),
    windowsInstallerText: fs.readFileSync(
      path.join(repoRoot, "scripts", "install-windows-hermes.ps1"),
      "utf8",
    ),
    windowsSourceBuildText: fs.readFileSync(
      path.join(repoRoot, "scripts", "build-hermes-windows.ps1"),
      "utf8",
    ),
    patchApplicationText: fs.readFileSync(
      path.join(repoRoot, "scripts", "apply-hermes-patches.sh"),
      "utf8",
    ),
    appleSourceBuildText: fs.readFileSync(
      path.join(repoRoot, "scripts", "build-hermes.sh"),
      "utf8",
    ),
    linuxSourceBuildText: fs.readFileSync(
      path.join(repoRoot, "scripts", "build-hermes-linux.sh"),
      "utf8",
    ),
    patches: fs
      .readdirSync(patchRoot, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith(".patch"))
      .map((entry) => ({
        sourcePath: `patches/hermes/${entry.name}`,
        content: fs.readFileSync(path.join(patchRoot, entry.name)),
      })),
  };
}

const REVIEWED_SHARED_RUNTIME_ROOTS = [
  "AbortController",
  "AbortSignal",
  "Atomics",
  "Blob",
  "BroadcastChannel",
  "Buffer",
  "Bun",
  "ByteLengthQueuingStrategy",
  "ClipboardItem",
  "CloseEvent",
  "CompressionStream",
  "CountQueuingStrategy",
  "Crypto",
  "CryptoKey",
  "CustomEvent",
  "DOMException",
  "DecompressionStream",
  "ErrorEvent",
  "Event",
  "EventSource",
  "EventTarget",
  "Exact",
  "ExactBundle",
  "File",
  "FileReader",
  "Float16Array",
  "FocusEvent",
  "FormData",
  "Headers",
  "IDBCursor",
  "IDBCursorWithValue",
  "IDBDatabase",
  "IDBIndex",
  "IDBKeyRange",
  "IDBObjectStore",
  "IDBOpenDBRequest",
  "IDBRequest",
  "IDBTransaction",
  "KeyboardEvent",
  "MediaQueryList",
  "MediaQueryListEvent",
  "MessageChannel",
  "MessageEvent",
  "MessagePort",
  "PerformanceEntry",
  "PerformanceMark",
  "PerformanceMeasure",
  "PerformanceObserver",
  "ProgressEvent",
  "PromiseRejectionEvent",
  "ReadableByteStreamController",
  "ReadableStream",
  "ReadableStreamBYOBReader",
  "ReadableStreamBYOBRequest",
  "ReadableStreamDefaultController",
  "ReadableStreamDefaultReader",
  "Request",
  "Response",
  "SharedArrayBuffer",
  "SubtleCrypto",
  "TextDecoder",
  "TextDecoderStream",
  "TextEncoder",
  "TextEncoderStream",
  "TransformStream",
  "TransformStreamDefaultController",
  "URL",
  "URLPattern",
  "URLSearchParams",
  "VideoFrame",
  "WebSocket",
  "WebSocketError",
  "WebSocketStream",
  "WritableStream",
  "WritableStreamDefaultController",
  "WritableStreamDefaultWriter",
  "atob",
  "btoa",
  "caches",
  "cancelAnimationFrame",
  "cancelIdleCallback",
  "clearImmediate",
  "crypto",
  "fetch",
  "global",
  "indexedDB",
  "localStorage",
  "matchMedia",
  "navigator",
  "performance",
  "process",
  "requestAnimationFrame",
  "requestIdleCallback",
  "self",
  "sessionStorage",
  "setImmediate",
  "structuredClone",
  "window",
];

function makeRuntimeFixture(
  files,
  buildEntry = "packages/ibex-runtime-js/src/runtime-entry.ts",
) {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "ibex-runtime-inventory-"),
  );
  fs.writeFileSync(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        "build:runtime": `bun bundle.mjs --entry ${buildEntry} --out vendored-generated/runtime.js`,
      },
    }),
  );
  for (const [relativePath, source] of Object.entries(files)) {
    const filePath = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, source);
  }
  return root;
}

describe("LLP 0021 WP1 source surface inventory", () => {
  test("C++ comments cannot create private native observations", () => {
    const source = String.raw`
      // rt.global().setProperty(rt, "__exactLineComment", value);
      /*
       * "__exactBlockComment"
       */
      const char* documentation = "not __exactEmbeddedText";
      const char* live = "__exactLive";
      const char* script = R"JS((function () {
        // var ignored = "__exactRawLineComment";
        /* var ignoredToo = '__exactRawBlockComment'; */
        var kept = "__exactRawLive";
      })())JS";
    `;

    expect(
      scanPrivateNativeIdentifiers(source, "synthetic.cc").map(
        (row) => row.name,
      ),
    ).toEqual(["__exactLive", "__exactRawLive"]);
  });

  test("multiline registrations are discovered and duplicate literals group", () => {
    const source = `
      rt.global().setProperty(
        rt,
        "__exactMultiline",
        std::move(firstFn)
      );
      auto name = facebook::jsi::PropNameID::forAscii(
        rt,
        "__exactMultiline"
      );
      rt.global().setProperty(rt, "__exactAnother", std::move(secondFn));
    `;
    const rows = scanPrivateNativeIdentifiers(source, "synthetic.mm");

    expect(rows.map((row) => row.name)).toEqual([
      "__exactAnother",
      "__exactMultiline",
    ]);
    expect(rows.find((row) => row.name === "__exactMultiline")).toEqual({
      kind: "native-op",
      name: "__exactMultiline",
      observedKey: "native-op:__exactMultiline",
      sourceRefs: ["synthetic.mm#__exactMultiline"],
      metadata: { occurrenceCount: 2 },
    });
  });

  test("C++ scan order is independent of source order", () => {
    const forward = scanPrivateNativeIdentifiers(
      'const char* z = "__exactZulu"; const char* a = "__exactAlpha";',
      "synthetic.cc",
    );
    const reverse = scanPrivateNativeIdentifiers(
      'const char* a = "__exactAlpha"; const char* z = "__exactZulu";',
      "synthetic.cc",
    );
    expect(forward).toEqual(reverse);
  });

  test("C++ adjacent strings concatenate and digit separators do not confuse scanners", () => {
    const source = String.raw`
      constexpr auto count = 1'000;
      const char* joined = "__exactFoo" /* C++ concatenation */ "Bar";
      extern "C" void ex_host_after_separator() {}
    `;
    expect(
      scanPrivateNativeIdentifiers(source, "synthetic.cc").map(
        (row) => row.name,
      ),
    ).toEqual(["__exactFooBar"]);
    expect(
      scanCppPublicAbiDefinitions(source, "synthetic.cc").map(
        (row) => row.name,
      ),
    ).toEqual(["ex_host_after_separator"]);
  });

  test("Rust comments and strings cannot fabricate public host ABI definitions", () => {
    const source = String.raw`
      // pub extern "C" fn ex_host_line_fake() {}
      /* pub extern "C" fn ex_host_block_fake() {} */
      const EXAMPLE: &str = r#"pub extern "C" fn ex_host_string_fake() {}"#;

      #[no_mangle]
      pub /* generated ABI */ extern "C" fn ex_host_live(
        value: u64,
      ) -> u64 {
        value
      }

      pub unsafe extern "C" fn ex_host_unsafe_live() {}
    `;
    const rows = scanRustHostExterns(source, "synthetic.rs");

    expect(rows.map((row) => row.name)).toEqual([
      "ex_host_live",
      "ex_host_unsafe_live",
    ]);
    expect(rows[0].metadata).toEqual({ unsafe: false });
    expect(rows[1].metadata).toEqual({ unsafe: true });
  });

  test("duplicate Rust host definitions fail closed", () => {
    const source = `
      pub extern "C" fn ex_host_duplicate() {}
      pub extern "C" fn ex_host_duplicate() {}
    `;
    expect(() => scanRustHostExterns(source, "duplicate.rs")).toThrow(
      /duplicate public host ABI definition ex_host_duplicate/,
    );
  });

  test("Rust export_name attributes define the effective public ABI symbol", () => {
    const source = String.raw`
      #[export_name = "ex_host_renamed"]
      pub extern "C" fn internal_host_name() {}

      #[unsafe(export_name = "ex_hermes_private_renamed")]
      unsafe extern "C" fn private_internal_name() {}

      #[unsafe(no_mangle)]
      extern "C" fn ex_worklet_private_no_mangle() {}

      #[cfg(test)]
      #[export_name = "ex_host_test_only"]
      pub extern "C" fn test_only_name() {}

      // #[export_name = "ex_host_comment_only"]
      const TEXT: &str = r#"#[export_name = \"ex_host_string_only\"]"#;
    `;
    const rows = scanRustPublicAbiDefinitions(source, "renamed.rs");
    expect(rows.map((row) => row.name)).toEqual([
      "ex_hermes_private_renamed",
      "ex_host_renamed",
      "ex_worklet_private_no_mangle",
    ]);
    expect(rows[0].metadata).toMatchObject({
      rustIdentifier: "private_internal_name",
      unsafe: true,
    });
    expect(rows[1].metadata).toMatchObject({
      rustIdentifier: "internal_host_name",
      unsafe: false,
    });
    expect(rows[2].metadata).toMatchObject({ unsafe: false });
    expect(
      scanRustHostExterns(source, "renamed.rs").map((row) => row.name),
    ).toEqual(["ex_host_renamed"]);

    expect(() =>
      scanRustPublicAbiDefinitions(
        '#[cfg_attr(feature = "hidden", export_name = "ex_host_hidden")] pub extern "C" fn hidden() {}',
        "conditional.rs",
      ),
    ).toThrow(/unreviewed Rust export_name attribute shape/);
    expect(() =>
      scanRustPublicAbiDefinitions(
        '#[cfg_attr(feature = "hidden", no_mangle)] extern "C" fn ex_host_hidden() {}',
        "conditional-no-mangle.rs",
      ),
    ).toThrow(/unreviewed Rust no_mangle attribute shape/);
    expect(() =>
      scanRustPublicAbiDefinitions(
        '#[export_name = "ex_host_wrong_abi"] fn hidden() {}',
        "wrong-abi.rs",
      ),
    ).toThrow(/not attached to an inventoried extern "C" function definition/);
  });

  test("Rust no_mangle data symbols cannot bypass public ABI inventory", () => {
    const dataSymbols = [
      ["#[no_mangle] pub static ex_host_hidden: u8 = 0;", "ex_host_hidden"],
      ["#[no_mangle] static ex_hermes_hidden: u8 = 0;", "ex_hermes_hidden"],
      [
        "#[unsafe(no_mangle)] pub static mut ex_worklet_hidden: u8 = 0;",
        "ex_worklet_hidden",
      ],
    ];
    for (const [source, name] of dataSymbols) {
      expect(() =>
        scanRustPublicAbiDefinitions(source, "data-symbol.rs"),
      ).toThrow(
        `data-symbol.rs: public ABI attribute for ${name} is not attached to an inventoried extern "C" function definition`,
      );
    }

    expect(
      scanRustPublicAbiDefinitions(
        String.raw`
          #[no_mangle]
          pub static ordinary_export: u8 = 0;

          #[cfg(test)]
          #[no_mangle]
          pub static ex_host_test_only: u8 = 0;

          // #[no_mangle] pub static ex_host_comment_only: u8 = 0;
          const TEXT: &str = r#"#[no_mangle] static ex_host_string_only: u8 = 0;"#;
        `,
        "irrelevant-data.rs",
      ),
    ).toEqual([]);

    expect(() =>
      scanRustPublicAbiDefinitions(
        "#[no_mangle] public_abi_items!();",
        "macro-data.rs",
      ),
    ).toThrow(/unreviewed Rust no_mangle item shape/);
  });

  test("all three public ABI families are discovered from real definitions only", () => {
    const rust = String.raw`
      // pub extern "C" fn ex_host_comment() {}
      const FAKE: &str = r#"pub extern \"C\" fn ex_hermes_string() {}"#;
      pub extern "C" fn ex_host_live() {}
      pub unsafe extern "C" fn ex_hermes_rust_live() {}
    `;
    expect(
      scanRustPublicAbiDefinitions(rust, "synthetic.rs").map((row) => row.name),
    ).toEqual(["ex_hermes_rust_live", "ex_host_live"]);

    const cpp = String.raw`
      // extern "C" void ex_hermes_comment() {}
      const char* fake = "extern C ex_worklet_string() {}";
      extern "C" void ex_hermes_declared_only();
      extern "C" void ex_hermes_live() {}
      extern "C" WEAK_STUB int ex_worklet_live(int value) { return value; }
    `;
    const rows = scanCppPublicAbiDefinitions(cpp, "synthetic.cc");
    expect(rows.map((row) => row.name)).toEqual([
      "ex_hermes_live",
      "ex_worklet_live",
    ]);
    expect(
      rows.find((row) => row.name === "ex_worklet_live").metadata.weak,
    ).toBe(true);
  });

  test("duplicate native ABI definitions fail closed", () => {
    expect(() =>
      scanCppPublicAbiDefinitions(
        'extern "C" void ex_hermes_duplicate() {} extern "C" void ex_hermes_duplicate() {}',
        "duplicate.cc",
      ),
    ).toThrow(/duplicate public ABI definition ex_hermes_duplicate/);
  });

  test("module specifier aliases preserve exposure flags while remaining importable", () => {
    const rows = scanModuleSpecifierEntries(
      {
        meta: { defaults: { bundleExternal: true, moduleBuiltin: true } },
        sources: {
          node_fs: { kind: "generated", path: "builtins/fs.js" },
          exact_sqlite: { kind: "generated", path: "builtins/sqlite.js" },
        },
        specifiers: [
          { names: ["node:fs", "fs"], source: "node_fs" },
          {
            names: ["exact:sqlite"],
            source: "exact_sqlite",
            bundleExternal: false,
            moduleBuiltin: false,
          },
        ],
      },
      "modules.ts",
    );

    expect(rows.map((row) => row.observedKey)).toEqual([
      "builtin:exact:sqlite",
      "builtin:fs",
      "builtin:node:fs",
    ]);
    expect(rows.find((row) => row.name === "node:fs").metadata).toEqual({
      sourceKey: "node_fs",
      bundleExternal: true,
      importReachability: "public",
      moduleBuiltin: true,
    });
    expect(rows.find((row) => row.name === "exact:sqlite").metadata).toEqual({
      sourceKey: "exact_sqlite",
      bundleExternal: false,
      importReachability: "public",
      moduleBuiltin: false,
    });
  });

  test("bootstrap internal aliases are distinct from their manifest source", () => {
    const rows = scanModuleSpecifierEntries({
      bootstrapInternalModules: ["internal/fs/utils"],
      sources: { internal_fs_utils: { kind: "inline", code: "" } },
      specifiers: [
        {
          names: ["internal/fs/utils"],
          source: "internal_fs_utils",
          bundleExternal: false,
          moduleBuiltin: false,
        },
      ],
    });

    expect(rows).toHaveLength(1);
    expect(rows[0].metadata).toEqual({
      sourceKey: "internal_fs_utils",
      bundleExternal: false,
      importReachability: "bootstrap-internal",
      moduleBuiltin: false,
    });
  });

  test("duplicate module specifiers fail closed", () => {
    expect(() =>
      scanModuleSpecifierEntries({
        sources: { one: {}, two: {} },
        specifiers: [
          { names: ["node:fs"], source: "one" },
          { names: ["node:fs"], source: "two" },
        ],
      }),
    ).toThrow(/duplicate builtin specifier "node:fs"/);
  });

  test("builtin export reachability classifications fail closed on overlap", () => {
    expect(() =>
      scanStaticBuiltinExports("module.exports = {};", {
        bootstrapInternalModuleSpecifiers: ["internal/example"],
        moduleSpecifiers: ["internal/example"],
        publicModuleSpecifiers: ["internal/example"],
        sourcePath: "overlap.js",
      }),
    ).toThrow(/cannot be both public and bootstrap-internal/);
  });

  test("builtin exports are parsed from code without comment or string false positives", () => {
    const source = String.raw`
      // module.exports.fakeComment = fake;
      const fake = "module.exports.fakeString = fake";
      const api = { read: function() {}, ['write']: function() {} };
      api.remove = function() {};
      Object.defineProperty(api, 'length', { get: function() { return 0; } });
      Object.assign(api, { clear: function() {} });
      module.exports = api;
      module.exports.close = function() {};
    `;
    const rows = scanStaticBuiltinExports(source, {
      sourceKey: "node_synthetic",
      sourcePath: "src/builtins/synthetic.js",
      moduleSpecifiers: ["node:synthetic", "synthetic"],
    });
    expect(rows.map((row) => row.name)).toEqual([
      "export:node_synthetic:clear",
      "export:node_synthetic:close",
      "export:node_synthetic:default",
      "export:node_synthetic:length",
      "export:node_synthetic:read",
      "export:node_synthetic:remove",
      "export:node_synthetic:write",
    ]);
    expect(
      rows.find((row) => row.name.endsWith(":read")).metadata,
    ).toMatchObject({
      exportName: "read",
      importReachability: "public",
      moduleSpecifiers: ["node:synthetic", "synthetic"],
      publicModuleSpecifiers: ["node:synthetic", "synthetic"],
      sourceKey: "node_synthetic",
      surfaceType: "export",
      valueShape: "callable",
    });
    expect(
      rows.find((row) => row.name.endsWith(":length")).metadata.valueShape,
    ).toBe("accessor");
    expect(
      rows.find((row) => row.name.endsWith(":default")).metadata.valueShape,
    ).toBe("data");
  });

  test("ESM declarations and array-driven CommonJS properties are static exports", () => {
    const esm = scanStaticBuiltinExports(
      "export function serve() {} export const status = 1; export default serve;",
      { sourceKey: "exact_http", sourceKind: "repo", sourcePath: "http.js" },
    );
    expect(esm.map((row) => row.name)).toEqual([
      "export:exact_http:default",
      "export:exact_http:serve",
      "export:exact_http:status",
    ]);

    const cjs = scanStaticBuiltinExports(
      "module.exports = {}; ['F_OK', 'R_OK'].forEach(function(name) { Object.defineProperty(module.exports, name, {}); });",
      { sourceKey: "node_fs", sourcePath: "fs.js" },
    );
    expect(cjs.map((row) => row.name)).toEqual([
      "export:node_fs:F_OK",
      "export:node_fs:R_OK",
      "export:node_fs:default",
    ]);
  });

  test("unresolved computed builtin registrations fail with source context", () => {
    expect(() =>
      scanStaticBuiltinExports(
        "module.exports[getOperationName()] = function() {};",
        { sourceKey: "node_dynamic", sourcePath: "src/builtins/dynamic.js" },
      ),
    ).toThrow(
      /src\/builtins\/dynamic\.js:1:1: module\.exports\[getOperationName\(\)\].*unresolved computed builtin export registration/,
    );

    expect(() =>
      scanStaticBuiltinExports(
        "const api = {}; api[getOperationName()] = 1; module.exports = api;",
        {
          sourceKey: "node_dynamic_alias",
          sourcePath: "src/builtins/dynamic-alias.js",
        },
      ),
    ).toThrow(
      /dynamic-alias\.js:1:17: api\[getOperationName\(\)\].*unresolved computed builtin/,
    );

    expect(() =>
      scanStaticBuiltinExports(
        "module.exports = { [getOperationName()]: function() {} };",
        {
          sourceKey: "node_dynamic_object",
          sourcePath: "src/builtins/dynamic-object.js",
        },
      ),
    ).toThrow(
      /dynamic-object\.js:1:20: \[getOperationName\(\)\].*unresolved computed builtin/,
    );
  });

  test("closed computed builtin tables produce concrete export facts", () => {
    const indexed = scanStaticBuiltinExports(
      String.raw`
        const names = ['read', 'write'];
        const api = {};
        for (let i = 0; i < names.length; i++) api[names[i]] = function() {};
        module.exports = api;
      `,
      { sourceKey: "node_indexed", sourcePath: "src/builtins/indexed.js" },
    );
    expect(indexed.map((row) => row.name)).toEqual([
      "export:node_indexed:default",
      "export:node_indexed:read",
      "export:node_indexed:write",
    ]);

    const copied = scanStaticBuiltinExports(
      String.raw`
        const first = { ALPHA: 1 };
        const second = { BETA: 2 };
        const constants = {};
        function assign(values) {
          for (const key in values) constants[key] = values[key];
        }
        assign(first);
        assign(second);
        module.exports = constants;
      `,
      { sourceKey: "node_copied", sourcePath: "src/builtins/copied.js" },
    );
    expect(copied.map((row) => row.name)).toEqual([
      "export:node_copied:ALPHA",
      "export:node_copied:BETA",
      "export:node_copied:default",
    ]);
    expect(
      copied
        .filter((row) => /:(?:ALPHA|BETA)$/u.test(row.name))
        .map((row) => row.metadata.valueShape),
    ).toEqual(["data", "data"]);
  });

  test("builtin constants retain source-derived platform availability", () => {
    const rows = scanStaticBuiltinExports(
      fs.readFileSync(path.join(repoRoot, "src/builtins/constants.js"), "utf8"),
      {
        sourceKey: "node_constants",
        sourcePath: "src/builtins/constants.js",
      },
    );
    const availability = Object.fromEntries(
      rows
        .filter((row) => row.metadata.platformAvailability)
        .map((row) => [
          row.metadata.exportName,
          row.metadata.platformAvailability,
        ]),
    );
    expect(availability).toEqual({
      EDQUOT: ["android", "linux"],
      EMULTIHOP: ["android", "linux"],
      ENODATA: ["android", "linux"],
      ENOLINK: ["android", "linux"],
      ENOSR: ["android", "linux"],
      ENOSTR: ["android", "linux"],
      ESTALE: ["android", "linux"],
      ETIME: ["android", "linux"],
      EWOULDBLOCK: ["android", "linux"],
      O_DIRECT: ["android", "linux"],
      O_NOATIME: ["android", "linux"],
      O_SYMLINK: ["darwin"],
      SIGINFO: ["darwin"],
      SIGPOLL: ["android", "linux"],
      SIGPWR: ["android", "linux"],
      SIGSTKFLT: ["android", "linux"],
    });
  });

  test("open table copies and opaque export-shape sources fail closed", () => {
    expect(() =>
      scanStaticBuiltinExports(
        String.raw`
          const api = { safe: 1 };
          for (const key in unknown) api[key] = unknown[key];
          module.exports = api;
        `,
        {
          sourceKey: "node_open_copy",
          sourcePath: "src/builtins/open-copy.js",
        },
      ),
    ).toThrow(/api\[key\].*unresolved computed builtin export registration/);

    const opaqueFactory = scanStaticBuiltinExports(
      "module.exports = makeUnknownApi();",
      {
        sourceKey: "node_opaque_factory",
        sourcePath: "src/builtins/opaque-factory.js",
      },
    );
    expect(
      opaqueFactory.some((row) =>
        /^default\.\[\[dynamic-table:inherited-[a-f0-9]{12}-properties\]\]$/u.test(
          row.metadata.exportName,
        ),
      ),
    ).toBe(true);

    for (const [label, source] of [
      ["assign", "Object.assign(module.exports, unknownApi);"],
      ["spread", "module.exports = { safe: 1, ...unknownApi };"],
      ["export-all", "export * from 'unknown-api';"],
    ]) {
      expect(() =>
        scanStaticBuiltinExports(source, {
          sourceKey: `node_opaque_${label.replace("-", "_")}`,
          sourcePath: `src/builtins/opaque-${label}.js`,
        }),
      ).toThrow(/unresolved opaque builtin export shape/);
    }
  });

  test("computed members fail only when their class or prototype is exported", () => {
    expect(() =>
      scanStaticBuiltinExports(
        "class PublicApi { [getOperationName()]() {} } module.exports = PublicApi;",
        {
          sourceKey: "node_public_class",
          sourcePath: "src/builtins/public-class.js",
        },
      ),
    ).toThrow(/unresolved computed exported prototype\/class member/);

    expect(() =>
      scanStaticBuiltinExports(
        "function PublicApi() {} PublicApi.prototype[getOperationName()] = function() {}; module.exports = { PublicApi };",
        {
          sourceKey: "node_public_prototype",
          sourcePath: "src/builtins/public-prototype.js",
        },
      ),
    ).toThrow(/unresolved computed exported prototype\/class member/);

    expect(() =>
      scanStaticBuiltinExports(
        "class PrivateApi { [getOperationName()]() {} } module.exports = { safe: 1 };",
        {
          sourceKey: "node_private_class",
          sourcePath: "src/builtins/private-class.js",
        },
      ),
    ).not.toThrow();
  });

  test("prototype methods on exported constructors become distinct builtin surfaces", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        function ReadStream() {}
        ReadStream.prototype.setRawMode = function() {};
        module.exports = { ReadStream: ReadStream };
      `,
      { sourceKey: "node_tty", sourcePath: "src/builtins/tty.js" },
    );
    expect(rows.map((row) => row.name)).toEqual([
      "export:node_tty:ReadStream",
      "export:node_tty:ReadStream.setRawMode",
      "export:node_tty:default",
    ]);
  });

  test("own prototype overrides take precedence over inherited facts", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        function Base() {}
        Base.prototype.run = function inheritedRun() {};
        function Public() {}
        Public.prototype = Object.create(Base.prototype);
        Public.prototype.constructor = Public;
        Public.prototype.run = function ownRun() {};
        module.exports = { Public: Public };
      `,
      {
        sourceKey: "node_prototype_override",
        sourcePath: "src/builtins/prototype-override.js",
      },
    );
    const idioms = (exportName) =>
      rows.find((row) => row.metadata.exportName === exportName).metadata
        .exportIdioms;
    expect(idioms("Public.constructor")).toEqual([
      "exported-constructor-prototype",
    ]);
    expect(idioms("Public.run")).toEqual([
      "exported-constructor-prototype",
    ]);
  });

  test("member aliases inherit source-proven callable value shapes", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        const methods = {};
        methods.read = function read() {};
        methods.readAlias = methods.read;
        function Base() {}
        Base.prototype.close = function close() {};
        function Public() {}
        Public.prototype.closeAlias = Base.prototype.close;
        Public.prototype.readAlias = methods.readAlias;
        module.exports = { Public };
      `,
      {
        sourceKey: "node_member_alias",
        sourcePath: "src/builtins/member-alias.js",
      },
    );
    for (const exportName of ["Public.closeAlias", "Public.readAlias"]) {
      expect(
        rows.find((row) => row.metadata.exportName === exportName)?.metadata
          .valueShape,
      ).toBe("callable");
    }
  });

  test("builtin exports retain exact transitive routes to native enforcement calls", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        function readImpl() { return globalThis.__exactReadFile('/tmp/input'); }
        function read() { return readImpl(); }
        function unrelated() { return __exactWriteFile('/tmp/output', 'x'); }
        class Handle {
          read() { return readImpl(); }
        }
        module.exports = { read, Handle };
      `,
      {
        sourceKey: "node_routes",
        sourcePath: "src/builtins/routes.js",
      },
    );
    const evidence = (name) =>
      rows.find((row) => row.name === `export:node_routes:${name}`).metadata
        .enforcementRouteEvidence;
    expect(evidence("read")).toEqual({
      ambiguousCallees: [],
      kind: "static-builtin-call-graph",
      paths: [
        "export:read -> read -> readImpl -> __exactReadFile",
      ],
      terminals: ["__exactReadFile"],
    });
    expect(evidence("Handle.read")).toEqual({
      ambiguousCallees: [],
      kind: "static-builtin-call-graph",
      paths: [
        "export:Handle.read -> Handle.read -> readImpl -> __exactReadFile",
      ],
      terminals: ["__exactReadFile"],
    });
    expect(evidence("read").terminals).not.toContain("__exactWriteFile");

    const defaultObjectRows = scanStaticBuiltinExports(
      String.raw`
        const api = {};
        api.read = function read() { return globalThis.__exactReadFile('/tmp/input'); };
        module.exports = api;
      `,
      {
        sourceKey: "node_object_routes",
        sourcePath: "src/builtins/object-routes.js",
      },
    );
    expect(
      defaultObjectRows.find(
        (row) => row.name === "export:node_object_routes:read",
      ).metadata.enforcementRouteEvidence,
    ).toEqual({
      ambiguousCallees: [],
      kind: "static-builtin-call-graph",
      paths: ["export:read -> api.read -> __exactReadFile"],
      terminals: ["__exactReadFile"],
    });
  });

  test("builtin routes follow only source-proven returned-callable wrappers", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        function decorate(getter) {
          const wrapped = function() { return getter(); };
          wrapped.toString = function() { return String(getter()); };
          return wrapped;
        }
        function platform() { return __exactAuthorizeSystemInfo(11); }
        module.exports = { platform: decorate(platform) };
      `,
      {
        sourceKey: "node_wrapped_route",
        sourcePath: "src/builtins/wrapped-route.js",
      },
    );
    expect(
      rows.find(
        (row) => row.name === "export:node_wrapped_route:platform",
      ).metadata.enforcementRouteEvidence,
    ).toEqual({
      ambiguousCallees: [],
      kind: "static-builtin-call-graph",
      paths: [
        "export:platform -> decorate -> wrapped -> parameter:getter -> platform -> __exactAuthorizeSystemInfo",
      ],
      terminals: ["__exactAuthorizeSystemInfo"],
    });

    const opaque = scanStaticBuiltinExports(
      "function factory(value) { return service.wrap(value); } function read() { return __exactReadFile('/tmp/x'); } module.exports = { read: factory(read) };",
      {
        sourceKey: "node_opaque_wrapped_route",
        sourcePath: "src/builtins/opaque-wrapped-route.js",
      },
    );
    expect(
      opaque.find(
        (row) => row.name === "export:node_opaque_wrapped_route:read",
      ).metadata.enforcementRouteEvidence.terminals,
    ).toEqual([]);
  });

  test("builtin enforcement routes reject shadowed, computed, and dynamic call ambiguity", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        function shadowed(__exactReadFile) { return __exactReadFile(); }
        function dynamicTerminal() { return service.__exactReadFile(); }
        function computed() { return globalThis['__exactReadFile'](); }
        const invokeRead = globalThis.__exactReadFile;
        function aliased() { return invokeRead('/tmp/input'); }
        class Reader {
          go() { return this.run(); }
          run() { return globalThis.__exactReadFile('/tmp/input'); }
        }
        class Writer {
          run() { return globalThis.__exactWriteFile('/tmp/output', 'x'); }
        }
        const helpers = {
          read() { return globalThis.__exactReadFile('/tmp/input'); }
        };
        function staticObject() { return helpers.read(); }
        let mutable = { read() { return globalThis.__exactReadFile('/tmp/input'); } };
        mutable = service;
        function mutableObject() { return mutable.read(); }
        function intrinsic() {
          const values = [];
          values.push('safe');
          return Object.keys({safe: values.join(',')});
        }
        function dynamicReceiver() { return service.run(); }
        var intrinsicRegistry = typeof WeakMap === 'function'
          ? new WeakMap()
          : null;
        var mutableRegistry = new Map();
        mutableRegistry = service;
        function intrinsicRegistryRead() {
          if (intrinsicRegistry) intrinsicRegistry.get(service);
          return globalThis.__exactReadFile('/tmp/input');
        }
        function mutableRegistryRead() {
          mutableRegistry.get('unsafe');
          return globalThis.__exactReadFile('/tmp/input');
        }
        module.exports = {
          shadowed, dynamicTerminal, computed, aliased,
          Reader, Writer, staticObject, mutableObject, intrinsic,
          dynamicReceiver, intrinsicRegistryRead, mutableRegistryRead
        };
      `,
      {
        sourceKey: "node_route_mutations",
        sourcePath: "src/builtins/route-mutations.js",
      },
    );
    const evidence = (name) =>
      rows.find(
        (row) => row.name === `export:node_route_mutations:${name}`,
      ).metadata.enforcementRouteEvidence;
    expect(evidence("shadowed").ambiguousCallees).toContain(
      "shadowed:__exactReadFile",
    );
    expect(evidence("dynamicTerminal").ambiguousCallees).toContain(
      "dynamic-terminal-receiver:__exactReadFile",
    );
    expect(evidence("computed").ambiguousCallees).toContain(
      "computed-terminal:__exactReadFile",
    );
    expect(evidence("aliased").terminals).toEqual(["__exactReadFile"]);
    expect(evidence("dynamicReceiver").ambiguousCallees).toContain(
      "dynamic-call-receiver:run",
    );
    expect(evidence("Reader.go").terminals).toEqual(["__exactReadFile"]);
    expect(evidence("Writer.run").terminals).toEqual(["__exactWriteFile"]);
    expect(evidence("staticObject").terminals).toEqual(["__exactReadFile"]);
    expect(evidence("mutableObject").ambiguousCallees).toContain(
      "dynamic-call-receiver:read",
    );
    expect(evidence("intrinsic").ambiguousCallees).toEqual([]);
    expect(evidence("intrinsicRegistryRead")).toMatchObject({
      ambiguousCallees: [],
      terminals: ["__exactReadFile"],
    });
    expect(evidence("mutableRegistryRead").ambiguousCallees).toContain(
      "dynamic-call-receiver:get",
    );
  });

  test("builtin routes follow only immutable constructor and callable provenance", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        function NativeHandle() {
          globalThis.__exactOpenHandle('/tmp/input');
        }
        NativeHandle.prototype.read = function read() {
          return globalThis.__exactReadHandle();
        };
        function construct() { return new NativeHandle(); }
        function readImpl() { return globalThis.__exactReadHandle(); }
        function invokeWithCall() { return readImpl.call(null); }
        function intrinsicCall() {
          return Array.prototype.slice.call(arguments);
        }
        function staticRequire() {
          require('node:path');
          return readImpl();
        }
        function dynamicConstructor(Constructor) { return new Constructor(); }
        function opaqueTarget(factory) { return factory()(); }
        module.exports = {
          construct,
          invokeWithCall,
          intrinsicCall,
          staticRequire,
          dynamicConstructor,
          opaqueTarget,
        };
      `,
      {
        sourceKey: "node_route_provenance",
        sourcePath: "src/builtins/route-provenance.js",
      },
    );
    const evidence = (name) =>
      rows.find(
        (row) => row.name === `export:node_route_provenance:${name}`,
      ).metadata.enforcementRouteEvidence;
    expect(evidence("construct").terminals).toEqual(["__exactOpenHandle"]);
    expect(evidence("invokeWithCall").terminals).toEqual([
      "__exactReadHandle",
    ]);
    expect(evidence("intrinsicCall").ambiguousCallees).toEqual([]);
    // Even a literal require can cross the package import gate when it runs
    // after builtin evaluation, so it remains a conservative route edge.
    expect(evidence("staticRequire").ambiguousCallees).toContain(
      "unresolved-call:require",
    );
    expect(evidence("staticRequire").terminals).toEqual([
      "__exactReadHandle",
    ]);
    expect(evidence("dynamicConstructor").ambiguousCallees).toContain(
      "unresolved-call:Constructor",
    );
    expect(evidence("opaqueTarget").ambiguousCallees).toContain(
      "dynamic-call-target:CallExpression",
    );
  });

  test("builtin route provenance fails closed under intrinsic and terminal tampering", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        Array.prototype.slice = service.slice;
        Number = service.Number;
        Array = service.Array;
        function mutatedIntrinsic() {
          return Array.prototype.slice.call(arguments);
        }
        function reassignedIntrinsicCall() { return Number(1); }
        function reassignedIntrinsicConstructor() { return new Array(); }
        function dynamicTerminalCall() {
          return service.__exactReadHandle.call(service);
        }
        function shadowedRequire(require) { return require('node:path'); }
        module.exports = {
          mutatedIntrinsic,
          reassignedIntrinsicCall,
          reassignedIntrinsicConstructor,
          dynamicTerminalCall,
          shadowedRequire,
        };
      `,
      {
        sourceKey: "node_route_tampering",
        sourcePath: "src/builtins/route-tampering.js",
      },
    );
    const evidence = (name) =>
      rows.find(
        (row) => row.name === `export:node_route_tampering:${name}`,
      ).metadata.enforcementRouteEvidence;
    expect(evidence("mutatedIntrinsic").ambiguousCallees).toContain(
      "dynamic-call-receiver:call",
    );
    expect(evidence("reassignedIntrinsicCall").ambiguousCallees).toContain(
      "unresolved-call:Number",
    );
    expect(
      evidence("reassignedIntrinsicConstructor").ambiguousCallees,
    ).toContain("unresolved-call:Array");
    expect(evidence("dynamicTerminalCall").ambiguousCallees).toContain(
      "dynamic-terminal-receiver:__exactReadHandle",
    );
    expect(evidence("dynamicTerminalCall").terminals).toEqual([]);
    expect(evidence("shadowedRequire").ambiguousCallees).toContain(
      "unresolved-call:require",
    );
  });

  test("builtin call/apply routes fail closed after Function prototype mutation", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        Function.prototype.call = service.call;
        function readImpl() { return globalThis.__exactReadHandle(); }
        function mutatedFunctionCall() { return readImpl.call(null); }
        module.exports = { mutatedFunctionCall };
      `,
      {
        sourceKey: "node_route_function_tampering",
        sourcePath: "src/builtins/route-function-tampering.js",
      },
    );
    const evidence = rows.find(
      (row) =>
        row.name ===
        "export:node_route_function_tampering:mutatedFunctionCall",
    ).metadata.enforcementRouteEvidence;
    expect(evidence.ambiguousCallees).toContain("dynamic-call-receiver:call");
    expect(evidence.terminals).toEqual([]);
  });

  test("builtin routes retain terminals from opaque callable alternatives", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        const api = {
          read: service.read || function readFallback() {
            return globalThis.__exactReadHandle();
          },
          choose: flag
            ? function readChoice() { return globalThis.__exactReadHandle(); }
            : function writeChoice() { return globalThis.__exactWriteHandle(); },
        };
        module.exports = api;
      `,
      {
        sourceKey: "node_route_alternatives",
        sourcePath: "src/builtins/route-alternatives.js",
      },
    );
    const evidence = (name) =>
      rows.find(
        (row) => row.name === `export:node_route_alternatives:${name}`,
      ).metadata.enforcementRouteEvidence;
    expect(evidence("read").terminals).toEqual(["__exactReadHandle"]);
    expect(evidence("read").ambiguousCallees).toContain(
      "dynamic-callable-alternative:api.read",
    );
    expect(evidence("choose").terminals).toEqual([
      "__exactReadHandle",
      "__exactWriteHandle",
    ]);
    expect(evidence("choose").ambiguousCallees).toContain("api.choose");
  });

  test("builtin routes retain exact required-export provenance and reject tampering", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        var safeFs = require('node:fs');
        var mutableFs = require('node:fs');
        mutableFs = service;
        var path = require('node:path');
        function read() { return safeFs.readFileSync('/tmp/input'); }
        function tampered() { return mutableFs.readFileSync('/tmp/input'); }
        function computed() { return path['resolve']('/tmp/input'); }
        module.exports = { read, tampered, computed };
      `,
      {
        sourceKey: "node_required_routes",
        sourcePath: "src/builtins/required-routes.js",
      },
    );
    const evidence = (name) =>
      rows.find(
        (row) => row.name === `export:node_required_routes:${name}`,
      ).metadata.enforcementRouteEvidence;
    expect(evidence("read").requiredExportCalls).toEqual([
      {
        exportName: "readFileSync",
        moduleSpecifier: "node:fs",
        paths: [
          "export:read -> read -> require:node:fs:readFileSync",
        ],
      },
    ]);
    expect(evidence("tampered").requiredExportCalls).toBeUndefined();
    expect(evidence("tampered").ambiguousCallees).toContain(
      "dynamic-call-receiver:readFileSync",
    );
    expect(evidence("computed").requiredExportCalls).toBeUndefined();
    expect(evidence("computed").ambiguousCallees).toContain("computed-call");
  });

  test("inherited CommonJS export shapes are enumerated or closed explicitly", () => {
    for (const source of [
      "module.exports = Object.create({ hidden() {} });",
      "module.exports = {}; Object.setPrototypeOf(module.exports, { hidden() {} });",
      "module.exports = {}; module.exports.__proto__ = { hidden() {} };",
    ]) {
      const rows = scanStaticBuiltinExports(source, {
        sourceKey: "node_inherited_object",
        sourcePath: "src/builtins/inherited-object.js",
      });
      expect(rows.map((row) => row.name)).toEqual([
        "export:node_inherited_object:default",
        "export:node_inherited_object:hidden",
      ]);
      expect(rows.some((row) => row.name.endsWith(":__proto__"))).toBe(false);
    }

    const classRows = scanStaticBuiltinExports(
      String.raw`
        class Base {
          static inheritedStatic() {}
          inheritedInstance() {}
        }
        class Public extends Base {}
        module.exports = { Public };
      `,
      {
        sourceKey: "node_inherited_class",
        sourcePath: "src/builtins/inherited-class.js",
      },
    );
    expect(classRows.map((row) => row.name)).toEqual([
      "export:node_inherited_class:Public",
      "export:node_inherited_class:Public.inheritedInstance",
      "export:node_inherited_class:Public.inheritedStatic",
      "export:node_inherited_class:default",
    ]);

    const opaqueRows = scanStaticBuiltinExports(
      "function Public() {} Public.prototype = Object.create(loadBase().prototype); module.exports = { Public };",
      {
        sourceKey: "node_opaque_inheritance",
        sourcePath: "src/builtins/opaque-inheritance.js",
      },
    );
    expect(
      opaqueRows.some((row) =>
        /Public\.\[\[dynamic-table:inherited-[a-f0-9]+-properties\]\]$/u.test(
          row.metadata.exportName,
        ),
      ),
    ).toBe(true);
  });

  test("direct public class expressions and util inheritance retain their complete shape", () => {
    const classExpression =
      "class extends Base { static ownStatic() {} ownInstance() {} }";
    const positions = [
      [`module.exports = ${classExpression};`, "default"],
      [`module.exports = { Public: ${classExpression} };`, "Public"],
      [`module.exports.Public = ${classExpression};`, "Public"],
      [
        `Object.assign(module.exports, { Public: ${classExpression} });`,
        "Public",
      ],
      [
        `Object.defineProperty(module.exports, 'Public', { value: ${classExpression} });`,
        "Public",
      ],
      [
        `Reflect.defineProperty(module.exports, 'Public', { value: ${classExpression} });`,
        "Public",
      ],
      [
        `Object.defineProperties(module.exports, { Public: { value: ${classExpression} } });`,
        "Public",
      ],
      [`Reflect.set(module.exports, 'Public', ${classExpression});`, "Public"],
      [
        `module.exports.Public = flag ? ${classExpression} : ${classExpression};`,
        "Public",
      ],
      [`module.exports.Public = flag && ${classExpression};`, "Public"],
      [`module.exports.Public = (sideEffect(), ${classExpression});`, "Public"],
      [
        `function make() { return ${classExpression}; } module.exports.Public = make();`,
        "Public",
      ],
      [
        `const make = () => ${classExpression}; module.exports.Public = make();`,
        "Public",
      ],
      [
        `const make = function() { return ${classExpression}; }; module.exports.Public = make();`,
        "Public",
      ],
      [
        `function make() { const C = ${classExpression}; return C; } module.exports.Public = make();`,
        "Public",
      ],
      [
        `const C = ${classExpression}; const make = () => C; module.exports.Public = make();`,
        "Public",
      ],
    ];
    for (const [installation, exportName] of positions) {
      const rows = scanStaticBuiltinExports(
        `class Base { static inheritedStatic() {} inheritedInstance() {} } ${installation}`,
        {
          sourceKey: "node_class_expression",
          sourcePath: "src/builtins/class-expression.js",
        },
      );
      for (const member of [
        "inheritedInstance",
        "inheritedStatic",
        "ownInstance",
        "ownStatic",
      ]) {
        expect(rows.map((row) => row.metadata.exportName)).toContain(
          `${exportName}.${member}`,
        );
      }
    }

    const inherited = scanStaticBuiltinExports(
      "function Base() {} Base.prototype.hidden = function() {}; function Public() {} util.inherits(Public, Base); module.exports = { Public };",
      {
        sourceKey: "node_util_inherits",
        sourcePath: "src/builtins/util-inherits.js",
      },
    );
    expect(inherited.map((row) => row.metadata.exportName)).toContain(
      "Public.hidden",
    );
    expect(() =>
      scanStaticBuiltinExports(
        `class Base { hidden() {} } module.exports.Public = decorate(${classExpression});`,
        {
          sourceKey: "node_opaque_decorator",
          sourcePath: "src/builtins/opaque-decorator.js",
        },
      ),
    ).toThrow(/unresolved public class decorator\/factory call/);
    for (const [source, sourceKey] of [
      ["module.exports.Public = unknownFactory();", "node_opaque_factory"],
      [
        "function first() { return second(); } function second() { return first(); } module.exports.Public = first();",
        "node_recursive_factory",
      ],
      [
        "function make() { return /hidden/; } module.exports.Public = make();",
        "node_object_return",
      ],
    ]) {
      const rows = scanStaticBuiltinExports(source, {
        sourceKey,
        sourcePath: `src/builtins/${sourceKey}.js`,
      });
      expect(
        rows.some((row) =>
          /^Public\.\[\[dynamic-table:inherited-[a-f0-9]{12}-properties\]\]$/u.test(
            row.metadata.exportName,
          ),
        ),
      ).toBe(true);
    }
    expect(() =>
      scanStaticBuiltinExports(
        "const builtinList = ['fs']; module.exports.builtinModules = builtinList.slice();",
        {
          sourceKey: "node_closed_array_copy",
          sourcePath: "src/builtins/closed-array-copy.js",
        },
      ),
    ).not.toThrow();
    expect(() =>
      scanStaticBuiltinExports(
        "function isWorker() { if (process) return false; return !!process; } module.exports.isWorker = isWorker();",
        {
          sourceKey: "node_closed_scalar_call",
          sourcePath: "src/builtins/closed-scalar-call.js",
        },
      ),
    ).not.toThrow();
  });

  test("legacy accessors and reflective prototype mutations are exact and fail closed", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        function Socket() {}
        Socket.prototype.__defineGetter__('bytesWritten', function() { return 0; });
        Socket.prototype.__defineSetter__('bytesWritten', function(value) {});
        Reflect.defineProperty(Socket.prototype, 'ready', { get: function() { return true; } });
        Reflect.set(Socket.prototype, 'close', function() {});
        Object.assign(Socket.prototype, { connect: function() {} });
        module.exports = { Socket: Socket };
      `,
      { sourceKey: "node_net", sourcePath: "src/builtins/net.js" },
    );
    expect(rows.map((row) => row.name)).toEqual([
      "export:node_net:Socket",
      "export:node_net:Socket.bytesWritten",
      "export:node_net:Socket.close",
      "export:node_net:Socket.connect",
      "export:node_net:Socket.ready",
      "export:node_net:default",
    ]);
    expect(
      rows.find((row) => row.name.endsWith(":Socket.ready")).metadata
        .valueShape,
    ).toBe("accessor");
    expect(
      rows.find((row) => row.name.endsWith(":Socket.close")).metadata
        .valueShape,
    ).toBe("callable");

    for (const source of [
      "function Socket() {} Socket.prototype.__defineGetter__(getName(), function() {}); module.exports = { Socket };",
      "function Socket() {} Reflect.set(Socket.prototype, getName(), function() {}); module.exports = { Socket };",
      "function Socket() {} Object.assign(Socket.prototype, { [getName()]: function() {} }); module.exports = { Socket };",
    ]) {
      expect(() =>
        scanStaticBuiltinExports(source, {
          sourceKey: "node_dynamic_net",
          sourcePath: "src/builtins/dynamic-net.js",
        }),
      ).toThrow(/unresolved computed exported prototype\/class member/);
    }
  });

  test("instance initializer methods flow to exported constructors", () => {
    const rows = scanStaticBuiltinExports(
      String.raw`
        function initStream(stream) {
          stream.open = function() {};
          Reflect.set(stream, 'close', function() {});
          Object.assign(stream, { destroy: function() {} });
        }
        function ReadStream() { return initStream(this); }
        module.exports = { ReadStream: ReadStream };
      `,
      { sourceKey: "node_fs", sourcePath: "src/builtins/fs.js" },
    );
    expect(rows.map((row) => row.name)).toEqual([
      "export:node_fs:ReadStream",
      "export:node_fs:ReadStream.close",
      "export:node_fs:ReadStream.destroy",
      "export:node_fs:ReadStream.open",
      "export:node_fs:default",
    ]);

    expect(() =>
      scanStaticBuiltinExports(
        "function init(stream, name) { stream[name] = function() {}; } function ReadStream() { return init(this, getName()); } module.exports = { ReadStream };",
        {
          sourceKey: "node_dynamic_fs",
          sourcePath: "src/builtins/dynamic-fs.js",
        },
      ),
    ).toThrow(/unresolved computed exported prototype\/class member/);
  });

  test("runtime commands retain their manifest class and cannot overlap", () => {
    const manifest = {
      visibleCommands: ["run"],
      hiddenHarnessCommands: ["self-test"],
      reservedCommands: ["install"],
      legacyProjectCommands: ["doctor"],
    };
    const rows = scanRuntimeCommandClasses(manifest);
    expect(rows.find((row) => row.name === "self-test")).toMatchObject({
      kind: "cli",
      variant: "hidden-harness",
      metadata: { commandClass: "hiddenHarnessCommands" },
    });

    manifest.reservedCommands.push("run");
    expect(() => scanRuntimeCommandClasses(manifest)).toThrow(
      /duplicate runtime command "run"/,
    );
  });

  test("recursive CLI routes and value shapes are exact observed surfaces", () => {
    const shape = {
      action: "Set",
      required: false,
      valueNames: ["MODE"],
      minValues: 0,
      maxValues: 1,
      valueDomain: "enumerated",
      possibleValues: [
        { value: "strict", aliases: ["s"], hidden: false },
        { value: "compat", aliases: [], hidden: true },
      ],
      possibleValuesHidden: false,
      defaultValues: ["strict"],
      defaultMissingValues: ["compat"],
      allowHyphenValues: false,
    };
    const manifest = {
      version: 4,
      visibleCommands: ["run"],
      hiddenHarnessCommands: ["self-test"],
      reservedCommands: ["install"],
      legacyProjectCommands: ["doctor"],
      clapSurface: {
        semanticRelations: {
          argumentConflicts: [
            {
              commandPath: "ibex",
              argumentId: "mode",
              conflictsWith: ["output"],
            },
          ],
          nonEnumeratedParsers: [
            {
              commandPath: "ibex",
              argumentId: "output",
              parserKind: "os-path",
            },
          ],
        },
        commands: [
          {
            path: "ibex",
            options: [
              {
                id: "mode",
                names: ["--mode", "-m"],
                hiddenAliases: ["--legacy-mode"],
                valueShape: shape,
              },
              {
                id: "output",
                names: ["--output"],
                valueShape: {
                  ...shape,
                  defaultMissingValues: [],
                  defaultValues: [],
                  possibleValues: [],
                  valueDomain: "arbitrary",
                  valueNames: ["PATH"],
                },
              },
            ],
          },
        ],
      },
    };
    const rows = scanRuntimeCliSurfaces(manifest);
    expect(rows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "command:ibex",
        "option:ibex:mode",
        "option-name:ibex:mode:--mode",
        "option-name:ibex:mode:-m",
        "option-name:ibex:mode:--legacy-mode",
        "option:ibex:mode:action:Set",
        "option:ibex:mode:arity:0:1",
        "option:ibex:mode:enum:strict",
        "option:ibex:mode:enum-alias:strict:s",
        "option:ibex:mode:default:strict",
        "option:ibex:mode:default-missing:compat",
        "argument-conflict:ibex:mode:output",
        "argument-parser:ibex:output:os-path",
      ]),
    );
    expect(
      rows.find((row) => row.name === "option-name:ibex:mode:--legacy-mode")
        .metadata,
    ).toMatchObject({ routeKind: "hidden-alias" });

    const drift = structuredClone(manifest);
    drift.clapSurface.commands[0].options[0].valueShape.unknownShape = true;
    expect(() => scanRuntimeCliSurfaces(drift)).toThrow(
      /unreviewed fields: unknownShape/,
    );

    const missingParser = structuredClone(manifest);
    missingParser.clapSurface.semanticRelations.nonEnumeratedParsers = [];
    expect(() => scanRuntimeCliSurfaces(missingParser)).toThrow(
      /every non-enumerated CLI argument must have exactly one reviewed parser relation/,
    );
  });

  test("global API discovery follows constructor prototypes and ignores source text lookalikes", () => {
    const source = String.raw`
      // globalThis.fakeComment = new StorageImpl();
      const fake = "globalThis.fakeString = new StorageImpl()";
      function StorageImpl() {}
      Object.defineProperty(StorageImpl.prototype, 'length', { get: function() { return 0; } });
      StorageImpl.prototype.getItem = function() {};
      StorageImpl.prototype.setItem = function() {};
      globalThis.localStorage = new StorageImpl();
    `;
    const rows = scanStaticGlobalApiSurfaces(
      source,
      "src/engine/bootstrap/storage.js",
    );
    expect(rows.map((row) => row.name)).toEqual([
      "global:localStorage",
      "global:localStorage.getItem",
      "global:localStorage.length",
      "global:localStorage.setItem",
    ]);
    expect(rows[1].metadata).toMatchObject({
      exportName: "localStorage.getItem",
      globalName: "localStorage",
      moduleSpecifiers: [],
      sourceKey: "global_storage",
      surfaceType: "global-api",
    });
  });

  test("installed class expressions, class declarations, and util inheritance retain members", () => {
    const classExpression =
      "class extends Base { static ownStatic() {} ownInstance() {} }";
    const installations = [
      `globalThis.Public = ${classExpression};`,
      `Object.assign(globalThis, { Public: ${classExpression} });`,
      `Object.defineProperty(globalThis, 'Public', { value: ${classExpression} });`,
      `Reflect.defineProperty(globalThis, 'Public', { value: ${classExpression} });`,
      `Object.defineProperties(globalThis, { Public: { value: ${classExpression} } });`,
      `Reflect.set(globalThis, 'Public', ${classExpression});`,
      `const Public = ${classExpression}; globalThis.Public = Public;`,
      "class Public extends Base { static ownStatic() {} ownInstance() {} } globalThis.Public = Public;",
      `globalThis.Public = flag ? ${classExpression} : ${classExpression};`,
      `globalThis.Public = flag && ${classExpression};`,
      `globalThis.Public = (sideEffect(), ${classExpression});`,
      `function make() { return ${classExpression}; } globalThis.Public = make();`,
      `const make = () => ${classExpression}; globalThis.Public = make();`,
      `const make = function() { return ${classExpression}; }; globalThis.Public = make();`,
      `function make() { const C = ${classExpression}; return C; } globalThis.Public = make();`,
      `const C = ${classExpression}; const make = () => C; globalThis.Public = make();`,
    ];
    for (const installation of installations) {
      const rows = scanStaticGlobalApiSurfaces(
        `class Base { static inheritedStatic() {} inheritedInstance() {} } ${installation}`,
        "src/engine/bootstrap/class-expression.js",
      );
      for (const member of [
        "inheritedInstance",
        "inheritedStatic",
        "ownInstance",
        "ownStatic",
      ]) {
        expect(rows.map((row) => row.name)).toContain(
          `global:Public.${member}`,
        );
      }
    }

    const inherited = scanStaticGlobalApiSurfaces(
      "function Base() {} Base.prototype.hidden = function() {}; function Public() {} util.inherits(Public, Base); globalThis.Public = Public;",
      "src/engine/bootstrap/util-inherits.js",
    );
    expect(inherited.map((row) => row.name)).toContain("global:Public.hidden");
    expect(() =>
      scanStaticGlobalApiSurfaces(
        `class Base { hidden() {} } globalThis.Public = decorate(${classExpression});`,
        "src/engine/bootstrap/opaque-decorator.js",
      ),
    ).toThrow(/unresolved public class decorator\/factory call/);
    const opaqueFactoryRows = scanStaticGlobalApiSurfaces(
      "globalThis.Public = unknownFactory();",
      "src/engine/bootstrap/opaque-factory.js",
    );
    expect(
      opaqueFactoryRows.some((row) =>
        /^global:Public\.\[\[dynamic-table:call-result-[a-f0-9]{12}-properties\]\]$/u.test(
          row.name,
        ),
      ),
    ).toBe(true);
    const duplicateRows = scanStaticGlobalApiSurfaces(
      "globalThis.Dynamic = unknownFactory(); globalThis.Dynamic = function Dynamic() {};",
      "src/engine/bootstrap/duplicate-dynamic.js",
    );
    expect(
      duplicateRows.find((row) => row.name === "global:Dynamic").metadata,
    ).toMatchObject({
      dynamicNamespace: true,
      dynamicNamespaceEvidence: expect.stringMatching(/^sha256-[a-f0-9]{64}$/u),
      dynamicNamespaceKind: "opaque-call-result",
    });
    expect(() =>
      scanStaticGlobalApiSurfaces(
        "globalThis.Dynamic = firstFactory(); globalThis.Dynamic = secondFactory();",
        "src/engine/bootstrap/conflicting-dynamic.js",
      ),
    ).toThrow(
      /conflicting dynamic-namespace evidence for native-op:global:Dynamic/,
    );
    const proxyRows = scanStaticGlobalApiSurfaces(
      "globalThis.Dynamic = (function() { return new Proxy({}, { get() { return 1; } }); })();",
      "src/engine/bootstrap/dynamic-proxy.js",
    );
    expect(
      proxyRows.find((row) => row.name === "global:Dynamic").metadata,
    ).toMatchObject({
      dynamicNamespace: true,
      dynamicNamespaceEvidence: expect.stringMatching(/^sha256-[a-f0-9]{64}$/u),
      dynamicNamespaceKind: "iife-call-result",
    });
    expect(
      proxyRows.some((row) =>
        /^global:Dynamic\.\[\[dynamic-table:call-result-[a-f0-9]{12}-properties\]\]$/u.test(
          row.name,
        ),
      ),
    ).toBe(true);
    const aliasedRows = scanStaticGlobalApiSurfaces(
      "var g = globalThis; var E = g.Exact || {}; E.CryptoHasher = (function() { function CH() {} return CH; })(); g.Bun = E;",
      "src/engine/bootstrap/aliased-dynamic.js",
    );
    const aliasedSentinel = aliasedRows.find((row) =>
      /^global:Bun\.CryptoHasher\.\[\[dynamic-table:call-result-[a-f0-9]{12}-properties\]\]$/u.test(
        row.name,
      ),
    );
    expect(aliasedSentinel?.metadata).toMatchObject({
      dynamicNamespace: true,
      dynamicNamespaceEvidence: expect.stringMatching(/^sha256-[a-f0-9]{64}$/u),
      dynamicNamespaceKind: "iife-call-result",
      dynamicNamespaceRoot: "Bun.CryptoHasher",
      semanticRoles: ["dynamic-call-result-shape"],
    });
    const constructorRows = scanStaticGlobalApiSurfaces(
      "globalThis.Constructor = (function() { function C() {} C.prototype.run = function() {}; return C; })();",
      "src/engine/bootstrap/iife-constructor.js",
    );
    expect(
      constructorRows.some((row) =>
        /^global:Constructor\.\[\[dynamic-table:call-result-[a-f0-9]{12}-properties\]\]$/u.test(
          row.name,
        ),
      ),
    ).toBe(true);
  });

  test("global discovery rejects open computed names and resolves closed installers", () => {
    expect(() =>
      scanStaticGlobalApiSurfaces(
        "globalThis[getOperationName()] = function() {};",
        "src/engine/bootstrap/dynamic-global.js",
      ),
    ).toThrow(
      /dynamic-global\.js:1:1: globalThis\[getOperationName\(\)\].*unresolved computed global property registration/,
    );
    expect(() =>
      scanStaticGlobalApiSurfaces(
        "Object.assign(globalThis, { [getOperationName()]: function() {} });",
        "src/engine/bootstrap/dynamic-global-object.js",
      ),
    ).toThrow(
      /dynamic-global-object\.js:1:29: \[getOperationName\(\)\].*unresolved computed global/,
    );

    const rows = scanStaticGlobalApiSurfaces(
      String.raw`
        function install(name) { globalThis[name] = function() {}; }
        const names = ['Alpha', 'Beta'];
        for (let i = 0; i < names.length; i++) install(names[i]);
        ['Gamma'].forEach((name) => { globalThis[name] = {}; });
      `,
      "src/engine/bootstrap/static-globals.js",
    );
    expect(rows.map((row) => row.name)).toEqual([
      "global:Alpha",
      "global:Beta",
      "global:Gamma",
    ]);
  });

  test("returned-object and reflective global mutations remain explicit", () => {
    const rows = scanStaticGlobalApiSurfaces(
      String.raw`
        function Handle() {}
        Handle.prototype.read = function() {};
        Reflect.defineProperty(Handle.prototype, 'scoped', { value: function() {} });
        globalThis.API = {};
        Reflect.set(globalThis.API, 'open', function() { return new Handle(); });
        Reflect.defineProperty(globalThis.API, 'status', { value: function() {} });
        Object.assign(globalThis.API, { close: function() {} });
      `,
      "src/engine/bootstrap/returned-api.js",
    );
    expect(rows.map((row) => row.name)).toEqual([
      "global:API",
      "global:API.close",
      "global:API.open",
      "global:API.open.[[return]].read",
      "global:API.open.[[return]].scoped",
      "global:API.status",
    ]);

    expect(() =>
      scanStaticGlobalApiSurfaces(
        "function Handle() {} Reflect.set(Handle.prototype, getName(), function() {}); globalThis.open = function() { return new Handle(); };",
        "src/engine/bootstrap/dynamic-return.js",
      ),
    ).toThrow(/unresolved computed public or returned-object member/);
    expect(() =>
      scanStaticGlobalApiSurfaces(
        "Reflect.set(globalThis, getName(), function() {});",
        "src/engine/bootstrap/dynamic-reflect.js",
      ),
    ).toThrow(/unresolved computed global property registration/);
    expect(() =>
      scanStaticGlobalApiSurfaces(
        "Object.assign(globalThis, unknownPublicShape);",
        "src/engine/bootstrap/opaque-assign.js",
      ),
    ).toThrow(
      /unresolved computed global property registration.*opaque-object-assign-source/,
    );
  });

  test("authored TypeScript install graph follows imports, delegates, exact members, and statics", () => {
    const root = makeRuntimeFixture({
      "packages/ibex-runtime-js/src/runtime-entry.ts": `
        import { installGlobals } from './bootstrap.js';
        installGlobals();
        const g = globalThis as any;
        g.exact = g.exact || {};
        g.exact.runtime = { version: '1', info() {} };
      `,
      "packages/ibex-runtime-js/src/bootstrap.ts": `
        import { Gadget } from './barrel.js';
        import { installDelegated } from './delegated.js';
        function defineLazyGlobal(target: any, name: string, factory: () => any) {
          Object.defineProperty(target, name, { get() { return factory(); } });
        }
        export function installGlobals() {
          const g = globalThis as any;
          defineLazyGlobal(g, 'Gadget', () => Gadget);
          g.Tools = { nested: { go() {} } };
          installDelegated(g);
        }
      `,
      "packages/ibex-runtime-js/src/barrel.ts": `export { Gadget } from './gadget.js';`,
      "packages/ibex-runtime-js/src/delegated.ts": `
        import { Gadget } from './gadget.js';
        export function installDelegated(target: any) {
          Object.defineProperties(target, { Delegated: { value: new Gadget() } });
        }
      `,
      "packages/ibex-runtime-js/src/base.ts": `
        export class Base {
          static baseVersion = '1';
          baseRun() {}
        }
      `,
      "packages/ibex-runtime-js/src/gadget.ts": `
        import { Base } from './base.js';
        export class Gadget extends Base {
          static version = '1';
          static create() { return new Gadget(); }
          value = 1;
          #hidden() {}
          get ready() { return true; }
          run() {}
        }
        (Gadget as any).after = () => {};
      `,
    });
    try {
      const first = scanSharedRuntimeGlobalSurfaces(root);
      const second = scanSharedRuntimeGlobalSurfaces(root);
      expect(first).toEqual(second);
      expect(first.map((row) => row.name)).toEqual(
        expect.arrayContaining([
          "global:Delegated",
          "global:Delegated.baseRun",
          "global:Delegated.ready",
          "global:Delegated.run",
          "global:Delegated.value",
          "global:Gadget",
          "global:Gadget.after",
          "global:Gadget.baseRun",
          "global:Gadget.baseVersion",
          "global:Gadget.create",
          "global:Gadget.ready",
          "global:Gadget.run",
          "global:Gadget.value",
          "global:Gadget.version",
          "global:Tools.nested.go",
          "global:exact.runtime.info",
          "global:exact.runtime.version",
        ]),
      );
      expect(first.some((row) => row.name.includes("hidden"))).toBe(false);
      expect(
        first.find((row) => row.name === "global:Gadget.create").metadata
          .memberKinds,
      ).toContain("static");
      expect(
        first.find((row) => row.name === "global:Gadget.run").metadata
          .memberKinds,
      ).toContain("prototype-method");
      expect(
        first.find((row) => row.name === "global:Gadget").metadata.valueShape,
      ).toBe("accessor");
      expect(
        first.find((row) => row.name === "global:Gadget.version").metadata
          .valueShape,
      ).toBe("data");
      expect(
        first.find((row) => row.name === "global:Gadget.create").metadata
          .valueShape,
      ).toBe("callable");
      expect(
        first.find((row) => row.name === "global:Gadget.ready").metadata
          .valueShape,
      ).toBe("accessor");
      expect(
        first.find((row) => row.name === "global:exact.runtime.version")
          .metadata.valueShape,
      ).toBe("data");
      expect(
        first.find((row) => row.name === "global:exact.runtime.info")
          .metadata.valueShape,
      ).toBe("callable");
    } finally {
      fs.rmSync(root, { force: true, recursive: true });
    }
  });

  test("TypeScript install authority rejects drift, generated bindings, escapes, and opaque shapes", () => {
    expect(() =>
      validateRuntimeBundleEntry(
        JSON.stringify({
          scripts: { "build:runtime": "bun bundle --entry src/other.ts" },
        }),
      ),
    ).toThrow(/build:runtime entry drift/);

    const cases = [
      {
        expected: /unresolved computed global property registration/,
        files: {
          "packages/ibex-runtime-js/src/runtime-entry.ts": `import { installGlobals } from './bootstrap.js'; installGlobals();`,
          "packages/ibex-runtime-js/src/bootstrap.ts": `
            function getName() { return 'Dynamic'; }
            export function installGlobals() { const g = globalThis as any; g[getName()] = {}; }
          `,
        },
      },
      {
        expected: /opaque spread in installed global object/,
        files: {
          "packages/ibex-runtime-js/src/runtime-entry.ts": `import { installGlobals } from './bootstrap.js'; installGlobals();`,
          "packages/ibex-runtime-js/src/bootstrap.ts": `
            declare const unknownShape: any;
            export function installGlobals() { const g = globalThis as any; g.Tools = { ...unknownShape }; }
          `,
        },
      },
      {
        expected: /generated or vendored output cannot be inventory authority/,
        files: {
          "packages/ibex-runtime-js/src/runtime-entry.ts": `import { installGlobals } from './bootstrap.js'; installGlobals();`,
          "packages/ibex-runtime-js/src/bootstrap.ts": `
            import { GeneratedThing } from './thing.generated.js';
            export function installGlobals() { (globalThis as any).Thing = GeneratedThing; }
          `,
          "packages/ibex-runtime-js/src/thing.generated.ts": `export class GeneratedThing { run() {} }`,
        },
      },
      {
        expected: /authored runtime path escapes source root/,
        files: {
          "packages/ibex-runtime-js/src/runtime-entry.ts": `import { installGlobals } from './bootstrap.js'; installGlobals();`,
          "packages/ibex-runtime-js/src/bootstrap.ts": `
            import { EscapedThing } from '../outside.js';
            export function installGlobals() { (globalThis as any).Thing = EscapedThing; }
          `,
          "packages/ibex-runtime-js/outside.ts": `export class EscapedThing { run() {} }`,
        },
      },
    ];
    for (const fixture of cases) {
      const root = makeRuntimeFixture(fixture.files);
      try {
        expect(() => scanSharedRuntimeGlobalSurfaces(root)).toThrow(
          fixture.expected,
        );
      } finally {
        fs.rmSync(root, { force: true, recursive: true });
      }
    }
  });

  test("evaluated C++ scripts require structural flow and retain implementation provenance", () => {
    const source = String.raw`
      static const char* unused = R"JS(globalThis.Fake = function Fake() {})JS";
      // rt.evaluateJavaScript(fakeBuffer, "<comment-fake>");
      const char* punctuationLookalike = ")";
      static const char* live = R"JS((function (g) {
        function Thing() {}
        Thing.prototype.run = function () {};
        Object.defineProperty(g, 'Thing', { value: Thing });
      })(globalThis))JS";
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(live);
      rt.evaluateJavaScript(buffer, "<live>");
      static const char* marker = R"JS(process.exit.__exactHostExit = true;)JS";
      auto markerBuffer = std::make_shared<facebook::jsi::StringBuffer>(marker);
      rt.evaluateJavaScript(markerBuffer, "<marker>");
    `;
    const rows = scanEvaluatedCppGlobalScripts(source, "synthetic.cc");
    expect(rows.map((row) => row.name)).toEqual([
      "global:Thing",
      "global:Thing.run",
      "global:process.exit.__exactHostExit",
    ]);
    expect(rows[0].metadata).toMatchObject({
      evaluatedScript: "live",
      sourceKey: "evaluated_native_script",
      sourceUrls: ["<live>"],
    });
    expect(rows[0].sourceRefs).toEqual(["synthetic.cc#embedded:live:Thing"]);
    expect(
      rows.find((row) => row.name === "global:process.exit.__exactHostExit"),
    ).toMatchObject({
      sourceRefs: ["synthetic.cc#embedded:marker:process.exit.__exactHostExit"],
      metadata: {
        evaluatedScript: "marker",
        sourceUrls: ["<marker>"],
      },
    });
  });

  test("native JSI global objects retain nested member and target provenance", () => {
    const source = `
      facebook::jsi::Object stream(rt);
      stream.setProperty(rt, "write", writeFn);
      facebook::jsi::Object processObj(rt);
      processObj.setProperty(rt, "stdout", std::move(stream));
      processObj.setProperty(rt, "platform", "test");
      rt.global().setProperty(rt, "process", std::move(processObj));
      rt.global().setProperty(rt, "print", printFn);
    `;
    const rows = scanCppGlobalPropertySurfaces(source, "synthetic_windows.cc");
    expect(rows.map((row) => row.name)).toEqual([
      "global:print",
      "global:process",
      "global:process.platform",
      "global:process.stdout",
      "global:process.stdout.write",
    ]);
    expect(
      rows.find((row) => row.name === "global:process.stdout.write").metadata
        .branches[0],
    ).toMatchObject({
      branchKind: "single",
      route: "native-jsi-global",
      targetVariant: "windows",
    });
  });

  test("Exact defineProperty helper retains late-bound capability members", () => {
    const source = `
      facebook::jsi::Object exactObject(rt);
      rt.global().setProperty(rt, "exact", std::move(exactObject));
      defineExactCapability(
        rt, exactObject, "invokeHostAsync", std::move(invoke), true);
    `;
    const rows = scanCppGlobalPropertySurfaces(source, "synthetic.cc");
    expect(rows.map((row) => row.name)).toEqual([
      "global:exact",
      "global:exact.invokeHostAsync",
    ]);
  });

  test("native JSI globals derive direct public function invocation descriptors", () => {
    const source = `
      auto directFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactDirect"), 4,
        [](facebook::jsi::Runtime&, const auto&, const auto*, size_t) {
          return facebook::jsi::Value::undefined();
        });
      rt.global().setProperty(rt, "__exactDirect", std::move(directFn));

      facebook::jsi::Object namespaceObject(rt);
      namespaceObject.setProperty(rt, "nested", directFn);
      rt.global().setProperty(rt, "namespaceObject", std::move(namespaceObject));
    `;
    const rows = scanCppGlobalPropertySurfaces(source, "synthetic.cc");
    expect(
      rows.find((row) => row.name === "__exactDirect")?.metadata
        .publicInvocation,
    ).toEqual({
      arity: 4,
      globalName: "__exactDirect",
      kind: "native-global-function",
      sourceRef: "synthetic.cc#jsi-global:__exactDirect",
    });
    expect(
      rows.find((row) => row.name === "global:namespaceObject.nested")
        ?.metadata.publicInvocation,
    ).toBeUndefined();
  });

  test("native environment enumeration exposes exact platform alternatives", () => {
    const source = `
      auto getAllEnvFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactGetAllEnv"), 0,
        [](facebook::jsi::Runtime&, const auto&, const auto*, size_t) {
        #if defined(_WIN32)
          GetEnvironmentStringsW();
        #else
        #if defined(__APPLE__)
          _NSGetEnviron();
        #else
          auto envp = ::environ;
        #endif
        #endif
        });
      rt.global().setProperty(rt, "__exactGetAllEnv", std::move(getAllEnvFn));
    `;
    const [row] = scanCppGlobalPropertySurfaces(source, "runtime.cc");
    expect(row.name).toBe("__exactGetAllEnv");
    expect(
      row.metadata.branches.map((branch) => [
        branch.targetVariant,
        branch.branchKind,
      ]),
    ).toEqual([
      ["apple", "alternative"],
      ["posix", "alternative"],
      ["windows", "alternative"],
    ]);
    expect(() =>
      scanCppGlobalPropertySurfaces(
        source.replace("_NSGetEnviron();", "missingAppleEnumeration();"),
        "runtime.cc",
      ),
    ).toThrow(/exact Windows\/Apple\/POSIX enumeration branches/u);
  });

  test("checked-in Hermes pins and patch stack bind one reviewed evaluator identity", () => {
    const inputs = liveHermesEvaluatorIdentityInputs();
    const profiles = scanHermesEvaluatorIdentityProfiles(inputs);
    expect(profiles.map((profile) => profile.id)).toEqual([
      "android-maven",
      "source-patched",
      "windows-source-patched",
    ]);
    expect(profiles.map((profile) => profile.targetVariant)).toEqual([
      "android",
      "default",
      "windows",
    ]);
    expect(discoverHermesEvaluatorIdentityProfiles(repoRoot)).toEqual(profiles);

    for (const mutated of [
      {
        ...inputs,
        hermesVersionText: inputs.hermesVersionText.replace(
          "ac8c6e6c80ec5fc22da39a77379ffb2fdbdde138",
          "bc8c6e6c80ec5fc22da39a77379ffb2fdbdde138",
        ),
      },
      {
        ...inputs,
        hermesVersionText: inputs.hermesVersionText.replace(
          "250829098.0.14",
          "250829098.0.15",
        ),
      },
      {
        ...inputs,
        windowsInstallerText: inputs.windowsInstallerText.replace(
          '"ccheever/ibex"',
          '"example/reviewed-fork"',
        ),
      },
      {
        ...inputs,
        patches: inputs.patches.map((patch, index) => ({
          ...patch,
          content:
            index === 0
              ? Buffer.concat([
                  patch.content,
                  Buffer.from("\n# reviewed mutation\n"),
                ])
              : patch.content,
        })),
      },
      {
        ...inputs,
        patchApplicationText: `${inputs.patchApplicationText}\n# reviewed authority mutation\n`,
      },
      {
        ...inputs,
        appleSourceBuildText: `${inputs.appleSourceBuildText}\n# reviewed consumer mutation\n`,
      },
      {
        ...inputs,
        linuxSourceBuildText: `${inputs.linuxSourceBuildText}\n# reviewed consumer mutation\n`,
      },
      {
        ...inputs,
        windowsSourceBuildText: `${inputs.windowsSourceBuildText}\n# reviewed consumer mutation\n`,
      },
    ]) {
      const mutatedProfiles = scanHermesEvaluatorIdentityProfiles(mutated);
      const mutatedRows = scanLockdownEvaluatorSurfaces(
        LOCKDOWN_EVALUATOR_SOURCE,
        "runtime.cc",
        mutatedProfiles,
      );
      expect(mutatedRows[0].metadata.engineIdentityReviewId).not.toBe(
        HERMES_EVALUATOR_REVIEW_ID,
      );
      expect(
        new Set(mutatedRows.map((row) => row.metadata.engineIdentityReviewId)),
      ).toEqual(new Set([mutatedRows[0].metadata.engineIdentityReviewId]));
    }

    expect(() =>
      scanHermesEvaluatorIdentityProfiles({
        ...inputs,
        patchApplicationText: inputs.patchApplicationText.replace(
          '  git apply "$patch"',
          '  echo "skipping $patch"',
        ),
      }),
    ).toThrow(/patch application.*source authority line/u);
    for (const [key, invocation] of [
      [
        "appleSourceBuildText",
        '"$SCRIPT_DIR/apply-hermes-patches.sh" "$HERMES_SRC"',
      ],
      [
        "linuxSourceBuildText",
        '"$SCRIPT_DIR/apply-hermes-patches.sh" "$SRC_DIR"',
      ],
      [
        "windowsSourceBuildText",
        "& bash $applyScriptUnix $sourceDirUnix",
      ],
    ]) {
      expect(() =>
        scanHermesEvaluatorIdentityProfiles({
          ...inputs,
          [key]: inputs[key].replace(invocation, "# patch application removed"),
        }),
      ).toThrow(/apply-hermes-patches\.sh.*source authority line/u);
    }

    const symbolicPatchRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "ibex-hermes-symbolic-patch-"),
    );
    try {
      const patchRoot = path.join(symbolicPatchRoot, "patches", "hermes");
      fs.mkdirSync(patchRoot, { recursive: true });
      const target = path.join(patchRoot, "target.txt");
      fs.writeFileSync(target, "synthetic patch target\n");
      fs.symlinkSync(target, path.join(patchRoot, "0009-symbolic.patch"));
      expect(() =>
        discoverHermesEvaluatorIdentityProfiles(symbolicPatchRoot),
      ).toThrow(/patch stack must not contain symbolic links/u);
    } finally {
      fs.rmSync(symbolicPatchRoot, { force: true, recursive: true });
    }
  });

  test("legacy evaluator wrapper routes retain Android and exclude Windows", () => {
    const sourcePath = "src/engine/hermes_bootstrap.cc";
    const source = fs.readFileSync(path.join(repoRoot, sourcePath), "utf8");
    expect(
      scanLegacyEvaluatorBootstrapInstallations(source, sourcePath),
    ).toEqual({
      "compat-polyfills.js": {
        sourceRefs: [
          `${sourcePath}#runLegacyCompatPolyfills`,
          `${sourcePath}#legacy-runner:runLegacyCompatPolyfills:sha256-85e5f64997c896a0b0fed5d1fdbb4903a17334b0e9a0bbe32c412ee13316e1ea`,
        ],
        targetVariants: ["android", "default"],
      },
      "process-compat-fix.js": {
        sourceRefs: [
          `${sourcePath}#runLegacyProcessCompatFix`,
          `${sourcePath}#legacy-runner:runLegacyProcessCompatFix:sha256-12bb5a3515187a9fd26f1f68d053496d1c15353fd95c4c603f7674d6d7f27045`,
        ],
        targetVariants: ["android", "default"],
      },
    });

    const processStart = source.indexOf("void runLegacyProcessCompatFix(");
    const mutatedGuard = `${source.slice(0, processStart)}${source
      .slice(processStart)
      .replace("#if defined(_WIN32)", "#if defined(_WIN64)")}`;
    expect(() =>
      scanLegacyEvaluatorBootstrapInstallations(mutatedGuard, sourcePath),
    ).toThrow(/Windows exclusion drift/u);
    const mutatedRoute = source.replace(
      "PROCESS_COMPAT_FIX_SRC,",
      "MISSING_PROCESS_COMPAT_FIX_SRC,",
    );
    expect(() =>
      scanLegacyEvaluatorBootstrapInstallations(mutatedRoute, sourcePath),
    ).toThrow(/legacy evaluator route/u);
  });

  test("inherited evaluator reachability is exactly reconciled to lockdown taming", () => {
    const source = LOCKDOWN_EVALUATOR_SOURCE;
    const profiles = syntheticHermesEvaluatorProfiles();
    const rows = scanLockdownEvaluatorSurfaces(source, "runtime.cc", profiles);
    expect(rows.map((row) => row.name)).toEqual([
      "global:AsyncFunction",
      "global:Function",
      "global:GeneratorFunction",
      "global:eval",
    ]);
    expect(rows[0].metadata.engineIdentityReviewId).toMatch(
      /^hermes-evaluators\.[a-f0-9]{64}$/u,
    );
    expect(rows[0].metadata.engineProfileIds).toEqual([
      "synthetic-android",
      "synthetic-default",
    ]);
    expect(
      rows[0].metadata.branches.map((branch) => branch.targetVariant),
    ).toEqual(["android", "default"]);

    expect(() =>
      scanLockdownEvaluatorSurfaces(
        source.replace(
          "tameCtor(getProto(async function(){}), 'AsyncFunction');",
          "",
        ),
        "runtime.cc",
        profiles,
      ),
    ).toThrow(/untamed \[AsyncFunction\]/u);
    expect(() =>
      scanLockdownEvaluatorSurfaces(
        source.replace(
          "makeTamed('eval');",
          "makeTamed('eval'); tameCtor(x, 'AsyncGeneratorFunction');",
        ),
        "runtime.cc",
        profiles,
      ),
    ).toThrow(/tamed-but-unreachable \[AsyncGeneratorFunction\]/u);

    const conditionalProfiles = syntheticHermesEvaluatorProfiles();
    conditionalProfiles[0] = {
      ...conditionalProfiles[0],
      reachableEvaluators: [
        ...conditionalProfiles[0].reachableEvaluators,
        "AsyncGeneratorFunction",
      ],
    };
    expect(() =>
      scanLockdownEvaluatorSurfaces(source, "runtime.cc", conditionalProfiles),
    ).toThrow(/untamed \[AsyncGeneratorFunction\]/u);

    const withAsyncGeneratorTaming = source.replace(
      "makeTamed('eval');",
      "tameCtor(getProto(async function*(){}), 'AsyncGeneratorFunction'); makeTamed('eval');",
    );
    const conditionalRows = scanLockdownEvaluatorSurfaces(
      withAsyncGeneratorTaming,
      "runtime.cc",
      conditionalProfiles,
    );
    const asyncGenerator = conditionalRows.find(
      (row) => row.name === "global:AsyncGeneratorFunction",
    );
    expect(asyncGenerator.metadata.engineProfileIds).toEqual([
      "synthetic-android",
    ]);
    expect(asyncGenerator.metadata.branches).toHaveLength(1);
    expect(asyncGenerator.metadata.branches[0]).toMatchObject({
      branchKind: "single",
      targetVariant: "android",
    });
  });

  test("reviewed lockdown content binds execution, targets, and taming helpers", () => {
    const liveSource = fs.readFileSync(
      path.join(repoRoot, "src", "engine", "hermes_runtime.cc"),
      "utf8",
    );
    const profiles = discoverHermesEvaluatorIdentityProfiles(repoRoot);
    const baseline = scanLockdownEvaluatorSurfaces(
      liveSource,
      "src/engine/hermes_runtime.cc",
      profiles,
    );
    expect(baseline[0].metadata.engineIdentityReviewId).toBe(
      HERMES_EVALUATOR_REVIEW_ID,
    );

    for (const mutatedSource of [
      liveSource.replace(
        "try { tameCtor(getProto(async function(){}), 'AsyncFunction'); } catch (e) { if (failClosed) throw e; }",
        "if (false) { tameCtor(getProto(async function(){}), 'AsyncFunction'); }",
      ),
      liveSource.replace(
        "try { tameCtor(getProto(async function(){}), 'AsyncFunction'); } catch (e) { if (failClosed) throw e; }",
        "function neverCalled() { tameCtor(getProto(async function(){}), 'AsyncFunction'); }",
      ),
      liveSource.replace(
        "tameCtor(getProto(async function(){}), 'AsyncFunction')",
        "tameCtor(null, 'AsyncFunction')",
      ),
      liveSource.replace(
        "var tamed = makeTamed(label);",
        "var tamed = function () {};",
      ),
    ]) {
      const mutated = scanLockdownEvaluatorSurfaces(
        mutatedSource,
        "src/engine/hermes_runtime.cc",
        profiles,
      );
      expect(mutated.map((row) => row.name)).toEqual(
        baseline.map((row) => row.name),
      );
      expect(mutated[0].metadata.lockdownTamingDigest).not.toBe(
        baseline[0].metadata.lockdownTamingDigest,
      );
      expect(mutated[0].metadata.engineIdentityReviewId).not.toBe(
        HERMES_EVALUATOR_REVIEW_ID,
      );
    }
    expect(() =>
      scanLockdownEvaluatorSurfaces(
        liveSource.replace(
          "StringBuffer>(lockdownJS.c_str())",
          'StringBuffer>("(function(){})()")',
        ),
        "src/engine/hermes_runtime.cc",
        profiles,
      ),
    ).toThrow(/exact StringBuffer source route/u);
    expect(() =>
      scanLockdownEvaluatorSurfaces(
        liveSource.replace(
          'var failClosed = )JS") + (handle->armed ? "true" : "false") + R"JS(;',
          'var failClosed = )JS") + (handle->diagnostic ? "true" : "false") + R"JS(;',
        ),
        "src/engine/hermes_runtime.cc",
        profiles,
      ),
    ).toThrow(/exact handle->armed selector/u);
    expect(() =>
      scanLockdownEvaluatorSurfaces(
        liveSource.replace(
          "std::string lockdownJS = std::string(",
          'lockdownJS = "shadow";\n    std::string lockdownJS = std::string(',
        ),
        "src/engine/hermes_runtime.cc",
        profiles,
      ),
    ).toThrow(/one exact lockdown script assignment/u);
  });

  test("loader branches are derived from JavaScript and Rust source", () => {
    const javascript = scanJavaScriptLoaderSurfaces(
      String.raw`
        // function fakeModuleLoader() { if (record.kind === 'fake') {} }
        const fake = "record.kind === 'string-fake'";
        function load(specifier) {
          if (record.kind === 'builtin') return specifier;
          const kind = record.kind || 'cjs';
          return kind;
        }
        var importImpl = function(specifier) { return load(specifier); };
      `,
      "loader.js",
    );
    expect(javascript.map((row) => row.name)).toEqual([
      "function:javascript:importImpl",
      "function:javascript:load",
      "kind:builtin",
      "kind:commonjs",
    ]);

    const rust = scanRustLoaderSurfaces(
      String.raw`
        fn resolve_with_oxc() {
          let a = ModuleKind::Esm;
          let b = ModuleType::Wasm;
          let c = ModuleType::Addon;
        }
        // fn load_fake() { let x = ModuleType::Fake; }
        #[cfg(test)]
        fn resolves_test_only() { let x = ModuleType::TestOnly; }
      `,
      "loader.rs",
    );
    expect(rust.map((row) => row.name)).toEqual([
      "function:rust:resolve_with_oxc",
      "kind:esm",
      "kind:native-addon",
      "kind:wasm",
    ]);

    const productionAfterTests = scanRustLoaderSurfaces(
      String.raw`
        #[cfg(test)]
        fn resolve_test_only() { let x = ModuleType::Wasm; }
        fn resolve_after_test() { let x = ModuleType::Json; }
      `,
      "loader-after-test.rs",
    );
    expect(productionAfterTests.map((row) => row.name)).toEqual([
      "function:rust:resolve_after_test",
      "kind:json",
    ]);
  });

  test("JavaScript loader routes include exact internal names and lazy installer aliases", () => {
    const source = String.raw`
      var internalModules = { 'internal/a': {}, direct: {} };
      function _loadNamedStreamInternal(name) {
        if (name === 'internal/streams/a') return {};
      }
      function loadInternal(specifier) {
        var normalized = specifier;
        if (normalized === 'special') return {};
        if (normalized.indexOf('internal/prefix') !== -1) return {};
        return _loadNamedStreamInternal(normalized);
      }
      function __exactResolvePath() {}
      var importImpl = function() {};
      function load(specifier) {
        if (typeof __exactEnsureFs === 'function') {
          if (specifier === 'fs' || specifier === 'node:fs') __exactEnsureFs();
        }
      }
      var localRequire = function() {};
      var moduleDynamicImport = function() {};
      var moduleStaticImport = function() {};
      globalThis.require = function() {};
      globalThis.require.resolve = function() {};
      globalThis.__exactRequire = function() {};
      Object.defineProperty(globalThis, 'import', { value: importImpl });
      globalThis.importModule = importImpl;
    `;
    const rows = scanJavaScriptLoaderRoutes(source, "loader-routes.js");
    expect(rows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "internal-route:direct",
        "internal-route:internal/a",
        "internal-route:internal/prefix",
        "internal-route:internal/streams/a",
        "internal-route:special",
        "lazy-installer:__exactEnsureFs:fs",
        "lazy-installer:__exactEnsureFs:node:fs",
        "entry:global-require",
        "entry:require-resolve",
        "entry:module-dynamic-import",
        "entry:module-static-import",
      ]),
    );

    expect(() =>
      scanJavaScriptLoaderRoutes(
        source.replace(
          "{ 'internal/a': {}, direct: {} }",
          "{ [routeName()]: {} }",
        ),
        "dynamic-loader-routes.js",
      ),
    ).toThrow(/unresolved computed internal loader route/);
  });

  test("live Rust loader routes separate resolution, cache, transform, and subprocess paths", () => {
    const rows = scanRustLoaderRoutes([
      {
        sourcePath: "src/module_loader/mod.rs",
        text: fs.readFileSync(
          path.join(repoRoot, "src/module_loader/mod.rs"),
          "utf8",
        ),
      },
      {
        sourcePath: "src/module_loader/transpile.rs",
        text: fs.readFileSync(
          path.join(repoRoot, "src/module_loader/transpile.rs"),
          "utf8",
        ),
      },
    ]);
    expect(rows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "route:resolution:rust:resolve",
        "route:load:rust:load_module_source",
        "route:cache:rust:ensure_transpile_cache_dir",
        "route:transform:rust:transpile_source_to_cjs",
        "route:subprocess:rust:run_transpile_subprocess",
        "external-calls:cache",
        "external-calls:subprocess",
        "operation:cache:write",
        "operation:cache:create_dir_all",
        "operation:subprocess:command-new",
        "transform-engine:oxc",
        "transform-engine:swc",
      ]),
    );
    expect(rows.some((row) => row.name === "transform-engine:from_value")).toBe(
      false,
    );
    expect(
      rows.find((row) => row.name === "operation:cache:write").metadata
        .qualifiedPaths,
    ).toContain("qualified:std::fs::write");
    expect(
      rows.find((row) => row.name === "external-calls:cache").sourceRefs,
    ).toContain(
      "src/module_loader/mod.rs#publish_transpile_artifact:external:qualified:std::fs::write:count-1",
    );

    const mutated = scanRustLoaderRoutes([
      {
        sourcePath: "src/module_loader/mod.rs",
        text: fs
          .readFileSync(path.join(repoRoot, "src/module_loader/mod.rs"), "utf8")
          .replace(
            "std::fs::write(\n            stage.join(\"manifest.json\"),",
            "std::fs::future_authority_call(\n            stage.join(\"manifest.json\"),",
          ),
      },
      {
        sourcePath: "src/module_loader/transpile.rs",
        text: fs.readFileSync(
          path.join(repoRoot, "src/module_loader/transpile.rs"),
          "utf8",
        ),
      },
    ]);
    expect(
      mutated.some(
        (row) => row.name === "operation:cache:future_authority_call",
      ),
    ).toBe(true);
    expect(() =>
      scanRustLoaderRoutes([
        { sourcePath: "empty.rs", text: "fn resolve() {}" },
      ]),
    ).toThrow(/Rust loader resolution root .* is absent/);
  });

  test("CDP routes and fallback are structural and comment-safe", () => {
    const sourcePath = "src/bin/ibex/cdp/mod.rs";
    const source = String.raw`
      // socket.bind(fake); listener.accept(); "/json/fake"
      fn fake_cdp_lookalikes() { let fake = "Runtime.fake"; }
      ${fs.readFileSync(path.join(repoRoot, sourcePath), "utf8")}
    `;
    const rows = scanCdpSurfaces(source, sourcePath);
    const names = rows.map((row) => row.name);
    expect(names).toEqual(
      expect.arrayContaining([
        "inspector.cdp-http:/json",
        "inspector.cdp-http:/json/list",
        "inspector.cdp-http:/json/version",
        "inspector.cdp-listener",
        "inspector.cdp-request-fallback:json-rpc-error--32601",
        "inspector.cdp-request:Debugger.enable",
        "inspector.cdp-request:Runtime.enable",
        "inspector.cdp-request:Runtime.evaluate",
      ]),
    );
    expect(names.some((name) => /fake/u.test(name))).toBe(false);
    expect(
      rows.find((row) => row.name === "inspector.cdp-listener").metadata,
    ).toEqual({
      evidenceType: "cdp-listener-route",
      listenerOperations: { accept: 1, bind: 1, listen: 1 },
    });
    expect(
      rows.find((row) => row.name.includes("cdp-request-fallback")).metadata,
    ).toMatchObject({
      errorCode: -32601,
      evidenceType: "cdp-unknown-method-fallback",
      responseDisposition: "json-rpc-error",
      responseHelper: "method_not_found_response",
      wildcardDisposition: "fallthrough",
    });

    const silent = scanCdpSurfaces(
      source.replace("_ => {}", "_ => return Ok(()),"),
      sourcePath,
    ).find((row) => row.name.includes("cdp-request-fallback"));
    expect(silent).toMatchObject({
      name: "inspector.cdp-request-fallback:silent-success",
      metadata: {
        evidenceType: "cdp-unknown-method-fallback",
        responseDisposition: "none",
        semanticEvidence: expect.any(String),
        wildcardDisposition: "return-ok",
      },
    });

    const fakeSuccess = scanCdpSurfaces(
      source.replace(
        String.raw`"message": format!("'{}' wasn't found", method)`,
        String.raw`"message": "ok"`,
      ),
      sourcePath,
    ).find((row) => row.name.includes("cdp-request-fallback"));
    expect(fakeSuccess.name).toMatch(
      /^inspector\.cdp-request-fallback:unreviewed-[a-z0-9]+$/u,
    );
    expect(fakeSuccess.metadata.responseDisposition).toBe("unreviewed");
    expect(fakeSuccess).not.toEqual(
      rows.find((row) => row.name.includes("cdp-request-fallback")),
    );

    for (const mutated of [
      source.replace(
        "match method {",
        'if method == "Runtime.hidden" { return Ok(()); }\n          match method {',
      ),
      source.replace(
        "let response = method_not_found_response(id, method);",
        'if method == "Runtime.hidden" { return Ok(()); }\n          let response = method_not_found_response(id, method);',
      ),
    ]) {
      expect(() => scanCdpSurfaces(mutated, sourcePath)).toThrow(
        /CDP method is used (?:before|after) its reviewed match dispatch/,
      );
    }
    for (const mutated of [
      source.replace(
        "match path {",
        'if path == "/json/hidden" { return Ok(()); }\n          match path {',
      ),
      source.replace(
        "    write_http_response(stream, status, &body).await",
        '    if path == "/json/hidden" { return Ok(()); }\n    write_http_response(stream, status, &body).await',
      ),
    ]) {
      expect(() => scanCdpSurfaces(mutated, sourcePath)).toThrow(
        /CDP path is used outside its reviewed match dispatch/,
      );
    }
    expect(() =>
      scanCdpSurfaces(
        source.replace(
          '        "/json/version" => (',
          '        HIDDEN_PATH => hidden(),\n        "/json/version" => (',
        ),
        sourcePath,
      ),
    ).toThrow(/unreviewed CDP path dispatch pattern/);

    expect(() =>
      scanCdpSurfaces(
        source.replace(
          "            accept = listener.accept() => {",
          "            accept = listener.opaque_accept() => {",
        ),
        sourcePath,
      ),
    ).toThrow(/CDP run_server body drifted from its reviewed token evidence/);
  });

  test("live CDP fallback mutations change source-derived discovery", () => {
    const sourcePath = "src/bin/ibex/cdp/mod.rs";
    const source = fs.readFileSync(path.join(repoRoot, sourcePath), "utf8");
    const fallback = (text) =>
      scanCdpSurfaces(text, sourcePath).find((row) =>
        row.name.includes("cdp-request-fallback"),
      );

    expect(fallback(source)).toMatchObject({
      name: "inspector.cdp-request-fallback:json-rpc-error--32601",
      metadata: {
        errorCode: -32601,
        responseDisposition: "json-rpc-error",
        wildcardDisposition: "fallthrough",
      },
    });
    expect(
      fallback(source.replace("_ => {}", "_ => return Ok(()),")),
    ).toMatchObject({
      name: "inspector.cdp-request-fallback:silent-success",
      metadata: { responseDisposition: "none" },
    });
    expect(
      fallback(source.replace('"code": -32601', '"code": -32000')),
    ).toMatchObject({
      name: "inspector.cdp-request-fallback:json-rpc-error--32000",
      metadata: { errorCode: -32000 },
    });
    expect(() =>
      scanCdpSurfaces(
        source.replace(
          "match method {",
          'if method == "Runtime.hidden" { return Ok(()); }\n    match method {',
        ),
        sourcePath,
      ),
    ).toThrow(/CDP method is used before its reviewed match dispatch/);
    expect(() =>
      scanCdpSurfaces(
        source.replace(
          "let (status, body) = match path {",
          'if path == "/json/hidden" { return Ok(()); }\n    let (status, body) = match path {',
        ),
        sourcePath,
      ),
    ).toThrow(/CDP path is used outside its reviewed match dispatch/);

    const hiddenPeekResponse =
      'write_http_response(&mut stream, "200 OK", "{}").await?; return Ok(());';
    const beforeUpgradeDispatch = (statement) =>
      source.replace(
        "    if !is_websocket_upgrade(&peek_text) {",
        `    ${statement}\n    if !is_websocket_upgrade(&peek_text) {`,
      );
    for (const statement of [
      `if peek_text.contains("/json/hidden") { ${hiddenPeekResponse} }`,
      `if peek_buf[..peek_len].windows(12).any(|w| w == b"/json/hidden") { ${hiddenPeekResponse} }`,
    ]) {
      expect(() =>
        scanCdpSurfaces(beforeUpgradeDispatch(statement), sourcePath),
      ).toThrow(
        /CDP handle_connection body drifted from its reviewed token evidence/,
      );
    }

    expect(() =>
      scanCdpSurfaces(
        source.replace(
          "                    if let Err(err) = handle_connection(",
          "                    alternate_connection_handler(&stream).await;\n                    if let Err(err) = handle_connection(",
        ),
        sourcePath,
      ),
    ).toThrow(/CDP run_server body drifted from its reviewed token evidence/);

    const hiddenResponse =
      'write_http_response(stream, "200 OK", "{}").await?; return Ok(());';
    const beforePathDispatch = (statement) =>
      source.replace(
        "    let (status, body) = match path {",
        `    ${statement}\n    let (status, body) = match path {`,
      );
    for (const statement of [
      `if buf.windows(12).any(|w| w == b"/json/hidden") { ${hiddenResponse} }`,
      `if tmp.windows(12).any(|w| w == b"/json/hidden") { ${hiddenResponse} }`,
      `if request.contains("GET /json/hidden ") { ${hiddenResponse} }`,
      `if request_line.contains("/json/hidden") { ${hiddenResponse} }`,
      `if parts.clone().any(|part| part == "/json/hidden") { ${hiddenResponse} }`,
      `if _method == "HIDDEN" { ${hiddenResponse} }`,
    ]) {
      expect(() =>
        scanCdpSurfaces(beforePathDispatch(statement), sourcePath),
      ).toThrow(
        /CDP HTTP handler prefix drifted from its reviewed token template/,
      );
    }

    for (const replacement of [
      [
        'let path = parts.next().unwrap_or("/");',
        'let parsed_path = parts.next().unwrap_or("/"); let path = parsed_path;',
      ],
      [
        'let path = parts.next().unwrap_or("/");',
        'let path = request_line.split_whitespace().nth(1).unwrap_or("/");',
      ],
    ]) {
      expect(() =>
        scanCdpSurfaces(source.replace(...replacement), sourcePath),
      ).toThrow(
        /CDP HTTP handler prefix drifted from its reviewed token template/,
      );
    }

    expect(() =>
      scanCdpSurfaces(
        beforePathDispatch(
          `let path_alias = path; if path_alias == "/json/hidden" { ${hiddenResponse} }`,
        ),
        sourcePath,
      ),
    ).toThrow(/CDP path is used outside its reviewed match dispatch/);
    expect(() =>
      scanCdpSurfaces(
        beforePathDispatch(
          `let reparsed_path = request_line.split_whitespace().nth(1).unwrap_or("/"); if reparsed_path == "/json/hidden" { ${hiddenResponse} }`,
        ),
        sourcePath,
      ),
    ).toThrow(
      /CDP HTTP handler prefix drifted from its reviewed token template/,
    );
  });

  test("runtime environment controls retain exact direction and dynamic sentinels", () => {
    const rows = scanRuntimeEnvironmentSurfaces({
      javascript: [
        {
          sourcePath: "runtime.js",
          text: String.raw`
            const env = process.env;
            const home = env.HOME;
            process.env.EXACT_MODE = '1';
            delete process.env.EXACT_OLD;
            const dynamic = process.env[key];
            readRuntimeEnv('IBEX_MODE');
            const lower = process.env.comspec;
            Object.assign(process.env, { EXACT_ASSIGNED: '1' });
            Reflect.set(process.env, 'IBEX_REFLECT_SET', '1');
            Object.defineProperty(process.env, dynamicName, { value: '1' });
            Reflect.deleteProperty(process.env, 'EXACT_REFLECT_DELETE');
            const processAlias = process;
            const aliased = processAlias.env.EXACT_ALIASED;
            const globalProcessAlias = globalThis.process;
            const { env: destructuredEnv } = globalProcessAlias;
            const destructured = destructuredEnv.IBEX_DESTRUCTURED;
            const unresolvedProcessMember = processAlias[processKey];
          `,
        },
      ],
      rust: [
        {
          sourcePath: "runtime.rs",
          text: String.raw`
            const PRIMARY: &str = "IBEX_MODE";
            fn read(name: &str) {
              std::env::var(PRIMARY);
              std::env::var(name);
              runtime_env("IBEX_WATCH", "EXACT_WATCH");
            }
          `,
        },
      ],
      native: [
        {
          sourcePath: "native_android_networking.cc",
          text: String.raw`
            void init() {
              setenv("EXACT_ANDROID_FILES_DIR", files, 1);
              auto shell = getenvString("ComSpec");
              auto apple = _NSGetEnviron();
              auto posix = ::environ;
              auto windows = GetEnvironmentStringsW();
            }
          `,
        },
        {
          sourcePath: "hermes_runtime_process.cc",
          text: String.raw`
            void prepareChildEnv() {
              s_setEnvEntry(plan.envEntries, "EXACT_QUIET", "1");
            }
          `,
        },
      ],
    });
    expect(rows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "env:<dynamic>:javascript:process.env[]",
        "env:<dynamic>:javascript:process[]",
        "env:<dynamic>:javascript:Object.defineProperty(process.env)",
        "env:<dynamic>:rust:env::var",
        "env:COMSPEC",
        "env:EXACT_ASSIGNED",
        "env:EXACT_ALIASED",
        "env:EXACT_ANDROID_FILES_DIR",
        "env:EXACT_MODE",
        "env:EXACT_OLD",
        "env:EXACT_QUIET",
        "env:EXACT_REFLECT_DELETE",
        "env:EXACT_WATCH",
        "env:HOME",
        "env:IBEX_MODE",
        "env:IBEX_DESTRUCTURED",
        "env:IBEX_REFLECT_SET",
        "env:IBEX_WATCH",
      ]),
    );
    expect(rows.filter((row) => row.name === "env:COMSPEC")).toHaveLength(1);
    expect(
      rows.find((row) => row.name === "env:COMSPEC").metadata.authoredNames,
    ).toEqual(["ComSpec", "comspec"]);
    expect(
      rows.find((row) => row.name === "env:EXACT_MODE").metadata
        .accessDirections,
    ).toEqual(["write"]);
    expect(
      rows.find((row) => row.name === "env:EXACT_OLD").metadata
        .accessDirections,
    ).toEqual(["unset"]);
    expect(
      rows.find((row) => row.name === "env:EXACT_ANDROID_FILES_DIR").metadata
        .contexts,
    ).toEqual(["trusted-bootstrap-output"]);
    expect(
      rows.find((row) => row.name === "env:EXACT_QUIET").metadata.contexts,
    ).toEqual(["spawn-child-env"]);
    for (const name of ["env:EXACT_ASSIGNED", "env:IBEX_REFLECT_SET"]) {
      expect(
        rows.find((row) => row.name === name).metadata.accessDirections,
      ).toEqual(["write"]);
    }
    expect(
      rows.find((row) => row.name === "env:EXACT_REFLECT_DELETE").metadata
        .accessDirections,
    ).toEqual(["unset"]);
    expect(
      rows
        .filter((row) => row.name.startsWith("env:<dynamic>:cpp:"))
        .map((row) => row.metadata.accessors[0]),
    ).toEqual(["::environ", "GetEnvironmentStringsW", "_NSGetEnviron"]);
  });

  test("process values crossing complex bindings remain visible to the environment inventory", () => {
    const scan = (addition) =>
      scanRuntimeEnvironmentSurfaces({
        javascript: [
          {
            sourcePath: "runtime.js",
            text: `const known = process.env.KNOWN;\n${addition}`,
          },
        ],
      }).map((row) => row.name);

    expect(scan("const { env: { SECRET } } = process;")).toContain(
      "env:SECRET",
    );
    for (const addition of [
      "function f(p = process) { return p.env.SECRET; }",
      "(function(p) { return p.env.SECRET; })(process);",
      "const [p] = [process]; const hidden = p.env.SECRET;",
      "holder.p = process; const hidden = holder.p.env.SECRET;",
      "const boxed = new Box(process);",
      "class Holder { p = process; }",
      "export default process;",
      "export const processAlias = process;",
      "const recoverProcess = () => process;",
      "tag`${process}`;",
    ]) {
      expect(scan(addition)).toContain(
        "env:<dynamic>:javascript:process-binding-flow",
      );
    }

    const tsxRows = scanRuntimeEnvironmentSurfaces({
      javascript: [
        {
          sourcePath: "runtime.tsx",
          text: "const known = process.env.KNOWN; const view = <Sink authority={process} />;",
        },
      ],
    });
    expect(tsxRows.map((row) => row.name)).toContain(
      "env:<dynamic>:javascript:process-binding-flow",
    );
  });

  test("environment authority excludes test, fixture, build, devtools, and compat harness sources", () => {
    for (const sourcePath of [
      "src/bin/ibex/runtime_tests.rs",
      "src/engine/native-test.cc",
      "src/engine/native_tests.cpp",
      "src/websocket/bridge.e2e.test.ts",
      "src/fixtures/runtime.ts",
      "packages/ibex-devtools/src/runtime.ts",
      "src/bin/ibex/compat/mod.rs",
      "build.rs",
    ]) {
      expect(isRuntimeEnvironmentSourceAllowed(sourcePath)).toBe(false);
    }
    expect(isRuntimeEnvironmentSourceAllowed("src/bin/ibex/runtime.rs")).toBe(
      true,
    );
    expect(
      isRuntimeEnvironmentSourceAllowed("src/engine/native_fetch_windows.cc"),
    ).toBe(true);
  });

  test("fixed evidence candidates require structural definitions of the declared type", () => {
    const javascript = scanFixedRuntimeEvidenceCandidates(
      String.raw`
        // function commentOnly() {}
        const fake = 'function stringOnly() {}';
        callOnly();
        function declaredFunction() {}
        const assignedFunction = () => {};
      `,
      "fixture.js",
    );
    expect(
      javascript.map((row) => [row.type, row.sourceRef, row.occurrenceCount]),
    ).toEqual([
      ["javascript-function", "fixture.js#assignedFunction", 1],
      ["javascript-function", "fixture.js#declaredFunction", 1],
    ]);

    const rust = scanFixedRuntimeEvidenceCandidates(
      String.raw`
        trait DeclaredOnly { fn resolve_declared_only(); }
        #[cfg(test)]
        fn resolve_test_only() {}
        fn resolve_after_test() {}
        pub extern "C" fn ex_host_live() {}
      `,
      "fixture.rs",
    );
    expect(rust.map((row) => [row.type, row.sourceRef])).toEqual([
      ["public-abi", "fixture.rs#ex_host_live"],
      ["rust-function", "fixture.rs#ex_host_live"],
      ["rust-function", "fixture.rs#resolve_after_test"],
    ]);

    const cpp = scanFixedRuntimeEvidenceCandidates(
      String.raw`
        // void commentOnly() {}
        const char* fake = "void stringOnly() {}";
        void declaredOnly();
        class ForwardOnly;
        void callSite() { invokedOnly(); }
        void definedFunction() {}
        class DefinedType { int value; };
        static const char* DefinedData = "value";
        extern "C" void ex_hermes_live() {}
      `,
      "fixture.cc",
    );
    const cppEvidence = new Set(
      cpp.map((row) => `${row.type}:${row.sourceRef}`),
    );
    expect(cppEvidence.has("cpp-function:fixture.cc#definedFunction")).toBe(
      true,
    );
    expect(cppEvidence.has("cpp-type:fixture.cc#DefinedType")).toBe(true);
    expect(cppEvidence.has("cpp-data:fixture.cc#DefinedData")).toBe(true);
    expect(cppEvidence.has("public-abi:fixture.cc#ex_hermes_live")).toBe(true);
    expect(cppEvidence.has("cpp-call:fixture.cc#invokedOnly")).toBe(true);
    expect(cppEvidence.has("cpp-function:fixture.cc#declaredOnly")).toBe(false);
    expect(cppEvidence.has("cpp-call:fixture.cc#declaredOnly")).toBe(false);
    expect(cppEvidence.has("cpp-type:fixture.cc#ForwardOnly")).toBe(false);
  });

  test("fixed reference validation is exact, typed, unique, and path confined", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-fixed-evidence-"));
    try {
      fs.writeFileSync(
        path.join(root, "implementation.js"),
        "function load() {}\n",
      );
      const definitions = [
        {
          kind: "loader",
          name: "first",
          evidence: [
            {
              type: "javascript-function",
              file: "implementation.js",
              symbol: "load",
              role: "implementation-container",
            },
          ],
        },
        {
          kind: "loader",
          name: "second",
          evidence: [
            {
              type: "javascript-function",
              file: "implementation.js",
              symbol: "load",
              role: "implementation-container",
            },
          ],
        },
      ];
      const rows = fixedRuntimeSurfaceInventory(definitions);
      expect(() =>
        validateFixedRuntimeSurfaceRefs(root, rows, definitions),
      ).not.toThrow();
      expect(rows.every((row) => row.metadata === undefined)).toBe(true);

      const unmarkedShared = structuredClone(definitions);
      unmarkedShared[0].evidence[0].role = "implementation";
      expect(() => fixedRuntimeSurfaceInventory(unmarkedShared)).toThrow(
        /must use role implementation-container/,
      );

      const nonCanonical = structuredClone(definitions.slice(0, 1));
      nonCanonical[0].evidence[0].role = "implementation";
      nonCanonical[0].evidence[0].file = "./implementation.js";
      expect(() => fixedRuntimeSurfaceInventory(nonCanonical)).toThrow(
        /non-canonical fixed evidence path/,
      );

      const singleDefinition = structuredClone(definitions.slice(0, 1));
      singleDefinition[0].evidence[0].role = "implementation";
      const singleRows = fixedRuntimeSurfaceInventory(singleDefinition);
      fs.writeFileSync(
        path.join(root, "implementation.js"),
        "function load() {}\nfunction load() {}\n",
      );
      expect(() =>
        validateFixedRuntimeSurfaceRefs(root, singleRows, singleDefinition),
      ).toThrow(
        /expected exactly one structural javascript-function definition; observed 2/,
      );

      fs.writeFileSync(
        path.join(root, "implementation.js"),
        '// function load() {}\nconst text = "function load() {}";\nload();\n',
      );
      expect(() =>
        validateFixedRuntimeSurfaceRefs(root, singleRows, singleDefinition),
      ).toThrow(/expected structural javascript-function definition is absent/);

      const wrongType = structuredClone(singleDefinition);
      wrongType[0].evidence[0].type = "cpp-function";
      const wrongTypeRows = fixedRuntimeSurfaceInventory(wrongType);
      expect(() =>
        validateFixedRuntimeSurfaceRefs(root, wrongTypeRows, wrongType),
      ).toThrow(/expected structural cpp-function definition is absent/);
    } finally {
      fs.rmSync(root, { force: true, recursive: true });
    }
  });

  test("callback producer and startup discovery is structural and exact-counted", () => {
    const rows = scanNativeLifecycleSurfaces(
      String.raw`
        // pushRuntimeCallback(runtime, fake);
        const char* fake = "pushRuntimeCallback(runtime, fake)";
        void pushRuntimeCallback(Runtime*, Callback);
        void installStorage(Runtime* runtime) {
          runtime->evaluateJavaScript(source, "<web-storage>");
          pushRuntimeCallback(runtime, first);
          pushRuntimeCallback(runtime, second);
        }
        void bootstrap(Runtime* runtime) { installStorage(runtime); }
      `,
      "synthetic.cc",
    );
    expect(
      rows.filter((row) => row.kind === "callback").map((row) => row.name),
    ).toEqual(["producer:synthetic.cc:installStorage:pushRuntimeCallback"]);
    expect(rows.find((row) => row.kind === "callback")).toMatchObject({
      sourceRefs: ["synthetic.cc#installStorage:pushRuntimeCallback"],
      metadata: {
        enclosingDefinition: "installStorage",
        evidenceType: "push-runtime-callback-producer",
        occurrenceCount: 2,
        producer: "pushRuntimeCallback",
      },
    });
    expect(
      rows.filter((row) => row.kind === "startup").map((row) => row.name),
    ).toEqual([
      "evaluation:installStorage:web-storage",
      "install-route:bootstrap:installStorage",
      "installer:installStorage",
      "script:web-storage",
    ]);
    expect(
      rows.find((row) => row.name === "evaluation:installStorage:web-storage")
        .metadata,
    ).toEqual({
      caller: "installStorage",
      evidenceType: "startup-evaluation-route",
      occurrenceCount: 1,
      sourceUrl: "<web-storage>",
    });

    const reordered = scanNativeLifecycleSurfaces(
      String.raw`
        void pushRuntimeCallback(Runtime*, Callback);
        void installStorage(Runtime* runtime) {
          int unrelated = 1;
          pushRuntimeCallback(runtime, second);
          pushRuntimeCallback(runtime, first);
        }
      `,
      "synthetic.cc",
    ).find((row) => row.kind === "callback");
    expect(reordered).toEqual(rows.find((row) => row.kind === "callback"));

    const inserted = scanNativeLifecycleSurfaces(
      String.raw`
        void pushRuntimeCallback(Runtime*, Callback);
        void installStorage(Runtime* runtime) {
          pushRuntimeCallback(runtime, first);
          pushRuntimeCallback(runtime, inserted);
          pushRuntimeCallback(runtime, second);
        }
      `,
      "synthetic.cc",
    ).find((row) => row.kind === "callback");
    expect(inserted.name).toBe(reordered.name);
    expect(inserted.sourceRefs).toEqual(reordered.sourceRefs);
    expect(inserted.metadata.occurrenceCount).toBe(3);

    const sameMethodNames = scanNativeLifecycleSurfaces(
      String.raw`
        void pushRuntimeCallback(Runtime*, Callback);
        struct FirstPool {
          void schedule(Runtime* runtime) { pushRuntimeCallback(runtime, first); }
        };
        struct SecondPool {
          void schedule(Runtime* runtime) { pushRuntimeCallback(runtime, second); }
        };
      `,
      "qualified.cc",
    );
    expect(
      sameMethodNames
        .filter((row) => row.kind === "callback")
        .map((row) => row.name),
    ).toEqual([
      "producer:qualified.cc:FirstPool::schedule:pushRuntimeCallback",
      "producer:qualified.cc:SecondPool::schedule:pushRuntimeCallback",
    ]);
  });

  test("unscoped native lifecycle calls use a stable explicit fallback", () => {
    const rows = scanNativeLifecycleSurfaces(
      'runtime->evaluateJavaScript(source, "<boot>"); installStorage(runtime);',
      "unscoped.cc",
    );
    expect(rows.map((row) => row.name)).toEqual([
      "evaluation:translation-unit-fallback:boot",
      "install-route:translation-unit-fallback:installStorage",
      "script:boot",
    ]);
    expect(
      rows.find((row) => row.name.startsWith("evaluation:"))?.metadata,
    ).toMatchObject({
      caller: "translation-unit-fallback",
      structuralFallback: "translation-unit",
    });
    expect(
      rows.find((row) => row.name.startsWith("install-route:"))?.metadata,
    ).toMatchObject({
      caller: "translation-unit-fallback",
      structuralFallback: "translation-unit",
    });
    expect(() =>
      scanNativeLifecycleSurfaces(
        'runtime->evaluateJavaScript(source, "<broken>";',
        "broken.cc",
      ),
    ).toThrow(/evaluateJavaScript call has no closing parenthesis/);
  });

  test("fixed paths use explicit branch names and symbol refs", () => {
    const rows = fixedRuntimeSurfaceInventory();
    expect(
      rows.find((row) => row.observedKey === "loader:import-policy-bare"),
    ).toEqual({
      kind: "loader",
      name: "import-policy-bare",
      observedKey: "loader:import-policy-bare",
      sourceRefs: ["src/engine/bootstrap/module-loader.js#checkImportGate"],
    });
    expect(
      rows.some(
        (row) => row.observedKey === "callback:native-principal-restore",
      ),
    ).toBe(true);
    expect(
      rows.some(
        (row) => row.observedKey === "startup:capability-hardening-seal",
      ),
    ).toBe(true);
    expect(
      rows.some(
        (row) => row.observedKey === "native-op:inspector.debugger-enable",
      ),
    ).toBe(true);
  });

  test("every live fixed reference joins one exact structural definition", () => {
    const rows = fixedRuntimeSurfaceInventory();
    expect(rows).toHaveLength(77);
    expect(() => validateFixedRuntimeSurfaceRefs(repoRoot, rows)).not.toThrow();
  });

  test("live lifecycle discovery preserves macro-obscured installer routes", () => {
    const rows = scanNativeLifecycleSurfaces(
      fs.readFileSync(
        path.join(repoRoot, "src/engine/hermes_runtime.cc"),
        "utf8",
      ),
      "src/engine/hermes_runtime.cc",
    );
    expect(
      rows.find(
        (row) =>
          row.name ===
          "install-route:translation-unit-fallback:installOsInfoGlobals",
      )?.metadata,
    ).toMatchObject({
      caller: "translation-unit-fallback",
      installer: "installOsInfoGlobals",
      structuralFallback: "translation-unit",
    });
  });

  test("live builtin manifest sources expose the full static export inventory", async () => {
    const rows = await scanBuiltinSurfaces(
      path.join(repoRoot, "modules.ts"),
      repoRoot,
    );
    const exports = rows.filter(
      (row) => row.metadata?.surfaceType === "export",
    );
    expect(exports.length).toBeGreaterThan(0);
    expect(new Set(exports.map((row) => row.name)).size).toBe(exports.length);
    expect(exports.map((row) => row.name)).toEqual(
      [...exports.map((row) => row.name)].sort(),
    );
    expect(exports.some((row) => row.name === "export:node_fs:readFile")).toBe(
      true,
    );
    expect(exports.some((row) => row.name === "export:exact_http:serve")).toBe(
      true,
    );
    expect(
      exports.some((row) => row.name === "export:exact_sqlite:Database"),
    ).toBe(true);
    expect(
      exports.some(
        (row) => row.name === "export:node_tty:ReadStream.setRawMode",
      ),
    ).toBe(true);
    expect(exports.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "export:node_fs:ReadStream._read",
        "export:node_fs:ReadStream.close",
        "export:node_fs:ReadStream.destroy",
        "export:node_fs:ReadStream.open",
        "export:node_fs:WriteStream._emitClose",
        "export:node_fs:WriteStream._final",
        "export:node_fs:WriteStream._write",
        "export:node_fs:WriteStream._writev",
        "export:node_fs:WriteStream.close",
        "export:node_fs:WriteStream.destroy",
        "export:node_fs:WriteStream.open",
        "export:node_net:Socket._connecting",
        "export:node_net:Socket.bufferSize",
        "export:node_net:Socket.bytesWritten",
        "export:node_net:Socket.readableHighWaterMark",
        "export:node_net:Socket.writableCorked",
        "export:node_net:Socket.writableEnded",
        "export:node_net:Socket.writableHighWaterMark",
        "export:node_net:Socket.writableLength",
        "export:node_net:Socket.writableNeedDrain",
        "export:node_stream:Duplex.emit",
        "export:node_zlib:Gzip.write",
      ]),
    );
    const inheritedRows = exports.filter(
      (row) => row.metadata.inheritedShape === true,
    );
    expect(inheritedRows).toHaveLength(455);
    expect(
      new Set(inheritedRows.map((row) => row.metadata.inheritedShapeReviewId)),
    ).toEqual(
      new Set([
        "sha256-92e80596e19cbd5fa2167c0374f84e695fb493ad9caa022e5ef97d48c80a7a04",
      ]),
    );
    expect(
      exports.some((row) => row.name === "export:node_constants:SIGINT"),
    ).toBe(true);
    expect(
      exports.some((row) => row.name === "export:node_constants:O_RDONLY"),
    ).toBe(true);
    expect(
      exports.find(
        (row) =>
          row.name === "export:internal_fs_utils:toPathIfFileURL",
      )?.metadata,
    ).toMatchObject({
      bootstrapInternalModuleSpecifiers: ["internal/fs/utils"],
      importReachability: "bootstrap-internal",
      moduleSpecifiers: ["internal/fs/utils"],
      publicModuleSpecifiers: [],
    });
    expect(
      exports.find(
        (row) => row.name === "export:node_fs_promises:readFile",
      )?.metadata,
    ).toMatchObject({
      importReachability: "public",
      moduleSpecifiers: [
        "bun:fs/promises",
        "fs/promises",
        "internal/fs/promises",
        "node:fs/promises",
      ],
      publicModuleSpecifiers: [
        "bun:fs/promises",
        "fs/promises",
        "internal/fs/promises",
        "node:fs/promises",
      ],
    });
    expect(
      exports.find(
        (row) => row.name === "export:node_fs_promises:writeFile",
      )?.metadata.enforcementRouteEvidence,
    ).toMatchObject({
      requiredExportCalls: [
        {
          exportName: "writeFileSync",
          moduleSpecifier: "node:fs",
        },
      ],
      terminals: expect.arrayContaining([
        "__exactFsOpen",
        "__exactFsWrite",
      ]),
    });
    expect(
      exports.find(
        (row) =>
          row.name ===
          "export:node_constants:[[dynamic-table:signal-number-overlay]]",
      )?.metadata.exportIdioms,
    ).toContain("closed-dynamic-table:signal-number-overlay");
    expect(exports.every((row) => row.sourceRefs.length > 0)).toBe(true);
  }, 15_000);

  test("live shared-runtime authority includes the reviewed roots, members, and opaque overlays", () => {
    expect(REVIEWED_SHARED_RUNTIME_ROOTS.length).toBeGreaterThan(0);
    expect(new Set(REVIEWED_SHARED_RUNTIME_ROOTS).size).toBe(
      REVIEWED_SHARED_RUNTIME_ROOTS.length,
    );
    const rows = scanSharedRuntimeGlobalSurfaces(repoRoot);
    const roots = new Set(
      rows
        .filter((row) => row.metadata.memberName === null)
        .map((row) => row.metadata.globalName),
    );
    for (const root of REVIEWED_SHARED_RUNTIME_ROOTS)
      expect(roots.has(root)).toBe(true);
    expect(rows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "__exactMemoryDebug.snapshot",
        "__exactHostNavigator.[[dynamic-table:host-navigator-properties]]",
        "global:BroadcastChannel.postMessage",
        "global:BroadcastChannel.addEventListener",
        "global:Buffer.from",
        "global:EventSource.close",
        "global:File.arrayBuffer",
        "global:Headers.append",
        "global:ReadableStream.getReader",
        "global:Request.arrayBuffer",
        "global:Request.blob",
        "global:Request.bytes",
        "global:Request.json",
        "global:Request.text",
        "global:Response.json",
        "global:Uint8Array",
        "global:WebSocket.send",
        "global:WebSocket.addEventListener",
        "global:exact.runtime.info",
        "global:process.[[dynamic-table:host-process-own-properties]]",
        "global:process.[[dynamic-table:host-process-prototype-properties]]",
        "global:process.chdir",
        "global:process.env.[[dynamic-table:host-process-env-properties]]",
      ]),
    );
    expect(
      rows.find((row) => row.name === "global:Request.arrayBuffer").metadata
        .memberKinds,
    ).toContain("inherited");
    expect(
      rows.every((row) =>
        row.sourceRefs.every(
          (sourceRef) =>
            !sourceRef.includes("vendored-generated") &&
            !sourceRef.includes(".generated.") &&
            !sourceRef.includes("/dist/"),
        ),
      ),
    ).toBe(true);
  });

  test("live evaluated shims and native target globals are exact and branch-provenanced", () => {
    const fetchShim = scanEvaluatedCppGlobalScripts(
      fs.readFileSync(
        path.join(repoRoot, "src/engine/hermes_runtime_fetch.cc"),
        "utf8",
      ),
      "src/engine/hermes_runtime_fetch.cc",
    );
    const webSocketShim = scanEvaluatedCppGlobalScripts(
      fs.readFileSync(
        path.join(repoRoot, "src/engine/hermes_runtime_websocket.cc"),
        "utf8",
      ),
      "src/engine/hermes_runtime_websocket.cc",
    );
    expect(fetchShim).toHaveLength(9);
    expect(webSocketShim).toHaveLength(17);
    expect(fetchShim.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "global:Headers.append",
        "global:Response.json",
        "global:fetch",
      ]),
    );
    expect(webSocketShim.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "global:WebSocket.CLOSED",
        "global:WebSocket.close",
        "global:WebSocket.onmessage",
        "global:WebSocket.send",
        "global:WebSocket.url",
      ]),
    );
    expect(
      [...fetchShim, ...webSocketShim].every(
        (row) =>
          row.metadata.branches[0].route === "windows-native-shim" &&
          row.metadata.branches[0].targetVariant === "windows",
      ),
    ).toBe(true);

    const processSource = fs.readFileSync(
      path.join(repoRoot, "src/engine/hermes_runtime_process_setup.cc"),
      "utf8",
    );
    const evaluatedProcessRows = scanEvaluatedCppGlobalScripts(
      processSource,
      "src/engine/hermes_runtime_process_setup.cc",
    );
    expect(
      evaluatedProcessRows.find(
        (row) => row.name === "global:process.exit.__exactHostExit",
      ),
    ).toMatchObject({
      sourceRefs: [
        "src/engine/hermes_runtime_process_setup.cc#embedded:markerBuffer:process.exit.__exactHostExit",
      ],
      metadata: {
        evaluatedScript: "markerBuffer",
        sourceUrls: ["<process-exit-marker>"],
      },
    });
    expect(
      evaluatedProcessRows
        .filter(
          (row) => row.metadata.evaluatedScript === "streamStabilityPatchJS",
        )
        .every(
          (row) => row.metadata.sourceUrls[0] === "<stream-stability-patch>",
        ),
    ).toBe(true);

    const runtimeRows = scanEvaluatedCppGlobalScripts(
      fs.readFileSync(
        path.join(repoRoot, "src/engine/hermes_runtime.cc"),
        "utf8",
      ),
      "src/engine/hermes_runtime.cc",
    );
    expect(
      runtimeRows
        .filter((row) => row.name.includes("[[return]]"))
        .map((row) => row.name),
    ).toEqual([
      "global:Ibex.fs.readHandle.[[return]].readFileSync",
      "global:Ibex.fs.readHandle.[[return]].readTextSync",
      "global:Ibex.fs.readHandle.[[return]].revoke",
      "global:Ibex.fs.readHandle.[[return]].scoped",
    ]);
    expect(
      runtimeRows.find(
        (row) =>
          row.name === "global:Ibex.fs.readHandle.[[return]].readFileSync",
      )?.sourceRefs,
    ).toEqual([
      "src/engine/hermes_runtime.cc#embedded:kFsHandleJS:Ibex.fs.readHandle.[[return]].readFileSync",
    ]);

    const processRows = scanCppGlobalPropertySurfaces(
      processSource,
      "src/engine/hermes_runtime_process_setup.cc",
    );
    const iosRows = scanCppGlobalPropertySurfaces(
      fs.readFileSync(
        path.join(repoRoot, "src/engine/hermes_runtime_ios.cc"),
        "utf8",
      ),
      "src/engine/hermes_runtime_ios.cc",
    );
    const workletRows = scanCppGlobalPropertySurfaces(
      fs.readFileSync(
        path.join(repoRoot, "src/engine/hermes_runtime_worklet.cc"),
        "utf8",
      ),
      "src/engine/hermes_runtime_worklet.cc",
    );
    expect(
      processRows.some((row) => row.name === "global:process.stdout.write"),
    ).toBe(true);
    expect(
      processRows.some(
        (row) =>
          row.name ===
          "global:process.env.[[dynamic-table:env-obj-properties]]",
      ),
    ).toBe(true);
    expect(iosRows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "global:exact.getLayout",
        "global:exact.getLayoutTree",
      ]),
    );
    expect(workletRows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "global:log",
        "global:measure",
        "global:scheduleOnAppRuntime",
      ]),
    );
  });

  test("live legacy aliases, closed tables, nested process IPC, and implementation containers are retained", () => {
    const exactRows = scanStaticGlobalApiSurfaces(
      fs.readFileSync(
        path.join(repoRoot, "src/engine/bootstrap/exact-global.js"),
        "utf8",
      ),
      "src/engine/bootstrap/exact-global.js",
    );
    expect(exactRows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "global:Bun.password.hash",
        "global:Bun.spawn",
        "global:Exact.dns.lookup",
        "global:Exact.password.hash",
        "global:Exact.spawn",
      ]),
    );

    const streamSource = fs.readFileSync(
      path.join(repoRoot, "src/engine/bootstrap/web-streams-polyfill.js"),
      "utf8",
    );
    const streamRows = scanStaticGlobalApiSurfaces(
      streamSource,
      "src/engine/bootstrap/web-streams-polyfill.js",
    );
    expect(
      scanStaticGlobalApiSurfaces(
        streamSource.replaceAll("\n", "\r\n"),
        "src/engine/bootstrap/web-streams-polyfill.js",
      ),
    ).toEqual(streamRows);
    expect(streamRows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "__exactWebStreamsPolyfillLoaded",
        "global:ReadableStream",
        "global:ReadableStream.prototype.getReader",
        "global:VideoFrame",
        "global:VideoFrame.close",
        "global:WebStreamsPolyfill",
      ]),
    );
    expect(
      streamRows.find((row) => row.name === "global:WebStreamsPolyfill")
        .metadata.semanticRole,
    ).toBe("implementation-container");

    const compatRows = scanStaticGlobalApiSurfaces(
      fs.readFileSync(
        path.join(repoRoot, "src/engine/bootstrap/compat-polyfills.js"),
        "utf8",
      ),
      "src/engine/bootstrap/compat-polyfills.js",
    );
    expect(compatRows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "global:process.channel",
        "global:process.chdir",
        "global:process.connected",
        "global:process.disconnect",
        "global:process.execve",
        "global:process.send",
      ]),
    );
    expect(
      compatRows.find((row) => row.name === "global:process.channel").metadata,
    ).toMatchObject({
      conditionalGate: "EXACT_IPC_FD",
      branches: [
        expect.objectContaining({
          route: "legacy-bootstrap-ipc",
          targetVariant: "conditional:EXACT_IPC_FD",
        }),
      ],
    });
    expect(
      compatRows.find((row) => row.name === "global:ok").metadata,
    ).toMatchObject({
      conditionalGate: "EXACT_COMPAT_TEST",
      semanticRole: "harness-only-compat-global",
      branches: [
        expect.objectContaining({
          route: "legacy-bootstrap-harness",
          targetVariant: "conditional:EXACT_COMPAT_TEST",
        }),
      ],
    });
  });

  test("live repository discovery has every non-empty category and stable ordering", async () => {
    const first = await discoverRepositorySurfaces(repoRoot);
    const second = await discoverRepositorySurfaces(repoRoot);

    for (const category of [
      "nativeOps",
      "globals",
      "hostAbi",
      "builtins",
      "cli",
      "loader",
      "callbacks",
      "startup",
      "inspector",
    ]) {
      expect(first[category].length).toBeGreaterThan(0);
    }
    expect(first).toEqual(second);
    expect(first.surfaces.map((row) => row.observedKey)).toEqual(
      [...first.surfaces.map((row) => row.observedKey)].sort(),
    );
    expect(new Set(first.surfaces.map((row) => row.observedKey)).size).toBe(
      first.surfaces.length,
    );
    expect(first.builtins.some((row) => row.name === "node:fs")).toBe(true);
    expect(
      first.builtins.some((row) => row.name === "export:node_fs:readFile"),
    ).toBe(true);
    expect(first.hostAbi.some((row) => row.name === "ex_host_fs_open")).toBe(
      true,
    );
    expect(
      first.startup.find((row) => row.name === "runtime-create").sourceRefs,
    ).toEqual([
      "src/engine/hermes_runtime.cc#ex_hermes_create_armed",
    ]);
    expect(
      first.hostAbi.filter((row) => row.name.startsWith("ex_host_")),
    ).toHaveLength(123);
    expect(
      first.hostAbi.filter((row) => row.name.startsWith("ex_host_")).length,
    ).toBeGreaterThan(0);
    const hermesAbi = first.hostAbi.filter((row) =>
      row.name.startsWith("ex_hermes_"),
    );
    expect(hermesAbi.length).toBeGreaterThan(0);
    expect(hermesAbi.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "ex_hermes_create_armed",
        "ex_hermes_current_principal_id",
        "ex_hermes_current_runtime_nonce",
        "ex_hermes_engine_mapped_object",
        "ex_hermes_runtime_nonce",
        "ex_hermes_schedule_watchdog_heartbeat_for_generation",
      ]),
    );
    expect(
      first.hostAbi.filter((row) => row.name.startsWith("ex_worklet_")),
    ).toHaveLength(15);
    expect(
      first.hostAbi.filter((row) => row.name.startsWith("ex_android_")),
    ).toHaveLength(1);
    expect(
      first.hostAbi.filter((row) =>
        row.name.startsWith("java:dev.ibex.runtime.IbexNetworking."),
      ),
    ).toHaveLength(39);
    expect(
      first.hostAbi.filter((row) =>
        row.name.startsWith("jni:dev.ibex.runtime.IbexNetworking."),
      ),
    ).toHaveLength(8);
    expect(
      first.hostAbi.find(
        (row) => row.name === "java:dev.ibex.runtime.IbexNetworking.fetch",
      ).sourceRefs,
    ).toEqual(
      expect.arrayContaining([
        "platform/android/java/dev/ibex/runtime/IbexNetworking.java#java:dev.ibex.runtime.IbexNetworking.fetch",
        "src/engine/native_android_networking.cc#java-call:fetch:fetch",
      ]),
    );
    expect(
      first.hostAbi.find(
        (row) =>
          row.name ===
          "jni:dev.ibex.runtime.IbexNetworking.nativeFetchDidComplete",
      ).sourceRefs,
    ).toEqual(
      expect.arrayContaining([
        "platform/android/java/dev/ibex/runtime/IbexNetworking.java#jni:dev.ibex.runtime.IbexNetworking.nativeFetchDidComplete",
        "src/engine/native_android_networking.cc#jni-callback:nativeFetchDidComplete:android_fetch_did_complete",
      ]),
    );
    expect(
      first.hostAbi
        .find((row) => row.name === "ex_hermes_notify_callback")
        .metadata.branches.map((branch) => [branch.targetVariant, branch.kind]),
    ).toEqual([["default", "single"]]);
    expect(
      first.hostAbi.find((row) => row.name === "ex_host_http_serve").metadata
        .branches,
    ).toEqual([
      expect.objectContaining({
        kind: "single",
        sourceRefs: [
          "src/engine/hermes_runtime.cc#ex_host_http_serve",
          "src/host/http_server.rs#ex_host_http_serve",
        ],
        stubDisposition: "contains-weak-fallback",
        targetVariant: "default",
      }),
    ]);
    expect(first.nativeOps.some((row) => row.name === "__exactFsOpen")).toBe(
      true,
    );
    expect(
      first.nativeOps
        .filter((row) => row.metadata?.surfaceType === "native-network-backend")
        .map((row) => row.name),
    ).toEqual([
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
    ]);
    expect(
      first.nativeOps.find((row) => row.name === "native_fetch_perform")
        .metadata.branches,
    ).toHaveLength(6);
    expect(
      first.nativeOps.find((row) => row.name === "__exactAccess").metadata,
    ).toMatchObject({
      surfaceType: "global-api",
      surfaceTypes: ["global-api", "private-native-operation"],
      semanticRoles: expect.arrayContaining([
        "global-api-installation",
        "private-native-operation",
      ]),
    });
    const spawnBranches = first.nativeOps.find(
      (row) => row.name === "__exactSpawn",
    ).metadata.branches;
    expect(spawnBranches).toHaveLength(2);
    expect(
      spawnBranches
        .map((branch) => [
          branch.route,
          branch.targetVariant,
          branch.branchKind,
        ])
        .sort((left, right) => left[1].localeCompare(right[1])),
    ).toEqual([
      ["native-jsi-global", "default", "alternative"],
      ["native-jsi-global", "windows", "alternative"],
    ]);
    const unixConnectBranches = first.nativeOps.find(
      (row) => row.name === "__exactUnixConnect",
    ).metadata.branches;
    expect(unixConnectBranches).toHaveLength(2);
    expect(
      unixConnectBranches
        .map((branch) => [branch.targetVariant, branch.sourceRefs])
        .sort((left, right) => left[0].localeCompare(right[0])),
    ).toEqual([
      [
        "default",
        [
          "src/engine/hermes_runtime_net.cc#__exactUnixConnect",
          "src/engine/hermes_runtime_net.cc#jsi-global:__exactUnixConnect",
        ],
      ],
      [
        "windows",
        [
          "src/engine/hermes_runtime_platform_windows.cc#__exactUnixConnect",
          "src/engine/hermes_runtime_platform_windows.cc#jsi-global:__exactUnixConnect",
        ],
      ],
    ]);
    expect(
      first.nativeOps
        .find((row) => row.name === "__exactGetAllEnv")
        .metadata.branches.map((branch) => [
          branch.targetVariant,
          branch.branchKind,
        ]),
    ).toEqual([
      ["apple", "alternative"],
      ["posix", "alternative"],
      ["windows", "alternative"],
    ]);
    expect(
      first.globals
        .map((row) => row.name)
        .filter((name) => name.startsWith("global:localStorage")),
    ).toEqual([
      "global:localStorage",
      "global:localStorage.[[Symbol.toStringTag]]",
      "global:localStorage.clear",
      "global:localStorage.getItem",
      "global:localStorage.key",
      "global:localStorage.length",
      "global:localStorage.persistence",
      "global:localStorage.removeItem",
      "global:localStorage.setItem",
    ]);
    expect(
      first.globals.find(
        (row) => row.name === "global:localStorage.persistence",
      ).sourceRefs,
    ).toEqual([
      "src/engine/bootstrap/web-storage.js#_load",
      "src/engine/bootstrap/web-storage.js#_save",
    ]);
    expect(
      first.globals
        .filter((row) =>
          [
            "global:AsyncFunction",
            "global:Function",
            "global:GeneratorFunction",
            "global:eval",
          ].includes(row.name),
        )
        .map((row) => row.name),
    ).toEqual([
      "global:AsyncFunction",
      "global:Function",
      "global:GeneratorFunction",
      "global:eval",
    ]);
    expect(
      first.globals.find((row) => row.name === "global:eval").sourceRefs,
    ).toContain("src/engine/hermes_runtime.cc#lockdownJS:eval");
    expect(
      first.globals.find((row) => row.name === "global:Headers.append").metadata
        .branches,
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          branchKind: "alternative",
          routes: ["shared-runtime"],
          targetVariant: "default",
        }),
        expect.objectContaining({
          branchKind: "alternative",
          routes: ["shared-runtime", "windows-native-shim"],
          targetVariant: "windows",
        }),
      ]),
    );
    expect(
      first.globals.find((row) => row.name === "global:process").metadata
        .branches,
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          branchKind: "alternative",
          routes: ["native-jsi-global", "shared-runtime"],
          targetVariant: "default",
        }),
        expect.objectContaining({
          branchKind: "alternative",
          routes: ["native-jsi-global", "shared-runtime"],
          targetVariant: "windows",
        }),
      ]),
    );
    for (const row of first.globals) {
      const branches = row.metadata.installationBranches;
      expect(branches.length).toBeGreaterThan(0);
      expect(
        [...new Set(branches.flatMap((branch) => branch.sourceRefs))].sort(),
      ).toEqual(row.sourceRefs);
      const normalizedRoutes = new Set(
        branches.map((branch) => `${branch.route}\0${branch.targetVariant}`),
      );
      expect(normalizedRoutes.size).toBe(branches.length);
      expect(new Set(branches.map((branch) => branch.branchKind))).toEqual(
        new Set([branches.length === 1 ? "single" : "alternative"]),
      );
    }
    for (const name of [
      "global:AsyncFunction",
      "global:Function",
      "global:GeneratorFunction",
      "global:eval",
    ]) {
      const evaluator = first.globals.find((row) => row.name === name);
      expect(evaluator.metadata.engineIdentityReviewId).toBe(
        HERMES_EVALUATOR_REVIEW_ID,
      );
      expect(evaluator.metadata.engineProfileIds).toEqual([
        "android-maven",
        "source-patched",
        "windows-source-patched",
      ]);
      expect(
        evaluator.metadata.branches.map((branch) => branch.targetVariant),
      ).toEqual(["android", "default", "windows"]);
      expect(
        evaluator.metadata.branches.map((branch) => branch.stubDisposition),
      ).toEqual([
        "not-structurally-proven",
        "not-structurally-proven",
        "not-structurally-proven",
      ]);
    }
    const evalBranches = first.globals.find((row) => row.name === "global:eval")
      .metadata.branches;
    for (const targetVariant of ["android", "default"]) {
      const branch = evalBranches.find(
        (candidate) => candidate.targetVariant === targetVariant,
      );
      expect(branch.routes).toContain("legacy-bootstrap");
      expect(branch.sourceRefs).toEqual(
        expect.arrayContaining([
          "src/engine/bootstrap/compat-polyfills.js#eval",
          "src/engine/bootstrap/process-compat-fix.js#eval",
          "src/engine/hermes_bootstrap.cc#runLegacyCompatPolyfills",
          "src/engine/hermes_bootstrap.cc#runLegacyProcessCompatFix",
        ]),
      );
    }
    const windowsEvalBranch = evalBranches.find(
      (branch) => branch.targetVariant === "windows",
    );
    expect(windowsEvalBranch.routes).not.toContain("legacy-bootstrap");
    expect(
      windowsEvalBranch.sourceRefs.some((sourceRef) =>
        /(?:compat-polyfills|process-compat-fix|runLegacy)/u.test(sourceRef),
      ),
    ).toBe(false);
    expect(
      first.globals.find(
        (row) => row.name === "global:localStorage.persistence",
      ).metadata.branches,
    ).toHaveLength(1);
    const producers = first.callbacks.filter((row) =>
      row.name.startsWith("producer:"),
    );
    expect(producers).toHaveLength(13);
    expect(
      producers.reduce((count, row) => count + row.metadata.occurrenceCount, 0),
    ).toBe(18);
    expect(
      first.loader
        .filter((row) => row.metadata?.evidenceType === "loader-kind-branch")
        .map((row) => row.metadata.loaderKind),
    ).toEqual(["builtin", "commonjs", "esm", "json", "native-addon", "wasm"]);
    expect(
      first.startup.some((row) => row.name === "installer:installGlobals"),
    ).toBe(true);
    expect(first.startup.some((row) => row.name === "script:web-storage")).toBe(
      true,
    );
    const environmentRows = first.startup.filter((row) =>
      row.name.startsWith("env:"),
    );
    expect(environmentRows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "env:COMSPEC",
        "env:EXACT_ANDROID_FILES_DIR",
        "env:EXACT_COMPAT_EXECUTABLE",
        "env:EXACT_RUNTIME_TRANSFORM",
        "env:EXACT_WATCH_SHUTDOWN_TIMEOUT_MS",
        "env:EXACT_WINHTTP_ENABLE_HTTP2",
        "env:IBEX_RUNTIME_TRANSFORM",
        "env:NODE_DEBUG",
      ]),
    );
    expect(environmentRows.some((row) => row.name === "env:ComSpec")).toBe(
      false,
    );
    expect(environmentRows.some((row) => row.name === "env:comspec")).toBe(
      false,
    );
    expect(
      environmentRows.find((row) => row.name === "env:COMSPEC").metadata
        .authoredNames,
    ).toEqual(["ComSpec", "comspec"]);
    expect(
      environmentRows.find((row) => row.name === "env:EXACT_ANDROID_FILES_DIR")
        .metadata,
    ).toMatchObject({
      accessDirections: expect.arrayContaining(["read", "write"]),
      contexts: expect.arrayContaining([
        "startup-input",
        "trusted-bootstrap-output",
      ]),
    });
    expect(
      environmentRows.find((row) => row.name === "env:EXACT_QUIET").metadata
        .contexts,
    ).toContain("spawn-child-env");
    expect(
      environmentRows.find((row) => row.name === "env:EXACT_IPC_FD").sourceRefs,
    ).toContain(
      "src/engine/bootstrap/stream-enhance.js#process.env:EXACT_IPC_FD:read",
    );
    expect(
      environmentRows.find((row) => row.name === "env:__exactEnvProxy")
        .sourceRefs,
    ).toContain("src/builtins/process.js#process.env:__exactEnvProxy:read");
    expect(
      environmentRows
        .filter((row) =>
          ["::environ", "GetEnvironmentStringsW", "_NSGetEnviron"].some(
            (accessor) => row.metadata.accessors.includes(accessor),
          ),
        )
        .map((row) => row.metadata.accessors[0]),
    ).toEqual(["::environ", "GetEnvironmentStringsW", "_NSGetEnviron"]);
    expect(
      environmentRows.find((row) =>
        row.metadata.accessors.includes("::environ"),
      ).sourceRefs,
    ).toContain(
      "src/engine/hermes_runtime_process_setup.cc#::environ:dynamic:read",
    );
    for (const row of environmentRows) {
      for (const ref of row.sourceRefs) {
        expect(ref).not.toMatch(
          /(?:^|\/)(?:__tests__|benchmarks?|devtools|fixtures?|tests?)(?:\/|$)|\.(?:bench|e2e|fixture|spec|test)\.[^/#]+#|(?:^|[/_-])tests?\.(?:c|cc|cpp|cxx|m|mm|rs)#|(?:^|\/)build\.rs#|^src\/bin\/ibex\/compat\//u,
        );
      }
    }
  }, 180_000);
});
