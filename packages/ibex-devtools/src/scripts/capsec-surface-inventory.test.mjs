// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — source
// discovery is deterministic, comment-aware, and fail-closed on duplicate keys.

import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CALLBACK_OUTPUT_CONTRACT_SCHEMA,
  deriveHostAbiOutputCatalogAccount,
  deriveDnsPromiseExportShapeReviewId,
  discoverRepositorySurfaces,
  discoverHermesEvaluatorIdentityProfiles,
  fixedRuntimeSurfaceInventory,
  HERMES_EVALUATOR_REVIEW_ID,
  HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
  isRuntimeEnvironmentSourceAllowed,
  PRINCIPAL_ENVIRONMENT_OVERLAY_DYNAMIC_MEMBER,
  PRINCIPAL_ENVIRONMENT_OVERLAY_SOURCE_CONTRACT_SCHEMA,
  PRINCIPAL_ENVIRONMENT_OVERLAY_SURFACE_NAME,
  REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID,
  scanBuiltinSurfaces,
  scanCdpSurfaces,
  scanCppConstructionPrivateBridgeSurfaces,
  scanCppGlobalPropertySurfaces,
  scanCppAbiTypeRegistry,
  scanCppPublicAbiDefinitions,
  scanCppVersionedCallbackTableIngresses,
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
  scanPrivateSessionWorkerBootstrap,
  scanPrincipalEnvironmentOverlayProxy,
  scanRuntimeCliSurfaces,
  scanRuntimeCommandClasses,
  scanRuntimeEnvironmentSurfaces,
  scanRuntimeReplSurfaces,
  scanRustHostExterns,
  scanRustLoaderSurfaces,
  scanRustLoaderRoutes,
  scanRustPublicAbiDefinitions,
  scanReviewedDnsPromisesProjection,
  scanSharedRuntimeGlobalSurfaces,
  scanStaticBuiltinExports,
  scanStaticGlobalApiSurfaces,
  validateRuntimeBundleEntry,
  validateFixedRuntimeSurfaceRefs,
} from "./capsec-surface-inventory.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..", "..");
const GPU_CANONICAL_INCLUDE_BLOCK = String.raw`#include "hermes_runtime_internal.h"
#include "../../include/exact_runtime.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>`;

function gpuIncludeInventoryMutations(source) {
  const firstLocal = '#include "hermes_runtime_internal.h"';
  const secondLocal = '#include "../../include/exact_runtime.h"';
  const firstSystem = "#include <algorithm>";
  const lastSystem = "#include <vector>";
  return [
    [
      "alternate include before canonical block",
      source.replace(
        firstLocal,
        '#include "alternate-before.h"\n#include "hermes_runtime_internal.h"',
      ),
    ],
    [
      "alternate include among local includes",
      source.replace(
        secondLocal,
        '#include "alternate-among.h"\n#include "../../include/exact_runtime.h"',
      ),
    ],
    [
      "alternate include between local and system inventories",
      source.replace(
        firstSystem,
        '#include "alternate-boundary.h"\n#include <algorithm>',
      ),
    ],
    [
      "alternate include after canonical block",
      source.replace(lastSystem, `${lastSystem}\n#include "alternate-after.h"`),
    ],
    [
      "alternate include after protected source",
      `${source}\n#include "alternate-late.h"`,
    ],
    [
      "altered canonical include path",
      source.replace(firstLocal, '#include "hermes_runtime_internal_alias.h"'),
    ],
    [
      "include_next canonical path",
      source.replace(firstLocal, '#include_next "hermes_runtime_internal.h"'),
    ],
    [
      "import canonical path",
      source.replace(firstLocal, '#import "hermes_runtime_internal.h"'),
    ],
    [
      "inactive canonical inventory with active alternate include",
      source.replace(
        GPU_CANONICAL_INCLUDE_BLOCK,
        `#if 0\n${GPU_CANONICAL_INCLUDE_BLOCK}\n#else\n#include "alternate-active.h"\n#endif`,
      ),
    ],
    [
      "included-file simulation after canonical inventory",
      source.replace(
        lastSystem,
        `${lastSystem}\n#include "synthetic_gpu_protected.inc"`,
      ),
    ],
  ];
}

function insertCppDirectiveBefore(source, needle, directive) {
  if (!source.includes(needle)) {
    throw new Error(
      `synthetic GPU source is missing insertion anchor: ${needle}`,
    );
  }
  return source.replace(needle, `${directive}\n${needle}`);
}

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
    expect(rows[0].metadata).toMatchObject({
      outputContract: {
        return: { kind: "scalar", role: "value" },
        schema: HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
        status: "resolved",
      },
      unsafe: false,
    });
    expect(rows[1].metadata).toMatchObject({
      outputContract: {
        outputChannels: [],
        return: { kind: "void", role: "none" },
        schema: HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
      },
      unsafe: true,
    });
  });

  test("Rust host ABI inventory includes typed listener authorization exactly once", () => {
    const source = fs.readFileSync(
      path.join(repoRoot, "src/host/abi.rs"),
      "utf8",
    );
    const rows = scanRustHostExterns(source, "src/host/abi.rs").filter(
      (row) => row.name === "ex_host_authorize_typed_listen_stack",
    );

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      kind: "host-abi",
      name: "ex_host_authorize_typed_listen_stack",
      observedKey: "host-abi:ex_host_authorize_typed_listen_stack",
      sourceRefs: ["src/host/abi.rs#ex_host_authorize_typed_listen_stack"],
      metadata: {
        outputContract: {
          return: { kind: "scalar", role: "value" },
          schema: HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
          sourceRef: "src/host/abi.rs#ex_host_authorize_typed_listen_stack",
        },
        unsafe: true,
      },
    });
  });

  test("Rust host ABI inventory includes typed environment-write authorization exactly once", () => {
    const source = fs.readFileSync(
      path.join(repoRoot, "src/host/abi.rs"),
      "utf8",
    );
    const rows = scanRustHostExterns(source, "src/host/abi.rs").filter(
      (row) => row.name === "ex_host_authorize_typed_environment_write_stack",
    );

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      kind: "host-abi",
      name: "ex_host_authorize_typed_environment_write_stack",
      observedKey: "host-abi:ex_host_authorize_typed_environment_write_stack",
      sourceRefs: [
        "src/host/abi.rs#ex_host_authorize_typed_environment_write_stack",
      ],
      metadata: {
        outputContract: {
          bufferLengthPairs: [
            {
              bufferParameter: "module_ids",
              direction: "input",
              lengthParameter: "module_ids_len",
            },
            {
              bufferParameter: "name",
              direction: "input",
              lengthParameter: "name_len",
            },
          ],
          return: { kind: "scalar", role: "value" },
          schema: HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
          sourceRef:
            "src/host/abi.rs#ex_host_authorize_typed_environment_write_stack",
        },
        unsafe: true,
      },
    });
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

  test("host ABI signatures distinguish real returns, outputs, callbacks, buffers, and ambiguity", () => {
    const rust = String.raw`
      /// @abi-output ex_host_signature_contract out_data role=output kind=buffer length=out_data_len ownership=caller-frees:ex_host_free_buffer
      #[no_mangle]
      pub unsafe extern "C" fn ex_host_signature_contract(
        input: *const u8,
        input_len: usize,
        scratch: *mut u8,
        out_data: *mut *mut u8,
        out_data_len: *mut u64,
        callback: Option<extern "C" fn(value: u32)>,
      ) -> u32 { 0 }

      #[no_mangle]
      pub extern "C" fn ex_host_no_return() {}
    `;
    const rustRows = scanRustPublicAbiDefinitions(rust, "signature.rs");
    const contract = rustRows.find(
      (row) => row.name === "ex_host_signature_contract",
    ).metadata.outputContract;
    expect(contract.return).toMatchObject({ kind: "scalar", role: "value" });
    expect(contract.bufferLengthPairs).toEqual([
      {
        bufferParameter: "input",
        direction: "input",
        lengthParameter: "input_len",
      },
      {
        bufferParameter: "out_data",
        direction: "output",
        lengthParameter: "out_data_len",
      },
    ]);
    expect(
      Object.fromEntries(
        contract.parameters.map((parameter) => [
          parameter.name,
          parameter.role,
        ]),
      ),
    ).toEqual({
      callback: "callback-payload",
      input: "input",
      input_len: "input",
      out_data: "output",
      out_data_len: "output",
      scratch: "unknown",
    });
    expect(
      contract.outputChannels.find(
        (channel) => channel.selector === "out:data",
      ),
    ).toMatchObject({
      kind: "buffer",
      lengthParameter: "out_data_len",
      ownership: {
        kind: "caller-owned",
        releaseFunction: "ex_host_free_buffer",
      },
    });
    expect(contract.unresolved).toEqual(["parameter-role:scratch"]);
    expect(
      contract.parameters.find((parameter) => parameter.name === "callback")
        .callbackContract,
    ).toMatchObject({
      delivery: "invoked",
      parameters: [
        {
          direction: "native-to-embedder",
          name: "value",
          valueKind: "scalar",
        },
      ],
      return: { direction: "none", role: "none" },
      status: "resolved",
    });
    expect(
      deriveHostAbiOutputCatalogAccount({
        kind: "host-abi",
        metadata: { outputContracts: [contract] },
        name: "ex_host_signature_contract",
        sourceRefs: [contract.sourceRef],
      }),
    ).toMatchObject({
      outputChannels: [
        { selector: "[[return]]" },
        { selector: "callback:callback/0" },
        { selector: "out:data" },
      ],
      membershipUnresolved: expect.arrayContaining([
        expect.stringContaining("parameter-role:scratch"),
      ]),
      status: "unresolved",
    });
    expect(
      rustRows.find((row) => row.name === "ex_host_no_return").metadata
        .outputContract,
    ).toMatchObject({
      outputChannels: [],
      return: { kind: "void", role: "none" },
    });

    const staticTableContract = scanRustPublicAbiDefinitions(
      String.raw`
        #[no_mangle]
        pub extern "C" fn ex_host_exact_gpu_authority_session_api_v2(
        ) -> *const super::gpu_authority::ExactGpuAuthoritySessionApiV2 {
          let api: &'static super::gpu_authority::ExactGpuAuthoritySessionApiV2 =
            super::gpu_authority::authority_session_api_v2();
          std::ptr::from_ref(api)
        }
      `,
      "static-table.rs",
    )[0].metadata.outputContract;
    expect(staticTableContract).toMatchObject({
      return: { kind: "pointer", ownership: { kind: "borrowed" } },
      status: "resolved",
    });
    const mutatedTableContract = scanRustPublicAbiDefinitions(
      String.raw`
        #[no_mangle]
        pub extern "C" fn ex_host_exact_gpu_authority_session_api_v2(
        ) -> *const super::gpu_authority::ExactGpuAuthoritySessionApiV2 {
          std::ptr::null()
        }
      `,
      "mutated-static-table.rs",
    )[0].metadata.outputContract;
    expect(mutatedTableContract).toMatchObject({
      return: { kind: "pointer", ownership: { kind: "unknown" } },
      status: "unresolved",
      unresolved: ["return-pointer-ownership"],
    });

    const cpp = String.raw`
      extern "C" char* ex_hermes_signature_contract(
        ExactHermesRuntime* runtime,
        const uint8_t* source,
        size_t source_len,
        char** out_value,
        ExHermesDispatchCallback callback) { return nullptr; }
    `;
    const cppContract = scanCppPublicAbiDefinitions(cpp, "signature.cc")[0]
      .metadata.outputContract;
    expect(cppContract.return).toMatchObject({
      kind: "pointer",
      ownership: {
        kind: "caller-owned",
        releaseFunction: "ex_hermes_free_string",
      },
      role: "value",
    });
    expect(
      Object.fromEntries(
        cppContract.parameters.map((parameter) => [
          parameter.name,
          parameter.role,
        ]),
      ),
    ).toEqual({
      callback: "callback",
      out_value: "output",
      runtime: "input",
      source: "input",
      source_len: "input",
    });
    expect(
      cppContract.parameters.find((parameter) => parameter.name === "runtime")
        .ownership,
    ).toEqual({ kind: "borrowed" });
    expect(cppContract.status).toBe("unresolved");

    const pointerInputRows = scanCppPublicAbiDefinitions(
      String.raw`
        extern "C" void ex_hermes_destroy(ExactHermesRuntime* runtime) {}
        extern "C" void ex_hermes_set_dispatch_callback(
          ExactHermesRuntime* runtime,
          void (*callback)(void* context),
          void* context) {}
      `,
      "pointer-inputs.cc",
    );
    expect(
      pointerInputRows.find((row) => row.name === "ex_hermes_destroy").metadata
        .outputContract.parameters[0],
    ).toMatchObject({
      name: "runtime",
      ownership: { kind: "callee-consumes" },
      role: "input",
    });
    expect(
      Object.fromEntries(
        pointerInputRows
          .find((row) => row.name === "ex_hermes_set_dispatch_callback")
          .metadata.outputContract.parameters.map((parameter) => [
            parameter.name,
            parameter.role,
          ]),
      ),
    ).toEqual({
      callback: "callback-payload",
      context: "input",
      runtime: "input",
    });

    expect(() =>
      scanRustPublicAbiDefinitions(
        "/// @abi-output ex_host_absent out_data role=output kind=buffer ownership=caller-storage\n",
        "orphan-annotation.rs",
      ),
    ).toThrow(/@abi-output names absent Rust ABI definition ex_host_absent/);
  });

  test("named ABI schemas expand aggregate members and bind callback directions without flattening", () => {
    const typeRegistry = scanCppAbiTypeRegistry(
      String.raw`
        typedef struct ExHermesOwnedBytes {
          uint8_t* data;
          size_t length;
        } ExHermesOwnedBytes;
        typedef struct ExHermesSourcePosition {
          ExHermesOwnedBytes source_label;
          uint32_t line;
          uint32_t column;
        } ExHermesSourcePosition;
        typedef struct ExHermesEvaluationResult {
          ExHermesOwnedBytes message;
          ExHermesSourcePosition* positions;
          size_t position_count;
        } ExHermesEvaluationResult;
        typedef struct ExWorkletSharedValueHandle {
          uint32_t slot;
          uint32_t generation;
          uint32_t epoch;
        } ExWorkletSharedValueHandle;
        typedef uint32_t (*ExWorkletReadCallback)(
          ExWorkletSharedValueHandle handle,
          float* out_value,
          void* context);
        typedef struct ExactGpuClientSinkV1 {
          void (*retain_client)(void* context);
        } ExactGpuClientSinkV1;
        typedef struct ExactGpuClientSinkV2 {
          void (*retain_client)(void* context);
        } ExactGpuClientSinkV2;
      `,
      "synthetic.h",
    );
    expect(Object.keys(typeRegistry.aggregates)).toEqual([
      "ExHermesEvaluationResult",
      "ExHermesOwnedBytes",
      "ExHermesSourcePosition",
      "ExWorkletSharedValueHandle",
    ]);
    expect(Object.keys(typeRegistry.callbacks)).toEqual([
      "ExWorkletReadCallback",
    ]);

    const rows = scanCppPublicAbiDefinitions(
      String.raw`
        // @abi-output ex_hermes_aggregate result role=inout kind=aggregate schema=ExHermesEvaluationResult members=* elements=positions ownership=caller-storage member-ownership=caller-frees:ex_hermes_evaluation_result_dispose
        extern "C" void ex_hermes_aggregate(
          ExHermesEvaluationResult* result) {}

        extern "C" int ex_worklet_callback(
          ExWorkletReadCallback read_callback,
          void* context) { return 0; }
      `,
      "synthetic.cc",
      { typeRegistry },
    );
    const aggregate = rows.find((row) => row.name === "ex_hermes_aggregate")
      .metadata.outputContract;
    expect(aggregate.status).toBe("resolved");
    expect(aggregate.outputChannels.map((channel) => channel.selector)).toEqual(
      [
        "out:result.message.data",
        "out:result.positions",
        "out:result.positions[].source_label.data",
        "out:result.positions[].line",
        "out:result.positions[].column",
      ],
    );
    expect(aggregate.outputChannels.map((channel) => channel.alias)).toEqual([
      "result.message.data",
      "result.positions",
      "result.positions[].source_label.data",
      "result.positions[].line",
      "result.positions[].column",
    ]);

    const callback = rows.find((row) => row.name === "ex_worklet_callback")
      .metadata.outputContract;
    expect(callback.status).toBe("resolved");
    expect(callback.outputChannels.map((channel) => channel.selector)).toEqual([
      "[[return]]",
      "callback:read_callback/0.slot",
      "callback:read_callback/0.generation",
      "callback:read_callback/0.epoch",
      "callback:read_callback/2",
    ]);
    expect(
      callback.parameters.find(
        (parameter) => parameter.name === "read_callback",
      ).callbackContract,
    ).toMatchObject({
      parameters: [
        { direction: "native-to-embedder", valueKind: "aggregate" },
        { direction: "embedder-to-native", valueKind: "scalar" },
        { direction: "native-to-embedder", valueKind: "pointer" },
      ],
      return: {
        direction: "embedder-to-native",
        kind: "scalar",
        role: "return",
      },
      status: "resolved",
    });
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

  test("compatibility-owned stream submodules cannot claim manifest source reachability", () => {
    const shadowed = [
      "node:stream/consumers",
      "node:stream/promises",
      "stream/consumers",
      "stream/promises",
    ];
    const rows = scanModuleSpecifierEntries({
      bootstrapInternalModules: shadowed,
      sources: {
        node_stream_consumers: { kind: "inline", code: "" },
        node_stream_promises: { kind: "inline", code: "" },
      },
      specifiers: [
        {
          names: ["node:stream/consumers", "stream/consumers"],
          source: "node_stream_consumers",
        },
        {
          names: ["node:stream/promises", "stream/promises"],
          source: "node_stream_promises",
        },
      ],
    });

    expect(rows.map((row) => row.name)).toEqual(shadowed);
    expect(
      rows.every(
        (row) => row.metadata.importReachability === "bootstrap-internal",
      ),
    ).toBe(true);
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
    expect(idioms("Public.run")).toEqual(["exported-constructor-prototype"]);
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
      paths: ["export:read -> read -> readImpl -> __exactReadFile"],
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
      rows.find((row) => row.name === "export:node_wrapped_route:platform")
        .metadata.enforcementRouteEvidence,
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
      opaque.find((row) => row.name === "export:node_opaque_wrapped_route:read")
        .metadata.enforcementRouteEvidence.terminals,
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
      rows.find((row) => row.name === `export:node_route_mutations:${name}`)
        .metadata.enforcementRouteEvidence;
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
      rows.find((row) => row.name === `export:node_route_provenance:${name}`)
        .metadata.enforcementRouteEvidence;
    expect(evidence("construct").terminals).toEqual(["__exactOpenHandle"]);
    expect(evidence("invokeWithCall").terminals).toEqual(["__exactReadHandle"]);
    expect(evidence("intrinsicCall").ambiguousCallees).toEqual([]);
    // Even a literal require can cross the package import gate when it runs
    // after builtin evaluation, so it remains a conservative route edge.
    expect(evidence("staticRequire").ambiguousCallees).toContain(
      "unresolved-call:require",
    );
    expect(evidence("staticRequire").terminals).toEqual(["__exactReadHandle"]);
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
      rows.find((row) => row.name === `export:node_route_tampering:${name}`)
        .metadata.enforcementRouteEvidence;
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
        row.name === "export:node_route_function_tampering:mutatedFunctionCall",
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
      rows.find((row) => row.name === `export:node_route_alternatives:${name}`)
        .metadata.enforcementRouteEvidence;
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
      rows.find((row) => row.name === `export:node_required_routes:${name}`)
        .metadata.enforcementRouteEvidence;
    expect(evidence("read").requiredExportCalls).toEqual([
      {
        exportName: "readFileSync",
        moduleSpecifier: "node:fs",
        paths: ["export:read -> read -> require:node:fs:readFileSync"],
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

    const cyclicFactoryRows = scanStaticBuiltinExports(
      "function first() { return second(); } function second() { return first(); } module.exports.Public = first();",
      {
        sourceKey: "node_cyclic_factory",
        sourcePath: "src/builtins/cyclic-factory.js",
      },
    );
    expect(
      cyclicFactoryRows.some((row) =>
        /^Public\.\[\[dynamic-table:inherited-[a-f0-9]{12}-properties\]\]$/u.test(
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

    const cyclicFactory = scanStaticBuiltinExports(
      "function first() { return second(); } function second() { return first(); } module.exports.Public = first();",
      {
        sourceKey: "node_cyclic_factory",
        sourcePath: "src/builtins/cyclic-factory.js",
      },
    );
    expect(
      cyclicFactory.some((row) =>
        /^Public\.\[\[dynamic-table:inherited-[a-f0-9]{12}-properties\]\]$/u.test(
          row.metadata.exportName,
        ),
      ),
    ).toBe(true);
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
      version: 5,
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
                global: true,
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
    expect(
      rows.find((row) => row.name === "option:ibex:mode").metadata,
    ).toMatchObject({
      global: true,
    });

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

  test("generated REPL commands, aliases, load dialects, and key controls are exact surfaces", () => {
    const manifest = JSON.parse(
      fs.readFileSync(path.join(repoRoot, "runtime-surface.json"), "utf8"),
    );
    const rows = scanRuntimeReplSurfaces(manifest);
    expect(rows).toHaveLength(28);
    expect(rows.map((row) => row.name)).toEqual(
      expect.arrayContaining([
        "repl-command-recognition:v1",
        "repl-command:help",
        "repl-command-alias:help:.h",
        "repl-command:load",
        "repl-load-extension:.d.ts",
        "repl-load-extension:default",
        "repl-keybinding:interrupt",
        "repl-keybinding:suspend",
      ]),
    );
    expect(
      rows.find((row) => row.name === "repl-command:load").metadata,
    ).toMatchObject({
      evidenceType: "repl-command-route",
      canonicalCommandId: "load",
      commandName: ".load",
      routeKind: "canonical",
      sourceSubmission: "advance-on-source-request",
      registryRelations: [
        {
          kind: "non-capability-rationale",
          id: "authenticated-code-ingress",
        },
        { kind: "capability", id: "fs:list" },
        { kind: "capability", id: "fs:read" },
      ],
    });
    expect(
      rows.find((row) => row.name === "repl-keybinding:interrupt").metadata,
    ).toMatchObject({
      action: "interrupt-machine",
      bytes: [3],
      countsAsEditorInput: false,
    });

    const duplicateAlias = structuredClone(manifest);
    duplicateAlias.replSurface.commands[1].aliases.push(".h");
    expect(() => scanRuntimeReplSurfaces(duplicateAlias)).toThrow(
      /invalid or duplicate route/,
    );

    const duplicateControl = structuredClone(manifest);
    duplicateControl.keybindingSurface.bindings[1].bytes = [9];
    expect(() => scanRuntimeReplSurfaces(duplicateControl)).toThrow(
      /invalid or duplicates a control/,
    );

    const unknownField = structuredClone(manifest);
    unknownField.replSurface.commands[0].unreviewed = true;
    expect(() => scanRuntimeReplSurfaces(unknownField)).toThrow(
      /unreviewed fields: unreviewed/,
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
      publicReadAccessSourceProven: true,
      sourceKey: "global_storage",
      surfaceType: "global-api",
      valueShape: "callable",
    });
    expect(
      Object.fromEntries(
        rows.map((row) => [
          row.name,
          [row.metadata.publicReadAccessSourceProven, row.metadata.valueShape],
        ]),
      ),
    ).toEqual({
      "global:localStorage": [true, "data"],
      "global:localStorage.getItem": [true, "callable"],
      "global:localStorage.length": [true, "accessor"],
      "global:localStorage.setItem": [true, "callable"],
    });
  });

  test("concrete IPC channel handles retain their parent and callable descendants", () => {
    const fixtures = [
      {
        binding: "channelHandleKey",
        owner: "process",
        sourcePath: "src/engine/bootstrap/ipc-listener.js",
      },
      {
        binding: "kChannelHandle",
        owner: "globalThis.process",
        conditionalGate: "EXACT_IPC_FD",
        sourcePath: "src/engine/bootstrap/compat-polyfills.js",
      },
    ];
    for (const fixture of fixtures) {
      const rows = scanStaticGlobalApiSurfaces(
        `
          var ${fixture.binding} = '__exactKChannelHandle';
          ${fixture.owner}[${fixture.binding}] = {
            readStop: function() {},
            readStart: function() {},
            status: function() {}
          };
        `,
        fixture.sourcePath,
      );
      const ownerName = "global:process.__exactKChannelHandle";
      expect(rows.map((row) => row.name)).toEqual(
        expect.arrayContaining([
          ownerName,
          `${ownerName}.readStart`,
          `${ownerName}.readStop`,
        ]),
      );
      expect(
        rows.some((row) =>
          /\[\[dynamic-table:(?:channel-handle-key|k-channel-handle)\]\]/u.test(
            row.name,
          ),
        ),
      ).toBe(false);
      for (const row of rows.filter((candidate) =>
        candidate.name.startsWith(ownerName),
      )) {
        expect(row.metadata).toMatchObject({
          publicReadAccessSourceProven: true,
          ...(fixture.conditionalGate
            ? { conditionalGate: fixture.conditionalGate }
            : {}),
        });
        expect(row.metadata.publicReadAccessSourceContract).toBeUndefined();
      }
      expect(
        rows.find((row) => row.name === ownerName).metadata.valueShape,
      ).toBe("data");
      expect(
        rows
          .filter((row) => /\.read(?:Start|Stop)$/u.test(row.name))
          .every((row) => row.metadata.valueShape === "callable"),
      ).toBe(true);
    }

    const dynamicFamily = scanStaticGlobalApiSurfaces(
      `
        var channelFamily = globalThis.__exactKChannelHandleKey;
        channelFamily = '__exactKChannelHandle';
        globalThis.__exactKChannelHandleKey = channelFamily;
        process[channelFamily] = { readStart: function() {} };
      `,
      "src/engine/bootstrap/ipc-listener.js",
    );
    const unresolvedRoot = "global:process.[[dynamic-table:channel-family]]";
    expect(dynamicFamily.map((row) => row.name)).toEqual(
      expect.arrayContaining([unresolvedRoot, `${unresolvedRoot}.readStart`]),
    );
    expect(
      dynamicFamily.some(
        (row) => row.name === "global:process.__exactKChannelHandle",
      ),
    ).toBe(false);
    expect(
      dynamicFamily
        .filter((row) => row.name.startsWith(unresolvedRoot))
        .every(
          (row) =>
            row.metadata.publicReadAccessSourceContract === undefined &&
            row.metadata.publicReadAccessSourceProven === undefined,
        ),
    ).toBe(true);
  });

  test("reviewed process wrapper factories bind the exact lexical definition", () => {
    const sourcePath = "src/engine/bootstrap/ipc-listener.js";
    const fixture = ({
      innerReturn = "return originalRegistrar.apply(this, arguments);",
      outerReturn = "return {};",
    } = {}) => `
      function wrapSingleUseListener(originalRegistrar) {
        ${outerReturn}
      }
      function installAsyncPatch() {
        function wrapSingleUseListener(originalRegistrar) {
          return function(event, listener) {
            ${innerReturn}
          };
        }
        process.once = wrapSingleUseListener(process.once);
        process.prependOnceListener =
          wrapSingleUseListener(process.prependOnceListener);
      }
      installAsyncPatch();
    `;
    const rows = scanStaticGlobalApiSurfaces(fixture(), sourcePath);
    const wrappers = rows.filter((row) =>
      new Set([
        "global:process.once",
        "global:process.prependOnceListener",
      ]).has(row.name),
    );
    expect(wrappers).toHaveLength(2);
    expect(
      rows.some((row) =>
        /^global:process\.(?:once|prependOnceListener)\.\[\[dynamic-table:call-result-/u.test(
          row.name,
        ),
      ),
    ).toBe(false);
    for (const row of wrappers) {
      const contract = row.metadata.factoryReturnedCallableSourceContract;
      expect(row.metadata).toMatchObject({
        publicReadAccessSourceProven: true,
        valueShape: "callable",
        factoryReturnedCallableSourceContract: {
          factoryBindingKind: "function-declaration",
          factoryName: "wrapSingleUseListener",
          installedPath: row.metadata.exportName,
          proofKind: "lexically-bound-factory-returned-function",
          returnedValueShape: "callable",
          schema: "ibex/factory-returned-callable-source-contract/1",
          sourcePath,
        },
      });
      for (const evidence of [
        contract.callsiteEvidence,
        contract.evidence,
        contract.factoryDefinitionEvidence,
      ]) {
        expect(evidence).toMatch(/^sha256-[a-f0-9]{64}$/u);
      }
    }
    const contracts = wrappers.map(
      (row) => row.metadata.factoryReturnedCallableSourceContract,
    );
    expect(
      new Set(contracts.map((contract) => contract.callsiteEvidence)).size,
    ).toBe(2);
    expect(
      new Set(contracts.map((contract) => contract.factoryDefinitionEvidence))
        .size,
    ).toBe(1);
    expect(new Set(contracts.map((contract) => contract.evidence)).size).toBe(
      2,
    );

    const changedOuter = scanStaticGlobalApiSurfaces(
      fixture({ outerReturn: "return function outerOnly() {};" }),
      sourcePath,
    ).filter((row) => row.metadata.factoryReturnedCallableSourceContract);
    expect(
      changedOuter.map(
        (row) => row.metadata.factoryReturnedCallableSourceContract,
      ),
    ).toEqual(contracts);

    const changedInner = scanStaticGlobalApiSurfaces(
      fixture({ innerReturn: "return originalRegistrar.call(this, event);" }),
      sourcePath,
    ).filter((row) => row.metadata.factoryReturnedCallableSourceContract);
    expect(
      new Set(
        changedInner.map(
          (row) =>
            row.metadata.factoryReturnedCallableSourceContract
              .factoryDefinitionEvidence,
        ),
      ),
    ).not.toEqual(
      new Set(contracts.map((contract) => contract.factoryDefinitionEvidence)),
    );
  });

  test("reviewed process wrapper factories reject shadowed, aliased, conditional, and dynamic calls", () => {
    const sourcePath = "src/engine/bootstrap/ipc-listener.js";
    const reviewedFactory = `
      function wrapSingleUseListener(originalRegistrar) {
        return function(event, listener) {
          return originalRegistrar.apply(this, arguments);
        };
      }
    `;
    const adversarialSources = [
      `${reviewedFactory}
       function install(wrapSingleUseListener) {
         process.once = wrapSingleUseListener(process.once);
       }
       install(getFactory());`,
      `${reviewedFactory}
       var alias = wrapSingleUseListener;
       process.once = alias(process.once);`,
      `${reviewedFactory}
       process.once = enabled
         ? wrapSingleUseListener(process.once)
         : wrapSingleUseListener(process.once);`,
      `function wrapSingleUseListener(originalRegistrar) {
         return enabled
           ? function() { return originalRegistrar.apply(this, arguments); }
           : originalRegistrar;
       }
       process.once = wrapSingleUseListener(process.once);`,
      `${reviewedFactory}
       wrapSingleUseListener = getFactory();
       process.once = wrapSingleUseListener(process.once);`,
      `${reviewedFactory}
       process.once = factories.wrapSingleUseListener(process.once);`,
    ];
    for (const source of adversarialSources) {
      const rows = scanStaticGlobalApiSurfaces(source, sourcePath);
      expect(
        rows.find((row) => row.name === "global:process.once").metadata
          .factoryReturnedCallableSourceContract,
      ).toBeUndefined();
      expect(
        rows.some((row) =>
          /^global:process\.once\.\[\[dynamic-table:call-result-[a-f0-9]{12}-properties\]\]$/u.test(
            row.name,
          ),
        ),
      ).toBe(true);
    }
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
    const cyclicFactoryRows = scanStaticGlobalApiSurfaces(
      "function first() { return second(); } function second() { return first(); } globalThis.Public = first();",
      "src/engine/bootstrap/cyclic-factory.js",
    );
    expect(
      cyclicFactoryRows.some((row) =>
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
      "globalThis.Constructor = (function() { function C() {} C.create = function() {}; C.prototype.run = function() {}; return C; })();",
      "src/engine/bootstrap/iife-constructor.js",
    );
    expect(
      constructorRows.some((row) =>
        /^global:Constructor\.\[\[dynamic-table:call-result-[a-f0-9]{12}-properties\]\]$/u.test(
          row.name,
        ),
      ),
    ).toBe(false);
    expect(
      constructorRows.map((row) => [row.name, row.metadata.valueShape]),
    ).toEqual([
      ["global:Constructor", "callable"],
      ["global:Constructor.create", "callable"],
      ["global:Constructor.prototype", "data"],
      ["global:Constructor.prototype.run", "callable"],
    ]);
    const computedConstructorRows = scanStaticGlobalApiSurfaces(
      "globalThis.Constructor = (function() { function C() {} C.prototype[getName()] = function() {}; return C; })();",
      "src/engine/bootstrap/iife-constructor-computed.js",
    );
    expect(
      computedConstructorRows.some((row) =>
        /^global:Constructor\.\[\[dynamic-table:call-result-[a-f0-9]{12}-properties\]\]$/u.test(
          row.name,
        ),
      ),
    ).toBe(true);
    const aliasedConstructorRows = scanStaticGlobalApiSurfaces(
      "globalThis.Constructor = (function() { function C() {} var P = C.prototype; P.run = function() {}; return C; })();",
      "src/engine/bootstrap/iife-constructor-aliased.js",
    );
    expect(
      aliasedConstructorRows.some((row) =>
        /^global:Constructor\.\[\[dynamic-table:call-result-[a-f0-9]{12}-properties\]\]$/u.test(
          row.name,
        ),
      ),
    ).toBe(true);
  });

  test("registry scanner authority is pinned to canonical LF checkout bytes", () => {
    const attributes = fs.readFileSync(
      path.join(repoRoot, ".gitattributes"),
      "utf8",
    );
    expect(attributes).toContain("build.rs text eol=lf");
    expect(attributes).toContain("include/** text eol=lf");
    expect(attributes).toContain("platform/android/** text eol=lf");
    expect(attributes).toContain("src/** text eol=lf");
    expect(attributes).toContain("src/engine/bootstrap/** text eol=lf");
    for (const sourcePath of [
      "build.rs",
      "include/exact_runtime.h",
      "platform/android/java/dev/ibex/runtime/IbexNetworking.java",
      "src/engine/bootstrap/web-streams-polyfill.js",
      "src/engine/evaluation.rs",
    ]) {
      expect(
        fs.readFileSync(path.join(repoRoot, sourcePath), "utf8").includes("\r"),
        sourcePath,
      ).toBe(false);
    }
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
    expect(
      rows
        .filter((row) => row.name !== "global:API")
        .map((row) => [
          row.name,
          row.metadata.publicReadAccessSourceProven,
          row.metadata.valueShape,
        ]),
    ).toEqual([
      ["global:API.close", true, "callable"],
      ["global:API.open", true, "callable"],
      ["global:API.open.[[return]].read", true, "callable"],
      ["global:API.open.[[return]].scoped", true, "callable"],
      ["global:API.status", true, "callable"],
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
        first.find((row) => row.name === "global:exact.runtime.info").metadata
          .valueShape,
      ).toBe("callable");
    } finally {
      fs.rmSync(root, { force: true, recursive: true });
    }
  });

  test("reviewed shared-runtime prefixes require exact membership or concrete owner reads", () => {
    const root = makeRuntimeFixture({
      "packages/ibex-runtime-js/src/runtime-entry.ts": `
        import { installGlobals } from './bootstrap.js';
        installGlobals();
      `,
      "packages/ibex-runtime-js/src/bootstrap.ts": `
        export function installGlobals() {
          const g = globalThis as any;
          if (g.__exactLoadTimings) {
            g.__exactLoadTimings.installGlobalsStart = 1;
          }
          const Intl = g.Intl;
          if (typeof Intl.DateTimeFormat === 'function') {
            const DTFProto = Intl.DateTimeFormat.prototype;
            Object.defineProperty(DTFProto, 'formatToParts', {
              value: function formatToParts() {},
            });
          }
          if (Intl.Locale?.prototype) {
            Object.defineProperty(Intl.Locale.prototype, 'textInfo', {
              get: function textInfo() { return {}; },
            });
          }
          if (typeof Intl.NumberFormat === 'function') {
            const NFProto = Intl.NumberFormat.prototype;
            Object.defineProperty(NFProto, 'formatToParts', {
              value: function formatToParts() {},
            });
          }
          const OriginalPromise = g.Promise;
          OriginalPromise.prototype.then = function then() {};
        }
      `,
    });
    try {
      const rows = scanSharedRuntimeGlobalSurfaces(root);
      const contracts = rows.filter(
        (row) => row.metadata.publicReadAccessSourceContract,
      );
      expect(contracts.map((row) => row.name)).toEqual([
        "__exactLoadTimings",
        "global:Intl.DateTimeFormat",
        "global:Intl.DateTimeFormat.prototype",
        "global:Intl.Locale.prototype",
        "global:Intl.NumberFormat",
        "global:Intl.NumberFormat.prototype",
        "global:Promise.prototype",
      ]);
      expect(
        Object.fromEntries(
          contracts.map((row) => [
            row.name,
            [
              row.metadata.valueShape,
              row.metadata.publicReadAccessSourceContract.proofKinds,
            ],
          ]),
        ),
      ).toEqual({
        __exactLoadTimings: ["data", ["concrete-member-owner"]],
        "global:Intl.DateTimeFormat": [
          "callable",
          ["typeof-callable-membership"],
        ],
        "global:Intl.DateTimeFormat.prototype": [
          "data",
          ["concrete-member-owner"],
        ],
        "global:Intl.Locale.prototype": ["data", ["concrete-member-owner"]],
        "global:Intl.NumberFormat": [
          "callable",
          ["typeof-callable-membership"],
        ],
        "global:Intl.NumberFormat.prototype": [
          "data",
          ["concrete-member-owner"],
        ],
        "global:Promise.prototype": ["data", ["concrete-member-owner"]],
      });
      expect(
        contracts.every(
          (row) =>
            row.metadata.publicReadAccessSourceProven === true &&
            row.metadata.publicReadAccessSourceContract.schema ===
              "ibex/public-read-access-source-contract/1" &&
            row.metadata.publicReadAccessSourceContract.presenceVariants.join(
              ",",
            ) === "absent,present",
        ),
      ).toBe(true);
      expect(
        contracts
          .filter((row) => row.metadata.valueShape === "callable")
          .every((row) => row.metadata.publicInvocation === undefined),
      ).toBe(true);
    } finally {
      fs.rmSync(root, { force: true, recursive: true });
    }

    const noMembershipGuard = makeRuntimeFixture({
      "packages/ibex-runtime-js/src/runtime-entry.ts": `
        import { installGlobals } from './bootstrap.js';
        installGlobals();
      `,
      "packages/ibex-runtime-js/src/bootstrap.ts": `
        export function installGlobals() {
          const g = globalThis as any;
          const Intl = g.Intl;
          Intl.DateTimeFormat.prototype.formatToParts = function() {};
        }
      `,
    });
    try {
      const rows = scanSharedRuntimeGlobalSurfaces(noMembershipGuard);
      expect(
        rows.find((row) => row.name === "global:Intl.DateTimeFormat")?.metadata
          .publicReadAccessSourceContract,
      ).toBeUndefined();
      expect(
        rows.find((row) => row.name === "global:Intl.DateTimeFormat.prototype")
          ?.metadata.publicReadAccessSourceContract,
      ).toMatchObject({
        proofKinds: ["concrete-member-owner"],
        valueShape: "data",
      });
    } finally {
      fs.rmSync(noMembershipGuard, { force: true, recursive: true });
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
    expect(
      rows
        .filter((row) => !row.name.includes("[[dynamic-table:"))
        .every((row) => row.metadata.publicReadAccessSourceProven === true),
    ).toBe(true);
  });

  test("native JSI stdio accessor helpers retain concrete member provenance", () => {
    const source = `
      auto installStdioQueryAccessor = [](facebook::jsi::Object& stream,
                                          int fd,
                                          const char* name) {
        defineProperty.call(rt, stream, name, descriptor);
      };
      facebook::jsi::Object stream(rt);
      installStdioQueryAccessor(stream, 1, "isTTY");
      installStdioQueryAccessor(stream, 1, "columns");
      installStdioQueryAccessor(stream, 1, "rows");
      facebook::jsi::Object processObj(rt);
      processObj.setProperty(rt, "stdout", std::move(stream));
      rt.global().setProperty(rt, "process", std::move(processObj));
    `;
    const rows = scanCppGlobalPropertySurfaces(source, "synthetic.cc");
    expect(rows.map((row) => row.name)).toEqual([
      "global:process",
      "global:process.stdout",
      "global:process.stdout.columns",
      "global:process.stdout.isTTY",
      "global:process.stdout.rows",
    ]);
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
      rows.find((row) => row.name === "global:namespaceObject.nested")?.metadata
        .publicInvocation,
    ).toEqual({
      arity: 4,
      globalName: "namespaceObject.nested",
      kind: "native-global-function",
      sourceRef: "synthetic.cc#jsi-global:namespaceObject.nested",
    });
    const dynamicRows = scanCppGlobalPropertySurfaces(
      `facebook::jsi::Object values(rt);
       values.setProperty(rt, runtimeName, 1);
       rt.global().setProperty(rt, "values", std::move(values));`,
      "synthetic.cc",
    );
    expect(
      dynamicRows.find((row) => row.name.includes("[[dynamic-table:"))?.metadata
        .publicReadAccessSourceProven,
    ).toBeUndefined();
  });

  test("construction-private HostFunctions require factory, property, root, and capture evidence", () => {
    const source = String.raw`
${GPU_CANONICAL_INCLUDE_BLOCK}

#if defined(IBEX_ENABLE_WEBGPU_BINDING)
#if defined(submitGpuBridgeCall) || defined(cancelGpuBridgeCall) || \
    defined(retireGpuBridgeCall)
#error "Ibex CapSec GPU terminal handlers must not be preprocessor macros"
#endif
      Value submitGpuBridgeCall(Runtime&, const Value*, size_t) { return {}; }

#if defined(submitGpuBridgeCall) || defined(cancelGpuBridgeCall) || \
    defined(retireGpuBridgeCall)
#error "Ibex CapSec GPU terminal handlers must not be preprocessor macros"
#endif
      Value cancelGpuBridgeCall(Runtime&, const Value*, size_t) { return {}; }

#if defined(submitGpuBridgeCall) || defined(cancelGpuBridgeCall) || \
    defined(retireGpuBridgeCall)
#error "Ibex CapSec GPU terminal handlers must not be preprocessor macros"
#endif
      Value retireGpuBridgeCall(Runtime&, const Value*, size_t) { return {}; }

#endif

#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
      bool exactSyntheticPublish() { return true; }
#else

#if defined(submitGpuBridgeCall) || defined(cancelGpuBridgeCall) || \
    defined(retireGpuBridgeCall)
#error "Ibex CapSec GPU terminal handlers must not be preprocessor macros"
#endif
      auto submit = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "submit"), 5,
        [runtime](facebook::jsi::Runtime& rt, const auto&, const auto* args, size_t count) {
          return submitGpuBridgeCall(runtime, rt, args, count);
        });
      auto cancel = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "cancel"), 1,
        [runtime](facebook::jsi::Runtime& rt, const auto&, const auto* args, size_t count) {
          return cancelGpuBridgeCall(runtime, rt, args, count);
        });
      auto retire = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "retire"), 1,
        [runtime](facebook::jsi::Runtime& rt, const auto&, const auto* args, size_t count) {
          return retireGpuBridgeCall(runtime, rt, args, count);
        });
      facebook::jsi::Object gpuNativeBridge(rt);
      defineGpuProperty(rt, gpuNativeBridge, "submit", std::move(submit), false);
      defineGpuProperty(rt, gpuNativeBridge, "cancel", std::move(cancel), false);
      defineGpuProperty(rt, gpuNativeBridge, "retire", std::move(retire), false);
      auto privateGpuNativeBridge =
        std::make_shared<facebook::jsi::Object>(std::move(gpuNativeBridge));
      auto revoke = capture.call(rt, *privateGpuNativeBridge);
#endif
    `;
    const rows = scanCppConstructionPrivateBridgeSurfaces(
      source,
      "synthetic_gpu.cc",
    );
    expect(rows.map((row) => row.name)).toEqual([
      "construction-private:gpuNativeBridge.cancel",
      "construction-private:gpuNativeBridge.retire",
      "construction-private:gpuNativeBridge.submit",
    ]);
    expect(
      rows.map((row) => [
        row.metadata.memberName,
        row.metadata.functionVariable,
        row.metadata.arity,
        row.metadata.terminalHandler,
        row.metadata.identityGuardCount,
        row.metadata.definitionConditionalContext,
        row.metadata.bindingConditionalContext,
      ]),
    ).toEqual([
      [
        "cancel",
        "cancel",
        1,
        "cancelGpuBridgeCall",
        4,
        "webgpu-enabled-if",
        "webgpu-enabled-else",
      ],
      [
        "retire",
        "retire",
        1,
        "retireGpuBridgeCall",
        4,
        "webgpu-enabled-if",
        "webgpu-enabled-else",
      ],
      [
        "submit",
        "submit",
        5,
        "submitGpuBridgeCall",
        4,
        "webgpu-enabled-if",
        "webgpu-enabled-else",
      ],
    ]);
    expect(
      rows.every(
        (row) =>
          row.metadata.evidenceType === "construction-private-host-function" &&
          row.metadata.externalFeatureGate === "IBEX_ENABLE_WEBGPU_BINDING" &&
          row.metadata.externalFeatureGateSourceMutationCount === 0 &&
          row.metadata.includeDirectiveCount === 20 &&
          row.metadata.includeInventory === "hermes-runtime-gpu-exact-v1" &&
          row.metadata.translationPhaseAuthenticated === true,
      ),
    ).toBe(true);
    expect(
      scanCppConstructionPrivateBridgeSurfaces(
        source.replace(
          "auto revoke = capture.call(rt, *privateGpuNativeBridge);",
          "auto revoke = privateGpuNativeBridge;",
        ),
        "synthetic_gpu.cc",
      ),
    ).toEqual([]);

    for (const [memberName, expectedHandler, crossedHandler] of [
      ["submit", "submitGpuBridgeCall", "cancelGpuBridgeCall"],
      ["cancel", "cancelGpuBridgeCall", "retireGpuBridgeCall"],
      ["retire", "retireGpuBridgeCall", "submitGpuBridgeCall"],
    ]) {
      const crossed = scanCppConstructionPrivateBridgeSurfaces(
        source.replace(
          `return ${expectedHandler}(`,
          `return ${crossedHandler}(`,
        ),
        "synthetic_gpu.cc",
      );
      expect(
        crossed.some(
          (candidate) =>
            candidate.metadata.memberName === memberName &&
            candidate.metadata.terminalHandler === expectedHandler,
        ),
        memberName,
      ).toBe(false);
    }

    const expectNoTerminalRows = (label, mutatedSource) => {
      expect(mutatedSource, label).not.toBe(source);
      expect(
        scanCppConstructionPrivateBridgeSurfaces(
          mutatedSource,
          "synthetic_gpu.cc",
        ),
        label,
      ).toEqual([]);
    };
    const firstDefinition =
      "Value submitGpuBridgeCall(Runtime&, const Value*, size_t) { return {}; }";
    const bindingGuard = "#else\n\n#if defined(submitGpuBridgeCall)";
    const terminalPhysicalGuard = String.raw`#if defined(submitGpuBridgeCall) || defined(cancelGpuBridgeCall) || \
    defined(retireGpuBridgeCall)
#error "Ibex CapSec GPU terminal handlers must not be preprocessor macros"
#endif`;
    for (const [label, mutatedSource] of gpuIncludeInventoryMutations(source)) {
      expectNoTerminalRows(label, mutatedSource);
    }
    const terminalGateGapAnchors = [
      ["before first include", '#include "hermes_runtime_internal.h"'],
      ["between local includes", '#include "../../include/exact_runtime.h"'],
      ["between local and system includes", "#include <algorithm>"],
      [
        "after canonical include block",
        "#if defined(IBEX_ENABLE_WEBGPU_BINDING)\n",
      ],
      ["before first terminal definition", firstDefinition],
      [
        "before cancel terminal definition",
        "Value cancelGpuBridgeCall(Runtime&, const Value*, size_t) { return {}; }",
      ],
      [
        "before retire terminal definition",
        "Value retireGpuBridgeCall(Runtime&, const Value*, size_t) { return {}; }",
      ],
      [
        "between enabled definitions and disabled gate",
        "#if !defined(IBEX_ENABLE_WEBGPU_BINDING)\n",
      ],
      ["inside disabled branch", "bool exactSyntheticPublish()"],
      ["before complementary else", bindingGuard],
      ["before binding guard", terminalPhysicalGuard],
      ["before submit binding", "auto submit ="],
      ["before cancel binding", "auto cancel ="],
      ["before retire binding", "auto retire ="],
      [
        "before bridge publication",
        'defineGpuProperty(rt, gpuNativeBridge, "submit"',
      ],
      ["before bridge capture", "auto revoke = capture.call"],
    ];
    for (const gateMutation of [
      "#define IBEX_ENABLE_WEBGPU_BINDING 1",
      "#undef IBEX_ENABLE_WEBGPU_BINDING",
    ]) {
      for (const [gap, anchor] of terminalGateGapAnchors) {
        expectNoTerminalRows(
          `${gateMutation}: ${gap}`,
          insertCppDirectiveBefore(source, anchor, gateMutation),
        );
      }
      expectNoTerminalRows(
        `${gateMutation}: after protected source`,
        `${source}\n${gateMutation}`,
      );
    }
    for (const [label, hiddenDirective] of [
      [
        "comment-separated external gate define",
        "#/**/define IBEX_ENABLE_WEBGPU_BINDING 1",
      ],
      [
        "comment-separated external gate undef",
        "#/**/undef IBEX_ENABLE_WEBGPU_BINDING",
      ],
      [
        "tab-separated external gate define",
        "#\tdefine IBEX_ENABLE_WEBGPU_BINDING 1",
      ],
      [
        "tab-separated external gate undef",
        "#\tundef IBEX_ENABLE_WEBGPU_BINDING",
      ],
      [
        "LF-spliced external gate define",
        "#def\\\nine IBEX_ENABLE_WEBGPU_BINDING 1",
      ],
      [
        "LF-spliced external gate undef",
        "#und\\\nef IBEX_ENABLE_WEBGPU_BINDING",
      ],
      [
        "CRLF-spliced external gate define",
        "#def\\\r\nine IBEX_ENABLE_WEBGPU_BINDING 1",
      ],
      [
        "CRLF-spliced external gate undef",
        "#und\\\r\nef IBEX_ENABLE_WEBGPU_BINDING",
      ],
    ]) {
      expectNoTerminalRows(
        label,
        insertCppDirectiveBefore(
          source,
          "#if defined(IBEX_ENABLE_WEBGPU_BINDING)\n",
          hiddenDirective,
        ),
      );
    }
    for (const [label, mutatedSource] of [
      [
        "LF-spliced include directive",
        source.replace("#include", "#inc\\\nlude"),
      ],
      [
        "CRLF-spliced include directive",
        source.replace("#include", "#inc\\\r\nlude"),
      ],
      [
        "LF-spliced include path",
        source.replace(
          "hermes_runtime_internal.h",
          "hermes_runtime_\\\ninternal.h",
        ),
      ],
      [
        "CRLF-spliced include path",
        source.replace(
          "hermes_runtime_internal.h",
          "hermes_runtime_\\\r\ninternal.h",
        ),
      ],
      [
        "tab-separated include directive",
        source.replace("#include", "#\tinclude"),
      ],
      [
        "LF-spliced external gate spelling",
        source.replace(
          "IBEX_ENABLE_WEBGPU_BINDING",
          "IBEX_ENABLE_WEBGPU_BIND\\\nING",
        ),
      ],
      [
        "CRLF-spliced external gate spelling",
        source.replace(
          "IBEX_ENABLE_WEBGPU_BINDING",
          "IBEX_ENABLE_WEBGPU_BIND\\\r\nING",
        ),
      ],
      [
        "comment-hidden external gate spelling",
        source.replace(
          "IBEX_ENABLE_WEBGPU_BINDING",
          "IBEX_ENABLE_WEBGPU_/**/BINDING",
        ),
      ],
      [
        "tab-separated external gate directive",
        source.replace(
          "#if defined(IBEX_ENABLE_WEBGPU_BINDING)",
          "#\tif defined(IBEX_ENABLE_WEBGPU_BINDING)",
        ),
      ],
      [
        "line-comment-spliced external gate spelling",
        source.replace(
          "IBEX_ENABLE_WEBGPU_BINDING)",
          "IBEX_ENABLE_WEBGPU_BIND//\\\nING)",
        ),
      ],
      [
        "LF-spliced terminal handler spelling",
        source.replace("submitGpuBridgeCall", "submitGpuBridge\\\nCall"),
      ],
      [
        "CRLF-spliced terminal handler spelling",
        source.replace("submitGpuBridgeCall", "submitGpuBridge\\\r\nCall"),
      ],
      [
        "comment-hidden terminal handler spelling",
        source.replace("submitGpuBridgeCall", "submitGpuBridge/**/Call"),
      ],
      [
        "tab-separated terminal handler spelling",
        source.replace("submitGpuBridgeCall", "submitGpuBridge\tCall"),
      ],
    ]) {
      expectNoTerminalRows(label, mutatedSource);
    }
    for (const handler of [
      "submitGpuBridgeCall",
      "cancelGpuBridgeCall",
      "retireGpuBridgeCall",
    ]) {
      const definition = `Value ${handler}(Runtime&, const Value*, size_t) { return {}; }`;
      expectNoTerminalRows(
        `${handler}: inactive canonical definition with active alternate include`,
        source.replace(
          definition,
          `#if 0\n      ${definition}\n#else\n#include "alternate-${handler}.h"\n#endif`,
        ),
      );
      expectNoTerminalRows(
        `${handler}: inactive canonical binding with active alternate include`,
        source.replace(
          `return ${handler}(runtime, rt, args, count);`,
          `#if 0\n          return ${handler}(runtime, rt, args, count);\n#else\n#include "alternate-${handler}-binding.h"\n#endif`,
        ),
      );
    }
    for (const identifier of [
      "submitGpuBridgeCall",
      "cancelGpuBridgeCall",
      "retireGpuBridgeCall",
    ]) {
      expectNoTerminalRows(
        `${identifier}: compatible macro alias before guard`,
        source.replace(
          "#if defined(submitGpuBridgeCall)",
          `#define ${identifier} compatibleGpuBridgeCall\n      #if defined(submitGpuBridgeCall)`,
        ),
      );
      expectNoTerminalRows(
        `${identifier}: undef/redefine after guard`,
        source.replace(
          firstDefinition,
          `#undef ${identifier}\n      #define ${identifier} compatibleGpuBridgeCall\n      ${firstDefinition}`,
        ),
      );
      expectNoTerminalRows(
        `${identifier}: source alias across definition/binding lifetime`,
        source.replace(
          bindingGuard,
          `\n      auto compatibleGpuBridgeCall = ${identifier};${bindingGuard}`,
        ),
      );
    }
    expectNoTerminalRows(
      "guard placement after first protected definition",
      source
        .replace(
          firstDefinition,
          `${firstDefinition}\n      #if defined(submitGpuBridgeCall) || defined(cancelGpuBridgeCall) || defined(retireGpuBridgeCall)\n      #error "Ibex CapSec GPU terminal handlers must not be preprocessor macros"\n      #endif`,
        )
        .replace(/\n\s*#if defined\(submitGpuBridgeCall\).*?#endif\n/su, "\n"),
    );
    expectNoTerminalRows(
      "conditional selection around a protected definition",
      source.replace(
        "Value cancelGpuBridgeCall(Runtime&, const Value*, size_t) { return {}; }",
        "#if SELECT_COMPATIBLE_HANDLER\n      Value cancelGpuBridgeCall(Runtime&, const Value*, size_t) { return {}; }\n      #endif",
      ),
    );
    expectNoTerminalRows(
      "include between guard and protected definition",
      source.replace(
        firstDefinition,
        `#include "compatible-handler.h"\n      ${firstDefinition}`,
      ),
    );
    expectNoTerminalRows(
      "digraph include between guard and protected definition",
      source.replace(
        firstDefinition,
        `%:include "compatible-handler.h"\n      ${firstDefinition}`,
      ),
    );
    expectNoTerminalRows(
      "pragma macro restore between guard and protected definition",
      source.replace(
        firstDefinition,
        `_Pragma("pop_macro(\\\"submitGpuBridgeCall\\\")")\n      ${firstDefinition}`,
      ),
    );
    expectNoTerminalRows(
      "wrapper directive between guard and protected definition",
      source.replace(
        firstDefinition,
        `#define GPU_HANDLER_WRAPPER(name) name\n      ${firstDefinition}`,
      ),
    );
    for (const [label, mutatedGuard] of [
      [
        "condition trailing comment",
        terminalPhysicalGuard.replace(
          "    defined(retireGpuBridgeCall)",
          "    defined(retireGpuBridgeCall) // accepted-looking guard",
        ),
      ],
      [
        "error trailing bytes",
        terminalPhysicalGuard.replace(
          'preprocessor macros"',
          'preprocessor macros" trailing',
        ),
      ],
      [
        "endif trailing comment",
        terminalPhysicalGuard.replace("#endif", "#endif // guard"),
      ],
      [
        "backslash-space splice",
        terminalPhysicalGuard.replace("\\\n", "\\ \n"),
      ],
      ["backslash-tab splice", terminalPhysicalGuard.replace("\\\n", "\\\t\n")],
      ["CRLF physical lines", terminalPhysicalGuard.replaceAll("\n", "\r\n")],
      [
        "alternate directive whitespace",
        terminalPhysicalGuard.replace("#if ", "# if "),
      ],
      [
        "digraph directive spelling",
        terminalPhysicalGuard.replace("#if", "%:if"),
      ],
      [
        "trigraph directive spelling",
        terminalPhysicalGuard.replace("#if", "??=if"),
      ],
      ["trigraph line splice", terminalPhysicalGuard.replace("\\\n", "??/\n")],
    ]) {
      expectNoTerminalRows(
        `physical terminal guard: ${label}`,
        source.replace(terminalPhysicalGuard, mutatedGuard),
      );
    }
    expectNoTerminalRows(
      "comment trigraph splices away terminal guard line",
      source.replace(terminalPhysicalGuard, `//??/\n${terminalPhysicalGuard}`),
    );
    expectNoTerminalRows(
      "MSVC pragma restores terminal macro after guard",
      source.replace(
        firstDefinition,
        `__pragma(pop_macro("submitGpuBridgeCall"))\n      ${firstDefinition}`,
      ),
    );
    expectNoTerminalRows(
      "outer inactive terminal branch",
      `#if 0\n${source}\n#endif`,
    );
    expectNoTerminalRows(
      "outer inactive terminal branch with active alternate include",
      `#if 0\n${source}\n#else\n#include "compatible-handler.h"\n#endif`,
    );
    expectNoTerminalRows(
      "nested terminal conditional depth",
      `#if 1\n#if 1\n${source}\n#endif\n#endif`,
    );
    for (const directive of ["#elif 1", "#else", "#endif"]) {
      expectNoTerminalRows(
        `intervening terminal ${directive}`,
        source.replace(firstDefinition, `${directive}\n${firstDefinition}`),
      );
    }
    expectNoTerminalRows(
      "terminal guard in inactive branch with active alternate include",
      source.replace(
        terminalPhysicalGuard,
        `#if 0\n${terminalPhysicalGuard}\n#else\n#include "compatible-handler.h"\n#endif`,
      ),
    );
    const secondGuardStart = source.lastIndexOf(
      "#if defined(submitGpuBridgeCall)",
    );
    const secondGuardEnd =
      source.indexOf("#endif", secondGuardStart) + "#endif".length;
    expectNoTerminalRows(
      "binding guard lifetime removed",
      `${source.slice(0, secondGuardStart)}${source.slice(secondGuardEnd)}`,
    );
  });

  test("V2 construction-private bridge discovers all nine guarded methods and fails closed under mutation", () => {
    const sourcePath = "src/engine/hermes_runtime_gpu_v2.cc";
    const source = fs.readFileSync(path.join(repoRoot, sourcePath), "utf8");
    const expected = [
      "construction-private:gpuNativeBridgeV2.cancel",
      "construction-private:gpuNativeBridgeV2.capturePresentationAuthority",
      "construction-private:gpuNativeBridgeV2.createMappedRangeAlias",
      "construction-private:gpuNativeBridgeV2.detachMappedRange",
      "construction-private:gpuNativeBridgeV2.recheckPresentationAuthority",
      "construction-private:gpuNativeBridgeV2.retire",
      "construction-private:gpuNativeBridgeV2.retirePresentationAuthority",
      "construction-private:gpuNativeBridgeV2.setEventSink",
      "construction-private:gpuNativeBridgeV2.submit",
    ];
    const rows = scanCppConstructionPrivateBridgeSurfaces(source, sourcePath);
    expect(rows.map((row) => row.name)).toEqual(expected);
    expect(
      rows.map((row) => [
        row.metadata.memberName,
        row.metadata.arity,
        row.metadata.terminalHandler,
        row.metadata.identityGuardCount,
      ]),
    ).toEqual([
      ["cancel", 2, "cancelGpuV2BridgeCall", 10],
      [
        "capturePresentationAuthority",
        2,
        "captureGpuPresentationAuthorityBridgeCall",
        10,
      ],
      [
        "createMappedRangeAlias",
        3,
        "createGpuV2MappedRangeAliasBridgeCall",
        10,
      ],
      ["detachMappedRange", 1, "detachGpuV2MappedRangeBridgeCall", 10],
      [
        "recheckPresentationAuthority",
        3,
        "recheckGpuPresentationAuthorityBridgeCall",
        10,
      ],
      ["retire", 1, "retireGpuV2BridgeCall", 10],
      [
        "retirePresentationAuthority",
        1,
        "retireGpuPresentationAuthorityBridgeCall",
        10,
      ],
      ["setEventSink", 1, "setGpuV2EventSinkBridgeCall", 10],
      ["submit", 4, "submitGpuV2BridgeCall", 10],
    ]);

    const guardError =
      '#error "Ibex CapSec GPU V2 terminal handlers must not be preprocessor macros"';
    const bindingReturn =
      "return submitGpuV2BridgeCall(runtime, rt, args, count);";
    const capturedRoot =
      "auto revokeValue = capture.call(rt, *captured);";
    for (const [label, mutated] of [
      [
        "guard error mutation",
        source.replace(guardError, '#error "compatible V2 guard"'),
      ],
      [
        "terminal cross-wire",
        source.replace(
          bindingReturn,
          "return cancelGpuV2BridgeCall(runtime, rt, args, count);",
        ),
      ],
      [
        "capture root removed",
        source.replace(capturedRoot, "auto revokeValue = captured;"),
      ],
    ]) {
      expect(mutated, label).not.toBe(source);
      expect(
        scanCppConstructionPrivateBridgeSurfaces(mutated, sourcePath),
        label,
      ).toEqual([]);
    }

    const renamedProperty = source.replace(
      '"setEventSink",\n        std::move(setEventSink)',
      '"setEventSinkMissing",\n        std::move(setEventSink)',
    );
    expect(renamedProperty).not.toBe(source);
    expect(
      scanCppConstructionPrivateBridgeSurfaces(
        renamedProperty,
        sourcePath,
      ).map((row) => row.name),
    ).not.toContain("construction-private:gpuNativeBridgeV2.setEventSink");
  });

  test("versioned callback-table ingress is source-derived from the bound slot", () => {
    const source = String.raw`
${GPU_CANONICAL_INCLUDE_BLOCK}

#if defined(IBEX_ENABLE_WEBGPU_BINDING)
#if defined(IBEX_CAPSEC_CALLBACK_TABLE_INGRESS) || \
    defined(receiveGpuEvent)
#error "Ibex CapSec GPU callback identifiers must not be preprocessor macros"
#endif
      int32_t receiveGpuEvent(void*, const Event*) noexcept { return 0; }

#define IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(table_type, field_name, callback) \
  callback
      const ExactGpuClientSinkV1 sink = {
        sizeof(ExactGpuClientSinkV1),
        EXACT_GPU_SERVICE_ABI_VERSION_V1,
        retainClient,
        releaseClient,
        IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(
          ExactGpuClientSinkV1, on_event, receiveGpuEvent),
      };
#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS
#endif
    `;
    const markerDefinition = String.raw`#define IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(table_type, field_name, callback) \
  callback`;
    const markerWithReplacement = (replacement) =>
      markerDefinition.replace(/\n  callback$/u, `\n  ${replacement}`);
    expect(
      scanCppVersionedCallbackTableIngresses(source, "synthetic_gpu.cc"),
    ).toEqual([
      expect.objectContaining({
        kind: "callback",
        name: "ingress:synthetic_gpu.cc:ExactGpuClientSinkV1.on_event:receiveGpuEvent",
        metadata: expect.objectContaining({
          abiVersionExpression: "EXACT_GPU_SERVICE_ABI_VERSION_V1",
          callback: "receiveGpuEvent",
          callbackDefinitionCount: 1,
          conditionalContext: "webgpu-enabled-if",
          conditionalStackAuthenticated: true,
          externalFeatureGate: "IBEX_ENABLE_WEBGPU_BINDING",
          externalFeatureGateSourceMutationCount: 0,
          effectiveCallbackExpression: "receiveGpuEvent",
          callbackFieldCount: 5,
          callbackFieldIndex: 4,
          evidenceType: "versioned-callback-table-ingress",
          fieldName: "on_event",
          initializerVariable: "sink",
          identityGuardCount: 1,
          identityGuardError:
            "Ibex CapSec GPU callback identifiers must not be preprocessor macros",
          identityGuardIdentifiers: [
            "IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
            "receiveGpuEvent",
          ],
          identityGuardLifetime: "guard-callback-definition-table-undef",
          includeDirectiveCount: 20,
          includeInventory: "hermes-runtime-gpu-exact-v1",
          interveningDirectiveCount: 0,
          macroConditionalDirectiveCount: 0,
          macroDefinitionCount: 1,
          macroInvocationCount: 1,
          macroLifetimeOrder: "define-invocation-undef",
          macroName: "IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
          macroParameters: ["table_type", "field_name", "callback"],
          macroReplacement: "callback",
          macroUndefCount: 1,
          occurrenceCount: 1,
          physicalGuardFormat: "exact-lf-physical-lines",
          protectedIdentifierTokenCounts: {
            IBEX_CAPSEC_CALLBACK_TABLE_INGRESS: 4,
            receiveGpuEvent: 3,
          },
          releaseCallback: "releaseClient",
          retainCallback: "retainClient",
          structSizeExpression: "sizeof(ExactGpuClientSinkV1)",
          sourceAliasCount: 0,
          tableType: "ExactGpuClientSinkV1",
          translationPhaseAuthenticated: true,
        }),
      }),
    ]);

    const outsideInitializer = source.replace(
      `IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(
          ExactGpuClientSinkV1, on_event, receiveGpuEvent),`,
      `receiveGpuEvent,
      };
      auto disconnected = IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(
        ExactGpuClientSinkV1, on_event, receiveGpuEvent);
      const ExactGpuClientSinkV1 ignored = {`,
    );
    expect(
      scanCppVersionedCallbackTableIngresses(
        outsideInitializer,
        "synthetic_gpu.cc",
      ),
    ).toEqual([]);

    const wrongPosition = source.replace(
      `releaseClient,
        IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(
          ExactGpuClientSinkV1, on_event, receiveGpuEvent),`,
      `IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(
          ExactGpuClientSinkV1, on_event, receiveGpuEvent),
        releaseClient,`,
    );
    expect(
      scanCppVersionedCallbackTableIngresses(wrongPosition, "synthetic_gpu.cc"),
    ).toEqual([]);

    const invalidMacroMutations = [
      [
        "alternate expansion",
        source.replace(
          markerDefinition,
          markerWithReplacement("receiveOtherEvent"),
        ),
      ],
      [
        "alias expansion",
        source.replace(
          markerDefinition,
          markerWithReplacement("callbackAlias"),
        ),
      ],
      [
        "wrapper expansion",
        source.replace(
          markerDefinition,
          markerWithReplacement("wrapCallback(callback)"),
        ),
      ],
      [
        "duplicate definition",
        source.replace(
          "const ExactGpuClientSinkV1 sink",
          `${markerDefinition}\n      const ExactGpuClientSinkV1 sink`,
        ),
      ],
      [
        "redefinition",
        source.replace(
          "const ExactGpuClientSinkV1 sink",
          `${markerWithReplacement("receiveOtherEvent")}\n      const ExactGpuClientSinkV1 sink`,
        ),
      ],
      [
        "conditional lifetime",
        source
          .replace(
            "const ExactGpuClientSinkV1 sink",
            "#if CALLBACK_PATH\n      const ExactGpuClientSinkV1 sink",
          )
          .replace(
            "#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
            "#endif\n      #undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
          ),
      ],
      [
        "definition after use",
        source
          .replace(`${markerDefinition}\n`, "")
          .replace(
            "#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
            `${markerDefinition}\n      #undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS`,
          ),
      ],
      [
        "premature undef",
        source
          .replace("#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS", "")
          .replace(
            "const ExactGpuClientSinkV1 sink",
            "#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS\n      const ExactGpuClientSinkV1 sink",
          ),
      ],
      ["missing definition", source.replace(`${markerDefinition}\n`, "")],
      [
        "missing undef",
        source.replace("#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS", ""),
      ],
      [
        "disconnected duplicate marker",
        source.replace(
          "#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
          "auto disconnected = IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(ExactGpuClientSinkV1, on_event, receiveGpuEvent);\n      #undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
        ),
      ],
    ];
    for (const [label, mutatedSource] of invalidMacroMutations) {
      expect(
        scanCppVersionedCallbackTableIngresses(
          mutatedSource,
          "synthetic_gpu.cc",
        ),
        label,
      ).toEqual([]);
    }

    const expectNoCallbackRows = (label, mutatedSource) => {
      expect(mutatedSource, label).not.toBe(source);
      expect(
        scanCppVersionedCallbackTableIngresses(
          mutatedSource,
          "synthetic_gpu.cc",
        ),
        label,
      ).toEqual([]);
    };
    const callbackDefinition =
      "int32_t receiveGpuEvent(void*, const Event*) noexcept { return 0; }";
    const callbackGuardStart = source.indexOf(
      "#if defined(IBEX_CAPSEC_CALLBACK_TABLE_INGRESS)",
    );
    const callbackGuardEnd =
      source.indexOf("#endif", callbackGuardStart) + "#endif".length;
    const callbackGuard = source.slice(callbackGuardStart, callbackGuardEnd);
    for (const [label, mutatedSource] of gpuIncludeInventoryMutations(source)) {
      expectNoCallbackRows(label, mutatedSource);
    }
    const callbackGateGapAnchors = [
      ["before first include", '#include "hermes_runtime_internal.h"'],
      ["between local includes", '#include "../../include/exact_runtime.h"'],
      ["between local and system includes", "#include <algorithm>"],
      [
        "after canonical include block",
        "#if defined(IBEX_ENABLE_WEBGPU_BINDING)\n",
      ],
      ["before callback guard", callbackGuard],
      ["before callback definition", callbackDefinition],
      ["before callback marker", markerDefinition],
      ["before callback table", "const ExactGpuClientSinkV1 sink"],
      ["before callback table slot", "IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(\n"],
      [
        "before callback marker undef",
        "#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
      ],
    ];
    for (const gateMutation of [
      "#define IBEX_ENABLE_WEBGPU_BINDING 1",
      "#undef IBEX_ENABLE_WEBGPU_BINDING",
    ]) {
      for (const [gap, anchor] of callbackGateGapAnchors) {
        expectNoCallbackRows(
          `${gateMutation}: ${gap}`,
          insertCppDirectiveBefore(source, anchor, gateMutation),
        );
      }
      expectNoCallbackRows(
        `${gateMutation}: after protected source`,
        `${source}\n${gateMutation}`,
      );
    }
    for (const [label, hiddenDirective] of [
      [
        "comment-separated external gate define",
        "#/**/define IBEX_ENABLE_WEBGPU_BINDING 1",
      ],
      [
        "comment-separated external gate undef",
        "#/**/undef IBEX_ENABLE_WEBGPU_BINDING",
      ],
      [
        "tab-separated external gate define",
        "#\tdefine IBEX_ENABLE_WEBGPU_BINDING 1",
      ],
      [
        "tab-separated external gate undef",
        "#\tundef IBEX_ENABLE_WEBGPU_BINDING",
      ],
      [
        "LF-spliced external gate define",
        "#def\\\nine IBEX_ENABLE_WEBGPU_BINDING 1",
      ],
      [
        "LF-spliced external gate undef",
        "#und\\\nef IBEX_ENABLE_WEBGPU_BINDING",
      ],
      [
        "CRLF-spliced external gate define",
        "#def\\\r\nine IBEX_ENABLE_WEBGPU_BINDING 1",
      ],
      [
        "CRLF-spliced external gate undef",
        "#und\\\r\nef IBEX_ENABLE_WEBGPU_BINDING",
      ],
    ]) {
      expectNoCallbackRows(
        label,
        insertCppDirectiveBefore(
          source,
          "#if defined(IBEX_ENABLE_WEBGPU_BINDING)\n",
          hiddenDirective,
        ),
      );
    }
    for (const [label, mutatedSource] of [
      [
        "LF-spliced include directive",
        source.replace("#include", "#inc\\\nlude"),
      ],
      [
        "CRLF-spliced include directive",
        source.replace("#include", "#inc\\\r\nlude"),
      ],
      [
        "LF-spliced include path",
        source.replace(
          "hermes_runtime_internal.h",
          "hermes_runtime_\\\ninternal.h",
        ),
      ],
      [
        "CRLF-spliced include path",
        source.replace(
          "hermes_runtime_internal.h",
          "hermes_runtime_\\\r\ninternal.h",
        ),
      ],
      [
        "tab-separated include directive",
        source.replace("#include", "#\tinclude"),
      ],
      [
        "LF-spliced external gate spelling",
        source.replace(
          "IBEX_ENABLE_WEBGPU_BINDING",
          "IBEX_ENABLE_WEBGPU_BIND\\\nING",
        ),
      ],
      [
        "CRLF-spliced external gate spelling",
        source.replace(
          "IBEX_ENABLE_WEBGPU_BINDING",
          "IBEX_ENABLE_WEBGPU_BIND\\\r\nING",
        ),
      ],
      [
        "comment-hidden external gate spelling",
        source.replace(
          "IBEX_ENABLE_WEBGPU_BINDING",
          "IBEX_ENABLE_WEBGPU_/**/BINDING",
        ),
      ],
      [
        "tab-separated external gate directive",
        source.replace(
          "#if defined(IBEX_ENABLE_WEBGPU_BINDING)",
          "#\tif defined(IBEX_ENABLE_WEBGPU_BINDING)",
        ),
      ],
      [
        "line-comment-spliced external gate spelling",
        source.replace(
          "IBEX_ENABLE_WEBGPU_BINDING)",
          "IBEX_ENABLE_WEBGPU_BIND//\\\nING)",
        ),
      ],
      [
        "LF-spliced callback spelling",
        source.replace("receiveGpuEvent", "receiveGpu\\\nEvent"),
      ],
      [
        "CRLF-spliced callback spelling",
        source.replace("receiveGpuEvent", "receiveGpu\\\r\nEvent"),
      ],
      [
        "comment-hidden callback spelling",
        source.replace("receiveGpuEvent", "receiveGpu/**/Event"),
      ],
      [
        "tab-separated callback spelling",
        source.replace("receiveGpuEvent", "receiveGpu\tEvent"),
      ],
      [
        "LF-spliced callback marker spelling",
        source.replace(
          "IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
          "IBEX_CAPSEC_CALLBACK_TABLE_INGR\\\nESS",
        ),
      ],
    ]) {
      expectNoCallbackRows(label, mutatedSource);
    }
    expectNoCallbackRows(
      "inactive canonical callback with active alternate include",
      source.replace(
        callbackDefinition,
        `#if 0\n      ${callbackDefinition}\n#else\n#include "alternate-callback.h"\n#endif`,
      ),
    );
    const callbackTable = String.raw`const ExactGpuClientSinkV1 sink = {
        sizeof(ExactGpuClientSinkV1),
        EXACT_GPU_SERVICE_ABI_VERSION_V1,
        retainClient,
        releaseClient,
        IBEX_CAPSEC_CALLBACK_TABLE_INGRESS(
          ExactGpuClientSinkV1, on_event, receiveGpuEvent),
      };`;
    expectNoCallbackRows(
      "inactive canonical callback table with active alternate include",
      source.replace(
        callbackTable,
        `#if 0\n      ${callbackTable}\n#else\n#include "alternate-callback-table.h"\n#endif`,
      ),
    );
    for (const identifier of [
      "IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
      "receiveGpuEvent",
    ]) {
      expectNoCallbackRows(
        `${identifier}: compatible macro alias before guard`,
        source.replace(
          "#if defined(IBEX_CAPSEC_CALLBACK_TABLE_INGRESS)",
          `#define ${identifier} compatibleGpuCallback\n      #if defined(IBEX_CAPSEC_CALLBACK_TABLE_INGRESS)`,
        ),
      );
      expectNoCallbackRows(
        `${identifier}: undef/redefine after guard`,
        source.replace(
          callbackDefinition,
          `#undef ${identifier}\n      #define ${identifier} compatibleGpuCallback\n      ${callbackDefinition}`,
        ),
      );
      expectNoCallbackRows(
        `${identifier}: source alias across callback-table lifetime`,
        source.replace(
          markerDefinition,
          `auto compatibleGpuCallback = ${identifier};\n      ${markerDefinition}`,
        ),
      );
    }
    const withoutCallbackGuard = `${source.slice(
      0,
      callbackGuardStart,
    )}${source.slice(callbackGuardEnd)}`;
    expectNoCallbackRows(
      "callback guard placement after protected definition",
      withoutCallbackGuard.replace(
        callbackDefinition,
        `${callbackDefinition}\n      ${callbackGuard}`,
      ),
    );
    expectNoCallbackRows(
      "callback guard lifetime removed",
      withoutCallbackGuard,
    );
    expectNoCallbackRows(
      "conditional selection between callback guard and definition",
      source.replace(
        callbackDefinition,
        `#if SELECT_COMPATIBLE_CALLBACK\n      ${callbackDefinition}\n      #endif`,
      ),
    );
    expectNoCallbackRows(
      "include between callback guard and definition",
      source.replace(
        callbackDefinition,
        `#include "compatible-callback.h"\n      ${callbackDefinition}`,
      ),
    );
    expectNoCallbackRows(
      "digraph include between callback guard and definition",
      source.replace(
        callbackDefinition,
        `%:include "compatible-callback.h"\n      ${callbackDefinition}`,
      ),
    );
    expectNoCallbackRows(
      "pragma macro restore between callback guard and definition",
      source.replace(
        callbackDefinition,
        `_Pragma("pop_macro(\\\"receiveGpuEvent\\\")")\n      ${callbackDefinition}`,
      ),
    );
    expectNoCallbackRows(
      "wrapper between callback guard and definition",
      source.replace(
        callbackDefinition,
        `#define GPU_CALLBACK_WRAPPER(name) name\n      ${callbackDefinition}`,
      ),
    );
    for (const [label, mutatedGuard] of [
      [
        "condition trailing comment",
        callbackGuard.replace(
          "    defined(receiveGpuEvent)",
          "    defined(receiveGpuEvent) // accepted-looking guard",
        ),
      ],
      [
        "error trailing bytes",
        callbackGuard.replace(
          'preprocessor macros"',
          'preprocessor macros" trailing',
        ),
      ],
      [
        "endif trailing comment",
        callbackGuard.replace("#endif", "#endif // guard"),
      ],
      ["backslash-space splice", callbackGuard.replace("\\\n", "\\ \n")],
      ["backslash-tab splice", callbackGuard.replace("\\\n", "\\\t\n")],
      ["CRLF physical lines", callbackGuard.replaceAll("\n", "\r\n")],
      [
        "alternate directive whitespace",
        callbackGuard.replace("#if ", "# if "),
      ],
      ["digraph directive spelling", callbackGuard.replace("#if", "%:if")],
      ["trigraph directive spelling", callbackGuard.replace("#if", "??=if")],
      ["trigraph line splice", callbackGuard.replace("\\\n", "??/\n")],
    ]) {
      expectNoCallbackRows(
        `physical callback guard: ${label}`,
        source.replace(callbackGuard, mutatedGuard),
      );
    }
    for (const [label, mutatedMarker] of [
      [
        "marker trailing comment",
        markerDefinition.replace(
          "  callback",
          "  callback // accepted-looking marker",
        ),
      ],
      [
        "marker backslash-space splice",
        markerDefinition.replace("\\\n", "\\ \n"),
      ],
      [
        "marker backslash-tab splice",
        markerDefinition.replace("\\\n", "\\\t\n"),
      ],
      ["marker CRLF physical lines", markerDefinition.replaceAll("\n", "\r\n")],
      [
        "marker digraph directive",
        markerDefinition.replace("#define", "%:define"),
      ],
    ]) {
      expectNoCallbackRows(
        `physical callback marker: ${label}`,
        source.replace(markerDefinition, mutatedMarker),
      );
    }
    expectNoCallbackRows(
      "callback undef trailing comment",
      source.replace(
        "#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
        "#undef IBEX_CAPSEC_CALLBACK_TABLE_INGRESS // retained alias",
      ),
    );
    expectNoCallbackRows(
      "comment trigraph splices away callback guard line",
      source.replace(callbackGuard, `//??/\n${callbackGuard}`),
    );
    expectNoCallbackRows(
      "MSVC pragma restores callback macro after guard",
      source.replace(
        callbackDefinition,
        `__pragma(pop_macro("receiveGpuEvent"))\n      ${callbackDefinition}`,
      ),
    );
    expectNoCallbackRows(
      "outer inactive callback branch",
      `#if 0\n${source}\n#endif`,
    );
    expectNoCallbackRows(
      "outer inactive callback branch with active alternate include",
      `#if 0\n${source}\n#else\n#include "compatible-callback.h"\n#endif`,
    );
    expectNoCallbackRows(
      "nested callback conditional depth",
      `#if 1\n#if 1\n${source}\n#endif\n#endif`,
    );
    for (const directive of ["#elif 1", "#else", "#endif"]) {
      expectNoCallbackRows(
        `intervening callback ${directive}`,
        source.replace(
          callbackDefinition,
          `${directive}\n${callbackDefinition}`,
        ),
      );
    }
    expectNoCallbackRows(
      "authenticated callback branch with active alternate include",
      `#if defined(IBEX_ENABLE_WEBGPU_BINDING)\n${source}\n#else\n#include "compatible-callback.h"\n#endif`,
    );
    const authenticatedCallback = scanCppVersionedCallbackTableIngresses(
      source,
      "synthetic_gpu.cc",
    );
    expect(authenticatedCallback).toHaveLength(1);
    expect(authenticatedCallback[0].metadata.conditionalContext).toBe(
      "webgpu-enabled-if",
    );

    for (const [before, after] of [
      ["on_event, receiveGpuEvent", "release_client, receiveGpuEvent"],
      ["on_event, receiveGpuEvent", "on_event, receiveOtherEvent"],
    ]) {
      const [mutated] = scanCppVersionedCallbackTableIngresses(
        source.replace(before, after),
        "synthetic_gpu.cc",
      );
      expect(mutated?.name).not.toBe(
        "ingress:synthetic_gpu.cc:ExactGpuClientSinkV1.on_event:receiveGpuEvent",
      );
    }
  });

  test("GPU identity guards deliberately reject external preprocessor aliases", () => {
    const gpuSourcePath = path.join(
      repoRoot,
      "src/engine/hermes_runtime_gpu.cc",
    );
    const gpuSource = fs.readFileSync(gpuSourcePath, "utf8");
    expect(
      scanCppVersionedCallbackTableIngresses(
        gpuSource,
        "src/engine/hermes_runtime_gpu.cc",
      ),
    ).toHaveLength(1);
    expect(
      scanCppConstructionPrivateBridgeSurfaces(
        gpuSource,
        "src/engine/hermes_runtime_gpu.cc",
      ),
    ).toHaveLength(3);

    const extractGuards = (errorMessage) => {
      const blocks = [];
      const errorDirective = `#error "${errorMessage}"`;
      let cursor = 0;
      while (true) {
        const errorStart = gpuSource.indexOf(errorDirective, cursor);
        if (errorStart === -1) break;
        const conditionNewline = gpuSource.lastIndexOf("\n#if ", errorStart);
        const conditionStart =
          conditionNewline === -1 ? 0 : conditionNewline + 1;
        const endStart = gpuSource.indexOf("\n#endif", errorStart) + 1;
        const end = gpuSource.indexOf("\n", endStart);
        expect(endStart, errorMessage).toBeGreaterThan(0);
        expect(end, errorMessage).toBeGreaterThan(endStart);
        blocks.push(gpuSource.slice(conditionStart, end));
        cursor = end;
      }
      return blocks;
    };
    const callbackError =
      "Ibex CapSec GPU callback identifiers must not be preprocessor macros";
    const terminalError =
      "Ibex CapSec GPU terminal handlers must not be preprocessor macros";
    const callbackGuards = extractGuards(callbackError);
    const terminalGuards = extractGuards(terminalError);
    expect(callbackGuards).toHaveLength(1);
    expect(terminalGuards).toHaveLength(4);
    expect(new Set(terminalGuards).size).toBe(1);

    const compiler = process.env.CXX || "c++";
    const compileGuard = (
      guard,
      modeArguments,
      { definition = null, includeRoot = null, prelude = "" } = {},
    ) =>
      spawnSync(
        compiler,
        [
          ...modeArguments,
          "-x",
          "c++",
          "-fsyntax-only",
          "-DIBEX_ENABLE_WEBGPU_BINDING=1",
          ...(definition ? [`-D${definition}=compatibleAlternate`] : []),
          ...(includeRoot ? ["-I", includeRoot] : []),
          "-",
        ],
        {
          encoding: "utf8",
          input: `#if !defined(IBEX_ENABLE_WEBGPU_BINDING)
#error "test external WebGPU gate must be compiler-defined"
#endif
${prelude}
#if defined(IBEX_ENABLE_WEBGPU_BINDING)
${guard}
#endif
int main() { return 0; }
`,
          timeout: 30_000,
        },
      );
    const includeRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "ibex-gpu-preprocessor-probe-"),
    );
    try {
      for (const [name, contents] of [
        ["callback-control.h", "#define receiveGpuEvent compatibleAlternate\n"],
        [
          "callback-exploit.h",
          "#undef IBEX_ENABLE_WEBGPU_BINDING\n#define receiveGpuEvent compatibleAlternate\n",
        ],
        [
          "terminal-control.h",
          "#define submitGpuBridgeCall compatibleAlternate\n",
        ],
        [
          "terminal-exploit.h",
          "#undef IBEX_ENABLE_WEBGPU_BINDING\n#define submitGpuBridgeCall compatibleAlternate\n",
        ],
      ]) {
        fs.writeFileSync(path.join(includeRoot, name), contents);
      }

      for (const [mode, modeArguments] of [
        ["c++17", ["-std=c++17"]],
        ["c++17-trigraphs", ["-std=c++17", "-trigraphs"]],
        ["c++14", ["-std=c++14"]],
      ]) {
        for (const [label, guard] of [
          ["callback", callbackGuards[0]],
          ["terminal", terminalGuards[0]],
        ]) {
          const clean = compileGuard(guard, modeArguments);
          expect(
            clean.error,
            `${mode} ${label}: compiler launch`,
          ).toBeUndefined();
          expect(clean.status, `${mode} ${label}: clean guard`).toBe(0);
        }
        for (const [identifier, guard, errorMessage] of [
          [
            "IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
            callbackGuards[0],
            callbackError,
          ],
          ["receiveGpuEvent", callbackGuards[0], callbackError],
          ["submitGpuBridgeCall", terminalGuards[0], terminalError],
          ["cancelGpuBridgeCall", terminalGuards[0], terminalError],
          ["retireGpuBridgeCall", terminalGuards[0], terminalError],
        ]) {
          const result = compileGuard(guard, modeArguments, {
            definition: identifier,
          });
          expect(
            result.error,
            `${mode} ${identifier}: compiler launch`,
          ).toBeUndefined();
          expect(result.status, `${mode} ${identifier}`).not.toBe(0);
          expect(result.stderr, `${mode} ${identifier}`).toContain(
            errorMessage,
          );
          expect(
            result.stderr,
            `${mode} ${identifier}: deliberate guard diagnostic`,
          ).not.toMatch(
            /conflicting declaration|duplicate symbol|no matching function|redefinition of/u,
          );
        }

        for (const [label, guard, identifier] of [
          ["callback", callbackGuards[0], "receiveGpuEvent"],
          ["terminal", terminalGuards[0], "submitGpuBridgeCall"],
        ]) {
          const sourceGateExploit = compileGuard(guard, modeArguments, {
            prelude: `#undef IBEX_ENABLE_WEBGPU_BINDING\n#define ${identifier} compatibleAlternate`,
          });
          expect(
            sourceGateExploit.error,
            `${mode} ${label}: source gate exploit compiler launch`,
          ).toBeUndefined();
          expect(
            sourceGateExploit.status,
            `${mode} ${label}: a source undef can hide the guarded branch`,
          ).toBe(0);

          const includedControl = compileGuard(guard, modeArguments, {
            includeRoot,
            prelude: `#include "${label}-control.h"`,
          });
          expect(
            includedControl.error,
            `${mode} ${label}: included control compiler launch`,
          ).toBeUndefined();
          expect(
            includedControl.status,
            `${mode} ${label}: included alias control`,
          ).not.toBe(0);
          expect(
            includedControl.stderr,
            `${mode} ${label}: included alias diagnostic`,
          ).toContain(label === "callback" ? callbackError : terminalError);

          const includedExploit = compileGuard(guard, modeArguments, {
            includeRoot,
            prelude: `#include "${label}-exploit.h"`,
          });
          expect(
            includedExploit.error,
            `${mode} ${label}: included exploit compiler launch`,
          ).toBeUndefined();
          expect(
            includedExploit.status,
            `${mode} ${label}: included gate undef can hide the guarded branch`,
          ).toBe(0);
        }
      }
    } finally {
      fs.rmSync(includeRoot, { force: true, recursive: true });
    }
  });

  test("native environment enumeration exposes exact platform alternatives", () => {
    const source = `
      void populateDiagnosticProcessEnvironment() {
      #if defined(_WIN32)
        GetEnvironmentStringsW();
      #else
      #if defined(__APPLE__)
        _NSGetEnviron();
      #else
        auto envp = ::environ;
      #endif
      #endif
      }
      auto getAllEnvFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactGetAllEnv"), 0,
        [](facebook::jsi::Runtime&, const auto&, const auto*, size_t) {
          populateDiagnosticProcessEnvironment();
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

    const windowsCrlfProfiles = scanHermesEvaluatorIdentityProfiles({
      ...inputs,
      windowsInstallerText: inputs.windowsInstallerText.replaceAll(
        "\n",
        "\r\n",
      ),
      windowsSourceBuildText: inputs.windowsSourceBuildText.replaceAll(
        "\n",
        "\r\n",
      ),
    });
    expect(windowsCrlfProfiles).toEqual(profiles);

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
        hermesVersionText: inputs.hermesVersionText.replace(
          "2399d266ed06c2a907f1ceb2606c0958a293751781f23774a292c438779c3285",
          "0399d266ed06c2a907f1ceb2606c0958a293751781f23774a292c438779c3285",
        ),
      },
      {
        ...inputs,
        hermesVersionText: inputs.hermesVersionText.replace(
          "46fc1bfcb0a0aa2c79a81d7804105c88de7d2936fce31ca14aa4ba0e847869ee",
          "06fc1bfcb0a0aa2c79a81d7804105c88de7d2936fce31ca14aa4ba0e847869ee",
        ),
      },
      {
        ...inputs,
        windowsInstallerText: inputs.windowsInstallerText.replace(
          '"expo/ibex"',
          '"example/reviewed-fork"',
        ),
      },
      {
        ...inputs,
        windowsInstallerText: inputs.windowsInstallerText.replace(
          "c6d2ba6bba442b44ce4f1d5c0e7eb2c9d3fcafe24765464e3a01607c0ccafadb4b028a4cb502e6779c7d0bf3c11d8e591d8a6150cbf9137aee70a2fe62371f74",
          "06d2ba6bba442b44ce4f1d5c0e7eb2c9d3fcafe24765464e3a01607c0ccafadb4b028a4cb502e6779c7d0bf3c11d8e591d8a6150cbf9137aee70a2fe62371f74",
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
    expect(
      rows.map((row) => [
        row.name,
        row.metadata.publicReadAccessSourceProven,
        row.metadata.tamingKind,
        row.metadata.valueShape,
      ]),
    ).toEqual([
      ["global:AsyncFunction", true, "constructor", "callable"],
      ["global:Function", true, "constructor", "callable"],
      ["global:GeneratorFunction", true, "constructor", "callable"],
      ["global:eval", true, "evaluator", "callable"],
    ]);

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
    expect(() =>
      scanLockdownEvaluatorSurfaces(
        source.replace(
          "makeTamed('eval');",
          "makeTamed('Function'); makeTamed('eval');",
        ),
        "runtime.cc",
        profiles,
      ),
    ).toThrow(/Function has conflicting taming shapes/u);

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
          if (record.kind === 'cjs' && typeof record.source === 'string') {
            return record.source;
          }
          if (principal.kind === 'root') return kind;
          if (row.definingPrincipal.kind === 'package') return kind;
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

    const publicRust = scanRustLoaderSurfaces(
      String.raw`
        fn output_has_esm_module_syntax() {}
        pub fn transpile_module_to_cjs() {}
      `,
      "transpile.rs",
      { publicOnly: true },
    );
    expect(publicRust.map((row) => row.name)).toEqual([
      "function:rust:transpile_module_to_cjs",
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
        "route:resolution:rust:resolve_meta_authenticated",
        "route:resolution:rust:open_resolver_boundary",
        "route:resolution:rust:canonicalize",
        "route:resolution:rust:read_link",
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
    for (const category of ["cache", "load", "resolution", "transform"]) {
      expect(rows.map((row) => row.name)).toContain(
        `route:${category}:rust:walk_transpile_tool_directory`,
      );
      for (const falsePositive of [
        `operation:${category}:from_raw_fd`,
        `operation:${category}:last_os_error`,
        `route:${category}:rust:digest_file`,
        `route:${category}:rust:directory_names`,
        `route:${category}:rust:stamp`,
        `route:${category}:rust:walk`,
      ]) {
        expect(rows.some((row) => row.name === falsePositive)).toBe(false);
      }
    }
    for (const category of ["cache", "load", "transform"]) {
      expect(
        rows.some((row) => row.name === `operation:${category}:read_link`),
      ).toBe(false);
    }
    for (const category of ["cache", "load", "subprocess", "transform"]) {
      for (const authenticatedResolverOnly of [
        "authenticated_module_resolve_options",
        "authenticated_resolver_base_dir",
        "bounded_unix_parent",
        "bounded_unix_read_link",
        "bounded_unix_symlink_metadata",
        "boundary_root",
        "canonicalize",
        "duplicate_resolver_fd",
        "file_system",
        "inputs",
        "lexical_absolute_path_for_resolver",
        "manifest_input",
        "metadata",
        "module_resolve_options",
        "new",
        "normalize_in_boundary",
        "normalized",
        "open_resolver_boundary",
        "parse_manifest",
        "read",
        "read_link",
        "read_to_string",
        "resolve_bounded_unix_path",
        "resolve_builtin_meta",
        "resolve_direct_file_meta_authenticated",
        "resolve_meta_authenticated",
        "resolve_meta_from_authenticated_bound_package",
        "resolver_boundary_refusal",
        "resolver_canonical_path",
        "resolver_component_cstring",
        "resolver_fstat",
        "resolver_fstatat_nofollow",
        "resolver_manifest_not_found",
        "resolver_metadata_from_stat",
        "resolver_open_directory_at",
        "resolver_read_link_at",
        "resolver_relative_components",
        "resolver_stat_is_dir",
        "resolver_stat_is_symlink",
        "symlink_metadata",
        "uncaptured_package_manifest_probes",
      ]) {
        expect(
          rows.some(
            (row) =>
              row.name ===
              `route:${category}:rust:${authenticatedResolverOnly}`,
          ),
          `${category}:${authenticatedResolverOnly}`,
        ).toBe(false);
      }
    }
    expect(rows.map((row) => row.name)).toContain(
      "route:resolution:rust:resolve_builtin_meta",
    );
    expect(rows.some((row) => row.name === "transform-engine:from_value")).toBe(
      false,
    );
    expect(rows.some((row) => row.name.endsWith(":rust:drop"))).toBe(false);
    for (const category of ["cache", "load", "resolution", "transform"]) {
      for (const accessor of [
        "cache_tag",
        "legacy_runtime_transform",
        "runtime_transform",
        "selected_engine_cache_tag",
        "transpile_source_to_cjs",
      ]) {
        expect(
          rows.map((row) => row.name),
          `${category}:${accessor}`,
        ).toContain(`route:${category}:rust:${accessor}`);
      }
    }
    expect(
      rows.find((row) => row.name === "route:load:rust:transpile_module")
        .metadata.calleeDefinitions,
    ).toEqual(
      expect.arrayContaining([
        "module_loader::CapturedModuleLoaderEnvironment::legacy_runtime_transform",
        "module_loader::CapturedModuleLoaderEnvironment::runtime_transform",
        "transpile::transpile_source_to_cjs",
      ]),
    );
    expect(
      rows.find(
        (row) => row.name === "route:cache:rust:selected_engine_cache_tag",
      ).metadata.calleeDefinitions,
    ).toEqual(
      expect.arrayContaining([
        "transpile::TransformEngine::cache_tag",
        "transpile::selected_transform_engine",
      ]),
    );
    expect(
      rows.find((row) => row.name === "route:resolution:rust:metadata").metadata
        .calleeDefinitions,
    ).toEqual(
      expect.arrayContaining([
        "module_loader::BoundedResolverFileSystem::manifest_input",
        "module_loader::BoundedResolverFileSystem::normalized",
        "module_loader::resolve_bounded_unix_path",
      ]),
    );
    expect(
      rows.find((row) => row.name === "route:resolution:rust:new").metadata
        .definitions,
    ).toEqual(["module_loader::AuthenticatedResolverInputs::new"]);
    for (const callback of [
      "canonicalize",
      "metadata",
      "read",
      "read_link",
      "read_to_string",
      "symlink_metadata",
    ]) {
      expect(
        rows.find((row) => row.name === `route:resolution:rust:${callback}`)
          .metadata.definitions,
        callback,
      ).toEqual([
        `module_loader::BoundedResolverFileSystem as ResolverFileSystem::${callback}`,
      ]);
    }
    expect(
      rows.find((row) => row.name === "route:resolution:rust:manifest_input")
        .metadata.definitions,
    ).toEqual([
      "module_loader::AuthenticatedResolverInputs::manifest_input",
      "module_loader::BoundedResolverFileSystem::manifest_input",
    ]);
    expect(
      rows.find((row) => row.name === "route:resolution:rust:resolver_fstat")
        .metadata.targetVariant,
    ).toBe("posix");
    expect(
      rows.find((row) => row.name === "route:resolution:rust:metadata").metadata
        .branches,
    ).toEqual([
      {
        id: "descriptor-relative-posix",
        implementationDisposition: "concrete",
        targetVariant: "posix",
      },
      {
        id: "windows-unsupported",
        implementationDisposition: "unsupported-stub",
        targetVariant: "windows",
      },
    ]);
    expect(
      rows.find(
        (row) =>
          row.name === "route:resolution:rust:authenticated_resolver_base_dir",
      ).metadata.calleeDefinitions,
    ).toEqual(
      expect.arrayContaining([
        "module_loader::BoundedResolverFileSystem as ResolverFileSystem::canonicalize",
        "module_loader::BoundedResolverFileSystem as ResolverFileSystem::metadata",
      ]),
    );
    expect(
      rows.find(
        (row) => row.name === "route:cache:rust:walk_transpile_tool_directory",
      ).metadata.calleeDefinitions,
    ).toContain(
      "module_loader::capture_transpile_tool_directory::walk_transpile_tool_directory",
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
    expect(
      rows.find((row) => row.name === "external-calls:resolution").sourceRefs,
    ).toContain(
      "src/module_loader/mod.rs#duplicate_resolver_fd:external:qualified:libc::fcntl:count-1",
    );
    expect(
      rows.find((row) => row.name === "operation:resolution:read").metadata
        .qualifiedPaths,
    ).toEqual(["qualified:std::fs::read"]);
    expect(
      rows.find((row) => row.name === "operation:resolution:metadata").metadata
        .qualifiedPaths,
    ).toEqual([
      "method:DirEntry:metadata",
      "method:File:metadata",
      "qualified:libc::fstat",
      "qualified:libc::fstatat",
      "qualified:std::fs::metadata",
    ]);
    expect(
      rows.find((row) => row.name === "operation:resolution:open").metadata
        .qualifiedPaths,
    ).toEqual(["qualified:libc::open", "qualified:libc::openat"]);
    expect(
      rows.find((row) => row.name === "operation:resolution:open").metadata
        .targetVariant,
    ).toBe("posix");
    expect(
      rows.find((row) => row.name === "operation:resolution:read_link")
        .sourceRefs,
    ).toContain(
      "src/module_loader/mod.rs#resolver_read_link_at:operation:qualified:libc::readlinkat",
    );
    expect(
      rows.find((row) => row.name === "operation:subprocess:status").metadata
        .qualifiedPaths,
    ).toEqual(["method:Command:status"]);

    const receiverFixtureSource = `${fs
      .readFileSync(path.join(repoRoot, "src/module_loader/mod.rs"), "utf8")
      .replace(
        "fn normalize_import_target(base: &Path, target: PathBuf) -> Option<PathBuf> {",
        "fn normalize_import_target(base: &Path, target: PathBuf) -> Option<PathBuf> {\n    scanner_receiver_fixture();",
      )
      .replace(
        ') -> Result<()> {\n    let private_environment = unique_tmp_path(&output.with_file_name("transpile-environment"));',
        ') -> Result<()> {\n    runner_name.status();\n    let private_environment = unique_tmp_path(&output.with_file_name("transpile-environment"));',
      )}
fn scanner_receiver_fixture() {
    scanner_receiver_positive();
    scanner_receiver_negative();
    scanner_receiver_ambiguous();
}
fn scanner_receiver_positive(
    entry: DirEntry,
    path: &Path,
    path_buf: PathBuf,
) {
    let mut options = OpenOptions::new();
    options.read(true);
    let file = options.open(path);
    file.read();
    file.metadata();
    entry.metadata();
    path_buf.as_path().canonicalize();
    path_buf.canonicalize();
    let command = Command::new(path);
    command.status();
}
fn scanner_receiver_negative(
    options: OpenOptions,
    lock: RwLock<()>,
    other: ArbitraryReceiver,
) {
    options.read();
    lock.read();
    other.read();
    other.metadata();
    other.canonicalize();
    other.status();
}
fn scanner_receiver_ambiguous(fd_one: OwnedFd, fd_two: OwnedFd, lock: RwLock<()>) {
    let ambiguous = choose(OpenOptions::new(), File::from(fd_one));
    ambiguous.read();
    let tuple = (File::from(fd_two), lock);
    tuple.metadata();
    let wrapped = Some(File::from(fd_two));
    wrapped.read();
    wrapped.metadata();
    let wrapped_postfix = File::from(fd_two).into_wrapper();
    wrapped_postfix.read();
    wrapped_postfix.metadata();
    let wrapped_struct = Wrapper { inner: File::from(fd_two) };
    wrapped_struct.read();
    wrapped_struct.metadata();
}
`;
    expect(
      receiverFixtureSource.match(/scanner_receiver_fixture\(\);/gu),
    ).toHaveLength(1);
    expect(
      receiverFixtureSource.match(/runner_name\.status\(\);/gu),
    ).toHaveLength(1);
    const receiverRows = scanRustLoaderRoutes([
      {
        sourcePath: "src/module_loader/mod.rs",
        text: receiverFixtureSource,
      },
      {
        sourcePath: "src/module_loader/transpile.rs",
        text: fs.readFileSync(
          path.join(repoRoot, "src/module_loader/transpile.rs"),
          "utf8",
        ),
      },
    ]);
    const receiverOperationRefs = (operation) =>
      receiverRows
        .find((row) => row.name === `operation:resolution:${operation}`)
        .sourceRefs.filter((sourceRef) =>
          sourceRef.includes("scanner_receiver"),
        );
    expect(receiverOperationRefs("read")).toEqual([
      "src/module_loader/mod.rs#scanner_receiver_positive:operation:method:File:read",
    ]);
    expect(receiverOperationRefs("metadata")).toEqual([
      "src/module_loader/mod.rs#scanner_receiver_positive:operation:method:DirEntry:metadata",
      "src/module_loader/mod.rs#scanner_receiver_positive:operation:method:File:metadata",
    ]);
    expect(receiverOperationRefs("canonicalize")).toEqual([
      "src/module_loader/mod.rs#scanner_receiver_positive:operation:method:Path:canonicalize",
      "src/module_loader/mod.rs#scanner_receiver_positive:operation:method:PathBuf:canonicalize",
    ]);
    expect(receiverOperationRefs("status")).toEqual([
      "src/module_loader/mod.rs#scanner_receiver_positive:operation:method:Command:status",
    ]);
    const subprocessStatus = receiverRows.find(
      (row) => row.name === "operation:subprocess:status",
    );
    expect(subprocessStatus.metadata.qualifiedPaths).toEqual([
      "method:Command:status",
    ]);
    expect(subprocessStatus.sourceRefs).toEqual([
      "src/module_loader/mod.rs#run_transpile_subprocess:operation:method:Command:status",
    ]);

    const mutated = scanRustLoaderRoutes([
      {
        sourcePath: "src/module_loader/mod.rs",
        text: fs
          .readFileSync(path.join(repoRoot, "src/module_loader/mod.rs"), "utf8")
          .replace(
            'std::fs::write(\n            stage.join("manifest.json"),',
            'std::fs::future_authority_call(\n            stage.join("manifest.json"),',
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
    const ownerDecoy = scanRustLoaderRoutes([
      {
        sourcePath: "src/module_loader/mod.rs",
        text: `${fs.readFileSync(
          path.join(repoRoot, "src/module_loader/mod.rs"),
          "utf8",
        )}\nstruct UnrelatedResolver;\nimpl UnrelatedResolver { fn metadata(&self) {} fn normalized(&self) {} }\n`,
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
      ownerDecoy.find((row) => row.name === "route:resolution:rust:metadata")
        .metadata.definitions,
    ).toEqual([
      "module_loader::BoundedResolverFileSystem as ResolverFileSystem::metadata",
    ]);
    expect(
      ownerDecoy.some((row) =>
        row.metadata?.definitions?.some((definition) =>
          definition.includes("UnrelatedResolver"),
        ),
      ),
    ).toBe(false);
    expect(() =>
      scanRustLoaderRoutes([
        { sourcePath: "empty.rs", text: "fn resolve() {}" },
      ]),
    ).toThrow(/Rust loader resolution root .* expected one definition/);
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
            use std::process::Command;
            const PRIMARY: &str = "IBEX_MODE";
            fn runtime_env(ibex_name: &str, legacy_name: &str) {
              std::env::var(ibex_name);
              std::env::var(legacy_name);
            }
            fn env_flag_enabled(name: &str) { std::env::var(name); }
            fn timeout_from_env(name: &str) { std::env::var(name); }
            fn read(name: &str) {
              std::env::var(PRIMARY);
              std::env::var(name);
              runtime_env("IBEX_WATCH", "EXACT_WATCH");
            }
            fn child(dynamic_name: &str) {
              let mut command = Command::new("runner");
              command.env("IBEX_CHILD_EXPLICIT", "1");
              command.env(dynamic_name, "1");
              command.env_remove("IBEX_CHILD_REMOVED");
              command.env_clear();
              let _qualified = std::process::Command::new("other");
            }
          `,
        },
        {
          sourcePath: "src/host/abi.rs",
          text: String.raw`
            fn capture_process_ipc_bootstrap() {
              std::env::var("EXACT_IPC_FD");
              std::env::var("EXACT_IPC_SERIALIZATION");
            }
          `,
        },
      ],
      native: [
        {
          sourcePath: "native_android_networking.cc",
          text: String.raw`
            extern char** environ;
            void init() {
              char* copied = nullptr;
              size_t copiedLength = 0;
              _dupenv_s(&copied, &copiedLength, dynamicEnvironmentName);
              setenv("EXACT_ANDROID_FILES_DIR", files, 1);
              auto shell = getenvString("ComSpec");
              auto apple = _NSGetEnviron();
              auto posix = ::environ;
              auto bare = environ;
              consume(environ);
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
        {
          sourcePath: "hermes_runtime_internal.h",
          text: String.raw`
            bool env_flag_enabled(const char* env_name);
            inline void observerDelay() {
              const char* value = std::getenv(
                  "IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS");
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
        "env:<dynamic>:rust:Command::default_env",
        "env:<dynamic>:rust:Command::env",
        "env:<dynamic>:rust:Command::env_clear",
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
        "env:IBEX_CHILD_EXPLICIT",
        "env:IBEX_CHILD_REMOVED",
        "env:IBEX_REFLECT_SET",
        "env:IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS",
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
    for (const name of ["env:IBEX_CHILD_EXPLICIT", "env:IBEX_CHILD_REMOVED"]) {
      expect(rows.find((row) => row.name === name).metadata.contexts).toEqual([
        "spawn-child-env",
      ]);
    }
    expect(
      rows.find((row) => row.name === "env:<dynamic>:rust:Command::default_env")
        .metadata.occurrences,
    ).toHaveLength(2);
    for (const name of ["env:EXACT_IPC_FD", "env:EXACT_IPC_SERIALIZATION"]) {
      expect(rows.find((row) => row.name === name).metadata.contexts).toEqual([
        "startup-input",
      ]);
    }
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
    ).toEqual([
      "::environ",
      "GetEnvironmentStringsW",
      "_NSGetEnviron",
      "_dupenv_s",
      "environ",
    ]);
    expect(
      rows.find((row) => row.name === "env:<dynamic>:cpp:environ").metadata
        .occurrences,
    ).toHaveLength(2);
    expect(
      rows.some((row) => row.name === "env:<dynamic>:cpp:env_flag_enabled"),
    ).toBe(false);
    expect(
      rows.some((row) =>
        new Set([
          "env:<dynamic>:rust:env_flag_enabled",
          "env:<dynamic>:rust:runtime_env",
          "env:<dynamic>:rust:timeout_from_env",
        ]).has(row.name),
      ),
    ).toBe(false);
    for (const row of rows) {
      expect(row.metadata.occurrences.length, row.name).toBeGreaterThan(0);
      expect(
        [
          ...new Set(
            row.metadata.occurrences.map((occurrence) => occurrence.sourceRef),
          ),
        ].sort(),
        row.name,
      ).toEqual(row.sourceRefs);
    }
  });

  test("private session worker bootstrap retains both implementation constants", () => {
    const row = scanPrivateSessionWorkerBootstrap(String.raw`
      pub(crate) const WORKER_BOOTSTRAP_ARG: &str = "__ibex-session-worker-v1";
      pub(crate) const WORKER_BOOTSTRAP_SURFACE_ID: &str =
          "private:ibex:session-worker-bootstrap:v1";
    `);
    expect(row).toMatchObject({
      kind: "startup",
      name: "private:ibex:session-worker-bootstrap:v1",
      metadata: {
        argument: "__ibex-session-worker-v1",
        evidenceType: "private-session-worker-bootstrap",
        javascriptReachability: "none",
        visibility: "private-supervisor-worker",
      },
    });
    expect(row.sourceRefs).toEqual([
      "src/bin/ibex/session_worker.rs#WORKER_BOOTSTRAP_ARG",
      "src/bin/ibex/session_worker.rs#WORKER_BOOTSTRAP_SURFACE_ID",
    ]);
    for (const [from, to] of [
      ["__ibex-session-worker-v1", "--public-worker"],
      [
        "private:ibex:session-worker-bootstrap:v1",
        "private:ibex:session-worker-bootstrap:v2",
      ],
    ]) {
      expect(() =>
        scanPrivateSessionWorkerBootstrap(
          String.raw`
            pub(crate) const WORKER_BOOTSTRAP_ARG: &str = "__ibex-session-worker-v1";
            pub(crate) const WORKER_BOOTSTRAP_SURFACE_ID: &str = "private:ibex:session-worker-bootstrap:v1";
          `.replace(from, to),
        ),
      ).toThrow(/private worker bootstrap/u);
    }
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
      "src/bin/ibex/engine/capsec_builtin_effects_output_batch.test.rs",
      "src/bin/ibex/engine/capsec_builtin_noncap_closed_output_batch.test.rs",
      "src/bin/ibex/engine/capsec_closed_control_output_batch.test.rs",
      "src/bin/ibex/engine/capsec_global_callable_batch.test.rs",
      "src/bin/ibex/engine/capsec_output_shape_sweep_batch.test.rs",
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

  test("fixed callback control boundaries are explicit and fail closed", () => {
    const definition = {
      kind: "callback",
      name: "test-control",
      callbackOutputBoundary: "none",
      evidence: [
        {
          type: "javascript-function",
          file: "implementation.js",
          symbol: "load",
          role: "implementation",
        },
      ],
    };
    expect(fixedRuntimeSurfaceInventory([definition])).toEqual([
      {
        kind: "callback",
        name: "test-control",
        observedKey: "callback:test-control",
        sourceRefs: ["implementation.js#load"],
        metadata: { callbackOutputBoundary: "none" },
      },
    ]);

    expect(() =>
      fixedRuntimeSurfaceInventory([
        { ...definition, callbackOutputBoundary: "payload" },
      ]),
    ).toThrow(/invalid callbackOutputBoundary "payload"/);
    expect(() =>
      fixedRuntimeSurfaceInventory([{ ...definition, kind: "loader" }]),
    ).toThrow(/invalid callbackOutputBoundary "none"/);

    const outputContract = {
      direction: "native-to-javascript",
      returnVariant: "success",
      role: "payload",
      selector: "callback:resolve/0",
      sourceRefs: ["implementation.js#load"],
      valueShape: "string",
    };
    const outputDefinition = {
      kind: "callback",
      name: "test-output",
      callbackOutputContracts: [outputContract],
      evidence: definition.evidence,
    };
    expect(fixedRuntimeSurfaceInventory([outputDefinition])).toEqual([
      {
        kind: "callback",
        name: "test-output",
        observedKey: "callback:test-output",
        sourceRefs: ["implementation.js#load"],
        metadata: {
          callbackOutputContractSchema: CALLBACK_OUTPUT_CONTRACT_SCHEMA,
          callbackOutputContracts: [outputContract],
        },
      },
    ]);

    for (const callbackOutputContracts of [
      [{ ...outputContract, selector: "callback:resolve" }],
      [{ ...outputContract, valueShape: "no-arguments" }],
      [{ ...outputContract, sourceRefs: ["implementation.js#missing"] }],
      [outputContract, structuredClone(outputContract)],
      [{ ...outputContract, unexpected: true }],
    ]) {
      expect(() =>
        fixedRuntimeSurfaceInventory([
          { ...outputDefinition, callbackOutputContracts },
        ]),
      ).toThrow(
        /callback output|expected exact keys|unreviewed fields|validated fixed evidence/,
      );
    }
    expect(() =>
      fixedRuntimeSurfaceInventory([{ ...outputDefinition, kind: "loader" }]),
    ).toThrow(/callbackOutputContracts require callback kind/);
    expect(() =>
      fixedRuntimeSurfaceInventory([
        { ...outputDefinition, callbackOutputBoundary: "none" },
      ]),
    ).toThrow(/mutually exclusive/);
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
      rows
        .filter((row) => row.metadata?.callbackOutputBoundary === "none")
        .map((row) => row.name),
    ).toEqual([
      "microtask-drain",
      "native-principal-restore",
      "next-tick-drain",
      "queue-drain",
      "queue-enqueue",
      "timer-invoke",
      "watchdog-heartbeat",
      "websocket-context-release",
      "worklet-scheduled-drain",
    ]);
    expect(
      rows
        .filter(
          (row) =>
            row.metadata?.callbackOutputContractSchema ===
            CALLBACK_OUTPUT_CONTRACT_SCHEMA,
        )
        .map((row) => row.name),
    ).toEqual([
      "android-animation-frame",
      "android-platform-event",
      "dns-async-delivery",
      "exact-host-call-async-resolve",
      "fetch-delivery",
      "filesystem-async-delivery",
      "host-call-async-resolve",
      "http-wait-delivery",
      "http-writable-delivery",
      "ios-dispatch",
      "ios-dispatch-debug-context",
      "ios-module-dispatch",
      "ios-module-sync",
      "signal-delivery",
      "websocket-binary-delivery",
      "websocket-bytes-sent-delivery",
      "websocket-close-delivery",
      "websocket-error-delivery",
      "websocket-open-delivery",
      "websocket-text-delivery",
      "worklet-measure",
    ]);
    expect(
      rows
        .filter((row) => row.kind === "callback")
        .every(
          (row) =>
            row.metadata?.callbackOutputBoundary === "none" ||
            row.metadata?.callbackOutputContractSchema ===
              CALLBACK_OUTPUT_CONTRACT_SCHEMA,
        ),
    ).toBe(true);
    expect(
      rows
        .flatMap((row) => row.metadata?.callbackOutputContracts ?? [])
        .some((contract) => contract.valueShape === "no-arguments"),
    ).toBe(false);
    expect(
      rows.find((row) => row.name === "signal-delivery")?.metadata
        ?.callbackOutputContracts,
    ).toEqual([
      {
        direction: "native-to-javascript",
        returnVariant: "signal-name",
        role: "payload",
        selector: "callback:process-listener/0",
        sourceRefs: [
          "src/engine/bootstrap/stream-enhance.js#__exactDispatchPendingSignals",
        ],
        valueShape: "string",
      },
    ]);
    expect(
      rows
        .find((row) => row.name === "android-platform-event")
        ?.metadata?.callbackOutputContracts.every((contract) =>
          contract.sourceRefs.includes(
            "src/engine/hermes_runtime_android.cc#dispatchAndroidPlatformEvents",
          ),
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
    expect(
      rows.find(
        (row) =>
          row.observedKey ===
          "startup:supervisor-history.authenticated-project-scope",
      ),
    ).toEqual({
      kind: "startup",
      name: "supervisor-history.authenticated-project-scope",
      observedKey: "startup:supervisor-history.authenticated-project-scope",
      sourceRefs: [
        "src/bin/ibex/history.rs#derive_authenticated_project_history_scope",
      ],
    });
    expect(
      rows.find(
        (row) =>
          row.observedKey ===
          "startup:supervisor-history.global-platform-data-root",
      )?.sourceRefs,
    ).toEqual([
      "src/bin/ibex/history.rs#capture_global_history_platform_data_root",
    ]);
  });

  test("supervisor history fixed refs are exact structural Rust functions", () => {
    const file = "src/bin/ibex/history.rs";
    const candidates = scanFixedRuntimeEvidenceCandidates(
      fs.readFileSync(path.join(repoRoot, file), "utf8"),
      file,
    );
    const symbols = [
      "acquire_history_sidecar_lock",
      "append_history_journal",
      "capture_global_history_platform_data_root",
      "capture_project_history_platform_data_root",
      "compact_history_journal_locked",
      "derive_authenticated_project_history_scope",
      "legacy_history_present",
      "load_or_create_history_user_key",
      "open_history_store",
      "recover_history_journal_locked",
    ];
    for (const symbol of symbols) {
      expect(
        candidates.find(
          (row) =>
            row.type === "rust-function" &&
            row.sourceRef === `${file}#${symbol}`,
        ),
        symbol,
      ).toMatchObject({ occurrenceCount: 1 });
    }
  });

  test("every live fixed reference joins one exact structural definition", () => {
    const rows = fixedRuntimeSurfaceInventory();
    expect(rows).toHaveLength(92);
    expect(() => validateFixedRuntimeSurfaceRefs(repoRoot, rows)).not.toThrow();
  });

  test("live lifecycle discovery preserves the explicit installGlobals route", () => {
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
          row.name === "install-route:installGlobals:installOsInfoGlobals",
      )?.metadata,
    ).toMatchObject({
      caller: "installGlobals",
      installer: "installOsInfoGlobals",
      occurrenceCount: 1,
    });
  });

  test("projects the exact reviewed dns/promises callable domain onto its public carrier", () => {
    const rows = scanReviewedDnsPromisesProjection(
      fs.readFileSync(
        path.join(repoRoot, "src/builtins/dns-promises.js"),
        "utf8",
      ),
      fs.readFileSync(path.join(repoRoot, "src/builtins/dns.js"), "utf8"),
    );
    const topOperations = [
      "Resolver",
      "getDefaultResultOrder",
      "getServers",
      "lookup",
      "lookupService",
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
      "setDefaultResultOrder",
      "setServers",
    ];
    const resolverOperations = [
      "_handle.cancel",
      "_handle.getServers",
      "_handle.setServers",
      "cancel",
      "getServers",
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
      "setLocalAddress",
      "setServers",
    ];
    expect(rows.map((row) => row.name)).toEqual(
      [
        ...topOperations.map(
          (name) => `export:node_dns_promises:${name}`,
        ),
        ...resolverOperations.map(
          (name) => `export:node_dns_promises:Resolver.${name}`,
        ),
      ].sort(),
    );
    expect(rows).toHaveLength(42);
    expect(rows.some((row) => row.name.endsWith(".constructor"))).toBe(false);
    expect(
      rows
        .filter((row) => row.metadata.inheritedShape === true)
        .map((row) => row.metadata.exportName),
    ).toEqual([
      "Resolver.cancel",
      "Resolver.getServers",
      "Resolver.setLocalAddress",
      "Resolver.setServers",
    ]);
    expect(
      rows.every(
        (row) =>
          row.sourceRefs.length >= 2 &&
          row.metadata.sourceKey === "node_dns_promises" &&
          row.metadata.importReachability === "public" &&
          row.metadata.valueShape === "callable" &&
          JSON.stringify(row.metadata.publicModuleSpecifiers) ===
            JSON.stringify(["dns/promises", "node:dns/promises"]) &&
          row.metadata.crossSourceExportProjection?.providerSourceKey ===
            "node_dns" &&
          row.metadata.dnsPromiseExportShapeReviewId ===
            REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID &&
          row.metadata.enforcementRouteEvidence.terminals.length === 0 &&
          row.metadata.enforcementRouteEvidence.paths.length === 0 &&
          row.metadata.enforcementRouteEvidence.ambiguousCallees.length === 1,
      ),
    ).toBe(true);
    for (const name of ["cancel", "getServers", "setServers"]) {
      expect(
        rows.find(
          (row) =>
            row.metadata.exportName === `Resolver._handle.${name}`,
        )?.sourceRefs,
      ).toEqual(
        expect.arrayContaining([
          "src/builtins/dns.js#PromiseResolver:Resolver.call:this:options",
          `src/builtins/dns.js#Resolver:instance:_handle.${name}`,
        ]),
      );
    }
  });

  test("binds the dns/promises projection to a whitespace-stable full-AST review", () => {
    const carrier = fs.readFileSync(
      path.join(repoRoot, "src/builtins/dns-promises.js"),
      "utf8",
    );
    const provider = fs.readFileSync(
      path.join(repoRoot, "src/builtins/dns.js"),
      "utf8",
    );
    expect(deriveDnsPromiseExportShapeReviewId(carrier, provider)).toBe(
      REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID,
    );
    expect(
      deriveDnsPromiseExportShapeReviewId(
        `/* review-ignored comment */\n${carrier}\n`,
        `${provider}\n// review-ignored comment\n`,
      ),
    ).toBe(REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID);
    for (const [label, changedCarrier, changedProvider] of [
      [
        "indirect carrier require",
        carrier.replace(
          "module.exports = promises;",
          '(0, require)("dns").promises.lookup = function() {};\nmodule.exports = promises;',
        ),
        provider,
      ],
      [
        "dynamic provider export",
        carrier,
        provider.replace(
          "module.exports.default = module.exports;",
          'module.exports["prom" + "ises"].lookup = function() {};\nmodule.exports.default = module.exports;',
        ),
      ],
      [
        "nested prototype mutation",
        carrier,
        provider.replace(
          "PromiseResolver.prototype.constructor = PromiseResolver;",
          "PromiseResolver.prototype.constructor = PromiseResolver;\nPromiseResolver.prototype.__proto__.extra = function() {};",
        ),
      ],
    ]) {
      expect(
        deriveDnsPromiseExportShapeReviewId(changedCarrier, changedProvider),
        label,
      ).not.toBe(REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID);
    }
  });

  for (const [label, carrierMutation, providerMutation, expected] of [
    [
      "computed carrier require",
      ["require('dns')", "require(String('dns'))"],
      null,
      /exact require\("dns"\)/u,
    ],
    [
      "different forwarded member",
      ["var promises = dns.promises;", "var promises = dns.promisez;"],
      null,
      /exact dns\.promises/u,
    ],
    [
      "different carrier export",
      ["module.exports = promises;", "module.exports = dns;"],
      null,
      /module\.exports must be the promises binding/u,
    ],
    [
      "local carrier overwrite",
      [
        "module.exports = promises;",
        "promises.lookup = function() {};\nmodule.exports = promises;",
      ],
      null,
      /one exact promises\[codes\[i\]\] copy/u,
    ],
    [
      "carrier require reacquisition",
      [
        "module.exports = promises;",
        'require("dns").promises.lookup = function() {};\nmodule.exports = promises;',
      ],
      null,
      /exactly one require call/u,
    ],
    [
      "indirect carrier require reacquisition",
      [
        "module.exports = promises;",
        '(0, require)("dns").promises.lookup = function() {};\nmodule.exports = promises;',
      ],
      null,
      /export-shape AST review drifted/u,
    ],
    [
      "missing provider operation",
      null,
      ["  resolveMx: _promisify1(resolveMx),\n", ""],
      /promises operation domain drift/u,
    ],
    [
      "opaque provider factory result",
      null,
      ["resolveMx: _promisify1(resolveMx)", "resolveMx: resolveMx()"],
      /promises\.resolveMx is not source-proven callable/u,
    ],
    [
      "different promise Resolver",
      null,
      [
        "promises.Resolver = PromiseResolver;",
        "promises.Resolver = Resolver;",
      ],
      /promises\.Resolver must bind PromiseResolver/u,
    ],
    [
      "public PromiseResolver instance operation",
      null,
      [
        "  Resolver.call(this, options);",
        "  Resolver.call(this, options);\n  this.extra = function() {};",
      ],
      /unreviewed public instance member/u,
    ],
    [
      "public base Resolver instance operation",
      null,
      [
        "  this._servers = _getSystemServers().slice();",
        "  this._servers = _getSystemServers().slice();\n  this.extra = function() {};",
      ],
      /unreviewed public instance member/u,
    ],
    [
      "reflective Resolver instance operation",
      null,
      [
        "  this._servers = _getSystemServers().slice();",
        "  this._servers = _getSystemServers().slice();\n  Object.assign(this, { extra: function() {} });",
      ],
      /Resolver constructor has an unreviewed this escape/u,
    ],
    [
      "different Resolver inheritance",
      null,
      [
        "PromiseResolver.prototype = Object.create(Resolver.prototype);",
        "PromiseResolver.prototype = Object.create(Object.prototype);",
      ],
      /must inherit exact Resolver\.prototype/u,
    ],
    [
      "extra PromiseResolver operation",
      null,
      [
        "PromiseResolver.prototype.constructor = PromiseResolver;",
        "PromiseResolver.prototype.constructor = PromiseResolver;\nPromiseResolver.prototype.extra = function() {};",
      ],
      /PromiseResolver\.prototype own domain drift/u,
    ],
    [
      "different provider export object",
      null,
      ["  promises: promises,", "  promises: {},"],
      /module\.exports\.promises must bind/u,
    ],
    [
      "nested provider export mutation",
      null,
      [
        "module.exports.default = module.exports;",
        "module.exports.promises.lookup = function() {};\nmodule.exports.default = module.exports;",
      ],
      /module\.exports has an unreviewed reference/u,
    ],
    [
      "dynamic provider export mutation",
      null,
      [
        "module.exports.default = module.exports;",
        'module.exports["prom" + "ises"].lookup = function() {};\nmodule.exports.default = module.exports;',
      ],
      /module\.exports has an unreviewed reference/u,
    ],
    [
      "reflective PromiseResolver prototype mutation",
      null,
      [
        "PromiseResolver.prototype = Object.create(Resolver.prototype);",
        "PromiseResolver.prototype = Object.create(Resolver.prototype);\nObject.assign(PromiseResolver.prototype, { extra: function() {} });",
      ],
      /unreviewed PromiseResolver\.prototype object escape/u,
    ],
    [
      "nested PromiseResolver prototype mutation",
      null,
      [
        "PromiseResolver.prototype.constructor = PromiseResolver;",
        "PromiseResolver.prototype.constructor = PromiseResolver;\nPromiseResolver.prototype.__proto__.extra = function() {};",
      ],
      /PromiseResolver\.prototype has an unreviewed member access or mutation/u,
    ],
  ]) {
    test(`dns/promises projection fails closed on ${label}`, () => {
      let carrier = fs.readFileSync(
        path.join(repoRoot, "src/builtins/dns-promises.js"),
        "utf8",
      );
      let provider = fs.readFileSync(
        path.join(repoRoot, "src/builtins/dns.js"),
        "utf8",
      );
      const replaceOnce = (text, mutation) => {
        if (!mutation) return text;
        const [from, to] = mutation;
        expect(text.includes(from), `${label}: mutation anchor`).toBe(true);
        return text.replace(from, to);
      };
      carrier = replaceOnce(carrier, carrierMutation);
      provider = replaceOnce(provider, providerMutation);
      expect(() =>
        scanReviewedDnsPromisesProjection(carrier, provider),
      ).toThrow(expected);
    });
  }

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
    const dnsPromiseOperations = exports.filter(
      (row) => row.metadata?.crossSourceExportProjection !== undefined,
    );
    expect(dnsPromiseOperations).toHaveLength(42);
    expect(
      new Set(dnsPromiseOperations.map((row) => row.metadata.sourceKey)),
    ).toEqual(new Set(["node_dns_promises"]));
    expect(
      dnsPromiseOperations.every(
        (row) =>
          row.metadata.crossSourceExportProjection.carrierSourceKey ===
            "node_dns_promises" &&
          row.metadata.crossSourceExportProjection.providerSourceKey ===
            "node_dns" &&
          row.sourceRefs.length >= 2,
      ),
    ).toBe(true);
    const reviewedDnsDerivedOperations = exports.filter(
      (row) => row.metadata?.dnsPromiseExportShapeReviewId !== undefined,
    );
    expect(reviewedDnsDerivedOperations).toHaveLength(45);
    expect(
      new Set(
        reviewedDnsDerivedOperations.map(
          (row) => row.metadata.dnsPromiseExportShapeReviewId,
        ),
      ),
    ).toEqual(new Set([REVIEWED_DNS_PROMISE_EXPORT_SHAPE_REVIEW_ID]));
    expect(
      reviewedDnsDerivedOperations
        .filter(
          (row) => row.metadata?.constructorInstanceProjection !== undefined,
        )
        .map((row) => row.name),
    ).toEqual([
      "export:node_dns:Resolver._handle.cancel",
      "export:node_dns:Resolver._handle.getServers",
      "export:node_dns:Resolver._handle.setServers",
    ]);
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
    expect(inheritedRows).toHaveLength(458);
    const dnsReviewedInheritedRows = inheritedRows.filter(
      (row) => row.metadata.dnsPromiseExportShapeReviewId !== undefined,
    );
    expect(dnsReviewedInheritedRows).toHaveLength(4);
    expect(
      dnsReviewedInheritedRows.every(
        (row) => row.metadata.inheritedShapeReviewId === undefined,
      ),
    ).toBe(true);
    const genericInheritedRows = inheritedRows.filter(
      (row) => row.metadata.dnsPromiseExportShapeReviewId === undefined,
    );
    expect(genericInheritedRows).toHaveLength(454);
    expect(
      new Set(
        genericInheritedRows.map(
          (row) => row.metadata.inheritedShapeReviewId,
        ),
      ),
    ).toEqual(
      new Set([
        "sha256-a38490336f46e4dd2791e1e1fa14a1164d7c0da99f2670894ded67a33d8d1e2c",
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
        (row) => row.name === "export:internal_fs_utils:toPathIfFileURL",
      )?.metadata,
    ).toMatchObject({
      bootstrapInternalModuleSpecifiers: ["internal/fs/utils"],
      importReachability: "bootstrap-internal",
      moduleSpecifiers: ["internal/fs/utils"],
      publicModuleSpecifiers: [],
    });
    for (const [name, moduleSpecifiers] of [
      [
        "export:node_stream_consumers:text",
        ["node:stream/consumers", "stream/consumers"],
      ],
      [
        "export:node_stream_promises:pipeline",
        ["node:stream/promises", "stream/promises"],
      ],
    ]) {
      expect(exports.find((row) => row.name === name)?.metadata).toMatchObject({
        bootstrapInternalModuleSpecifiers: moduleSpecifiers,
        importReachability: "bootstrap-internal",
        moduleSpecifiers,
        publicModuleSpecifiers: [],
      });
    }
    expect(
      exports.find((row) => row.name === "export:node_fs_promises:readFile")
        ?.metadata,
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
      exports.find((row) => row.name === "export:node_fs_promises:writeFile")
        ?.metadata.enforcementRouteEvidence,
    ).toMatchObject({
      requiredExportCalls: [
        {
          exportName: "writeFileSync",
          moduleSpecifier: "node:fs",
        },
      ],
      terminals: expect.arrayContaining(["__exactFsOpen", "__exactFsWrite"]),
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

  test("principal environment Proxy inventory binds its facade, traps, and native routes", () => {
    const sourcePath = "packages/ibex-runtime-js/src/node/process.ts";
    const source = fs.readFileSync(path.join(repoRoot, sourcePath), "utf8");
    const contract = scanPrincipalEnvironmentOverlayProxy(source, sourcePath);

    expect(contract).toMatchObject({
      schema: PRINCIPAL_ENVIRONMENT_OVERLAY_SOURCE_CONTRACT_SCHEMA,
      surfaceName: PRINCIPAL_ENVIRONMENT_OVERLAY_SURFACE_NAME,
      dynamicMember: PRINCIPAL_ENVIRONMENT_OVERLAY_DYNAMIC_MEMBER,
      globalPath: "process.env",
      binding: {
        factory: "createEnvProxy",
        member: "Process.prototype.env",
        sourceRef: `${sourcePath}#Process.prototype.env`,
      },
      factory: {
        name: "createEnvProxy",
        sourceRef: `${sourcePath}#createEnvProxy`,
      },
      nativeBridges: ["__exactGetAllEnv", "__exactGetEnv", "__exactSetEnv"],
      proxyTraps: [
        {
          name: "deleteProperty",
          nativeBridges: ["__exactSetEnv"],
        },
        {
          name: "get",
          nativeBridges: ["__exactGetAllEnv", "__exactGetEnv"],
        },
        {
          name: "ownKeys",
          nativeBridges: ["__exactGetAllEnv", "__exactGetEnv"],
        },
        { name: "set", nativeBridges: ["__exactSetEnv"] },
      ],
    });
    expect(contract.sourceRefs).toEqual(
      expect.arrayContaining([
        `${sourcePath}#Process.prototype.env`,
        `${sourcePath}#createEnvProxy:Proxy.deleteProperty`,
        `${sourcePath}#createEnvProxy:Proxy.get`,
        `${sourcePath}#createEnvProxy:Proxy.ownKeys`,
        `${sourcePath}#createEnvProxy:Proxy.set`,
      ]),
    );

    for (const [label, mutated] of [
      [
        "facade binding",
        source.replace(
          "readonly env: Record<string, string | undefined> = createEnvProxy();",
          "readonly env: Record<string, string | undefined> = {};",
        ),
      ],
      [
        "scalar read route",
        source.replace("value = __exactGetEnv(key);", "value = undefined;"),
      ],
      [
        "write route",
        source.replace(
          "setPrincipalOverlay(key, normalized);",
          "void normalized;",
        ),
      ],
      [
        "delete route",
        source.replace("setPrincipalOverlay(key, undefined);", "void key;"),
      ],
    ]) {
      expect(
        () => scanPrincipalEnvironmentOverlayProxy(mutated, sourcePath),
        label,
      ).toThrow(/principal environment|process\.env|Process\.env/u);
    }
  });

  test("live shared-runtime authority includes the reviewed roots and closed members", () => {
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
        "global:process.chdir",
        PRINCIPAL_ENVIRONMENT_OVERLAY_SURFACE_NAME,
      ]),
    );
    const authenticatedWebGpuRows = rows.filter((row) =>
      row.sourceRefs.some((sourceRef) =>
        sourceRef.startsWith(
          "packages/ibex-runtime-js/src/webgpu/production-wrapper.ts#installValue:globals:",
        ),
      ),
    );
    expect(authenticatedWebGpuRows.map((row) => row.name).sort()).toEqual([
      "global:GPU",
      "global:GPUAdapter",
      "global:GPUBindGroupLayout",
      "global:GPUBuffer",
      "global:GPUBufferUsage",
      "global:GPUCanvasContext",
      "global:GPUColorWrite",
      "global:GPUCommandBuffer",
      "global:GPUCommandEncoder",
      "global:GPUComputePassEncoder",
      "global:GPUComputePipeline",
      "global:GPUDevice",
      "global:GPUDeviceLostInfo",
      "global:GPUError",
      "global:GPUInternalError",
      "global:GPUMapMode",
      "global:GPUOutOfMemoryError",
      "global:GPUPipelineLayout",
      "global:GPUQuerySet",
      "global:GPUQueue",
      "global:GPURenderPassEncoder",
      "global:GPURenderPipeline",
      "global:GPUSampler",
      "global:GPUShaderModule",
      "global:GPUShaderStage",
      "global:GPUSupportedFeatures",
      "global:GPUSupportedLimits",
      "global:GPUTexture",
      "global:GPUTextureUsage",
      "global:GPUTextureView",
      "global:GPUUncapturedErrorEvent",
      "global:GPUValidationError",
      "global:createImageBitmap",
      "global:navigator.gpu",
    ].sort());
    expect(
      authenticatedWebGpuRows.every(
        (row) => row.metadata.sourceKey === "shared_runtime",
      ),
    ).toBe(true);
    expect(
      rows.find(
        (row) => row.name === PRINCIPAL_ENVIRONMENT_OVERLAY_SURFACE_NAME,
      ),
    ).toMatchObject({
      observedKey: `native-op:${PRINCIPAL_ENVIRONMENT_OVERLAY_SURFACE_NAME}`,
      metadata: {
        exportName: `process.env.${PRINCIPAL_ENVIRONMENT_OVERLAY_DYNAMIC_MEMBER}`,
        globalName: "process",
        memberKinds: ["dynamic-table"],
        memberName: `env.${PRINCIPAL_ENVIRONMENT_OVERLAY_DYNAMIC_MEMBER}`,
        principalEnvironmentOverlaySourceContract: {
          schema: PRINCIPAL_ENVIRONMENT_OVERLAY_SOURCE_CONTRACT_SCHEMA,
          nativeBridges: ["__exactGetAllEnv", "__exactGetEnv", "__exactSetEnv"],
        },
        semanticRoles: [
          "principal-environment-overlay",
          "runtime-property-overlay",
        ],
        sourceKey: "shared_runtime",
        surfaceType: "global-api",
      },
    });
    expect(
      rows
        .map((row) => row.name)
        .filter((name) =>
          new Set([
            "global:process.[[dynamic-table:host-process-own-properties]]",
            "global:process.[[dynamic-table:host-process-prototype-properties]]",
          ]).has(name),
        ),
    ).toEqual([]);
    expect(
      rows.find((row) => row.name === "global:Request.arrayBuffer").metadata
        .memberKinds,
    ).toContain("inherited");
    expect(
      rows.find((row) => row.name === "global:Request.arrayBuffer").metadata
        .publicReadAccessSourceProven,
    ).toBe(true);
    expect(
      rows
        .filter((row) => row.metadata.publicReadAccessSourceContract)
        .map((row) => row.name),
    ).toEqual([
      "__exactLoadTimings",
      "global:Intl.DateTimeFormat",
      "global:Intl.DateTimeFormat.prototype",
      "global:Intl.Locale.prototype",
      "global:Intl.NumberFormat",
      "global:Intl.NumberFormat.prototype",
      "global:Promise.prototype",
    ]);
    expect(
      rows
        .filter((row) =>
          new Set([
            "global:Intl.DateTimeFormat",
            "global:Intl.NumberFormat",
          ]).has(row.name),
        )
        .every(
          (row) =>
            row.metadata.valueShape === "callable" &&
            row.metadata.publicInvocation === undefined &&
            row.metadata.publicReadAccessSourceContract.proofKinds.join(",") ===
              "typeof-callable-membership",
        ),
    ).toBe(true);
    expect(
      rows
        .filter((row) => row.name.includes("[[dynamic-table:"))
        .every(
          (row) =>
            row.metadata.publicReadAccessSourceProven === undefined &&
            row.metadata.publicReadAccessSourceContract === undefined,
        ),
    ).toBe(true);
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
      evaluatedProcessRows.some(
        (row) => row.name === "global:process.exit.__exactHostExit",
      ),
    ).toBe(false);
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
    const windowsStreamRows = scanStaticGlobalApiSurfaces(
      streamSource.replace(/\n/gu, "\r\n"),
      "src/engine/bootstrap/web-streams-polyfill.js",
    );
    expect(windowsStreamRows.map((row) => row.name)).toEqual(
      streamRows.map((row) => row.name),
    );

    const compatRows = scanStaticGlobalApiSurfaces(
      fs.readFileSync(
        path.join(repoRoot, "src/engine/bootstrap/compat-polyfills.js"),
        "utf8",
      ),
      "src/engine/bootstrap/compat-polyfills.js",
    );
    const ipcListenerRows = scanStaticGlobalApiSurfaces(
      fs.readFileSync(
        path.join(repoRoot, "src/engine/bootstrap/ipc-listener.js"),
        "utf8",
      ),
      "src/engine/bootstrap/ipc-listener.js",
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
      compatRows.find(
        (row) => row.name === "global:process.__exactKChannelHandle",
      ).metadata,
    ).toMatchObject({
      conditionalGate: "EXACT_IPC_FD",
      publicReadAccessSourceProven: true,
      valueShape: "data",
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
    for (const rows of [ipcListenerRows, compatRows]) {
      expect(
        rows.some((row) =>
          /\[\[dynamic-table:(?:channel-handle-key|k-channel-handle)\]\]/u.test(
            row.name,
          ),
        ),
      ).toBe(false);
      const handleRows = rows.filter((row) =>
        row.name.startsWith("global:process.__exactKChannelHandle"),
      );
      expect(handleRows.map((row) => row.name)).toEqual(
        expect.arrayContaining([
          "global:process.__exactKChannelHandle",
          "global:process.__exactKChannelHandle.readStart",
          "global:process.__exactKChannelHandle.readStop",
        ]),
      );
      expect(
        handleRows.every(
          (row) => row.metadata.publicReadAccessSourceProven === true,
        ),
      ).toBe(true);
      expect(
        handleRows
          .filter((row) => /\.read(?:Start|Stop)$/u.test(row.name))
          .every((row) => row.metadata.valueShape === "callable"),
      ).toBe(true);
    }
    const wrapperRows = ipcListenerRows.filter((row) =>
      new Set([
        "global:process.once",
        "global:process.prependOnceListener",
      ]).has(row.name),
    );
    expect(wrapperRows).toHaveLength(2);
    expect(
      wrapperRows.every(
        (row) =>
          row.metadata.valueShape === "callable" &&
          row.metadata.factoryReturnedCallableSourceContract?.proofKind ===
            "lexically-bound-factory-returned-function",
      ),
    ).toBe(true);
    expect(
      ipcListenerRows.some((row) =>
        /^global:process\.(?:once|prependOnceListener)\.\[\[dynamic-table:call-result-/u.test(
          row.name,
        ),
      ),
    ).toBe(false);
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
    const callbackDelayEnvironment = first.startup.find(
      (row) => row.name === "env:IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS",
    );
    expect(callbackDelayEnvironment).toBeDefined();
    expect(
      callbackDelayEnvironment.metadata.occurrences.some(
        (occurrence) =>
          occurrence.sourcePath === "src/engine/hermes_runtime_internal.h",
      ),
    ).toBe(true);
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
      first.hostAbi.some(
        (row) =>
          row.name ===
          "ex_host_build_exact_experimental_webgpu_pre1a_armed_embedder_artifacts",
      ),
    ).toBe(true);
    expect(
      first.hostAbi.some(
        (row) =>
          row.name === "ex_host_install_armed_experimental_webgpu_pre1a",
      ),
    ).toBe(true);
    expect(first.hostAbi).toHaveLength(356);
    for (const [name, sourceRef] of [
      [
        "evaluation:installGlobals:native-freeze-conformance-observation",
        "src/engine/hermes_runtime.cc#installGlobals:evaluateJavaScript:<native-freeze-conformance-observation>",
      ],
      [
        "script:native-freeze-conformance-observation",
        "src/engine/hermes_runtime.cc#script:<native-freeze-conformance-observation>",
      ],
    ]) {
      expect(
        first.startup.find((row) => row.name === name),
        name,
      ).toMatchObject({ sourceRefs: [sourceRef] });
    }
    expect(
      first.hostAbi.every(
        (row) =>
          Array.isArray(row.metadata?.outputContracts) &&
          row.metadata.outputContracts.length > 0 &&
          row.metadata.outputContracts.every(
            (contract) =>
              contract.schema === HOST_ABI_OUTPUT_CONTRACT_SCHEMA &&
              contract.functionName === row.name &&
              row.sourceRefs.includes(contract.sourceRef),
          ),
      ),
    ).toBe(true);
    for (const [surfaceName, alias] of [
      ["__exactOSRelease", "process.__exactOSRelease"],
      ["__exactOSVersion", "process.__exactOSVersion"],
    ]) {
      const row = first.nativeOps.find(
        (candidate) => candidate.name === surfaceName,
      );
      expect(row, surfaceName).toMatchObject({
        observedKey: `native-op:${surfaceName}`,
        metadata: {
          branches: [
            expect.objectContaining({
              route: "native-jsi-global-property-alias",
              targetVariant: "android",
            }),
          ],
          exportName: alias,
          globalName: "process",
          memberName: surfaceName,
          publicOutputAccess: {
            alias,
            kind: "property-read",
          },
          publicReadAccessSourceProven: true,
          sourceKey: "native_jsi_global",
          surfaceType: "global-api",
          valueShape: "data",
        },
      });
      expect(row.sourceRefs).toContain(
        `src/engine/hermes_runtime_android.cc#jsi-global-property:${alias}`,
      );
    }
    const primaryAbiContracts = first.hostAbi.map(
      (row) => row.metadata.outputContracts[0],
    );
    const catalogAbiAccounts = first.hostAbi.map(
      deriveHostAbiOutputCatalogAccount,
    );
    expect(
      Object.fromEntries(
        [...Map.groupBy(catalogAbiAccounts, (account) => account.status)]
          .map(([status, accounts]) => [status, accounts.length])
          .sort(),
      ),
    ).toEqual({
      "output-bearing": 306,
      "structural-only": 50,
    });
    expect(
      catalogAbiAccounts.filter(
        (account) =>
          account.status === "output-bearing" &&
          account.evidenceUnresolved.length > 0,
      ),
    ).toHaveLength(0);
    expect(
      catalogAbiAccounts
        .filter((account) => account.status === "unresolved")
        .every((account) => account.membershipUnresolved.length > 0),
    ).toBe(true);
    expect(
      Object.fromEntries(
        [
          ...Map.groupBy(
            catalogAbiAccounts
              .filter((account) => account.status === "output-bearing")
              .flatMap((account) => account.outputChannels),
            (channel) =>
              channel.selector === "[[return]]"
                ? "return"
                : channel.selector.startsWith("callback:")
                  ? "callback"
                  : "out",
          ),
        ]
          .map(([role, channels]) => [role, channels.length])
          .sort(),
      ),
    ).toEqual({ callback: 59, out: 217, return: 288 });
    expect(
      Object.fromEntries(
        [
          ...Map.groupBy(
            primaryAbiContracts,
            (contract) => `${contract.return.role}:${contract.return.kind}`,
          ),
        ]
          .map(([role, contracts]) => [role, contracts.length])
          .sort(),
      ),
    ).toEqual({
      "none:void": 68,
      "value:aggregate": 17,
      "value:pointer": 51,
      "value:scalar": 220,
    });
    expect(
      Object.fromEntries(
        [
          ...Map.groupBy(
            primaryAbiContracts.flatMap((contract) => contract.parameters),
            (parameter) => parameter.role,
          ),
        ]
          .map(([role, parameters]) => [role, parameters.length])
          .sort(),
      ),
    ).toEqual({
      "callback-payload": 38,
      inout: 9,
      input: 909,
      output: 88,
    });

    const accountFor = (name) =>
      deriveHostAbiOutputCatalogAccount(
        first.hostAbi.find((row) => row.name === name),
      );
    const aggregateAccounts = [
      "ex_hermes_eval_lowered_session",
      "ex_hermes_eval_structured_diagnostic",
      "ex_hermes_eval_structured_session",
      "ex_hermes_evaluation_result_dispose",
      "ex_hermes_evaluation_result_init",
      "ex_hermes_resume_structured_session",
      "ex_hermes_take_async_failure_event",
      "ex_hermes_take_cancellation_event",
      "ex_hermes_take_work_unit_event",
      "ex_hermes_value_safe_throw_metadata",
    ];
    const callbackAccounts = [
      "ex_hermes_schedule_watchdog_heartbeat",
      "ex_hermes_schedule_watchdog_heartbeat_for_generation",
      "ex_hermes_set_dispatch_callback",
      "ex_hermes_set_dispatch_with_debug_context_callback",
      "ex_hermes_set_exact_host_call_async",
      "ex_hermes_set_host_call",
      "ex_hermes_set_host_call_async",
      "ex_hermes_set_host_wake_hook",
      "ex_hermes_set_module_dispatch_callback",
      "ex_hermes_set_module_sync_callback",
      "ex_worklet_bind_shared_value_accessors",
      "ex_worklet_set_measure_callback",
    ];
    expect(
      Object.fromEntries(
        [...aggregateAccounts, ...callbackAccounts].map((name) => [
          name,
          accountFor(name).status,
        ]),
      ),
    ).toEqual({
      ...Object.fromEntries(
        [...aggregateAccounts, ...callbackAccounts]
          .filter((name) => name !== "ex_hermes_schedule_watchdog_heartbeat")
          .map((name) => [name, "output-bearing"]),
      ),
      ex_hermes_schedule_watchdog_heartbeat: "structural-only",
    });
    expect(
      first.hostAbi
        .find((row) => row.name === "ex_hermes_schedule_watchdog_heartbeat")
        .metadata.outputContracts[0].parameters.find(
          (parameter) => parameter.name === "callback",
        ).callbackContract,
    ).toMatchObject({
      delivery: "none",
      outputChannels: [],
      parameters: [
        {
          direction: "native-to-embedder",
          name: "context",
          valueKind: "pointer",
        },
      ],
      return: { direction: "none", role: "none" },
      status: "resolved",
    });

    const resultInit = accountFor("ex_hermes_evaluation_result_init");
    expect(
      resultInit.outputChannels.map((channel) => channel.selector),
    ).toEqual([
      "out:result.abi_version",
      "out:result.capability_flags",
      "out:result.fault",
      "out:result.lifecycle_exit_code",
      "out:result.message.data",
      "out:result.outcome_tag",
      "out:result.positions",
      "out:result.stack.data",
      "out:result.struct_size",
      "out:result.throw_error_class",
      "out:result.throw_metadata_fields",
      "out:result.throw_metadata_status",
      "out:result.value.handle_id",
      "out:result.value.runtime_nonce",
      "out:result.work_target_id",
    ]);
    expect(
      resultInit.outputChannels
        .filter((channel) =>
          /(?:message|positions|stack)/u.test(channel.selector),
        )
        .map((channel) => channel.variants[0].alias),
    ).toEqual(["result.message.data", "result.positions", "result.stack.data"]);
    expect(
      accountFor("ex_hermes_eval_structured_diagnostic")
        .outputChannels.filter((channel) =>
          channel.selector.includes("positions[]"),
        )
        .map((channel) => [channel.selector, channel.variants[0].alias]),
    ).toEqual([
      ["out:result.positions[].column", "result.positions[].column"],
      ["out:result.positions[].line", "result.positions[].line"],
      [
        "out:result.positions[].source_label.data",
        "result.positions[].source_label.data",
      ],
    ]);
    expect(
      accountFor("ex_hermes_take_work_unit_event").outputChannels.map(
        (channel) => channel.selector,
      ),
    ).toEqual([
      "[[return]]",
      "out:event.kind",
      "out:event.phase",
      "out:event.scheduling_id",
      "out:event.target_id",
    ]);
    expect(
      accountFor("ex_hermes_value_safe_throw_metadata").outputChannels.map(
        (channel) => channel.selector,
      ),
    ).toEqual([
      "[[return]]",
      "out:error_class",
      "out:message.data",
      "out:metadata_fields",
      "out:stack.data",
    ]);

    const moduleSyncContract = first.hostAbi.find(
      (row) => row.name === "ex_hermes_set_module_sync_callback",
    ).metadata.outputContracts[0];
    expect(moduleSyncContract.status).toBe("resolved");
    expect(
      moduleSyncContract.outputChannels.map((channel) => channel.selector),
    ).toEqual(["callback:callback/0", "callback:callback/4"]);
    expect(
      moduleSyncContract.parameters.find(
        (parameter) => parameter.name === "callback",
      ).callbackContract,
    ).toMatchObject({
      parameters: [
        { direction: "native-to-embedder", valueKind: "buffer" },
        { direction: "native-to-embedder", valueKind: "length" },
        {
          direction: "embedder-to-native",
          ownership: { kind: "native-consumes" },
          valueKind: "buffer",
        },
        { direction: "embedder-to-native", valueKind: "length" },
        { direction: "native-to-embedder", valueKind: "pointer" },
      ],
      return: {
        direction: "embedder-to-native",
        kind: "scalar",
        role: "return",
      },
    });
    const measureCallback = first.hostAbi
      .find((row) => row.name === "ex_worklet_set_measure_callback")
      .metadata.outputContracts[0].parameters.find(
        (parameter) => parameter.name === "callback",
      ).callbackContract;
    expect(measureCallback.parameters[1]).toMatchObject({
      direction: "embedder-to-native",
      fixedLength: 4,
      ownership: { kind: "caller-storage" },
      valueKind: "buffer",
    });
    expect(
      first.hostAbi
        .find((row) => row.name === "ex_hermes_set_host_call")
        .metadata.outputContracts[0].parameters.find(
          (parameter) => parameter.name === "callback",
        ).callbackContract.return,
    ).toMatchObject({
      direction: "embedder-to-native",
      ownership: { kind: "native-consumes" },
      role: "return",
    });
    expect(
      Object.fromEntries(
        [
          ...Map.groupBy(
            first.hostAbi.filter(
              (row) => row.metadata.outputContracts[0].language === "java-jni",
            ),
            (row) => row.metadata.outputContracts[0].status,
          ),
        ]
          .map(([status, rows]) => [status, rows.length])
          .sort(),
      ),
    ).toEqual({ resolved: 47 });
    for (const [name, selectors] of [
      [
        "java:dev.ibex.runtime.IbexNetworking.CameraHostProvider.cameraHostCall",
        ["[[return]]", "callback:0", "callback:1"],
      ],
      [
        "java:dev.ibex.runtime.IbexNetworking.DialogHostProvider.dialog",
        ["[[return]]", "callback:0", "callback:1", "callback:2"],
      ],
      [
        "jni:dev.ibex.runtime.IbexNetworking.nativeAnimationFrame",
        ["callback:0", "callback:1"],
      ],
    ]) {
      expect(
        first.hostAbi
          .find((row) => row.name === name)
          .metadata.outputContracts[0].outputChannels.map(
            (channel) => channel.selector,
          ),
      ).toEqual(selectors);
    }
    for (const [name, selectors] of [
      ["ex_host_vfs_bind_runtime", ["[[return]]"]],
      ["ex_host_vfs_unbind_runtime", ["[[return]]"]],
      ["ex_host_vfs_get_cwd", ["[[return]]", "out:virtual", "out:errno"]],
      ["ex_host_vfs_chdir", ["[[return]]", "out:virtual", "out:errno"]],
      [
        "ex_host_vfs_resolve_path",
        ["[[return]]", "out:backing", "out:virtual", "out:errno"],
      ],
    ]) {
      const contract = first.hostAbi.find((row) => row.name === name).metadata
        .outputContracts[0];
      expect(contract.status).toBe("resolved");
      expect(
        contract.outputChannels.map((channel) => channel.selector),
      ).toEqual(selectors);
    }
    expect(
      first.startup.find((row) => row.name === "runtime-create").sourceRefs,
      ).toEqual(["src/engine/hermes_runtime.cc#ex_hermes_create_armed"]);
    expect(
      first.hostAbi.filter((row) => row.name.startsWith("ex_host_")),
    ).toHaveLength(163);
    expect(
      first.hostAbi.some((row) => row.name === "ex_host_seal_bootstrap_phase"),
    ).toBe(true);
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
    const mergedProcessWrappers = first.globals.filter((row) =>
      new Set([
        "global:process.once",
        "global:process.prependOnceListener",
      ]).has(row.name),
    );
    expect(mergedProcessWrappers).toHaveLength(2);
    expect(
      mergedProcessWrappers.every(
        (row) =>
          row.metadata.valueShape === "callable" &&
          row.metadata.factoryReturnedCallableSourceContract?.installedPath ===
            row.metadata.exportName,
      ),
    ).toBe(true);
    expect(
      first.globals.some((row) =>
        /^global:process\.(?:once|prependOnceListener)\.\[\[dynamic-table:call-result-/u.test(
          row.name,
        ),
      ),
    ).toBe(false);
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
    expect(producers).toHaveLength(15);
    expect(
      producers.reduce((count, row) => count + row.metadata.occurrenceCount, 0),
    ).toBe(20);
    expect(
      producers.find(
        (row) =>
          row.name ===
          "producer:src/engine/hermes_runtime_gpu.cc:scheduleGpuMailboxDrain:pushRuntimeCallback",
      ),
    ).toMatchObject({
      metadata: {
        enclosingDefinition: "scheduleGpuMailboxDrain",
        evidenceType: "push-runtime-callback-producer",
        occurrenceCount: 1,
        producer: "pushRuntimeCallback",
      },
    });
    const gpuPrivateBridge = first.nativeOps.filter(
      (row) =>
        row.metadata?.evidenceType === "construction-private-host-function",
    );
    expect(gpuPrivateBridge.map((row) => row.name)).toEqual([
      "construction-private:gpuNativeBridge.cancel",
      "construction-private:gpuNativeBridge.retire",
      "construction-private:gpuNativeBridge.submit",
      "construction-private:gpuNativeBridgeV2.cancel",
      "construction-private:gpuNativeBridgeV2.capturePresentationAuthority",
      "construction-private:gpuNativeBridgeV2.createMappedRangeAlias",
      "construction-private:gpuNativeBridgeV2.detachMappedRange",
      "construction-private:gpuNativeBridgeV2.recheckPresentationAuthority",
      "construction-private:gpuNativeBridgeV2.retire",
      "construction-private:gpuNativeBridgeV2.retirePresentationAuthority",
      "construction-private:gpuNativeBridgeV2.setEventSink",
      "construction-private:gpuNativeBridgeV2.submit",
    ]);
    expect(
      gpuPrivateBridge.map((row) => [
        row.metadata.memberName,
        row.metadata.arity,
        row.metadata.terminalHandler,
      ]),
    ).toEqual([
      ["cancel", 1, "cancelGpuBridgeCall"],
      ["retire", 1, "retireGpuBridgeCall"],
      ["submit", 5, "submitGpuBridgeCall"],
      ["cancel", 2, "cancelGpuV2BridgeCall"],
      [
        "capturePresentationAuthority",
        2,
        "captureGpuPresentationAuthorityBridgeCall",
      ],
      [
        "createMappedRangeAlias",
        3,
        "createGpuV2MappedRangeAliasBridgeCall",
      ],
      ["detachMappedRange", 1, "detachGpuV2MappedRangeBridgeCall"],
      [
        "recheckPresentationAuthority",
        3,
        "recheckGpuPresentationAuthorityBridgeCall",
      ],
      ["retire", 1, "retireGpuV2BridgeCall"],
      [
        "retirePresentationAuthority",
        1,
        "retireGpuPresentationAuthorityBridgeCall",
      ],
      ["setEventSink", 1, "setGpuV2EventSinkBridgeCall"],
      ["submit", 4, "submitGpuV2BridgeCall"],
    ]);
    const gpuEventIngress = first.callbacks.filter(
      (row) =>
        row.metadata?.evidenceType === "versioned-callback-table-ingress",
    );
    expect(gpuEventIngress).toEqual([
      expect.objectContaining({
        name: "ingress:src/engine/hermes_runtime_gpu.cc:ExactGpuClientSinkV1.on_event:receiveGpuEvent",
        metadata: expect.objectContaining({
          abiVersionExpression: "EXACT_GPU_SERVICE_ABI_VERSION_V1",
          callback: "receiveGpuEvent",
          effectiveCallbackExpression: "receiveGpuEvent",
          callbackFieldCount: 5,
          callbackFieldIndex: 4,
          fieldName: "on_event",
          initializerVariable: "kGpuClientSink",
          macroConditionalDirectiveCount: 0,
          macroDefinitionCount: 1,
          macroInvocationCount: 1,
          macroLifetimeOrder: "define-invocation-undef",
          macroName: "IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
          macroParameters: ["table_type", "field_name", "callback"],
          macroReplacement: "callback",
          macroUndefCount: 1,
          occurrenceCount: 1,
          releaseCallback: "releaseGpuClient",
          retainCallback: "retainGpuClient",
          structSizeExpression: "sizeof(ExactGpuClientSinkV1)",
          tableType: "ExactGpuClientSinkV1",
        }),
      }),
      expect.objectContaining({
        name: "ingress:src/engine/hermes_runtime_gpu_v2.cc:ExactGpuClientSinkV2.on_event:receiveGpuEvent",
        metadata: expect.objectContaining({
          abiVersionExpression: "EXACT_GPU_SERVICE_ABI_VERSION_V2",
          callback: "receiveGpuEvent",
          effectiveCallbackExpression: "receiveGpuEvent",
          callbackFieldCount: 5,
          callbackFieldIndex: 4,
          fieldName: "on_event",
          initializerVariable: "kGpuClientSinkV2",
          macroConditionalDirectiveCount: 0,
          macroDefinitionCount: 1,
          macroInvocationCount: 1,
          macroLifetimeOrder: "define-invocation-undef",
          macroName: "IBEX_CAPSEC_CALLBACK_TABLE_INGRESS",
          macroParameters: ["table_type", "field_name", "callback"],
          macroReplacement: "callback",
          macroUndefCount: 1,
          occurrenceCount: 1,
          releaseCallback: "releaseGpuClientV2",
          retainCallback: "retainGpuClientV2",
          structSizeExpression: "sizeof(ExactGpuClientSinkV2)",
          tableType: "ExactGpuClientSinkV2",
        }),
      }),
    ]);
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
    const ipcFdEnvironment = environmentRows.find(
      (row) => row.name === "env:EXACT_IPC_FD",
    );
    expect(ipcFdEnvironment.sourceRefs).toContain(
      "src/host/abi.rs#env::var:EXACT_IPC_FD:read",
    );
    expect(ipcFdEnvironment.metadata.contexts).toEqual(
      expect.arrayContaining(["startup-input", "spawn-child-env"]),
    );
    expect(
      ipcFdEnvironment.sourceRefs.some((sourceRef) =>
        sourceRef.includes("#process.env:EXACT_IPC_FD:read"),
      ),
    ).toBe(false);
    const ipcSerializationEnvironment = environmentRows.find(
      (row) => row.name === "env:EXACT_IPC_SERIALIZATION",
    );
    expect(ipcSerializationEnvironment.sourceRefs).toContain(
      "src/host/abi.rs#env::var:EXACT_IPC_SERIALIZATION:read",
    );
    expect(
      ipcSerializationEnvironment.sourceRefs.some((sourceRef) =>
        sourceRef.includes("#process.env:EXACT_IPC_SERIALIZATION:read"),
      ),
    ).toBe(false);
    expect(
      environmentRows.some((row) => row.name.startsWith("env:IBEX_CAPSEC_")),
    ).toBe(true);
    for (const environmentName of [
      "IBEX_CAPSEC_CLOSED_CONTROL_OUTPUT_PLAN",
      "IBEX_CAPSEC_CLOSED_CONTROL_OUTPUT_RESULT",
      "IBEX_CAPSEC_GLOBAL_CALLABLE_DIAGNOSTIC_OUTPUT",
      "IBEX_CAPSEC_OUTPUT_SHAPE_BATCH_OUTPUT",
      "IBEX_CAPSEC_OUTPUT_SHAPE_PLAN",
      "IBEX_CAPSEC_REPL_256_REPRO",
    ]) {
      expect(
        environmentRows.some((row) => row.name === `env:${environmentName}`),
        environmentName,
      ).toBe(false);
    }
    expect(
      environmentRows.find((row) => row.name === "env:__exactEnvProxy")
        .sourceRefs,
    ).toContain("src/builtins/process.js#process.env:__exactEnvProxy:read");
    expect(
      environmentRows
        .filter((row) =>
          [
            "::environ",
            "GetEnvironmentStringsW",
            "_NSGetEnviron",
            "_dupenv_s",
            "environ",
          ].some((accessor) => row.metadata.accessors.includes(accessor)),
        )
        .map((row) => row.metadata.accessors[0]),
    ).toEqual([
      "::environ",
      "GetEnvironmentStringsW",
      "_NSGetEnviron",
      "_dupenv_s",
      "environ",
    ]);
    expect(
      environmentRows.find((row) =>
        row.metadata.accessors.includes("::environ"),
      ).sourceRefs,
    ).toContain(
      "src/engine/hermes_runtime_process_setup.cc#::environ:dynamic:read",
    );
    expect(
      environmentRows.find((row) => row.metadata.accessors.includes("environ"))
        .sourceRefs,
    ).toEqual(["src/engine/hermes_runtime_process.cc#environ:dynamic:read"]);
    for (const row of environmentRows) {
      for (const ref of row.sourceRefs) {
        expect(ref).not.toMatch(
          /(?:^|\/)(?:__tests__|benchmarks?|devtools|fixtures?|tests?)(?:\/|$)|\.(?:bench|e2e|fixture|spec|test)\.[^/#]+#|(?:^|[/_-])tests?\.(?:c|cc|cpp|cxx|m|mm|rs)#|(?:^|\/)build\.rs#|^src\/bin\/ibex\/compat\//u,
        );
      }
    }
  }, 180_000);
});
