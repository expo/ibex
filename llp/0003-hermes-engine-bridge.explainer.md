# LLP 0003: The Hermes Engine Bridge

**Type:** Explainer
**Status:** Draft
**Systems:** Engine, Runtime, Crypto
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Related:** LLP 0000; LLP 0002 (Host ABI); LLP 0004 (Module loading); LLP 0005 (Build pipeline)

## Summary

`src/engine/*.cc` is the C++ that drives the Hermes JS engine: it creates the
runtime, installs native globals and host functions through JSI, runs the
bootstrap JS, evaluates user code, pumps an event loop, and routes JS-to-native
calls. It also carries the **platform shims** — crypto, fs, process, net, http,
dns, etc. — each implemented natively per OS. This document maps that surface;
it does not restate the embedding ABI ([LLP 0002](./0002-host-embedding-abi.spec.md)).

## How Hermes is driven

`ex_hermes_create()` (`src/engine/hermes_runtime.cc:1388-1453`) `[observed]`:

1. Builds a `hermes::vm::RuntimeConfig` with a microtask queue and `eval`
   enabled, then `facebook::hermes::makeHermesRuntime(config)`
   (`src/engine/hermes_runtime.cc:1391-1403`).
2. Wraps it in an `ExactHermesRuntime` handle, records the owning thread
   (`src/engine/hermes_runtime.cc:1409-1411`).
3. Optionally constructs the async debugger if the Hermes build supports it
   (`src/engine/hermes_runtime.cc:1415-1432`).
4. Calls `installGlobals(handle)` — which installs the native host functions and
   runs the bootstrap scripts — then registers the runtime
   (`src/engine/hermes_runtime.cc:1436, 1449`).

`ex_hermes_eval()` evaluates UTF-8 source or Hermes bytecode (`is_bytecode`
flag) and returns a result string `[observed]`
(`src/engine/hermes_runtime.cc:1464`).

The engine uses Hermes through **JSI** (`<jsi/jsi.h>`) `[observed]`
(`src/engine/hermes_runtime.cc:14-15`). Native functions are registered with
`jsi::Function::createFromHostFunction` and set as properties on `rt.global()`
`[observed]` (e.g. `__exactModuleResolve`, `__exactEnsure*`, and `__hostCall`,
`src/engine/hermes_runtime.cc:1160-1283, 1754-1806`).

### The `__hostCall` bridge

`ex_hermes_set_host_call` installs the generic `__hostCall(op, argsJson)` JSI
host function `[observed]` (`src/engine/hermes_runtime.cc:1754-1806`). The
protocol — a `+` (JSON success) / `-` (error) status sigil on the returned C
string, freed by the C++ side and `JSON.parse`d — is documented in
[LLP 0002 §The `__hostCall` bridge](./0002-host-embedding-abi.spec.md#the-hostcall-bridge--the-generic-host-channel).
It is the catch-all native channel; higher-traffic subsystems get dedicated
host functions instead `[inferred: dedicated functions avoid per-call JSON
encode/parse overhead and string-typed dispatch]`.

### Lazy installation of host functions

Several subsystem functions are installed lazily on first use through
`__exactEnsure*` shims. Filesystem functions are behind `__exactEnsureFs` on
non-Windows platforms, while Windows installs them eagerly because the Windows
FS implementation is a separate file compiled only for that target `[observed]`
(`src/engine/hermes_runtime.cc:1056-1072`). HTTP, SQLite, DNS, child-process,
and Net are also registered on demand `[observed]`
(`src/engine/hermes_runtime.cc:1197-1283`). `[inferred: this trims startup cost
for runtimes that never touch those subsystems.]`

### The bootstrap sequence

`hermes_bootstrap.cc` runs bootstrap JS after the runtime is created
`[observed]`. `eval_bootstrap_script` prefers precompiled Hermes bytecode when
available and falls back to the generated source header `[observed]`
(`src/engine/hermes_bootstrap.cc:19-69`). Two layers exist:

- The **shared runtime bundle** (`embedded_runtime_bundle.js`, the rolldown
  output of `packages/ibex-runtime-js`) is installed via
  `installSharedRuntimeBundle` `[observed]`
  (`src/engine/hermes_bootstrap.cc:71-154`).
- The per-file **bootstrap scripts** under `src/engine/bootstrap/*.js` install
  the module loader, compatibility globals, process/exact globals, and legacy
  lazy getters `[observed]` (`src/engine/hermes_bootstrap.cc:156-302, 413-797`).
  When the shared runtime bundle is successfully installed, the legacy
  `bootstrap_globals` step is skipped `[observed]`
  (`src/engine/hermes_bootstrap.cc:240-246`).

The HBC-vs-source selection and how these headers are produced is the build
pipeline's concern — see [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md).

## The event loop

The host pumps the loop by calling `ex_hermes_poll(runtime, now_ms)`
repeatedly `[observed]` (`src/engine/hermes_runtime.cc:1815`). Each poll:
cleans up fetch callbacks, drains the cross-thread callback queue (HTTP
responses etc.), runs queued cross-thread tasks on the runtime thread, runs the
`nextTick` queue, and drains microtasks `[observed]`
(`src/engine/hermes_runtime.cc:1820-1849`). Background threads signal readiness
via `ex_hermes_notify_callback`, whose default implementation sets an atomic
flag polled by the host `[observed]` (`src/engine/mod.rs:33-43`); the
`cli-notify` feature replaces it with a tokio `Notify`-based version
`[observed]` (`src/engine/mod.rs:18-32`; `Cargo.toml:66-80`).

## The platform shims (map)

Each `src/engine/hermes_runtime_*.cc` file installs a family of native host
functions / globals for one subsystem and carries per-OS implementations behind
`#if` guards. `build.rs` lists the C++ sources and target-specific defines
`[observed]` (`build.rs:804-1224`):

| Subsystem | Files | Notes |
|---|---|---|
| Crypto | `hermes_runtime_crypto.cc`, `hermes_runtime_crypto_windows.cc` | platform-dependent; see below |
| Filesystem | `hermes_runtime_fs.cc`, `hermes_runtime_fs_windows.cc` | also via `ex_host_fs_*` Rust ABI |
| Process | `hermes_runtime_process.cc`, `_process_setup.cc`, `_platform_windows.cc` | spawn, env, signals |
| Net / sockets | `hermes_runtime_net.cc` | TCP/UDP |
| HTTP | `hermes_runtime_http.cc`, `hermes_runtime_fetch.cc`, `native_fetch_*` | fetch + server |
| WebSocket | `hermes_runtime_websocket.cc`, `native_websocket_*` | per-OS native impls |
| DNS | `hermes_runtime_dns.cc` | resolver |
| SQLite | `hermes_runtime_sqlite.cc` | bridges to rusqlite via `ex_host_sqlite_*` |
| Console/IPC/timers | `hermes_runtime_console.cc`, `_ipc.cc`, `_timers.cc` | |
| OS info / iOS | `hermes_runtime_osinfo.cc`, `hermes_runtime_ios.cc` | |
| Debugger | `hermes_runtime_debugger.cc` | gated on `HERMES_ENABLE_DEBUGGER` |

The `native_fetch_*` / `native_websocket_*` files are per-OS. macOS/iOS use
Foundation/NSURLSession implementations `[observed]`
(`src/engine/native_fetch_macos.mm:1-14`;
`src/engine/native_websocket_macos.mm:1-9`). Windows uses WinHTTP
implementations `[observed]` (`src/engine/native_fetch_windows.cc:1-5`;
`src/engine/native_websocket_windows.cc:1-5`; `build.rs:1072-1104`). Android
uses `native_android_networking.cc`, which preserves the same C++ fetch and
WebSocket ABI while delegating HTTP/WebSocket work to the Java OkHttp bridge
`IbexNetworking`; Android clipboard, raw DNS, locale/screen/appearance globals,
and platform-version data are also fed through that app-context bridge
`[observed]` (`src/engine/native_android_networking.cc`;
`src/engine/hermes_runtime_android.cc`;
`platform/android/java/dev/ibex/runtime/IbexNetworking.java`; `build.rs`).
Linux uses system libcurl as the supported native networking backend: `build.rs`
requires `pkg-config` and libcurl >= 7.86 so fetch and WebSocket both compile
with `EXACT_HAS_CURL` `[observed]`
(`build.rs:1175-1236`). A degraded fetch-only curl CLI fallback exists only
when `IBEX_ALLOW_CURL_CLI_FALLBACK=1`; WebSocket remains unavailable in that
profile `[observed]` (`src/engine/native_fetch_linux.cc`;
`src/engine/native_websocket_linux.cc`).

### Crypto is platform-dependent (the fragile axis)

Crypto is split between the non-Windows crypto shim and a Windows-specific file:

- **Apple / non-Windows file:** `hermes_runtime_crypto.cc` includes
  CommonCrypto/Security on Apple platforms `[observed]`
  (`src/engine/hermes_runtime_crypto.cc:23-44`). macOS sign/verify use Security
  APIs when not building iOS `[observed]`
  (`src/engine/hermes_runtime_crypto.cc:1335-1443`). Apple key generation is
  registered, but some iOS paths throw because OpenSSL/PEM export are not
  available `[observed]` (`src/engine/hermes_runtime_crypto.cc:1445-1691`).
- **OpenSSL profile:** when `EXACT_NO_OPENSSL` is not defined, the non-Windows
  file compiles OpenSSL-backed AES, PBKDF2/scrypt/HKDF, asymmetric
  sign/verify/key-generation, ECDH/X25519/Ed25519, RSA-OAEP, and key
  import/export paths `[observed]` (`src/engine/hermes_runtime_crypto.cc`).
- **Android:** `build.rs` defines `EXACT_PLATFORM_ANDROID` and requires the
  `openssl-crypto` profile, using vendored OpenSSL until an Android-native
  crypto backend exists `[observed]` (`build.rs:933-949`).
- **Non-Windows reduced profile:** when `EXACT_NO_OPENSSL` is defined outside
  Apple-specific branches, Linux compiles without OpenSSL and keeps a reduced
  runtime surface: portable MD5/SHA-1/SHA-2 hash/HMAC/hashRaw, PBKDF2, scrypt,
  and HKDF, plus throwing stubs for asymmetric sign/verify/key generation
  `[observed]` (`src/engine/hermes_runtime_crypto.cc`). AES and asymmetric key
  import/export remain outside the reduced profile.
- **Windows:** `build.rs` compiles `hermes_runtime_crypto_windows.cc` and
  defines `EXACT_NO_OPENSSL` `[observed]` (`build.rs:729-765`). That file
  registers Windows BCrypt-backed hash/hashRaw/HMAC functions plus stdin/signal
  noops; it does not register the non-Windows asymmetric throwing stubs
  `[observed]` (`src/engine/hermes_runtime_crypto_windows.cc:1-8, 141-221`).

The crypto profile axis and the platform matrix are owned by
[LLP 0001](./0001-target-platforms-and-ci-matrix.rfc.md); this section only maps
where the selection happens in the engine.

### Windows native smoke coverage

The Windows native backend contract is covered by the
`windows_runtime_uses_native_platform_backends` lib test in `src/engine/mod.rs`.
It exercises the public JS APIs against local test services so the C++ shims are
reached through the same bootstrap/builtin path embedders use: `fetch` and
`WebSocket` through WinHTTP, `crypto` hash/HMAC through BCrypt, `fs` through the
host filesystem ABI, `child_process.spawnSync` through `CreateProcessW`, and
DNS/TCP through Winsock. This is intentionally an end-to-end smoke, not a unit
test of individual C symbols.

## Boundaries

- This crate compiles the C++ via `build.rs` (`cc`); the engine links Hermes
  from platform-specific paths or `HERMES_*` overrides (see
  [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md)).
- The Rust-side `ex_host_*` implementations the shims call into live in
  `src/host` ([LLP 0002](./0002-host-embedding-abi.spec.md)); the engine declares
  them as `extern "C"` `[observed]` (`src/engine/hermes_runtime.cc:203-235`).
- Hermes is the only engine today, and the public C symbols still name Hermes
  (`ex_hermes_*`) `[observed]` (`include/exact_runtime.h:34-65, 151-156`).
  Any future engine-agnostic seam is a design posture, not an implemented
  abstraction `[inferred]` — see [LLP 0006](./0006-design-principles.principles.md).
