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
   (`hermes_runtime.cc:1391-1403`).
2. Wraps it in an `ExactHermesRuntime` handle, records the owning thread
   (`hermes_runtime.cc:1409-1411`).
3. Optionally constructs the async debugger if the Hermes build supports it
   (`hermes_runtime.cc:1415-1432`).
4. Calls `installGlobals(handle)` — which installs the native host functions and
   runs the bootstrap scripts — then registers the runtime
   (`hermes_runtime.cc:1436, 1449`).

`ex_hermes_eval()` (`hermes_runtime.cc:1464`) evaluates UTF-8 source or Hermes
bytecode (`is_bytecode` flag) and returns a result string `[observed]`.

The engine uses Hermes through **JSI** (`<jsi/jsi.h>`, `hermes_runtime.cc:15`):
native functions are registered with `jsi::Function::createFromHostFunction` and
set as properties on `rt.global()` `[observed]` (e.g. the `__hostCall`,
`__StringBuffer`, `__exactModuleResolve`, and `__exactEnsure*` installers,
`hermes_runtime.cc:1191-1267`).

### The `__hostCall` bridge

`ex_hermes_set_host_call` installs the generic `__hostCall(op, argsJson)` JSI
host function `[observed]` (`hermes_runtime.cc:1754-1806`). The protocol — a `+`
(JSON success) / `-` (error) status sigil on the returned C string, freed by the
C++ side and `JSON.parse`d — is documented in
[LLP 0002 §The `__hostCall` bridge](./0002-host-embedding-abi.spec.md#the-hostcall-bridge--the-generic-host-channel).
It is the catch-all native channel; higher-traffic subsystems get dedicated
host functions instead `[inferred: dedicated functions avoid per-call JSON
encode/parse overhead and string-typed dispatch]`.

### Lazy installation of host functions

Several subsystems are installed lazily on first use through `__exactEnsure*`
shims — HTTP, SQLite, DNS, and child-process host functions are each registered
only when JS first calls the corresponding `__exactEnsure*()` `[observed]`
(`hermes_runtime.cc:1197-1249`). `[inferred: this trims startup cost for
runtimes that never touch those subsystems.]`

### The bootstrap sequence

`hermes_bootstrap.cc` runs a fixed sequence of bootstrap JS scripts after the
runtime is created `[observed]` (`src/engine/hermes_bootstrap.cc`). Each script
is run via `eval_bootstrap_script`, which prefers precompiled Hermes bytecode
(`bootstrap_bytecode.h`) when available and falls back to source
(`bootstrap_source.h`) `[observed]` (`hermes_bootstrap.cc:44-69`). Two layers
exist:

- The per-file **bootstrap scripts** under `src/engine/bootstrap/*.js`
  (module-loader, bootstrap-globals, compat-polyfills, exact-global,
  web-crypto, web-storage, stream-enhance, etc.) `[observed]` (directory listing;
  bootstrap order `hermes_bootstrap.cc:193-650`).
- The **shared runtime bundle** (`embedded_runtime_bundle.js`, the rolldown
  output of `packages/ibex-runtime-js`) installed via
  `installSharedRuntimeBundle` `[observed]` (`hermes_bootstrap.cc:19-27, 71-110`).
  When the bundle is present it supplies the globals and the legacy
  `bootstrap_globals` step is skipped `[observed]` (`hermes_bootstrap.cc:240-253`).

The HBC-vs-source selection and how these headers are produced is the build
pipeline's concern — see [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md).

## The event loop

The host pumps the loop by calling `ex_hermes_poll(runtime, now_ms)`
repeatedly `[observed]` (`hermes_runtime.cc:1815`). Each poll: cleans up fetch
callbacks, drains the cross-thread callback queue (HTTP responses etc.), runs
queued cross-thread tasks on the runtime thread, runs the `nextTick` queue, and
drains microtasks `[observed]` (`hermes_runtime.cc:1820-1849`). Background
threads signal readiness via `ex_hermes_notify_callback`, whose default
implementation sets an atomic flag polled by the host `[observed]`
(`src/engine/mod.rs:33-43`); the CLI replaces it with a tokio `Notify`-based
version under the `cli-notify` feature `[observed]` (`src/engine/mod.rs:18-32`,
`Cargo.toml` `cli-notify`).

## The platform shims (map)

Each `src/engine/hermes_runtime_*.cc` file installs a family of native host
functions / globals for one subsystem and carries per-OS implementations behind
`#if` guards `[observed]` (file listing; defines set in `build.rs`):

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

The `native_fetch_*` / `native_websocket_*` files are per-OS (linux/macos/
windows) `[observed]` (file listing); on Linux/Windows they build against curl
(`EXACT_HAS_CURL`) `[observed]` (`build.rs:1017, 1037`).

### Crypto is platform-dependent (the fragile axis)

`hermes_runtime_crypto.cc` selects its backend with `EXACT_NO_OPENSSL` and
`__APPLE__` `[observed]`:

- **Apple** (`__APPLE__`): CommonCrypto/Security headers, no OpenSSL
  `[observed]` (`hermes_runtime.cc:91-96`, `crypto.cc:24-27`).
- **OpenSSL profile** (`!EXACT_NO_OPENSSL`): the full asymmetric sign/verify and
  key-generation paths compile `[observed]` (`crypto.cc:35-43`, and the many
  `#if !defined(EXACT_NO_OPENSSL)` guards).
- **Windows**: `hermes_runtime_crypto_windows.cc` (BCrypt) with
  `EXACT_NO_OPENSSL` `[observed]` (`build.rs:751-763`).
- **Reduced / no-OpenSSL profile** (e.g. Linux default, iOS for asymmetric):
  the same JS surface is registered as **throwing stubs** so callers get a clear
  runtime error ("rebuild ... with the openssl-crypto feature") rather than a
  missing global `[observed]` (`crypto.cc:1995-2026`). On iOS, asymmetric key
  generation throws "requires OpenSSL (not available on iOS)" `[observed]`
  (`crypto.cc:1535`).

The crypto profile axis and the platform matrix are owned by
[LLP 0001](./0001-target-platforms-and-ci-matrix.rfc.md); this section only maps
where the selection happens in the engine.

## Boundaries

- This crate compiles the C++ via `build.rs` (`cc`); the engine links a prebuilt
  Hermes per platform (see [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md)).
- The Rust-side `ex_host_*` implementations the shims call into live in
  `src/host` ([LLP 0002](./0002-host-embedding-abi.spec.md)); the engine declares
  them as `extern "C"` (`hermes_runtime.cc:203-213`).
- Hermes is the only engine today, but the C ABI + JSI seam is deliberately
  engine-agnostic in shape `[inferred]` — see
  [LLP 0006](./0006-design-principles.principles.md).
