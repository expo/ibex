# LLP 0003: The Hermes Engine Bridge

**Type:** Explainer
**Status:** Draft
**Systems:** Engine, Runtime, Crypto
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Revised:** 2026-07-11 (ENG-24219: engine entry points now scope frame attribution to the runtime handle being driven, so same-thread nested runtimes restore the outer attribution context); 2026-07-08 (ENG-23541: Windows async fs worker-pool hooks)
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

Frame attribution is runtime-handle scoped, not merely thread scoped. A thread
may drive multiple runtimes or re-enter `ex_hermes_eval()` for a nested runtime
from an outer runtime's host call; `ex_hermes_create()`, `ex_hermes_eval()`, and
`ex_hermes_poll()` select the handle's attribution VM for the duration of that
entry and restore the prior selection on unwind `[observed]`
(`src/engine/hermes_runtime_internal.h`; `src/engine/hermes_runtime.cc`). This
keeps capability checks attached to the executing runtime without weakening LLP
0013's fail-closed no-user-principal rule.

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
flag and invokes a registerable host wake hook `[observed]`
(`src/engine/mod.rs`); the `cli-notify` feature replaces it with a tokio
`Notify`-based version. Since ENG-23234 the CLI's default (non-`cli-notify`)
profile registers that hook at engine creation to signal the same parked
`select!` — previously the default profile had no wake-up at all, so a
cross-thread callback push racing a long timer park was not dispatched until
the timer expired. OS signal delivery rides this same path: the sigaction
handler marks a per-signal pending counter and writes to a self-pipe; a
detached watcher thread turns that into a `pushRuntimeCallback` that drains
pending signals into the JS `process` emitter `[observed]`
(`src/engine/hermes_runtime_crypto.cc`, `src/engine/bootstrap/stream-enhance.js`).

Async failures are fatal, matching Node: a callback that throws with no
`uncaughtException` handler consuming it — a timer, a `process.nextTick`, a
cross-thread task or callback — makes the poll report `-1`, which the host
loop turns into a nonzero process exit. Timers return `-1` directly; the other
paths set a one-shot `fatal_async_error` flag on the runtime that the same or
next poll consumes (one-shot so a REPL survives it the way it survives a
throwing timer). Likewise the JS-side `unhandledrejection` default action sets
`process.exitCode = 1` (preserving a user-set nonzero code) rather than
crashing mid-run. Before ENG-23130, all of these logged and exited 0 — a
silent green for any CI or agent using the exit code as the pass/fail signal.

### Blocking-work worker pools

Anything that would block the JS thread for longer than a scheduling quantum
runs on a bounded pool of detached worker threads and delivers its completion
back through `pushRuntimeCallback` + `ex_hermes_notify_callback`: DNS
resolution (`DnsWorkerPool`, ENG-22995), fetch on Linux (`FetchWorkerPool`,
ENG-23471), and — since ENG-23497/ENG-23541 — the async fs API
(`FsWorkerPool`, `src/engine/hermes_runtime_fs.cc` and
`src/engine/hermes_runtime_fs_windows.cc`). The fs pool backs
`__exactFsReadFileAsync` / `__exactFsWriteFileAsync` / `__exactFsReadAsync` /
`__exactFsWriteAsync` / `__exactFsReadvAsync` / `__exactFsWritevAsync` /
`__exactFsPathAsync` / `__exactFsStatAsync`; `src/builtins/fs.js` routes
`readFile`/`writeFile`/`appendFile`/`read`/`write`/`readv`/`writev`/
`stat`/`lstat`/`fstat`, directory/metadata path operations, `fs.promises`,
`FileHandle`, and the ReadStream/WriteStream data paths through them when
present, and falls back to the historical deferred-sync path when absent.
`*Sync` entry points remain synchronous by design. Before ENG-23497 the whole
"async" fs API ran its syscalls synchronously on the JS thread and only
deferred the callback, so one large `readFile` starved timers and sockets for
its full duration.

The Windows fs pool runs over the Rust `ex_host_fs_*` ABI rather than POSIX
file descriptors. Its opaque file handles are shared between sync JS-thread
calls and worker-thread async calls with a per-handle I/O mutex, because the
Windows positional read/write shims are save-cursor/seek/op/restore sequences
on one handle rather than atomic `pread`/`pwrite` syscalls. Close removes the
JS fd mapping immediately while an in-flight worker retains shared ownership,
so the native handle is released exactly once after the last operation. Append
is an open-handle mode rather than a reopen-by-path operation, preserving fd
identity across rename/unlink and OS append serialization. Filesystem failures
cross the ABI through a thread-local normalized errno slot; probing the path
after failure is forbidden because it misclassifies permission/type errors as
`ENOENT`. The same handle ABI exposes real `sync_all`/`sync_data` durability
for Windows `fsync`/`fdatasync`.

The shared pool discipline, learned the hard way:

- **Immortal heap singleton.** A pool with detached workers must be
  `static Pool* pool = new Pool(); return *pool;` — never a function-local
  by-value static. glibc deadlocks `exit()` when static destructors destroy a
  mutex/condvar that still has parked waiters (Linux-only; macOS never
  reproduces it). See `native_fetch_linux.cc`'s `FetchWorkerPool` and
  ENG-23471/ENG-23498.
- **Queue, don't early-reject.** Reject an enqueue only when the backlog is
  genuinely full; an `idle == 0 && total >= kMaxWorkers` early-reject turns a
  one-tick fan-out (`Promise.all`) into spurious failures (ENG-23022).
- **Keepalive counter.** Each subsystem counts in-flight ops in an atomic on
  the runtime handle (`pending_dns_lookups`, `pending_fs_ops`) that the loop's
  referenced-work checks consult; otherwise the process exits before the
  worker delivers its completion.
- **No JSI off-thread; checks stay on the JS thread.** Workers touch plain
  data only. Argument validation and capability checks (the deputy stack is
  JS-thread-local) run before enqueue; errno capture happens on the worker at
  failure time and is rehydrated into a Node-shaped error on delivery.
- **Ordering matches Node.** Independent ops on the pool may reorder, exactly
  like Node's libuv threadpool (verified against Node v25: `writeFile`
  immediately followed by `readFile` of the same path can observe ENOENT).
  Anything that needs ordering must chain on the completion, which is what
  WriteStream's serialized `pendingWrites` queue does.

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
`IbexNetworking`; Android clipboard, raw DNS, location, camera
permission/device metadata, locale/screen/appearance globals,
app-state/deep-link/configuration events, and platform-version data are also
fed through that app-context bridge
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

### WebSocket bridge threading and context ownership

The desktop WebSocket backends share two invariants that are easy to break
because nothing enforces them mechanically (ENG-23469 fixed violations of
both on Linux and Windows):

- **Context ownership transfers on success.** `__exactWsConnect` allocates
  the `NativeWebSocketCallbackContext` with `ref_count == 1` and releases it
  only when `native_ws_connect` returns 0. A nonzero ws_id transfers that
  single reference to the native implementation, whose teardown path
  (`remove_connection` / `destroy_entry`) performs the one balancing
  release. Backends must **not** retain again at connect time — the extra
  reference leaks the context and the `jsi::Object` pinning the whole JS
  WebSocket instance on every successful connection. Callback invocations
  take their own short-lived retain/release pairs around each call.
- **Connect returns immediately; the handshake runs off the JS thread.**
  WHATWG requires connection establishment to run "in parallel". All three
  desktop backends allocate the ws_id, register the entry (so `close`/
  `destroy` on a CONNECTING socket work), and return; the
  handshake runs on the backend's io/delegate thread and reports failure as
  an error callback followed by `close(1006, unclean)`.

On Linux there is a third: **the io thread exclusively owns the CURL easy
handle.** libcurl forbids using one handle from two threads, and the io
thread frees the handle on exit, so the JS thread never touches it — sends
and client closes are enqueued (`outbound`, `close_requested` +
`close_code`/`close_reason` under `io_mutex`) and performed by the io
thread. A client close arms a 5s give-up deadline the moment the request is
observed (so a CLOSE frame that can never be written still cannot park
`readyState` at CLOSING forever), sends the CLOSE frame from the io loop,
then keeps reading — through a flow-control pause, discarding incoming data
frames, since WHATWG only fires message events while OPEN — until the
peer's CLOSE arrives (reporting the peer's code/reason) or the deadline /
connection teardown ends the wait (reporting the requested code with
`was_clean = 1`, the same shape Windows uses). The close-ack wait bounds
intentionally differ per backend: Windows completes the close handshake
synchronously inside `WinHttpWebSocketClose`, macOS delegates to
NSURLSession with a 1s grace period for the peer's frame, and Linux polls a
non-blocking socket so it uses a looser 5s upper bound.

Windows handle lifetime follows the same single-owner idea: pre-upgrade
handles (session/connect/request) belong to the handshake thread — a
concurrent close()/destroy only marks the entry closed (reporting an
unclean 1006, per WHATWG "fail the connection" for close-while-CONNECTING)
and the handshake thread disposes of its own handles when it notices,
because closing a handle out from under a blocking synchronous WinHTTP call
is documented-unpredictable. Post-upgrade, `WinHttpWebSocketSend` and
handle teardown serialize on `send_mutex` so a send can never run on a
freed (and possibly recycled) handle, and the per-entry `context_mutex`
makes a callback's context snapshot+retain atomic against the final
teardown release.

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
