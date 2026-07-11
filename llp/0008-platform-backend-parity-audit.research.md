# LLP 0008: Platform Backend Parity Audit

**Type:** Research
**Status:** Draft
**Systems:** Engine, Build, Runtime
**Author:** Codex
**Date:** 2026-06-14
**Revised:** 2026-07-11 (ENG-23541: Windows async fs worker-pool hooks and verified error/handle/durability semantics; previously 2026-07-09: Linux curl CLI fallback now spawns via posix_spawnp instead of std::system — ENG-23874; Windows Child Process section — ENG-23485; default-path DNS rcode fidelity and the raw UDP transport decision — ENG-23506)
**Related:** LLP 0001; LLP 0003; LLP 0005

## Purpose

This audit records Ibex's best-choice native backend for each runtime surface
and the June 2026 Linux parity pass. It is scoped to the host surfaces installed
by `installGlobals()` and wired by `build.rs`; product targets without a
`build.rs` arm, currently tvOS, remain tracked in LLP 0001.

## Linux Networking

Linux native networking is a libcurl-backed profile for Fetch and WebSocket:

- `native_fetch_linux.cc` uses libcurl for HTTP(S) fetch when `EXACT_HAS_CURL`
  is defined.
- `native_websocket_linux.cc` uses libcurl's WebSocket API, which requires
  libcurl >= 7.86.
- `build.rs` now treats libcurl >= 7.86 plus `pkg-config` as the supported
  Linux profile and fails closed when they are absent.
- `IBEX_ALLOW_CURL_CLI_FALLBACK=1` intentionally opts into a degraded local
  build: fetch runs the `curl` CLI, WebSocket is unavailable, and the build
  emits a warning.
- The CLI fallback spawns `curl` via `posix_spawnp` with an argv array — never
  a shell — and binds the URL with `--url` so request data (method, headers,
  URL) cannot be reinterpreted as shell syntax or curl options; request/response
  bodies stage through `mkstemp` (0600) temp files (ENG-23874; the earlier
  `std::system` transport made every future flag change a potential
  command-injection surface even though its arguments were shell-quoted).

This pass also added Linux fetch cancellation plumbing. With libcurl, aborts
are observed by `CURLOPT_XFERINFOFUNCTION` and suppress the response callback;
in the degraded CLI fallback, abort suppresses callbacks but cannot kill the
already-running child `curl` process.

## Windows Child Process

Windows has a real native **sync** spawn bridge (`__exactSpawnSync` in
`hermes_runtime_platform_windows.cc`; ENG-23115 brought base64 stdio, real
`process.env`, and `maxBuffer` parity), but **no async native spawn**.
`cp.spawn`/`exec`/`execFile` on win32 are emulated by
`_spawnSyncBackedChildProcess` in `src/builtins/child-process.js`: the child
runs to completion inside spawnSync and its buffered output is replayed
afterwards. Consequences (ENG-23485 finding #5):

- the event loop blocks for the child's entire lifetime;
- stdin writes and `kill()` can never reach the live child;
- IPC could never deliver a message to or from a live child.

Since ENG-23485 this is loud instead of silent: the emulation emits a one-time
`process.emitWarning`, and `'ipc'` stdio (including `fork`) throws `ENOTSUP`
on win32. A real async backend (CreateProcess + overlapped pipes implementing
the same `__exactSpawn*` host-function contract as POSIX) is tracked in
ENG-23500.

Android uses a Java/JNI OkHttp bridge for fetch and WebSocket. The C++ runtime
keeps the same `native_fetch_*` and `native_ws_*` symbols, while
`platform/android/java/dev/ibex/runtime/IbexNetworking.java` owns the Android
HTTP/WebSocket stack. The same app-context bridge supplies Android framework
data for raw DNS, clipboard, location, locale, screen metrics,
appearance/accessibility, camera permission/device metadata,
app lifecycle/configuration/deep-link events, and platform version. Apps
initialize it with `ex_android_initialize()`.

## Android Backend Matrix

The Android target should not be treated as "small Linux" when Android offers a
better app-runtime integration point. The June 2026 Android backend target is:

| Surface | Best Android backend | Current state | Completion rule |
| --- | --- | --- | --- |
| Fetch / `http` client / `https` client | OkHttp for HTTP(S), redirects, TLS, compression, connection pooling, and cancellation; app Network Security Config remains authoritative for cleartext, pins, and trust anchors. | C++/JNI bridge to `IbexNetworking.fetch()`; OkHttp redirects are disabled because JS implements Fetch redirect policy. | Verify HTTP, HTTPS, headers, POST body, redirect behavior, gzip/decompression, abort, and network errors on an Android runtime. |
| WebSocket / `ws` client | OkHttp `WebSocket`, using the same client/trust configuration as fetch. | C++/JNI bridge to `IbexNetworking.connectWebSocket()`. | Verify open, text/binary messages, close codes/reasons, errors, pause/resume semantics, and flow-control callbacks on Android. |
| DNS | Android `DnsResolver` where available for raw DNS record queries; fallback to Bionic/POSIX resolver for older API levels, unsupported record types, or resolver failure. | `resolve*` raw record queries call Android `DnsResolver` on API 29+ and fall back to `res_query`; `lookup` and reverse lookup still use Bionic/POSIX resolver APIs. | Verify `lookup`, `resolve*`, reverse lookup, and the Android API-level/failure fallback boundary. |
| TCP / UDP sockets | Bionic/POSIX sockets. These are Android's NDK-native socket APIs and preserve Node-compatible stream semantics better than Java sockets. | Uses POSIX socket code. | Keep POSIX backend; verify TCP connect/listen, UDP bind/send/recv, and Unix socket behavior expected by Android API levels. |
| Filesystem | Bionic/POSIX file APIs inside app-specific internal/cache directories supplied by the embedding host; Storage Access Framework belongs in app-level file pickers, not Node-compatible `fs`. | Uses POSIX plus host ABI. Android initialization now reads `Context` storage roots and seeds cwd/`HOME` from `filesDir`, temp env from `cacheDir`, explicit `EXACT_ANDROID_*` storage env vars, `__exactAndroidStoragePaths`, and the Rust runtime cache helper's Android cache root. | Keep POSIX backend; verify file, dir, stat, statfs, symlink/link unsupported cases, relative paths under `filesDir`, and temp/cache paths under `cacheDir`. |
| SQLite / IndexedDB / Web Storage | Bundled SQLite via `rusqlite` for deterministic runtime semantics; Android `SQLiteDatabase` is not a better fit for Bun/Node-style SQLite or IndexedDB compatibility. | Uses `rusqlite` and bundled SQLite. Shared-bundle `localStorage` now registers a lazy SQLite-backed native storage module under Android app `filesDir` when the native SQLite bridge is present; `sessionStorage` remains process-local. IndexedDB now opens per-database SQLite files under the same app storage root and persists version metadata. | Keep bundled SQLite; verify `exact:sqlite`, IndexedDB smoke, and web storage persistence on Android app storage. |
| Crypto / WebCrypto / Node `crypto` | Broad algorithmic crypto stays in the runtime crypto backend because WebCrypto and Node crypto need extractable keys and exact algorithm behavior. Android Keystore is the right backend only for future non-extractable, hardware-backed key storage APIs. | Requires vendored OpenSSL for full crypto. | Keep OpenSSL until an Android crypto provider covers the same algorithm matrix; separately add Keystore-backed non-extractable keys only when the JS surface can expose that distinction. Verify random, hash, HMAC, AES, PBKDF2/scrypt/HKDF, sign/verify, key generation/import/export, ECDH/X25519/Ed25519, RSA-OAEP. |
| Compression / zlib / Brotli | Vendored zlib/Brotli-compatible native code for deterministic JS semantics. | Vendored native code. | Keep; verify zlib and Brotli round trips. |
| Console | Android logcat through NDK logging for native runtime console output, while retaining host console callbacks for embedders. | `ex_host_console_log` mirrors Android console lines to `__android_log_print` and keeps the host/stdout queue. | Verify by logcat or an injectable test sink. |
| Timers / event loop / `performance` / RAF | Runtime timer queue driven by the host event loop; Android hosts should wake/poll from their Looper/Choreographer integration. `performance.now()` should use an NDK/native monotonic clock rather than wall-clock JS fallback, and `requestAnimationFrame()` should use Android `Choreographer` when the Java helper is present. | Engine-host facility. The Hermes host now exposes native steady-clock `__exactPerformanceNow()` plus runtime `__exactPerformanceTimeOrigin()`, and the JS `performance` singleton consumes them before installing globals. Android now exposes `__exactRequestAnimationFrame`, which posts through Java `Choreographer` and marshals the frame callback back onto the Hermes runtime thread; older helpers fall back to timer-based RAF. | Keep runtime timers; verify timeout/interval/immediate, cancellation, ref/unref, host wake callback, monotonic `performance.now()`, and Choreographer-backed RAF on Android. |
| HTTP server | Rust/hyper localhost server behind `host-http-server`; Android can run loopback servers when the embedding app opts in. | Feature-gated host backend or stubs. | Keep opt-in host server; verify listen, request body, response streaming, close, and Android app-network policy interactions. |
| Child process / IPC / signals | Android app sandboxes do not provide desktop Node child-process semantics. Best behavior is capability-gated POSIX where available and explicit unsupported errors where Android forbids it. | Android now installs child-process host functions that report `ERR_FEATURE_UNAVAILABLE_ON_PLATFORM` for spawn/exec/IPC instead of attempting desktop POSIX `fork`/`exec`/`popen` semantics in app sandboxes. POSIX process code remains for non-Android Unix targets. | Verify Android child-process, IPC, and signal surfaces produce honest unsupported or permission-denied behavior without fabricating process success. |
| OS info / process metadata | Bionic/sysconf/sysinfo/getifaddrs plus Android-specific values where exposed by the host. | POSIX plus Android Java/JNI globals for SDK version, locale tags, 24-hour preference, screen metrics, font scale, appearance, and accessibility snapshot. `os.type()` now reports Android, `os.release()`/`os.version()` use the Java host SDK version when present, and capability/permission diagnostics consume the same Android platform hints. | Verify `os`, `process`, `navigator`, `Dimensions`, `Appearance`, locale, and accessibility values on Android. |
| Clipboard | Android `ClipboardManager` through an app/Java host bridge. | Android installs `__exactClipboardRead/Write` backed by the initialized app context's `ClipboardManager`; `exact:clipboard` and `navigator.clipboard` use those hooks. | Verify read/write text and permission/foreground restrictions. |
| Location | Android framework `LocationManager` as the platform baseline; apps may adapt Google Play services above this runtime if desired. | Java/JNI bridge exposes permission status, location-services state, and current fixes through `__exactAndroidLocation`; JS `NativeLocationBackend` now uses it for `getCurrentPosition()` and a polling `watchPosition()` implementation. | Verify foreground app permissions, one-shot current fixes, permission-denied errors, timeout/errors, and watch behavior; replace polling with provider update callbacks if app-process testing shows polling is not sufficient. |
| Camera | CameraX for app-facing camera capture; Camera2/CameraManager for framework enumeration and lower-level specialized needs. | Android installs `__exactAndroidCameraHostCall` plus module metadata so the camera JS uses native permission, device inventory, and session-capability data from the Java/JNI bridge. The JS camera factory can now create an Android native session controller when `camera.provider.get` reports an app-installed session provider, and `IbexNetworking.setCameraHostProvider()` lets an app delegate those session/capture operations to a CameraX implementation. The built-in Java helper remains metadata-only without that provider. | Add/verify a production CameraX provider for preview lifecycle, photo capture, video capture, errors, and permission callbacks; keep the current CameraManager inventory smoke as a lower-level metadata check. |
| Window / navigator / React Native device APIs | App host bridge to Android resources, display metrics, locale, app state, deep links, appearance, and native dialogs. | Initial locale/screen/appearance/accessibility/platform-version values come from Android Resources, DateFormat, and AccessibilityManager through the Java/JNI bridge; Java `ComponentCallbacks` and `Application.ActivityLifecycleCallbacks` enqueue configuration, memory-warning, and app-state events, with public host hooks for Activity/intents/deep links. JS dispatch updates locale/accessibility/media queries, window resize/orientation events, navigator platform/app-version/CPU/memory/online hints, Android `AlertDialog`-backed `alert`/`confirm`/`prompt` when an Activity is available, and React Native `Dimensions`, `Appearance`, `AppState`, and `Linking` notifiers. | Verify initial values and foreground app-process change events for configuration, app state, memory warning, deep links, and native dialogs. |
| Inspector / workers / WASI / HTTP2 | Deliberate compatibility stubs unless a real Android-capable backend is designed. | Stubs/unsupported surfaces. | Keep explicit unsupported errors until an LLP defines support; tests should assert honest failure, not pretend success. |

The primary Android networking answer is therefore: use OkHttp. It is the
Android app stack with HTTP/2, pooling, transparent gzip, response caching, and
WebSocket support, and it naturally participates in Android's platform TLS and
Network Security Config behavior. The runtime should expose this through a
small Java/JNI bridge rather than linking libcurl into Android apps.

Reference points used for this matrix: OkHttp overview
<https://square.github.io/okhttp/>, Android Network Security Config
<https://developer.android.com/privacy-and-security/security-config>, Android
`DnsResolver` <https://developer.android.com/reference/android/net/DnsResolver>,
Android Keystore
<https://developer.android.com/privacy-and-security/keystore>, Android app data
storage <https://developer.android.com/training/data-storage>, CameraX
<https://developer.android.com/media/camera/camerax>, Android NDK logging
<https://developer.android.com/ndk/reference/group/logging>, Android
`Configuration` <https://developer.android.com/reference/android/content/res/Configuration>,
Android `DateFormat.is24HourFormat()`
<https://developer.android.com/reference/kotlin/android/text/format/DateFormat#is24HourFormat(android.content.Context)>,
and Android `AccessibilityManager`
<https://developer.android.com/reference/android/view/accessibility/AccessibilityManager>.

## Filesystem

The best Linux filesystem backend is POSIX syscalls plus the Rust `ex_host_fs_*`
ABI for shared file operations. This pass fixed `fs.statfs()` on Linux to use
`statfs(2)` for the filesystem type field. Android and other non-Linux Unix
targets keep `statvfs(3)`.

Known platform reality: `lchmod()` is unavailable on Linux and remains an
`ENOSYS` path rather than a fabricated success.

Windows uses `hermes_runtime_fs_windows.cc` over the same Rust host filesystem
ABI rather than CRT file descriptors. Since ENG-23541 it also registers the
worker-pool async hooks for whole-file reads/writes, fd chunk reads/writes,
`readv`/`writev`, `stat`/`lstat`/`fstat`, and supported directory/path ops
(`readdir`, `mkdir`, `rmdir`, `unlink`, `rename`, `copyfile`, `realpath`,
`access`, `chmod`, `mkdtemp`). The Windows fd handles are shared between sync
and async paths through a `shared_ptr` wrapper with a per-handle I/O mutex so
the Rust save-cursor positional read/write shims cannot interleave on the same
fd. Unsupported Windows fs operations still fail honestly with `ENOSYS` until
host hooks exist. Durability is no longer one of those gaps: the opaque host
handle exposes `File::sync_all` / `File::sync_data`, so Windows
`fsync`/`fdatasync` reach `FlushFileBuffers`. The remaining unsupported set is
the path metadata/link operations that the Windows shim does not implement.

## Sockets, DNS, and Process

TCP, UDP, Unix sockets, DNS, child processes, IPC, and signals use POSIX APIs on
Linux, Android, and Apple platforms. Windows has separate Win32/WinSock
implementations in `hermes_runtime_platform_windows.cc`.

This pass made TCP server listen setup try all `getaddrinfo()` candidates before
failing, matching the normal POSIX dual-stack pattern.

Default-path DNS record queries (`dns.resolve*` without `setServers`) do not use
`res_query`/`res_nsend` as their primary transport, because libresolv flattens
resolver rcodes: `res_nsend` treats SERVFAIL/NOTIMP/REFUSED responses as "skip
to the next server" and, once all servers are skipped, fails with a generic
timeout (verified empirically on macOS libresolv against a loopback mock server;
glibc's `send_dg` has the same next-ns skip). Node's c-ares resolver reports the
actual rcode, so to match its error codes (`ESERVFAIL`, `EREFUSED`, `ETIMEOUT`,
`ENOTFOUND`, `ENODATA`) the native side sends the query on its own UDP socket
against the nameservers `res_ninit` reports and inspects the rcode itself
(`src/engine/hermes_runtime_dns.cc`, ENG-23506). Truncated responses and
configurations without a usable IPv4 nameserver fall back to `res_query` (which
handles the TCP retry) at the cost of rcode fidelity. `IBEX_DNS_SERVER`
(`ip[:port]`) overrides the nameserver list so tests can exercise the default
path against a loopback mock server hermetically, and the standard `RES_OPTIONS`
`timeout:`/`attempts:` tokens are honored on every platform (macOS libresolv
ignores them natively). Android keeps the `DnsResolver`/`res_query` transports
but maps non-zero rcodes in returned packets the same way. `lookup` and reverse
lookup stay on `getaddrinfo`/`getnameinfo` and map `EAI_*` failures the way
libuv does (`EAI_NONAME`/`EAI_NODATA` → `ENOTFOUND`, `EAI_AGAIN` passes
through). Windows' `__exactDnsResolve` is a `getaddrinfo`-based stub with no
record-query transport, so it has no rcode to preserve; the JS-side code mapping
in `src/builtins/dns.js` is shared across platforms.

## OS Info

`os` host functions use `sysconf`, `sysinfo`, `sysctl`, `getifaddrs`, and
platform user APIs. This pass changed network interface reporting to read real
link-layer MAC addresses from `AF_PACKET` on Linux and `AF_LINK` on Apple
instead of returning `00:00:00:00:00:00` for every interface.

## Crypto

Crypto remains a two-profile Linux surface:

- Default Linux profile: no OpenSSL link; portable hash/HMAC/PBKDF2/scrypt/HKDF
  support.
- `openssl-crypto`: full Linux native crypto through OpenSSL, including AES,
  asymmetric operations, key import/export, ECDH/X25519/Ed25519, and RSA-OAEP.

Apple uses CommonCrypto/Security in the non-Windows shim. Android currently
requires `openssl-crypto` with vendored OpenSSL. Windows uses the
Windows-specific crypto file and BCrypt/CNG.

## HTTP Server, SQLite, Console, Timers, and IPC

The host HTTP server is Rust/hyper behind the `host-http-server` feature; builds
without that feature intentionally compile C++ stubs. SQLite bridges to
`rusqlite` and bundled SQLite. Console, timers, and callback dispatch are
engine-host facilities rather than OS-specialized backends. IPC uses the POSIX
or Windows process/socket primitives provided by the platform files.

## Current Residual Gaps

- tvOS still has no first-class `build.rs` target arm; see LLP 0001.
- Android fetch/WebSocket now use the OkHttp bridge and have an emulator
  OkHttp smoke, but still need full fixture verification for redirects,
  request/response bodies, aborts, WebSocket frames, close, and error paths.
- Android raw DNS record queries use `DnsResolver` on API 29+ with POSIX
  fallback, while lookup and reverse lookup remain on Bionic/POSIX resolver
  APIs; all DNS paths still need app-process verification.
- Android console output is routed to logcat but still needs device/emulator
  verification.
- Android app/device APIs that need Java/Kotlin host participation remain
  incomplete for full CameraX preview/capture. Initial window/navigator locale,
  screen, appearance/accessibility, platform version, app storage roots,
  clipboard, location, camera permission/device metadata,
  camera session-provider dispatch, app-state, deep-link, and configuration data/events now use the Android
  Java/JNI bridge. The environment, location permission, queued platform-event,
  app storage root, and camera metadata probes were smoke-tested on an emulator
  through `app_process`; foreground app-process verification is still required
  for clipboard, granted-location fixes, real Activity/configuration/deep-link
  event delivery, and CameraX preview/capture.
- Android crypto still uses vendored OpenSSL. That is acceptable for today's
  broad WebCrypto/Node crypto algorithm surface, but it is not a Keystore-backed
  non-extractable key backend.
- Android child-process host functions now return explicit
  `ERR_FEATURE_UNAVAILABLE_ON_PLATFORM` results for spawn/exec/IPC instead of
  running POSIX child-process code in app sandboxes; JS mapping still needs a
  runtime smoke on Android.
- Android OS metadata now maps the Java host SDK version into
  `__exactPlatformVersion`, platform state, and `process.__exactOS*`, and the
  JS `os` builtin reports Android-specific type/release/version values.
  Capability/permission diagnostics now use those same hints when no native
  capability module supplies system info; this still needs an Android runtime
  smoke.
- Linux full AES/asymmetric crypto still requires `openssl-crypto`; the default
  profile is intentionally reduced.
- The degraded Linux curl CLI fallback is not a production networking backend.

## Android Verification Required

Android completion requires more than cross-compilation. The verification pass
must run on an Android runtime or emulator and exercise:

- Fetch and WebSocket against local HTTP/HTTPS/WS/WSS fixtures, including
  cancellation and error paths.
- DNS lookup/resolve/reverse, including the Android API-level fallback branch.
- TCP, UDP, filesystem, SQLite, Web Storage, IndexedDB, crypto, compression,
  timers, console/logcat, OS/process metadata, and HTTP server smoke tests.
- Honest unsupported behavior for child-process restrictions, inspector,
  workers, WASI, HTTP2, and any mobile API whose host bridge is not installed.
- App-bridge APIs: clipboard, location, camera, window/navigator, React Native
  device/app-state/deep-link data, and accessibility/configuration changes.

## Verification From This Pass

- `bun run build:builtins` regenerated the clipboard builtin after adding
  `__exactClipboardRead/Write` hooks.
- `bun run build:runtime` regenerated `vendored-generated/embedded_runtime_bundle.js`
  after wiring `packages/ibex-runtime-js/src/location/index.ts` to the Android
  location bridge.
- A later `bun run build:runtime` regenerated the same runtime bundle after
  wiring Android platform-event dispatch to the JS window and React Native
  compatibility shims.
- A later `bun run build:runtime` regenerated the same runtime bundle after
  wiring the camera module to Android camera host metadata and host-call
  globals.
- A later `bun run build:builtins` regenerated the OS builtin after mapping
  Android `os.type()`, `os.release()`, and `os.version()` to platform-native
  metadata.
- A later Bun source smoke verified capability/permission diagnostics report
  Android OS name and SDK version from platform-native metadata. `bun run
  build:runtime` was run afterward and produced no generated bundle diff for
  this exported diagnostics-only path.
- A later `bun run build:runtime` regenerated the runtime bundle after making
  navigator app-version, hardware-concurrency, and device-memory hints consume
  Android/native platform metadata.
- A later `bun run build:runtime` regenerated the runtime bundle after making
  `navigator.onLine` infer online status from native network-interface data
  when available.
- A later `bun run build:runtime` regenerated the runtime bundle after wiring
  window `alert()`, `confirm()`, and `prompt()` to an Android
  Activity/`AlertDialog` bridge with an app-installed provider hook.
- A later `bun run build:runtime` regenerated the runtime bundle after wiring
  the web `performance` singleton to native Hermes host timing functions backed
  by `std::chrono::steady_clock`.
- A later `bun run build:runtime` regenerated the runtime bundle after wiring
  shared-bundle `localStorage` to a lazy SQLite-backed native storage module
  rooted under Android app storage and moving default IndexedDB databases from
  in-memory SQLite to per-database SQLite files with persisted version metadata.
- A later `bun run build:runtime` regenerated the runtime bundle after wiring
  `requestAnimationFrame()` to an optional Android `Choreographer` bridge with
  timer fallback for older Java helpers.
- The dialog bridge slice could not rerun a local Java helper compile because
  `javac` failed with no installed Java Runtime in this environment. The
  JS dialog-hook smoke and Android C++ cross-build passed; foreground Activity
  dialog verification remains part of the Android app-process pass.
- The Choreographer RAF slice had the same local Java compiler limitation. The
  source and generated-bundle RAF host-hook smokes and Android C++ cross-build
  passed; device/emulator verification must still confirm the Java
  `Choreographer` callback path.
- `cargo fmt --check` passed.
- `git diff --check` passed.
- ENG-23541 Windows fs verification passed on the Windows build host with
  Visual Studio Build Tools and the local Hermes Windows SDK:
  `cargo check --lib` compiled the Windows C++ bridge, and an
  `IBEX_NO_BYTECODE=1 cargo run --bin ibex -- run winfs-smoke.js` smoke
  confirmed all eight async fs hooks were installed and exercised
  readFile/writeFile/stat/readv/writev, zero-length fd read/write, empty
  append-create, and directory/path operations. The smoke output reported all
  hooks `true`, `readvText:"bc"`, `out:"abcZZf"`, zero byte counts, and
  `emptyAppendExists:true`.
- The recovered ENG-23541 hardening was recompiled on that Windows host with
  `cargo check --lib`. `cargo test --test windows_fs_bridge_contract` passed
  four source/ABI contract checks, and `cargo test --test windows_fs_async`
  passed the runtime regression covering normalized `ENOENT`/`EEXIST`, append
  through an fd after its path was renamed, handle-based `fstat`, and real
  `fsync`/`fdatasync`. The older cross-platform fs suites currently assume a
  POSIX `/tmp` from `os.tmpdir()` and therefore are not valid Windows evidence.
- The Android Java helper compiled with Android API 36 plus OkHttp 5.4.0,
  Okio 3.17.0, and Kotlin stdlib 2.1.21.
- `ANDROID_TARGET=aarch64-linux-android ./scripts/cargo-android.sh` passed,
  linking the Android Hermes/JSI, vendored OpenSSL, Android log, and JNI bridge
  path. The only warnings were the pre-existing OpenSSL RSA deprecation and
  `hermes_runtime_fs.cc` unused `mode` warning.
- `cargo metadata --format-version 1 --no-deps` plus `rg` found no remaining
  `curl-sys` or `libz-sys` dependency entries after removing Android libcurl.
- Emulator smoke on `sdk_gphone64_arm64` API 36 through `app_process` verified
  the Java bridge can initialize with an Android context and read SDK version
  `36`, locale `[en-US]`, 24-hour preference fallback, screen metrics, and
  accessibility flags. The same smoke confirmed OkHttp reached
  `https://example.com/` with status `200` over `h2`.
- The same emulator smoke verified the UID-aware Android location permission
  guard returns `denied` under shell/system context and `getCurrentLocation()`
  reports `PERMISSION_DENIED` instead of crashing or fabricating a fix.
- The emulator smoke also verified queued Java platform events can be produced
  through `notifyDeepLink()`, `notifyActivityStarted()`, `notifyActivityStopped()`,
  and `drainPlatformEvents()` in the Java helper. Foreground Activity delivery
  through a real app process is still required.
- Later emulator smokes verified the Android Java camera host call returns
  native camera and microphone permission JSON, visible camera device IDs from
  CameraManager, session-capability JSON, metadata-only provider status, and an
  app-installed provider dispatch path through `cameraHostCall()`. Full CameraX
  preview/session/photo/video capture still requires foreground app
  verification.
- A later Java/JNI storage smoke verified Android `Context` storage roots are
  exposed through `IbexNetworking.storagePaths()`, cached by the JNI bridge,
  and used to seed app `HOME`/cwd and cache-backed `TMPDIR`/`TMP`/`TEMP`.
- A 2026-06-14 rerun on connected emulator `emulator-5554` verified the
  existing dex smoke jars still execute through `app_process`. The platform
  smoke confirmed app-specific storage roots under `/data/local/tmp`, deep-link
  event queuing, and active/background app-state transitions. The camera smoke
  confirmed Android permission JSON reports shell-context UID mismatch instead
  of a false grant, CameraManager device inventory is visible, session
  capabilities are returned, metadata-only sessions fail explicitly, and an
  app-installed camera provider dispatch path is honored.
- A later Android cross-build verified the child-process host functions compile
  to explicit Android unsupported results; full JS-level Android runtime smoke
  remains required.
- The emulator smoke also exposed two shell-harness limits: direct Java
  `DnsResolver.rawQuery()` timed out under `app_process`, so the C++ DNS path
  now falls back to POSIX resolver on Android resolver failure; clipboard was
  denied because shell UID 2000 is not a foreground app package.
- `ref-check` was attempted and still fails only on inherited exact/snapback
  `@ref` comments documented as known debt in `AGENTS.md`.
