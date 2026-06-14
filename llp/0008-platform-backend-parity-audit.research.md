# LLP 0008: Platform Backend Parity Audit

**Type:** Research
**Status:** Draft
**Systems:** Engine, Build, Runtime
**Author:** Codex
**Date:** 2026-06-14
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
  build: fetch shells out to `curl`, WebSocket is unavailable, and the build
  emits a warning.

This pass also added Linux fetch cancellation plumbing. With libcurl, aborts
are observed by `CURLOPT_XFERINFOFUNCTION` and suppress the response callback;
in the degraded CLI fallback, abort suppresses callbacks but cannot kill the
already-running child `curl` process.

Android reuses the Linux native fetch/WebSocket files, but `build.rs` supplies
libcurl through the target-specific vendored `curl-sys` dependency and always
defines `EXACT_HAS_CURL` for that target.

## Filesystem

The best Linux filesystem backend is POSIX syscalls plus the Rust `ex_host_fs_*`
ABI for shared file operations. This pass fixed `fs.statfs()` on Linux to use
`statfs(2)` for the filesystem type field. Android and other non-Linux Unix
targets keep `statvfs(3)`.

Known platform reality: `lchmod()` is unavailable on Linux and remains an
`ENOSYS` path rather than a fabricated success.

## Sockets, DNS, and Process

TCP, UDP, Unix sockets, DNS, child processes, IPC, and signals use POSIX APIs on
Linux, Android, and Apple platforms. Windows has separate Win32/WinSock
implementations in `hermes_runtime_platform_windows.cc`.

This pass made TCP server listen setup try all `getaddrinfo()` candidates before
failing, matching the normal POSIX dual-stack pattern.

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
- Android is compile-wired with vendored curl/OpenSSL, but does not yet have an
  Android-native crypto backend.
- Linux full AES/asymmetric crypto still requires `openssl-crypto`; the default
  profile is intentionally reduced.
- The degraded Linux curl CLI fallback is not a production networking backend.
- Local macOS Cargo test builds are blocked by the currently installed Hermes
  headers not matching the C++ runtime API used by this checkout.

## Verification From This Pass

- `git diff --check` passed.
- `native_fetch_linux.cc` passed direct C++ syntax checks in both fallback and
  `EXACT_HAS_CURL` profiles.
- `native_websocket_linux.cc` passed direct C++ syntax checks in both fallback
  and `EXACT_HAS_CURL` profiles.
- `ref-check` was attempted and still fails only on inherited exact/snapback
  `@ref` comments documented as known debt in `AGENTS.md`.
- `cargo test --no-run --tests` was attempted. Without
  `EXACT_ALLOW_FALLBACK=1`, hermesc rejected the minified Web Streams bootstrap
  artifact. With `EXACT_ALLOW_FALLBACK=1`, the build reached the pre-existing
  Hermes header/API mismatch described above.
