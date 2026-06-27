# LLP 0002: The Host / Embedding ABI

**Type:** Spec
**Status:** Draft
**Systems:** Host ABI, Engine, Runtime
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Related:** LLP 0000; LLP 0003 (Hermes engine bridge)

## Summary

This document describes the boundary that consumers (Exact, Snapback) link
against to embed Ibex. There are two halves: a small **C ABI** exposed from the
C++ Hermes adapter (`ex_hermes_*`) that creates and drives a runtime instance,
and a **Rust host surface** (`host::{install_host, Host}` plus the `ex_host_*` C
functions) that the engine calls back into for native capabilities. The
"narrow, stable contract" the root document names is the subset of this surface
treated as semver-major: the lifecycle/eval functions plus the host-call bridge
installer. The full `ex_host_*` callback surface is broader but is an
implementation detail of how the engine reaches native services.

This doc records what is observable in the extracted repo and owns the local
Ibex embedding contract map.

## The narrow consumer contract (semver-major)

The root document (LLP 0000 §Key invariants) names five C functions as the
stable contract. All five are declared in
`include/exact_runtime.h` and defined in `src/engine/hermes_runtime.cc`:

- `ExactHermesRuntime* ex_hermes_create(void)` `[observed]`
  (`include/exact_runtime.h:38`; defined `src/engine/hermes_runtime.cc:1388`) —
  creates a Hermes runtime with all globals/bootstrap installed; returns an
  opaque handle or NULL.
- `void ex_hermes_destroy(ExactHermesRuntime*)` `[observed]`
  (`include/exact_runtime.h:41`; `src/engine/hermes_runtime.cc:1455`).
- `int ex_hermes_eval(runtime, data, len, source_url, is_bytecode, out_value)`
  `[observed]` (`include/exact_runtime.h:56`; `src/engine/hermes_runtime.cc:1464`) —
  evaluates UTF-8 JS source or Hermes bytecode; on success `out_value` points to
  a malloc'd result string (or NULL for `undefined`); returns 0 on success,
  non-zero on error with the message in `out_value`.
- `void ex_hermes_free_string(char*)` `[observed]`
  (`include/exact_runtime.h:65`; `src/engine/hermes_runtime.cc:1809`) — frees any string the
  ABI returns; it is a thin wrapper over `free()`.
- `void ex_hermes_set_host_call(runtime, callback)` `[observed]`
  (`include/exact_runtime.h:154`; `src/engine/hermes_runtime.cc:1754`) — installs the
  generic `__hostCall(op, argsJson)` JS function backed by the host callback.

Treating these as the semver-major contract is asserted in LLP 0000; this doc
does not re-derive the inherited rationale `[inferred: the five are singled out
because they are the minimum surface a host must call to stand up and drive a
runtime — everything else is either a richer convenience (poll, timers,
debugger) or a callback the engine makes, not one the host makes]`.

## What actually crosses the boundary

The header `include/exact_runtime.h` declares far more than five functions
`[observed]` — runtime lifecycle, an event-loop poll API
(`ex_hermes_poll`, `ex_hermes_next_timer`, `ex_hermes_has_pending_tasks`,
`ex_hermes_notify_callback`, `include/exact_runtime.h:76-98`), iOS rendering
callbacks (`ex_hermes_set_dispatch_callback` and siblings,
`include/exact_runtime.h:109-195`), a
debugger surface (`include/exact_runtime.h:216-249`), and GC/heap introspection
(`include/exact_runtime.h:256-264`).
These are part of the embedding API but are convenience/optional layers, not the
minimal contract `[inferred]`.

### The `__hostCall` bridge — the generic host channel

`ex_hermes_set_host_call` installs a JSI host function named `__hostCall` on the
global object `[observed]` (`src/engine/hermes_runtime.cc:1754-1806`). It is the generic,
string-typed channel from JS to the host:

- JS calls `__hostCall(op, argsJson)` with two strings `[observed]`
  (`src/engine/hermes_runtime.cc:1773-1774`).
- The host callback returns a malloc'd C string whose **first byte is a status
  sigil**: `+` = success (the remainder is a JSON payload), `-` = error (the
  remainder is the message, raised as a `jsi::JSError`) `[observed]`
  (`src/engine/hermes_runtime.cc:1781-1804`). A NULL or empty return becomes JS `null`.
- The C++ side frees the returned string with `free()` and `JSON.parse`s the
  success payload back into a JS value `[observed]` (`src/engine/hermes_runtime.cc:1785,
  1802-1804`).

On the JS side, the runtime wrapper calls `globalThis.__hostCall` directly and
throws if it is not installed `[observed]`
(`packages/ibex-runtime-js/src/core/host-call-bridge.ts:1-16`).

## The Rust host surface

The engine declares the `ex_host_*` callbacks as `extern "C"` functions on the
C++ side `[observed]` (`src/engine/hermes_runtime.cc:203-235`). They are
implemented in Rust in `src/host/abi.rs` and resolve their behavior through a
process-global `Host` singleton.

### Installing the host

- `host::install_host(host: Host)` stores (or replaces) the singleton in a
  `OnceLock<RwLock<Host>>` `[observed]` (`src/host/abi.rs:64, 107-121`). A second
  call replaces the current host rather than failing `[observed]`
  (`src/host/abi.rs:108-118`, test `install_host_replaces_existing_host` at
  `src/host/abi.rs:1857`).
- `ex_host_install()` is the C entry point that installs a default permissive
  ("legacy"/allow-all) host `[observed]` (`src/host/abi.rs:586-592`). The source
  comment says the iOS/Swift path calls this, while the CLI calls
  `install_host` with a configured `Host` `[observed]`
  (`src/host/abi.rs:586-588`; `src/bin/ibex/runtime.rs`).
- `EXACT_HOST_ABI_VERSION` is `1`, returned by `ex_host_version()` `[observed]`
  (`src/host/abi.rs:62, 579-581`).

### The `Host` type

`Host` (`src/host/mod.rs:71-76`) holds a `HostConfig`, an
`Arc<CapabilityManager>`, and an `Arc<ModuleLoader>` `[observed]`. Constructors
include `Host::new(config)`, `Host::default_legacy()` (permissive), and
`Host::strict()` `[observed]` (`src/host/mod.rs:80, 130, 138`). `HostConfig`
itself defaults to `SecurityMode::Strict`, so "default host" is ambiguous:
Rust configuration defaults strict, while `ex_host_install()` intentionally
installs the legacy permissive host `[observed]`
(`src/host/mod.rs:57-68, 129-143`; `src/host/abi.rs:586-592`). `Host` exposes
`check_capability`, `is_allow_all`, and `resolve_module` `[observed]`
(`src/host/mod.rs:146-174`). `SecurityMode` is `Permissive | Capability |
Strict` `[observed]` (`src/host/mod.rs:29-38`); the C++ bridge short-circuits
capability checks when `ex_host_is_allow_all()` returns 1 `[observed]`
(`src/host/abi.rs:597-599`).

### What the host backs

The `ex_host_*` functions in `src/host/abi.rs` implement, against std/rusqlite/
getrandom: filesystem ops (`ex_host_fs_*`, `src/host/abi.rs:601-1262`), SQLite
(open/prepare/all/get/run/exec, `src/host/abi.rs:1264-1698`), env/time/random
(`src/host/abi.rs:1700-1737`), console mirroring (`ex_host_console_log`,
`src/host/abi.rs:1739`), capability check/grant/log
(`src/host/abi.rs:661-727`), and module resolution (`ex_host_module_resolve`,
`src/host/abi.rs:730-779` — see [LLP 0004](./0004-module-loading-and-builtins.explainer.md)).
Strings returned to C are malloc'd via `CString::into_raw` and freed by
`ex_host_free_string`/`ex_host_free_buffer` `[observed]`
(`src/host/abi.rs:781-789, 650-659`).

### Memory ownership rules (observed)

- Strings out of the `ex_hermes_*` API are freed with `ex_hermes_free_string`
  `[observed]` (`include/exact_runtime.h:64-65`).
- Strings out of the `ex_host_*` API are freed with `ex_host_free_string`; raw
  buffers from `ex_host_fs_read_file` are freed with `ex_host_free_buffer`
  `[observed]` (`src/host/abi.rs:650-659, 781-789`).
- The `__hostCall` callback's returned string is freed by the C++ side, not the
  host `[observed]` (`src/engine/hermes_runtime.cc:1785`).

## Lifecycle (observed)

1. Host installs itself first: a Rust embedder can call
   `install_host(Host::new(...))`; the local `ibex` binary does this from CLI
   security flags, while the C entry point `ex_host_install()` installs the
   legacy permissive host `[observed]`
   (`src/host/abi.rs:107-121, 586-592`). The CLI/iOS split is recorded in a
   source comment and now in the local binary implementation `[observed]`
   (`src/host/abi.rs:586-588`; `src/bin/ibex/runtime.rs`;
   [LLP 0010](./0010-ibex-binary-ownership.decision.md)).
2. `ex_hermes_create()` builds the Hermes runtime, installs globals and runs
   bootstrap (see [LLP 0003](./0003-hermes-engine-bridge.explainer.md)).
3. `ex_hermes_set_host_call()` wires `__hostCall` so JS can reach the host.
4. The host drives execution via `ex_hermes_eval` and may pump the loop with
   `ex_hermes_poll(now_ms)` `[observed]` (`include/exact_runtime.h:71-91`;
   `src/engine/hermes_runtime.cc:1815-1949`). Source comments document a
   `cli-notify` replacement for the default callback path `[observed]`
   (`src/engine/mod.rs:18-37`).
5. `ex_hermes_destroy()` tears the runtime down `[observed]`.

## Notes / boundaries

- The Rust crate is named `ibex-runtime`. Many C ABI symbols and JavaScript
  internals remain `ex_`/`EXACT_`-prefixed for compatibility `[observed]`
  (`Cargo.toml:2`; LLP 0000 §Architecture).
- This is a Spec of the *observed* contract surface; changes to the narrow
  consumer contract should update this document and LLP 0000 together.
