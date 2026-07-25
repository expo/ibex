# Expose the inherited host environment through process.env in insecure mode

**Status:** Closed (2026-07-24)

## Resolution

Implemented as a launcher-installed **ambient environment projection**, doubly
gated: it compiles only under the `insecure` feature, and even then activates
only through an explicit `install_insecure_ambient_environment()` call at the
top of the CLI `main` (parent and re-exec'd session worker alike), so eval,
run, REPL/stdin-worker, and package-script routes observe one projection while
embedded runtimes never acquire it implicitly.

- Store: `src/host/process.rs` (`install_insecure_ambient_environment` +
  `insecure_ambient_env_*`) — snapshot of `std::env::vars_os()` at startup
  plus JS mutations; skips the `EXACT_IPC_FD`/`EXACT_IPC_SERIALIZATION`
  construction handshake and Windows `=C:=` pseudo-names; Windows lookups are
  case-insensitive with first-seen display spelling preserved.
- ABI: `ex_host_env_ambient_{active,get,set,key_count,key_at}`
  (`src/host/abi.rs`), classified in the CapSec coverage model
  (`env:read`/`env:write` effects; `active` is control-plane).
- Bridges: the armed branches of `__exactGetEnv`/`__exactSetEnv`/
  `__exactGetAllEnv` (`src/engine/hermes_runtime.cc`) serve the ambient store
  when active; the JS proxy needed no changes, so assignment, deletion,
  string coercion, enumeration, and child-process default-inheritance/`env`
  overlays are Node-compatible end to end.
- Secure boundary: the empty digest-bound base and per-principal overlays are
  untouched in every secure mode. Negative regressions:
  `tests/secure_process_env.rs` (dev-arming build; sentinel unreadable,
  unenumerated, base empty — passing), an `env_sentinel_hidden` probe in
  `scripts/check-secure-mode.sh`, and `tests/ambient_env_requires_install.rs`
  (runtime creation alone never activates the projection — the embedded
  contract). Positive coverage: `tests/insecure_process_env.rs` (eval, stdin
  worker, child inheritance/overlay, store semantics).
- Inventory/artifacts: the new `env::vars_os` read is dispositioned as a
  `launcher-pre-arm-read` in `capsec/registry/runtime-environment-inventory.json`;
  compiled-environment-profile classifies it `capture-primitive`; capsec
  registry/contract artifacts regenerated; `check:drift` green.
- Docs: LLP 0038 §"Fully open mode (insecure)" rewritten (the "empty in every
  mode" decision is superseded for insecure only), LLP 0025 §2 records why the
  projection is not a post-arm host read, Cargo.toml feature comment updated.

Windows behavior (case-insensitivity, `GetEnvironmentStringsW`-side pseudo-var
filtering) is implemented but was verified only by unit tests on macOS; the
Windows CI matrix exercises the rest.
**Severity:** P2
**Systems:** Runtime, Node Compatibility, Security, Embedded API
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-24
**Related:** LLP 0025 §2; LLP 0038 “Fully open mode (insecure)”; LLP 0039; ENG-22976; ENG-23115

## Problem

The `insecure` Cargo feature is intended to provide a no-sandbox development
mode with the ambient authority of the invoking user, close to Ibex's
pre-CapSec behavior. Filesystem access, process spawning, and networking are
open in this mode, but `process.env` remains empty because the runtime never
projects the inherited host environment into JavaScript.

That exception is surprising, breaks ordinary Node-compatible programs and
developer tooling, and makes insecure mode less useful as the compatibility
path while secure mode and target advertisement are still under construction.
LLP 0038 currently documents the empty environment as intentional in every
mode; that decision should change for `insecure` only.

## Required behavior

- An explicitly built `insecure` CLI exposes the process environment inherited at
  Ibex startup through `process.env`.
- Enumeration, direct reads, assignment, deletion, string coercion, and
  platform name semantics match Node closely enough for existing compatibility
  tests; Windows names remain case-insensitive.
- Child-process default inheritance and explicit `env` overlays observe the
  JavaScript-visible insecure environment consistently.
- REPL, `eval`, `run`, and package-script routes receive the same projection.
- Define and test the embedded-runtime contract. If an embedder must supply the
  initial environment explicitly, make that API clear; do not silently give
  secure embedded runtimes ambient host access.
- The red insecure-build banner remains. Making `process.env` useful does not
  weaken the warning that this mode has the invoking user's ambient authority.

## Security boundary

This must be gated by the compile-time `insecure` feature. Secure builds,
including `unadvertised-dev-arming`, must retain their authenticated empty base
plus explicitly authorized principal overlays and must not acquire an ambient
fallback. Add a negative regression proving a host-only sentinel is absent in
secure mode.

Update the runtime environment inventory, compiled environment profile,
generated artifacts, and LLP 0038/0039 language in the same change. Preserve
the environment-name and process-global mutation invariants owned by LLP 0025.

## Done when

- In insecure mode, an inherited sentinel is readable and enumerable through
  `process.env` on macOS/Linux and Windows.
- Assignment/deletion and subprocess inheritance have Node-compatible
  regression coverage.
- Secure CLI and embedded tests prove the same sentinel cannot leak without an
  explicit authorized projection.
- All environment-inventory, generated-drift, Node-compatibility, and secure
  mode checks pass.
