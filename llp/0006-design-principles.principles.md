# LLP 0006: Ibex Design Principles

**Type:** Principles
**Status:** Draft
**Systems:** Runtime, Engine, Host ABI, Build, Crypto
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Related:** LLP 0000; LLP 0002 (Host ABI); LLP 0003 (engine bridge); LLP 0005 (build pipeline)

## Summary

These are the cross-cutting beliefs that show through Ibex's structure — the
"always/never" that explain choices an individual file doesn't justify on its
own. Each principle states what is **observed** in the code and, separately,
the **inferred** rationale. Because the rationale here is reconstructed rather
than confirmed by a named author, this document stays `Draft`.

## A runtime, not a framework

**Observed:** The repo is the JS/TS runtime (Hermes engine, module loader, host
ABI, embedded JS layer) and explicitly *not* the app/CLI layer; the README says
it is "not a full application framework" `[observed]` (`README.md:3-10`). The
crate is a `staticlib`+`rlib` meant to be linked, not run as a product
`[observed]` (`Cargo.toml:1-11`).

**Inferred:** `[inferred: keeping the runtime free of app concerns is what lets
two unrelated consumers (Exact, Snapback) depend on it without each vendoring a
monorepo — the same reason it was extracted (LLP 0000 §Overview, exact LLP
0180).]`

## A narrow, stable embedding contract

**Observed:** The consumer surface named in the README is small and explicitly
bounded: five C functions plus `host::{install_host, Host}` `[observed]`
(`README.md:24-30`). The C header exports additional poll/render/debugger/heap
helpers beyond those five `[observed]` (`include/exact_runtime.h:71-98,
109-195, 215-264`; [LLP 0002](./0002-host-embedding-abi.spec.md)). There is an
explicit ABI version constant (`EXACT_HOST_ABI_VERSION = 1`) `[observed]`
(`src/host/abi.rs:62, 578-581`).

**Inferred:** `[inferred: a deliberately narrow contract is what makes a shared
runtime safe to version and depend on — the broad poll/debugger/render surface
is convenience that can evolve, while the five-function core is the part
consumers pin against. The semver-major framing is inherited from exact LLP
0038 rather than proven by code in this checkout.]`

## Hermetic by default, regeneration by opt-in

**Observed:** The default generated-JS path uses committed
`vendored-generated/` artifacts and does not need bun or `node_modules`;
regeneration is gated behind `IBEX_REGENERATE_RUNTIME=1`; missing artifacts fail
the build loudly rather than silently regenerating `[observed]`
(`build.rs:321-345`; [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md)).

**Inferred:** `[inferred: failing closed is a direct response to the
silent-Linux-regression that triggered the extraction (LLP 0001, exact LLP
0180) — a hermetic default makes builds reproducible for consumers who don't
have the JS toolchain, and the loud failure keeps "is this build still
hermetic?" an observable property rather than a latent surprise.]`

## Platform-native crypto, with honest reduced profiles

**Observed:** Crypto backend is chosen per platform/profile, but the reduced
profiles are not uniform. Apple uses CommonCrypto/Security in the non-Windows
crypto file `[observed]` (`src/engine/hermes_runtime_crypto.cc:23-44`); Windows
compiles a separate BCrypt-backed file `[observed]`
(`build.rs:729-765`; `src/engine/hermes_runtime_crypto_windows.cc:141-221`);
Linux defines `EXACT_NO_OPENSSL` unless `openssl-crypto` is enabled
`[observed]` (`build.rs:824-831`). The non-Windows no-OpenSSL path registers
throwing stubs for asymmetric sign/verify/key generation `[observed]`
(`src/engine/hermes_runtime_crypto.cc:1995-2026`), while the Windows file does
not register those asymmetric stubs and the non-Apple hash/HMAC code still
contains OpenSSL references outside the feature gate `[observed]`
(`src/engine/hermes_runtime_crypto.cc:61-73, 441-458, 519-532`).

**Inferred:** `[inferred: preferring the OS-native crypto avoids shipping and
trusting a bundled crypto library on platforms that already provide a vetted
one; the throwing-stub choice trades a clean ReferenceError for a clear
"rebuild with openssl-crypto" error on the paths that implement it, which is
more debuggable. This is also the most fragile build axis (LLP 0001), so making
degraded states explicit at the JS boundary is defensive.]`

## Hermes today, but keep an engine seam

**Observed:** Hermes is the only engine, reached through **JSI** and a C ABI:
`src/engine/hermes_runtime.cc` includes Hermes/JSI headers and constructs a
Hermes runtime `[observed]` (`src/engine/hermes_runtime.cc:14-15, 1391-1403`).
The public C symbols still name Hermes (`ex_hermes_*`) `[observed]`
(`include/exact_runtime.h:34-65, 151-156`). Native capability access is routed
through a generic `__hostCall(op, argsJson)` string channel plus typed host
functions
([LLP 0002](./0002-host-embedding-abi.spec.md),
[LLP 0003](./0003-hermes-engine-bridge.explainer.md)).

**Inferred:** `[inferred: routing through JSI and a C ABI rather than
Hermes-specific internals keeps the embedding boundary shaped like an
engine-replaceable seam in some places, even though the current API names Hermes
and no second engine exists in the tree.]` This is a posture, not a committed
multi-engine plan.

## Prefer typed host functions; reserve the generic bridge

**Observed:** High-traffic subsystems get dedicated JSI host functions installed
(often lazily via `__exactEnsure*`) `[observed]`
(`src/engine/hermes_runtime.cc:1056-1072, 1197-1283`), while `__hostCall` is
the catch-all string/JSON channel `[observed]`
(`src/engine/hermes_runtime.cc:1754-1806`).

**Inferred:** `[inferred: the generic bridge keeps the surface small and easy to
add to; dedicated functions exist where the per-call JSON encode/parse and
string dispatch of `__hostCall` would cost too much. The split is "narrow
default, specialize under load."]`

## Capability-gated host, explicit host mode

**Observed:** `Host` carries a `SecurityMode` (`Permissive | Capability |
Strict`) and a `CapabilityManager`; module/file access is checked against
capabilities, and the C++ bridge fast-paths allow-all mode via
`ex_host_is_allow_all()` `[observed]` (`src/host/mod.rs:29-38, 156-174`;
`src/host/abi.rs:597-599`). `HostConfig::default()` is strict, while
`Host::default_legacy()` and `ex_host_install()` install a permissive legacy
host `[observed]` (`src/host/mod.rs:57-68, 129-143`;
`src/host/abi.rs:586-592`).

**Inferred:** `[inferred: the capability layer exists so an embedder can
sandbox untrusted JS, while the legacy C entry point stays permissive so
existing embedders/tests can preserve old behavior; stricter behavior is
available to Rust embedders through explicit host configuration.]`

## Degrade diagnostics, never the caller

**Observed:** Best-effort diagnostics are made non-fatal: console stdio
mirroring goes through a bounded queue that *drops* lines under backpressure
rather than blocking or aborting `[observed]` (`src/host/abi.rs:157-225,
1789-1814`); a throwing one-shot timer is retired so it cannot refire
`[observed]` (`src/engine/mod.rs:94-128`).

**Inferred:** `[inferred: the runtime is embedded in long-lived app hosts (iOS),
so a stalled console consumer or a misbehaving timer must not take down the
host — diagnostics are sacrificed before liveness.]`

## Notes

Several of these are reconstructed from code structure and in-code `@tactical`/
`@system` annotations that point at exact/snapback LLPs (0038, 0086, 0159, 0176,
0177, 0178) not present in this repo. Where this document marks rationale
`[inferred]`, a maintainer with that history can confirm or correct it; until
then it stays `Draft`.
