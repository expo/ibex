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
ABI, embedded JS layer) and explicitly *not* the app/CLI layer — those live in
`exact` (`README.md`; LLP 0000 §Overview). The crate is a `staticlib`+`rlib`
(`Cargo.toml` `[lib] crate-type`) meant to be linked, not run as a product.

**Inferred:** `[inferred: keeping the runtime free of app concerns is what lets
two unrelated consumers (Exact, Snapback) depend on it without each vendoring a
monorepo — the same reason it was extracted (LLP 0000 §Overview, exact LLP
0180).]`

## A narrow, stable embedding contract

**Observed:** The consumer surface is small and explicitly bounded: five C
functions plus `host::{install_host, Host}`, called out as semver-major in
LLP 0000 and exact LLP 0038, even though the C++ adapter exports many more
symbols (`include/exact_runtime.h`; [LLP 0002](./0002-host-embedding-abi.spec.md)).
There is an explicit ABI version constant (`EXACT_HOST_ABI_VERSION = 1`,
`src/host/abi.rs:62`).

**Inferred:** `[inferred: a deliberately narrow contract is what makes a shared
runtime safe to version and depend on — the broad poll/debugger/render surface
is convenience that can evolve, while the five-function core is the part
consumers pin against.]`

## Hermetic by default, regeneration by opt-in

**Observed:** The default `cargo build` uses committed `vendored-generated/`
artifacts and must not need bun or `node_modules`; regeneration is gated behind
`IBEX_REGENERATE_RUNTIME=1`; missing artifacts fail the build loudly rather than
silently regenerating (`build.rs:321-345`;
[LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md)).

**Inferred:** `[inferred: failing closed is a direct response to the
silent-Linux-regression that triggered the extraction (LLP 0001, exact LLP
0180) — a hermetic default makes builds reproducible for consumers who don't
have the JS toolchain, and the loud failure keeps "is this build still
hermetic?" an observable property rather than a latent surprise.]`

## Platform-native crypto, with honest reduced profiles

**Observed:** Crypto backend is chosen per platform — CommonCrypto/Security on
Apple, BCrypt (`crypto_windows.cc`) on Windows, OpenSSL on Linux/Android — and
where a real backend is absent the runtime registers the **same JS surface as
throwing stubs** with an actionable message rather than omitting the global
(`src/engine/hermes_runtime_crypto.cc:1995-2026`; LLP 0001 §2.1;
[LLP 0003](./0003-hermes-engine-bridge.explainer.md#crypto-is-platform-dependent-the-fragile-axis)).

**Inferred:** `[inferred: preferring the OS-native crypto avoids shipping and
trusting a bundled crypto library on platforms that already provide a vetted
one; the throwing-stub choice trades a clean ReferenceError for a clear
"rebuild with openssl-crypto" error, which is more debuggable. This is also the
most fragile build axis (LLP 0001), so making its degraded state explicit at
the JS boundary is defensive.]`

## Hermes today, but keep an engine seam

**Observed:** Hermes is the only engine, reached entirely through **JSI** and a
C ABI (`src/engine/hermes_runtime.cc` uses `<jsi/jsi.h>`; the embedding boundary
is the engine-neutral `ex_hermes_*` C functions in `include/exact_runtime.h`).
Native capability access is routed through a generic `__hostCall(op, argsJson)`
string channel plus typed host functions
([LLP 0002](./0002-host-embedding-abi.spec.md),
[LLP 0003](./0003-hermes-engine-bridge.explainer.md)).

**Inferred:** `[inferred: routing through JSI and a C ABI rather than
Hermes-specific internals keeps the embedding boundary shaped like an
engine-agnostic seam, even though only Hermes is wired today; nothing in the
consumer contract names Hermes.]` This is a posture, not a committed
multi-engine plan — no second engine exists in the tree.

## Prefer typed host functions; reserve the generic bridge

**Observed:** High-traffic subsystems get dedicated JSI host functions installed
(often lazily via `__exactEnsure*`, `hermes_runtime.cc:1197-1249`), while
`__hostCall` is the catch-all string/JSON channel
(`hermes_runtime.cc:1754-1806`).

**Inferred:** `[inferred: the generic bridge keeps the surface small and easy to
add to; dedicated functions exist where the per-call JSON encode/parse and
string dispatch of `__hostCall` would cost too much. The split is "narrow
default, specialize under load."]`

## Capability-gated host, permissive by default

**Observed:** `Host` carries a `SecurityMode` (`Permissive | Capability |
Strict`) and a `CapabilityManager`; module/file access is checked against
capabilities, and the C++ bridge fast-paths allow-all mode via
`ex_host_is_allow_all()` (`src/host/mod.rs:29-38, 156-174`;
`src/host/abi.rs:597-599`). The iOS C entry installs a permissive host by
default; the CLI installs a configured one (`abi.rs:586-592`).

**Inferred:** `[inferred: the capability layer exists so an embedder can
sandbox untrusted JS, but the default stays permissive so existing
embedders/tests keep working; strictness is opt-in per host.]`

## Degrade diagnostics, never the caller

**Observed:** Best-effort diagnostics are made non-fatal: console stdio
mirroring goes through a bounded queue that *drops* lines under backpressure
rather than blocking or aborting (`src/host/abi.rs:157-225`, annotated
`@tactical @ref LLP 0178`); a throwing one-shot timer is retired so it can't
refire (`src/engine/mod.rs:96-128`, test).

**Inferred:** `[inferred: the runtime is embedded in long-lived app hosts (iOS),
so a stalled console consumer or a misbehaving timer must not take down the
host — diagnostics are sacrificed before liveness.]`

## Notes

Several of these are reconstructed from code structure and in-code `@tactical`/
`@system` annotations that point at exact/snapback LLPs (0038, 0086, 0159, 0176,
0177, 0178) not present in this repo. Where this document marks rationale
`[inferred]`, a maintainer with that history can confirm or correct it; until
then it stays `Draft`.
