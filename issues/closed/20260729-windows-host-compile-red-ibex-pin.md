# Windows host compile red at current Ibex pin

**Status:** Closed
**Resolution:** Restored the compatibility `HostConfig.allow` embedder field
and corrected reduced-feature gating around published native records.
**Systems:** Host Embedding, Module Runner, Windows
**Author:** Codex
**Date:** 2026-07-29
**Related:** Exact-side ticket 20260729-windows-host-compile-red-ibex-pin;
LLP 0021

Two Ibex regressions blocked Exact's registered Windows host compile:

- `module_runner.rs` referenced published-record types and collections in
  reduced-feature builds while their declarations/imports remained gated;
- the Exact Windows compatibility host still constructs
  `HostConfig { mode: Enforce, allow, .. }`, but Ibex removed `allow`.

The published-record carrier and the two bridge methods needed by the base
ABI now compile independent of `module-runner`; feature-only construction
and graph indexes remain gated. `HostConfig.allow` is restored only for the
unarmed compatibility constructor with its historical `grant("*", cap)`
semantics. Armed hosts refuse a non-empty legacy grant list.

Verification:

- `cargo check --no-default-features --lib` passes in Ibex.
- Exact `origin/main` with this Ibex revision passes its registered
  `windows-host-compile` profile: 7/7 Hermes-profile closure tests, warning-clean
  `cargo xwin clippy` for `exact-host-windows`, and the required compile-only
  non-linkability refusal.
