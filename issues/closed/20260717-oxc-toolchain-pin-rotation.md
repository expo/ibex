# Rust toolchain bump + Oxc re-pin (atomic with identity rotation)

**Status:** Closed
**Resolution:** Closed by f5688afb with the atomic Rust/Oxc pin rotation, generated identity drift gates, native corpus, and performance evidence in place.
**Severity:** P2
**Systems:** Build, CI
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §1, LLP 0009
**Depends-on:** oxc-transform-config-manifest, oxc-native-tier3-runner, oxc-behavioral-transform-corpus

Re-measure LLP 0009's matrix at execution time; adopt an exact Rust
version and coherent version set for all ten direct `oxc_*` deps
(exact-pin `oxc_resolver` too); record pins in a `Revised:` entry to
LLP 0009 with lock-resolved source/checksum authoritative. Update every
pin site (`rust-toolchain.toml`; `ci.yml`, `module-loader-baselines.yml`,
`compartment-conformance.yml`, `hermes-patch-canary.yml`; performance
fixtures) and convert workflows to consume `rust-toolchain.toml` with a
drift check. Land the non-gating latest-Oxc canary CI job (and
optionally a Rust-beta canary). The pin change lands atomically with
the manifest-driven identity rotation.

**Done when:** Phase 0 corpora + LLP 0026 performance gates
(`ibex/module-runner-performance-gate/1`) green on the new pins;
rotation goldens pass; canary job running; all pin sites enumerated in
the PR.

## Result

The repository now consumes Rust 1.97.0 from `rust-toolchain.toml` through the
shared drift-checking installer in every required workflow. All ten direct Oxc
dependencies are exact-pinned: the lockstep set is 0.140.0, with
`oxc_resolver` 11.24.2 and `oxc_sourcemap` 8.1.1. LLP 0009 carries the Revised
entry and the generated transform configuration binds the complete locked set,
options, cache tag, and producer fingerprint.

Pin-site audit:

- `rust-toolchain.toml` is the sole active Rust authority;
- `ci.yml`, `module-loader-baselines.yml`, `compartment-conformance.yml`, and
  `hermes-patch-canary.yml` invoke `scripts/install-rust-toolchain.sh`;
- `Cargo.toml` exact-pins all direct Oxc crates and `Cargo.lock` supplies the
  resolved sources/checksums;
- the macOS module-loader baseline is refreshed from the uncontended Rust 1.97
  report; and
- `module-runner-spike/performance-macos-arm64.json` plus
  `test262-results-macos-arm64.json` intentionally remain immutable Oxc 0.121
  adoption baselines, not active pin sites. The dual-produce report binds and
  executes that historical producer separately.

Evidence:

- Phase 0 behavioral corpus: 24/24 source/prepared rows;
- native Tier-3 corpus: 22/22 rows;
- performance gate `ibex/module-runner-performance-gate/1`: all predeclared
  ratios passed, including 1.038 clean-build and 1.067 binary-size ratios;
- transform rotation goldens and generated-config drift checks pass;
- content-addressed old/new dual-produce report archived under `llp/evidence/`;
  and
- the advisory latest-Oxc canary is present in `ci.yml`.
