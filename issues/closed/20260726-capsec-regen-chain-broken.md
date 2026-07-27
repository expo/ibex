# CapSec registry/contract regen chain is broken by unreviewed surface drift

**Status:** Closed (2026-07-27 — all drifted review affirmations discharged; full chain green)
**Date:** 2026-07-26
**Priority:** High
**Related:** [20260726-native-fetch-jsi-last-owner-race](./20260726-native-fetch-jsi-last-owner-race.md)

## Problem

`bun run generate:capsec-registry` and `bun run generate:capsec-contract`
(and therefore `bun run check:drift`) fail on this branch and on the commits
they inherit, before any new change is applied. The chain has been broken by
landed work that did not run the fail-closed regen/review steps:

1. ~~`cli:argument-parser:ibex%20compat:probe:utf8-string` unclassified~~ —
   f3a527d6 ("ibex compat --probe") added the `--probe EXPR` option without
   adding its reviewed CLI rows. **Fixed alongside the fetch owner-race work**:
   `argument-parser`/`option-name`/`option:*` rows for `probe` added to
   `capsec-coverage-model.mjs`, mirroring `--section` (mechanical, matches the
   clap definition in `src/bin/ibex/cli.rs`).
2. ~~`native-op:global:AsyncFunction` unclassified~~ — was a documented
   consequence of the reviewed lockdown-taming-digest drift: the classifier
   fails closed on an unreviewed engine identity. **Fixed 2026-07-26** with an
   actual review of the drift (4c6ac052, the error-prototype override-mistake
   repair) — see
   [closed/20260726-capsec-reviewed-lockdown-identity-drift](./20260726-capsec-reviewed-lockdown-identity-drift.md)
   for the review record, the restamped
   `REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST`/evaluator review id, and the two
   companion reviewed-count/name updates (host-ABI 362 from 1407af0e;
   `env:IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS` startup row from the fetch
   owner-race fix). Both capsec test suites are green again.
3. `generate:capsec-contract`: reviewed source-range digest for
   `src/bin/ibex/runtime.rs#authenticated-file-ingress` expected
   `sha256-34TG8qsLMKVHeS3eBWFdFRhFphFttu_yKi8PkxX1rKw`, got
   `sha256-yxzWt9SORBND7uk_dofBp-OZzWzd3BwBNpm3l8OAsQE` — someone edited
   inside the pinned range without repinning
   (`capsec-ingress-obligations.mjs`). Repinning is a review affirmation for
   the edit that moved the bytes; it belongs to that edit's author.

## Impact

- `capsec/generated/surface-inventory.md` (and downstream contract/policy
  artifacts) cannot absorb new reviewed rows. The fetch owner-race fix
  registered `env:IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS` in
  `capsec/registry/runtime-environment-inventory.json`
  (`generate:runtime-environment-inventory` passes) and refreshed
  `host-task-ingress-inventory.json`, but the generated surface inventory
  cannot be regenerated until items 2–3 are resolved.
- `check:drift` is red for every branch until this is fixed.
- The `--bin ibex` observer test suite on this branch has 45 failing
  armed/capsec-batch tests (e.g.
  `armed_fs_open_denial_cannot_truncate_or_create` counts 14 denials where 21
  are expected — the seven async-fs denial probes no longer throw). Verified
  identical with the working tree stashed, against the freshly restamped
  no-debugger framework (`./scripts/build-hermes.sh --no-debugger`, cache key
  `...pcd3dd1da3755...blaf521ddda077...`): this is branch/main drift, likely
  the same unreviewed engine-identity change, not the fetch owner-race fix.
  Note the observer suite was entirely unrunnable locally before that restamp
  (build.rs provenance gate; the branch's `build-hermes-linux.sh` edit in
  69e28bb7 invalidated the local macOS receipt). The `--lib` engine suite is
  fully green (653/653).

## Required fix

- Owner of the `AsyncFunction` observation drift classifies the surface (or
  suppresses the observation) with an actual review.
- Owner of the `runtime.rs` authenticated-file-ingress edit repins the range
  digest per the fail-closed restamp chain.
- Then run the full chain: `generate:capsec-registry` →
  `generate:host-task-ingress-inventory` → `generate:capsec-contract` →
  example policies → `generate:compiled-environment-profile` →
  `regenerate:vendored` → `check:drift`, confirming the
  `IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS` row lands in
  `capsec/generated/surface-inventory.md`.

## Resolution — 2026-07-27

Item 3 turned out to be one of **four** stale review affirmations; running the
chain fail-closed surfaced each in turn, and each got its own review before
its repin (all four drifting edits are already-landed main commits):

1. `src/bin/ibex/runtime.rs#authenticated-file-ingress` — drift is 8 added
   `StartupPhaseTrace` lines from 9968127c ("perf: attribute native module
   startup phases"). Reviewed: the tracer is opt-in via the already-reviewed
   `env:IBEX_STARTUP_TRACE`, `mark()` prints only a static label and elapsed
   time to stderr, holds no authenticated data, and the diff is pure
   additions — no authentication step is skipped, reordered, or made
   conditional. Repinned to `sha256-yxzWt9SORBND7uk_dofBp-OZzWzd3BwBNpm3l8OAsQE`.
2. `src/bin/ibex/engine/hermes.rs#authenticated-native-graph-join` — same
   family: 8 pure `phase.mark(...)` additions from the same commit. Repinned
   to `sha256-CpplWmPpU7Tw5VWkVeru-QobNMIFc8M2FakeayrnSQw`.
3. `src/bin/ibex/main.rs#authenticated-product-routing` — the range matched
   its pin through 1407af0e and drifted at f3a527d6 (`ibex compat --probe`):
   exactly two lines threading the reviewed `probe` option through the
   `Commands::Compat` routing, mirroring the neighboring `section`/`module`
   args; no new authority. Repinned to
   `sha256-Jyk-aRGDH9a3z1vOn2nXFVy0s5lTbGJXWb8U1SD09Qk`.
4. The debugger native-alias audit's `REVIEWED_BINARY_RUST_PATHS` — f3a527d6
   added `src/bin/ibex/compat/probe.rs`. Reviewed: the probe harness
   references no debugger alias or CDP surface (it shells the pinned
   standalone `hermes` binary and a fresh in-process engine for fault
   localization). Added to the reviewed corpus.

Then the full chain ran clean end to end: `generate:capsec-registry` →
`generate:host-task-ingress-inventory` → `generate:capsec-contract` (7617
coverage edges, 15234 target cells, 217 ingress sites) → all four example
policies (digest-only diffs; no grant or mode changes) →
`generate:compiled-environment-profile` (profile digest only) →
`regenerate:vendored` → `check:drift` **green**. The
`env:IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS` row is present in
`capsec/generated/surface-inventory.md` as required.

Note: the 45 failing `--bin ibex` observer tests recorded under Impact were
branch/main drift diagnosed alongside the identity-drift ticket; with the
reviewed identity restamped there, re-verify on a current observer build if
they persist (tracked there, not here).

**Correction 2026-07-27:** re-verified after the restamp — the observer
failures were NOT engine drift at all. They are an artifact of `insecure`
being in the default feature set: the armed batches fail on an
insecure-featured binary and are green on an explicit secure build
(`--no-default-features --features standard,capsec-conformance-observer`).
See [20260727-armed-observer-suite-needs-secure-build](../20260727-armed-observer-suite-needs-secure-build.md).
