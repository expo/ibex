# CapSec registry/contract regen chain is broken by unreviewed surface drift

**Status:** Open
**Date:** 2026-07-26
**Priority:** High
**Related:** [20260726-native-fetch-jsi-last-owner-race](./closed/20260726-native-fetch-jsi-last-owner-race.md)

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
   [closed/20260726-capsec-reviewed-lockdown-identity-drift](./closed/20260726-capsec-reviewed-lockdown-identity-drift.md)
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
