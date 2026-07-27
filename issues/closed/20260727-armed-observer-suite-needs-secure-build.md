# Armed observer test batches fail confusingly on the default (insecure) build

**Status:** Closed (2026-07-27 — armed observer batches cfg-gated off insecure builds; run-tests.sh gained --secure)
**Severity:** P3
**Systems:** Engine, Build, Testing
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-27
**Related:** LLP 0039 (insecure default; mode-divergence risk), LLP 0018 (test entry point), [closed/20260726-capsec-regen-chain-broken](./20260726-capsec-regen-chain-broken.md)

## Problem

Since `insecure` joined the default feature set (dc0712c0, per LLP 0039), a
plain `cargo test --bin ibex --features capsec-conformance-observer` — and
`scripts/run-tests.sh`, which does not strip default features — builds the
armed/capsec observer batches into an **insecure-featured** binary. The
`insecure` feature changes armed-runtime seams (ambient environment
projection, fs/VFS behavior), so 44 armed/capsec conformance tests fail with
misleading symptoms, e.g.
`armed_fs_open_rejects_parent_and_final_symlink_escape` dying on
`ENOENT: lstat '/project/final-link'` because the armed VFS fixture mapping
is not honored, and armed denial-count mismatches (14 ≠ 21).

The same suite is fully green on an explicit secure build:

```
cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer
```

None of the ~86 observer-gated test blocks in `src/bin/ibex/engine/hermes.rs`
carries a `not(feature = "insecure")` cfg, so the tests compile, run, and
fail instead of being excluded or skipping loudly.

## History this corrects

The "45 failing `--bin ibex` observer tests" recorded on 2026-07-26 in
[closed/20260726-capsec-regen-chain-broken](./20260726-capsec-regen-chain-broken.md)
and
[closed/20260726-native-fetch-jsi-last-owner-race](./20260726-native-fetch-jsi-last-owner-race.md)
were **mostly** this artifact. Measured 2026-07-27 at 43ef63e9: the default
(insecure) build fails 44; the explicit secure build fails 8, of which one
(`public_os_read_denial_stops_before_commit_and_data_access`) passes when
run serially (parallelism-flaky) and seven fail deterministically. The same
seven fail identically on pre-landing main (3c1f24b3, verified in a clean
worktree with the same secure feature set), so they are pre-existing red
tests, not identity drift and not introduced by the 2026-07-26/27 landings —
tracked separately in
[20260727-secure-observer-suite-seven-red-tests](./20260727-secure-observer-suite-seven-red-tests.md).
So: 36 of the 44 are the insecure-default artifact this ticket covers.

## Fix options (pick one)

1. cfg-gate the armed/capsec observer batches on
   `all(feature = "capsec-conformance-observer", not(feature = "insecure"))`
   so an insecure build simply doesn't contain them (mirrors how secure
   negatives are pinned by `tests/secure_process_env.rs` on the other side).
2. Have the batches assert the compiled mode at runtime and fail with one
   clear message ("armed conformance requires a secure build; run
   cargo test --no-default-features --features standard,capsec-conformance-observer").
3. Teach `scripts/run-tests.sh` a `--secure` flag (LLP 0018 owns that
   entry point) and document the invocation where the observer suite is
   described.

Option 1 is the least surprising: the tests are meaningless under
`insecure`, and LLP 0039's mode-divergence risk section already anticipates
mode-conditional coverage. Whichever lands should also note the invocation
in LLP 0039.

## Resolution — 2026-07-27

Options 1 and 3 landed together:

- **cfg-gate (option 1):** every observer test that fails on an
  insecure-default build — 40 as measured after the seven real reds were
  fixed — now carries `#[cfg(not(feature = "insecure"))]`, extending the
  LLP 0039 precedent already applied to five lib tests. A default
  (insecure) observer build compiles without the armed/capsec conformance
  batches and its `--bin ibex` suite runs green; the secure build still
  contains and passes all of them (620 non-ignored, serially).
- **run-tests.sh --secure (option 3):** the LLP 0018 test entry point now
  accepts `--secure`, which expands to
  `--no-default-features --features standard,...` so the armed suites have
  a one-flag sanctioned invocation:
  `scripts/run-tests.sh --secure --features capsec-conformance-observer
  --scope bin -- --test-threads=1`.
- LLP 0039 §"Secure mode must stay exercised" records the extended gating
  and the invocation.

Option 2 (runtime mode assert) was unnecessary once the tests no longer
compile into insecure builds.
