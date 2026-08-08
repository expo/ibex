# Armed observer suite: 3 pre-existing reds on main (compatibility window ×2, promise checkpoint)

**Date:** 2026-08-07
**Severity:** P2 (suite hygiene; masks real regressions)
**Found by:** supervised P1 remediation session (evaluator-identity restamp + __exactWhich typed enforcement), while verifying its changes were not the cause.

## Symptom

`scripts/run-tests.sh --secure --features capsec-conformance-observer --scope bin -- --test-threads=1` on main fails 3/648:

1. `runtime::tests::closed_compatibility_window_keeps_call_time_import_and_require_native`
   — panics at `src/bin/ibex/runtime.rs:14517`: `failed to claim the file submission
   sequence: the session already has an unsettled evaluation`.
2. `runtime::tests::compatibility_call_time_refusals_preserve_import_and_require_error_timing`
   — asserts at `src/bin/ibex/runtime.rs:15615`: expected `Completed`, got
   `Failed { status: 1, diagnostic: "… authenticated module graph preparation failed:
   authenticated artifact repeats one literal dynamic-import spelling" }`.
3. `engine::hermes::tests::authenticated_promise_checkpoint_preserves_provenance_and_tla_is_not_duplicated`.

## Adjudication of provenance

All three fail **identically at clean d604d116b** (working tree stashed), so they
pre-date both the four-evaluator restamp (d604d116b) and the __exactWhich typed
enforcement (54f69d0df). They are not in the 4-test parallelism-flaky set — these
runs were `--test-threads=1`. The failure signatures (unsettled evaluation claim,
literal dynamic-import spelling repetition in authenticated module graph prep) point
at the recent LLP 0049 Phase 1 landing sequence (slices s2b–s7 / seam
reconciliation, 848400857..1c3806832 era) or the LLP 0050 landing — both landed
without this suite in their verified lists. Bisection over that range is the next
step; likely owned by the LLP 0049 Phase 1 session.

## Not covered here

The 16 additional socket/listener failures seen when running this suite inside a
sandboxed agent are environment artifacts (seatbelt refuses local sockets), not
repo defects; run unsandboxed.

## Resolution

(unresolved)
