# Observer test delay/hold injection rides process-global env vars, so parallel runs race

**Status:** Open
**Severity:** P3
**Systems:** Testing, Engine
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-27
**Related:** [closed/20260727-secure-observer-suite-seven-red-tests](./closed/20260727-secure-observer-suite-seven-red-tests.md),
[20260727-host-abi-batch-helpers-race-in-parallel](./20260727-host-abi-batch-helpers-race-in-parallel.md)

## Problem

`exactTestDelayRuntimeProducer` (`src/engine/hermes_runtime_internal.h:340`)
reads `IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS` with `std::getenv` on **every
call** — no caching, which is otherwise good. But the value is a
process-global environment variable that three `--lib` tests set and then
`remove_var` (`src/engine/mod.rs` ~3913/3994/4299), and the same pattern
holds for `IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS`.

Under parallel `cargo test`, any test that clears the variable while another
test's producer thread is between publish and `getenv` silently removes that
test's hold. The observed symptom is
`destroy_drains_delayed_dns_and_fs_producers_before_recreate` failing with
"destroy returned before the pinned filesystem worker drained": the drain
worked, but the hold that was supposed to make it observable never happened.

Confirmed not fixable by timing: anchoring the measurement at job submission
rather than at `destroy` (landed 2026-07-27, a strictly more correct
measurement) does not help, because the elapsed time really is short when the
hold is skipped. The three env-setting tests do serialize on
`host_test_lock`, so the interfering clear comes from outside that set —
which is precisely why a lock-based fix is the wrong shape.

## Fix shape

Replace env-var injection with per-runtime, in-process state that cannot be
clobbered by another test:

- an observer-only setter (e.g. `ibex_test_set_runtime_callback_delay_ms(runtime, ms)`
  / `..._producer_hold_ms(...)`) storing the value on the runtime handle, read
  by `exactTestDelayRuntimeProducer` from the handle instead of `getenv`; or
- a process-global atomic set/reset through a test-only ABI, still better
  than env vars because it is typed and can be scoped by a guard object with
  `Drop`.

Prefer the per-runtime form: it makes the hold observable only for the
runtime under test and removes the cross-test channel entirely. Note
`env:IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS` and
`env:IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS` are reviewed capsec surfaces
(`REVIEWED_STARTUP_NAMES` / `HARNESS_STARTUP_ENVIRONMENT_CONTROLS` in
`capsec-coverage-model.mjs`), so removing the reads means retiring those rows
and running the regen chain; adding an `ibex_test_*` observer symbol is not a
public `ex_host_*`/`ex_hermes_*` ABI addition but still wants a reviewed row.

Until this lands the observer suites stay serial-only
(`--test-threads=1`), which CI already uses.

## Also seen once in the same sweep

`engine::tests::pinned_self_image_survives_path_replacement` failed once in a
parallel `--lib` run with `await pathname replacement: UnexpectedEof: failed
to fill whole buffer` (`src/engine/mod.rs:602`) — a separate parallel-hostile
test (it replaces its own executable path while another test reads it). Same
disposition: serial-only for now, worth its own guard when touched.

## Resolution (2026-07-31)

Replaced env-var injection with typed, in-process observer state.

- `exactTestDelayRuntimeProducer` / `exactTestHoldRuntimeProducerAfterEnqueue`
  (src/engine/hermes_runtime_internal.h) now read process-global
  `std::atomic<uint64_t>` knobs set through observer-only
  `ibex_test_set_runtime_callback_delay_ms` /
  `ibex_test_set_runtime_producer_hold_ms` (src/engine/hermes_runtime.cc).
  No test's env capture/restore/clear can drop another test's hold anymore,
  and no getenv happens on producer threads racing set_var/remove_var.
- Deliberately NOT the ticket's preferred per-runtime form, with rationale
  recorded at the definition: producers consult the delay BEFORE validating
  their `RuntimeCallbackTarget`, so they hold no runtime handle that is safe
  to dereference at that point. The process-global-atomic form is the
  ticket's second shape, including the Drop-scoped guard.
- All six `--lib` env sites converted to RAII guards
  (`RuntimeCallbackDelayGuard` / `RuntimeProducerHoldGuard` in
  src/engine/mod.rs tests); the functional bin consumer
  (`authenticated_native_tla_wakes_from_host_io_without_a_javascript_timer`,
  src/bin/ibex/runtime.rs) uses its own cfg-gated guard against the same C
  symbol, and `ProductionEnvGuard` no longer captures the retired name.
- CapSec tail: `env:IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS` and
  `env:IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS` retired from
  `HARNESS_STARTUP_ENVIRONMENT_CONTROLS`/`REVIEWED_STARTUP_NAMES` and from
  the reviewed runtime-environment inventory; full regen chain green
  (`check:drift` passes). Following the `ibex_test_jsi_owner_*` precedent,
  the new `ibex_test_set_*` observer symbols are not public
  `ex_host_*`/`ex_hermes_*` ABI and carry no registry row. LLP 0003
  §The event loop updated to name the typed knob.

Verification: observer `--lib` suite serial → 695 passed / 3 failed, the
3 being exactly the pre-existing module_runner/vfs reds fixed on the
sibling branch fix/lib-regression-triple (not this change);
`fetch_completion_releases_jsi_owners_on_runtime_thread_only`,
`host_call_completion_releases_jsi_owners_on_runtime_thread_only`,
`destroy_drains_delayed_dns_and_fs_producers_before_recreate`,
`delayed_fetch_completion_cannot_enter_recreated_runtime` all green on the
typed knob; secure observer bin tests compile; capsec JS suites 266 green;
ref-check green.

Residuals (out of scope, recorded):
- `IBEX_TEST_HTTP_WAIT_IDLE_DELAY_MS` keeps the getenv pattern — it was not
  implicated (nothing captures or clears it) and remains a reviewed row.
- `engine::tests::pinned_self_image_survives_path_replacement` stays
  parallel-hostile — filed as
  issues/20260731-pinned-self-image-test-parallel-hostile.md.
