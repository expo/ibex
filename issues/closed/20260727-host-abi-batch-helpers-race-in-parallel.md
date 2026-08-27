# capsec_host_abi_output_batch immediate helpers race on the global Host in parallel runs

**Status:** Closed
**Resolution:** Resolved
**Severity:** P3
**Systems:** Testing, Engine
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-27
**Related:** [closed/20260727-secure-observer-suite-seven-red-tests](./closed/20260727-secure-observer-suite-seven-red-tests.md) (documents the observer suites as serial-only)

`src/bin/ibex/engine/capsec_host_abi_output_batch.test.rs` serializes engine
access per-helper: every owned-runtime constructor
(`OwnedAuthenticatedVfsRuntime::new`, `OwnedAuthenticatedTypedContext::new`,
…) takes `hermes_engine_test_lock().blocking_lock()` itself and holds the
guard in the struct. The batch tests therefore take no top-level lock — and
MUST NOT: adding one self-deadlocks the non-reentrant tokio mutex the moment
`execute_host_abi_output_rows` constructs an owned runtime (verified
2026-07-27: a top-level guard hung the whole parallel suite at 0% CPU).

The gap: some immediate-row helpers reached from
`execute_immediate_host_abi_output` (the "may install a diagnostic Host"
tranche — `execute_fs`, `execute_sqlite`, …) touch the process-global Host
registry WITHOUT taking the engine lock. Under parallel `cargo test` they
can stomp a host another (locked) test installed —
`legacy_host_path_variants_and_readdir_emit_only_bounded_observations`
failed exactly once this way in a full parallel run and passes serially.

**Fix shape:** audit each helper reachable from
`execute_immediate_host_abi_output` for global-Host/engine mutation and push
the lock DOWN into the helpers that need it (matching the file's per-helper
design), never up into the tests. Until then the suite remains serial-only
(`--test-threads=1`), which CI already uses.

## Resolution (2026-07-31)

Fixed per the recorded fix shape: the engine lock is pushed DOWN into the
immediate-row helpers that touch the process-global Host registry, matching
the file's per-helper locking design, and never up into the tests.

Audit of the `execute_immediate_host_abi_output` dispatch:

- **Now take `ambient_host_registry_lock()`** (global-Host readers/writers
  with no owned-runtime constructor of their own): `execute_fs`,
  `execute_sqlite`, `execute_terminal`, `execute_basic` (installs the legacy
  Host), and `execute_legacy_output` (installs legacy/armed Hosts; one lock
  at its top also covers `execute_legacy_path_success`/`_error`/`_refusal`,
  `execute_legacy_readdir`, and `prime_non_eperm_fs_error`, which are only
  reachable from it).
- **Also take the lock** (correction from the pre-merge adversarial review:
  `OwnedDiagnosticRuntime::new()` takes NO lock and installs the legacy Host
  via `fresh_legacy_host()`, so these were a live stomp path too):
  `execute_hermes_diagnostic`, `execute_app_bundle_route`,
  `execute_bounded_dispatch`, `execute_owned_value`.
- **Deliberately untouched** (their owned-runtime constructors take the same
  non-reentrant lock and hold it in the struct — wrapping them would
  self-deadlock): `execute_javascript_absence`, `execute_http_output`,
  `execute_module_runner_output`, `execute_authenticated_armed_create`,
  `execute_authenticated_session_output`, `execute_owned_runtime_teardown`
  (locks at its top itself).
- **No lock needed**: `execute_hermes_stateless`, `execute_engine_path_output`,
  `execute_host_wake_hook_callback` (no global-Host access);
  `execute_worklet` (its `install*` hits are worklet-private, on its own
  `OwnedWorkletRuntime`, not the Host registry).

Verification: `scripts/run-tests.sh --secure --features
capsec-conformance-observer --scope bin capsec_host_abi_output --
--test-threads=1` → 10 passed / 0 failed, no deadlock. The observer suites
stay serial-only in CI until the sibling env-var injection ticket
(20260727-test-delay-injection-is-a-global-env-var) also lands; four tests
remain documented parallelism-flaky independent of this race.
