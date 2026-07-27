# capsec_host_abi_output_batch immediate helpers race on the global Host in parallel runs

**Status:** Open
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
