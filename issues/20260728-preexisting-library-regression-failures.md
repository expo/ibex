# Repair persistent module-runner and VFS library regression failures

**Status:** Open
**Severity:** P2
**Systems:** Module Runner, VFS, CI
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-28
**Related:** issues/closed/20260724-native-call-time-module-activation.md

## Problem

The CapSec rev2 convergence run of `cargo test --lib` passes 675 tests, ignores
3 diagnostic tests, and persistently fails these 3 assertions:

- `engine::module_runner::tests::every_authenticated_linker_refuses_call_time_edges_before_authorization`
  receives `ERR_REQUIRE_ASYNC_MODULE` for `guarded-entry` instead of the
  expected call-time authorization refusal.
- `engine::module_runner::tests::reached_commonjs_require_refuses_tla_before_target_execution`
  observes `Bool(true)` where the target-execution marker must remain false.
- `vfs::tests::runtime_vfs_chdir_rejects_replaced_package_root_ancestor`
  receives `StaleIdentity` where the test expects `Absent`.

All three reproduce with one test thread. The first also reproduces from a
clean detached worktree at pre-`exact_crypto` revision `9a7d7169`; the
`exact_crypto` closure modifies neither `src/engine/module_runner.rs` nor
`src/vfs/mod.rs`. They are therefore not regressions caused by that closure
and do not justify reopening the completed security tranche.

## Done when

- each assertion is adjudicated against the governing module-activation or VFS
  contract, fixing implementation or expectation without weakening fail-closed
  behavior;
- the three exact serial commands pass;
- `cargo test --lib` passes as a suite; and
- any behavior change updates its governing LLP or existing filesystem ticket.
