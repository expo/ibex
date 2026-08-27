# Repair persistent module-runner and VFS library regression failures

**Status:** Closed
**Resolution:** Resolved
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

## Resolution (2026-07-30)

All three assertions were adjudicated against their governing contracts at
origin/main (661dd16e). Two were implementation regressions; one was a wrong
test expectation. No fail-closed behavior was weakened — every fix makes a
refusal happen *earlier* or restores the corpus's established refusal
classification.

### 1. `every_authenticated_linker_refuses_call_time_edges_before_authorization`
**Adjudication: implementation regression — fixed in the implementation.**
The four eager authenticated linkers (`NativeSynchronousGraph::link_authorized`
/ `link_authorized_prepared`, `NativeAsynchronousGraph::link_authorized` /
`link_authorized_prepared`) historically opened with
`plan.ensure_native_call_time_edges_supported()?` (see ea218dda). Commit
97fe265b dropped those four calls; the mailbox commit a5b681a7 then re-added
this test, which proves exactly that boundary (its `PanicGraphPolicy` panics if
authorization is ever consulted). The contract still requires the boundary:
`SynchronousGraphPlan::ensure_native_call_time_edges_supported`'s doc comment
("Keep this independent check at the authenticated linker boundary so a
prepared graph or another internal caller cannot reintroduce eager
authorization"), `runner_pipeline.rs`'s
`ensure_source_graph_call_time_edges_supported` ("The native linker repeats
this check at its own trust boundary"), and LLP 0024 §3 / LLP 0021's
no-eager-discovery rule. Deferred plans go through the
`link_authorized_deferred*` entry points, which production selects whenever
deferred links exist, so restoring the check cannot refuse a legitimate
production graph. Fix: the eager-boundary call is restored as the first
statement of all four linkers, ordered before TLA classification (which is why
the test previously surfaced `ERR_REQUIRE_ASYNC_MODULE` instead of the
call-time refusal).

### 2. `reached_commonjs_require_refuses_tla_before_target_execution`
**Adjudication: implementation regression — fixed in the implementation.**
Commit c7bb5e14 inserted `evaluateSynchronousRequiredEsm(...)` ahead of
`requireEsmRecord(...)` in the CommonJS require host function
(`src/engine/hermes_module_runner.cc`). That pre-evaluation walk detects
asynchrony only *after* a member body runs (it observes the returned promise),
so a prelinked TLA target linked with `esm_synchronous_eligible == false`
executed its body as a side effect of the refusal — the test observed the
target-execution marker flipped to `true` even though the require correctly
threw `ERR_REQUIRE_ASYNC_MODULE`. The contract requires refusal before any
target execution: LLP 0026 §7 (CommonJS interop), the graph algebra's
"an unrelated TLA record neither poisons the request nor begins executing as a
side effect of refusal" (`synchronous_evaluation_order` doc), and
`requireEsmRecord`'s own "Refuse every async/cyclic/incomplete closure before
starting a new body". Fix: the host function now refuses
`!esm_synchronous_eligible` bindings before `evaluateSynchronousRequiredEsm`
runs; `requireEsmRecord` retains its own check for other callers. Activation
bindings are unaffected (the provider refuses async-tainted targets before
publication and marks published ESM targets eligible).

### 3. `runtime_vfs_chdir_rejects_replaced_package_root_ancestor`
**Adjudication: wrong test expectation — reverted to `StaleIdentity`.**
The test was introduced (1fd31c34) asserting `VfsReason::StaleIdentity` and
passed. Commit 3ef32606 ("fix(security): retain Windows append writes")
flipped the expectation to `Absent` with no rationale, no implementation
change, and no related LLP 0023 change (that commit's spec edits are the
Windows append protocol only) — the test has been red ever since. The
corpus-wide classification of a replaced armed binding root on a fresh lookup
is stale identity, not absence: `authenticated_package_binding_root_replacement_is_stale`
(armed read path, same scenario, green) and
`root_replacement_is_refused_without_leaking_host_path` (replaced project
root, fresh lookup, green) both assert `StaleIdentity`, and
`verify_authenticated_binding_root` implements it uniformly for chdir and
armed reads. Reporting `ENOENT` here would misclassify tampering with an
armed identity (an attacker-controlled substitute directory present at the
bound spelling) as ordinary absence — a *weaker* signal — and would make
chdir diverge from the read path for the same event. The expectation is
restored to `StaleIdentity`; the operation still refuses and the cwd is
unchanged, so no behavior changed and no LLP update is required.

### Evidence
- `cargo test --lib -- --test-threads=1 <the three tests>`: 3 passed, 0 failed.
- Full `cargo test --lib`: 685 passed, 0 failed, 4 ignored (the pre-existing
  intentional ignores).
- `./ref-check`: ok (43 docs, 2285 refs, 0 errors).
- `cargo fmt --check`: clean for the files touched here; pre-existing
  formatting drift exists at origin/main in
  `src/module_loader/admission_cost_profile.rs`,
  `src/module_loader/runner_pipeline.rs`, and
  `tests/llp0413_dev_committed_embedder.rs` (not touched, reported upstream).
