# Catalog HBC compile recipe omits -Xes6-block-scoping; leave-raw for-of loops with closures can miscompile

**Status:** Open
**Severity:** P2
**Systems:** Transforms, Module loader, SFE
**Author:** Claude Fable 5 (Claude Code), directed by Charlie Cheever
**Date:** 2026-07-31
**Related:** LLP 0034 (Hermes ES6 block scoping),
issues/closed/20260729-tier3-forof-canonical-pass-parity.md,
`src/module_loader/catalog_compiler.rs` (`run_fixed_hermesc`),
`crates/sfe-format/src/lib.rs` (`HermescRecipeV1::production()`)

Found during the tier-3 for-of parity stand-down investigation (the ticket
itself was already closed upstream; these are adjacent gaps).

1. **The catalog HBC carrier compile path does not pass
   `-Xes6-block-scoping`.** `run_fixed_hermesc` and the digest-bound
   `HermescRecipeV1::production()` invoke the pinned hermesc without the
   flag, which appears to contradict LLP 0034's "every Ibex-owned hermesc
   invocation that emits executable HBC passes the flag." Empirically
   confirmed on the pinned toolchain: flagless hermesc AOT gives
   capture-last for-of `let` semantics (`bb` / `2x,2x,2x`) while the flag
   gives correct per-iteration capture. Consequence: any *leave-raw*
   hazard-bailed loop (break/continue/return/var-in-body/yield bodies)
   whose closures capture the loop binding would be miscompiled in HBC
   prepared carriers produced through that recipe. Node/V8 and
   loaded-Hermes (in-process compiler) tests are structurally blind to
   this divergence.

2. **Engine-truth coverage for the previously quarantined for-of shapes is
   loaded-Hermes only** (`tier3_for_of_canonical_parity_executes_on_loaded_hermes`,
   src/engine/module_runner.rs). The closed parity ticket's acceptance
   named the hermesc-AOT pattern (compile via pinned hermesc, execute on
   the pinned VM) as the regression harness of record; if no hermesc-AOT
   leg exists, the quarantine closure is only evidenced on the flagged
   path.

Done when: the recipe passes the flag (with the digest/recipe regeneration
that implies) OR the omission is justified in LLP 0034 with the leave-raw
closure hazard explicitly accepted; and a hermesc-AOT engine-truth test
covers at least one leave-raw closure-capturing loop shape either way.

Note the recipe digest is load-bearing (`HermescRecipeV1` is digest-bound
into carrier admission), so changing flags is a coordinated artifact bump,
not a one-line edit.
