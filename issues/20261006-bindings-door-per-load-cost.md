# The bindings door costs an embedder about 2 ms per module load

**Status:** Open
**Systems:** Bindings, Runtime, Performance
**Severity:** P3
**Author:** Claude (Opus 5.5) for Charlie Cheever
**Date:** 2026-10-06
**Related:** LLP 0068 §3 (Decision C: harden before app code), exact2 LLP 1027 (startup measurements)

exact2's exact-js moved onto the bindings door on 2026-10-06. It creates one Hermes runtime per
TypeScript data-source module, installs `PURE|CRYPTO|ABORT` (+ `INTL` on Linux/Windows), runs its
trusted prelude, captures the intrinsic baseline (`defer_intrinsic_snapshot` +
`capture_intrinsics()`), and hardens. Measured on macOS (15 timed loads, median): **0.90 ms →
2.05 ms per load**; stripped minimal binary +259 KB (+4.8%). exact2's own LLP 1027 budgets
runtime creation at ~0.3 ms, and cold start at 100 ms p50, so each data source now costs ~2% of
that budget.

Known parts (from Ibex's own tests; not yet broken down for this embedder):
- `harden()`: 0.72–0.81 ms best-of-20 (`the_freeze_stays_within_its_budget`).
- Deferred intrinsic capture: walks the realm once (unmeasured here).
- Group install: evaluating the binding bytecode for each group (unmeasured here).

## Next

Break the 2.05 ms down per phase in an exact-js-shaped embedding (the combined borrowed-runtime
test in `ibex2-runtime/tests/embedding.rs` is the right fixture), then look for structural wins:
a shared frozen intrinsic snapshot reused across runtimes, a cheaper reachability walk in
`harden`, lazily installed families, or a Hermes heap snapshot of a hardened, installed realm.
Keep Decision C's guarantee (no app code before harden) intact.
