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

## Full-VM borrowed-runtime breakdown (2026-10-13)

The ignored diagnostic
`phase_cost::exact_shaped_borrowed_runtime_phase_costs` now times the lifecycle
through the existing borrowed-runtime FFI. It uses `PURE|CRYPTO|ABORT`, requests
the private abort-hook handoff, defers the intrinsic baseline, and preserves the
required order:

```text
Context::new -> full Hermes runtime + Adapter::new
  -> binding install
  -> trusted prelude
  -> capture_intrinsics
  -> harden
```

All binding and hardening inputs are the build's precompiled bytecode. The test
invokes `hermesc` exactly once before warmup to compile its trusted-prelude
fixture, then reuses those bytes for every sample. The fixture captures and
deletes the private abort-hook global, retains `subscribe` in a closure,
replaces `Number.prototype.toLocaleString`, and adds one property to
`Array.prototype`. It is the shape already covered by the functional embedding
test, not Exact's complete production prelude or an application module. The
prelude line also includes the existing test ABI's completion-value
stringify/copy/free.

This run linked the release, source-capable `libhermesvm_a.a`
(`sha256-c44fbaba0f201abb76ddbfa61ff5a2096188e6f3be8c9e6faa46f0983f1060eb`)
from the receipted `aarch64-apple-darwin` v4 bundle, HBC 99. It does **not**
measure `libhermesvmlean_a.a`, so it cannot by itself explain or replace
Exact's production 2.05 ms observation.

Reproduction, with an explicit complete install and two build jobs:

```sh
HERMES_LEAN_SYS_DIR=/Users/ccheever/.cargo/hermes-lean-sys/hermes-vanilla-d412d3bd8512-v4/457565d12cc1bdbf7a12b5ea72253742565b0a6837f44b28660049e2d9056299 \
CARGO_BUILD_JOBS=2 \
cargo test -p ibex2-runtime --release --no-default-features --features crypto \
  --test embedding phase_cost::exact_shaped_borrowed_runtime_phase_costs \
  -- --ignored --nocapture
```

The 2026-10-13 run discarded 20 warmups and measured 200 lifecycles. The host
had 18 logical CPUs and was severely overloaded: load averages were
100.30/87.42/95.48 before the samples and 100.75/87.73/95.55 after them. Times
are microseconds:

| phase | min | p25 | median | p75 | p95 | max |
|---|---:|---:|---:|---:|---:|---:|
| `Context::new` | 14.2 | 20.9 | 23.7 | 26.5 | 103.2 | 771.1 |
| full runtime + `Adapter::new` | 881.2 | 1,136.8 | 1,473.1 | 2,068.8 | 4,235.8 | 8,950.6 |
| binding install | 240.9 | 291.0 | 334.5 | 542.5 | 1,408.5 | 7,191.7 |
| trusted prelude eval | 6.0 | 7.5 | 8.1 | 9.3 | 17.3 | 217.2 |
| `capture_intrinsics` | 221.2 | 254.0 | 272.0 | 410.0 | 1,630.9 | 5,890.9 |
| `harden` | 2,912.5 | 3,738.8 | 4,735.5 | 6,386.2 | 10,459.8 | 16,392.4 |
| four-phase door total | 3,505.8 | 4,540.3 | 5,621.0 | 7,590.8 | 13,322.4 | 17,736.0 |
| startup through harden | 4,770.4 | 6,135.7 | 7,438.6 | 9,585.3 | 15,602.1 | 26,030.2 |
| borrowed runtime destroy | 296.9 | 810.1 | 2,043.2 | 3,827.4 | 7,500.6 | 12,387.4 |
| `Context` drop | 11.2 | 17.2 | 20.0 | 24.0 | 73.0 | 815.3 |

Within this specific full-VM, abort-handoff run, `harden` is the dominant
measured door phase: its 4.736 ms median is about 84% of the 5.621 ms door
median. Install and deferred capture are the next two material phases; this
small prelude is negligible. The load spread and the VM/prelude mismatch make
the absolute numbers unsuitable for a regression claim or an optimization
decision. The evidence ranks the next qualification rather than a rewrite:
repeat the same boundaries in Exact's lean-VM embedding with its actual trusted
prelude on an idle host. If hardening remains dominant there, split its
abort-hook reachability guard from the freeze bytecode before choosing among
the structural ideas above. The P3 remains open until that production-shaped
result explains the observed 2.05 ms cost.
