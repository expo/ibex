# Runtime benchmarks

## `compartment_overhead` — LLP 0013 Goal 3 steady-state overhead

[LLP 0013](../llp/0013-per-package-capability-compartments.rfc.md) Goal 3 budgets
the per-package capability compartments at **"steady-state overhead =<1% on the
runtime benchmark suite"**. This bench is that suite's first member.

### What it measures

The carried Hermes patch stack (`patches/hermes/0004-…` and `0005-…`) re-points
the interpreter's three hottest global/`this` opcodes — `GetGlobalObject`,
`CoerceThisNS`, `LoadThisNS` — through `globalForFrame(runtime, curCodeBlock)`,
guarded by `Runtime::anyCompartmentActive_`:

```cpp
static LLVM_ATTRIBUTE_ALWAYS_INLINE HermesValue
globalForFrame(Runtime &runtime, CodeBlock *cb) {
  if (LLVM_LIKELY(!runtime.anyCompartmentActive()))   // guard false -> skip walk
    return runtime.getGlobal().getHermesValue();
  // guard armed: resolve through the executing frame's Domain compartment global
  ...
}
```

The A/B is the **same** compute-heavy JS workload run with that guard:

| Arm | Command flag | `anyCompartmentActive_` | On the hot opcodes |
|-----|--------------|-------------------------|--------------------|
| baseline | (none) | `false` | one predicted-not-taken branch, return real global |
| active | `IBEX_COMPARTMENTS=1` | `true` | the Domain walk runs |

`overhead = (active − baseline) / baseline`.

### How the A/B maps to `anyCompartmentActive_`

The guard is armed the first time a compartment is bound to a package's `Domain`
(the native `__exactSetCompartmentFor`, which the module loader calls when
`IBEX_COMPARTMENTS=1` / lockdown is on). The workload
(`fixtures/compartment_overhead/app.js`) `require`s a trivial `arm-pkg` for
exactly that purpose; under the active arm the loader binds its compartment,
arming the guard process-wide. The workload reads `arm-pkg.processWithheld` back
and prints `armed=<bool>`, and the harness asserts the baseline arm is *not*
armed and the active arm *is* — so the run confirms the guard actually flipped,
not merely that an env var was set.

The heavy loop itself runs in the **root** Domain, which has no compartment
global, so under the active arm the walk resolves straight back to the real
global. That deliberately isolates the branch + Domain walk with **no
Proxy-trap confound** (package code reading globals through its withholding
compartment Proxy is a separate, larger, expected cost; it is not what Goal 3's
=<1% always-on budget is about). The loop is dominated by `Math.*` global reads
and a sloppy-mode bare call (`this` coercion) so those three opcodes are dense,
and is tuned to run well over a few hundred ms so process startup does not
dominate.

### Running

```sh
cargo build --bin ibex          # the harness drives the built binary
cargo bench --bench compartment_overhead
```

Tunables (env): `BENCH_ITERS` (default 12,000,000), `BENCH_SAMPLES` (15),
`BENCH_WARMUP` (3), and `IBEX_BENCH_BIN` to point at an already-built binary
(e.g. `target/debug/ibex`) for a quick reduced-iteration check without a release
rebuild:

```sh
BENCH_ITERS=12000000 BENCH_SAMPLES=15 \
  IBEX_BENCH_BIN=target/debug/ibex \
  cargo bench --bench compartment_overhead --profile dev
```

The harness warms up, then interleaves the two arms sample-by-sample, reports the
**median** wall-clock per arm and the workload's own startup-free **inner** loop
time per arm, and prints the overhead of each.

### Caveats

- It measures **wall-clock end-to-end**. Process startup (Hermes init, and for
  the active arm the one-time compartment-registry build) is a constant that
  *partially* cancels across arms; the workload is tuned so steady-state loop
  time dominates. The `inner` number excludes startup entirely and is the
  cleaner steady-state signal.
- The =<1% budget is reported **informationally** (a `PASS` / `OVER-BUDGET`
  line), never asserted. Wall-clock perf is environment-sensitive and a CI gate
  on it would be flaky. `harness = false` (no criterion): the unit of work is a
  whole subprocess, not an in-process microbenchmark, so the bench rolls its own
  warmup + median-of-N.

### Observed (reference)

On an Apple-silicon dev machine, debug `ibex`, 12M iters × 15 samples: baseline
inner median ≈ 1684 ms, active inner median ≈ 1680 ms → **inner overhead
≈ −0.2%** (wall ≈ −0.15%) — i.e. within measurement noise and comfortably inside
the Goal 3 =<1% budget. (Runs an order of magnitude shorter, e.g. ~430 ms, sit
near the 1 ms `Date.now()` quantization floor and are noticeably noisier — prefer
the default iteration count.)
