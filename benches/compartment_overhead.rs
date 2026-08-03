//! Steady-state overhead benchmark for LLP 0013 per-package compartments.
//!
//! LLP 0013 Goal 3 budgets the runtime overhead of the per-package capability
//! compartments at "=<1% on the runtime benchmark suite". This harness is that
//! suite's first (and, today, only) member: it measures the cost the carried
//! Hermes patch stack adds to the interpreter's hottest opcodes.
//!
//! ## What is measured
//!
//! Patches 0004/0005 re-point `GetGlobalObject`, `CoerceThisNS` and `LoadThisNS`
//! through `globalForFrame(runtime, curCodeBlock)`, which is guarded by
//! `Runtime::anyCompartmentActive_`:
//!
//! ```text
//!   if (LLVM_LIKELY(!runtime.anyCompartmentActive()))   // guard false -> skip
//!     return runtime.getGlobal().getHermesValue();
//!   ... resolve through the frame's Domain compartment global ...
//! ```
//!
//! So the meaningful A/B is the SAME compute-heavy workload with the guard
//! false (baseline) vs armed (active). The workload's hot loop runs in the ROOT
//! Domain, which has no compartment global, so the active arm resolves back to
//! the real global — isolating the branch + Domain walk with no Proxy-trap
//! confound. overhead = (active - baseline) / baseline.
//!
//! The guard is armed only when a compartment is bound to some package's Domain
//! (`__exactSetCompartmentFor`). The workload requires a trivial `arm-pkg`; under
//! `IBEX_COMPARTMENTS=1` the diagnostic fixture loader binds its compartment,
//! arming the guard for the whole process. The bench uses `ibex capsec audit`
//! with `EXACT_COMPAT_TEST=1`: this deliberately exercises the fixture
//! fidelity shims while ordinary production execution remains fail-closed
//! until this exact engine target has a verified advertisement.
//! `IBEX_COMPAT_LOADER_TEST=1` separately keeps the bounded fixture loader
//! selected, as required by LLP 0028's split between fixture fidelity and
//! preparation bypass. The bench reads `armed=<bool>` back from the run to
//! confirm the flag actually flipped (not just the env var).
//!
//! ## Running
//!
//!   cargo bench --bench compartment_overhead
//!
//! Wired as `harness = false`, so this file's `main` runs directly (no
//! criterion): criterion is built for in-process microbenchmarks, but the unit
//! of work here is a whole `ibex` subprocess, so a hand-rolled warmup +
//! median-of-N loop measures the subprocess wall-clock (and the run's own
//! startup-free inner loop time) more honestly.
//!
//! Tunable via env: `BENCH_ITERS`, `BENCH_SAMPLES`, `BENCH_WARMUP`, and
//! `IBEX_BENCH_BIN` (override the `ibex` binary path). Cargo-test execution, or
//! a debug binary with none of those measurement controls set, runs one small
//! correctness-only A/B pair and prints no performance verdict.
//!
//! ## Caveat
//!
//! Wall-clock is environment-sensitive; the =<1% budget is reported as
//! INFORMATIONAL (PASS / OVER-BUDGET), never asserted — a wall-clock perf gate
//! in CI would be flaky. The `inner` number excludes process boot and is the
//! cleaner steady-state signal.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// Path to the `ibex` binary. A runtime override (`IBEX_BENCH_BIN`) wins so a
/// reduced-iteration validation can point at an already-built debug binary
/// without a release rebuild; otherwise Cargo's per-bench `CARGO_BIN_EXE_ibex`.
fn ibex_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("IBEX_BENCH_BIN") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}

fn fixture_app() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("fixtures")
        .join("compartment_overhead")
        .join("app.js")
}

fn env_num(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

struct RunResult {
    wall_ms: f64,
    inner_ms: f64,
    result: u64,
    armed: bool,
}

/// Run one arm through the explicit diagnostic fixture route, with the
/// compartment guard either armed (`IBEX_COMPARTMENTS=1`) or not. Times the
/// whole subprocess and parses the workload's self-reported inner-loop time +
/// arming signal.
fn run_arm(bin: &Path, app: &Path, iters: u64, active: bool) -> RunResult {
    let mut cmd = Command::new(bin);
    cmd.args(["capsec", "audit"]).arg(app);
    cmd.env("BENCH_ITERS", iters.to_string());
    // Fixture mode bypasses the normal audit bundler (which always requests
    // compartments), preserving IBEX_COMPARTMENTS as the sole A/B toggle.
    // @ref LLP 0028#4-reachability-inventory-and-retirement-matrix — fixture
    // fidelity and compatibility-loader selection are distinct controls.
    cmd.env("EXACT_COMPAT_TEST", "1");
    cmd.env("IBEX_COMPAT_LOADER_TEST", "1");
    cmd.env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1");
    // Keep the two arms otherwise identical.
    cmd.env_remove("IBEX_LOCKDOWN");
    cmd.env_remove("IBEX_PER_PACKAGE_CHUNKS");
    if active {
        cmd.env("IBEX_COMPARTMENTS", "1");
    } else {
        cmd.env_remove("IBEX_COMPARTMENTS");
    }

    let t0 = Instant::now();
    let out = cmd.output().expect("failed to spawn ibex binary");
    let wall_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !stdout.contains("BENCH result=") {
        eprintln!(
            "bench workload failed (active={active}, status={:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status.code(),
            stdout,
            String::from_utf8_lossy(&out.stderr),
        );
        std::process::exit(1);
    }

    let mut result = 0u64;
    let mut inner_ms = f64::NAN;
    let mut armed = false;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("BENCH result=") {
            for field in rest.split_whitespace() {
                if let Some(v) = field.strip_prefix("result=") {
                    result = v.parse().unwrap_or(result);
                } else if let Some(v) = field.strip_prefix("ms=") {
                    inner_ms = v.parse().unwrap_or(inner_ms);
                } else {
                    // first token is the bare result value (no `result=` prefix)
                    result = field.parse().unwrap_or(result);
                }
            }
        } else if let Some(v) = line.strip_prefix("armed=") {
            armed = v.trim() == "true";
        }
    }

    RunResult {
        wall_ms,
        inner_ms,
        result,
        armed,
    }
}

fn cargo_test_invocation() -> bool {
    std::env::args_os().any(|arg| arg == "--test")
}

fn debug_binary(path: &Path) -> bool {
    path.components().any(|part| part.as_os_str() == "debug")
}

fn measurement_controls_set() -> bool {
    ["BENCH_ITERS", "BENCH_SAMPLES", "BENCH_WARMUP"]
        .iter()
        .any(|key| std::env::var_os(key).is_some())
}

fn verify_preconditions(base: &RunResult, active: &RunResult) {
    let mut failed = false;
    if base.armed {
        eprintln!(
            "FAIL: baseline arm reported the compartment guard ARMED — the A/B is not clean."
        );
        failed = true;
    }
    if !active.armed {
        eprintln!("FAIL: active arm did NOT report the compartment guard armed — IBEX_COMPARTMENTS did not take effect (unpatched engine? the bench needs the compartment-capable engine).");
        failed = true;
    }
    if base.result != active.result {
        eprintln!(
            "FAIL: arms computed different results (baseline={}, active={}); the workloads diverged — the A/B is not comparing like with like.",
            base.result, active.result
        );
        failed = true;
    }
    if failed {
        std::process::exit(1);
    }
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = xs.len();
    if n == 0 {
        return f64::NAN;
    }
    if n % 2 == 1 {
        xs[n / 2]
    } else {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    }
}

// @ref LLP 0013#goals — Goal 3: "Steady-state overhead =<1% on the runtime
// benchmark suite." This is that suite: it measures (active - baseline) /
// baseline for the compartment walk on the hottest interpreter opcodes and
// reports it against the 1% budget (informationally; the wall-clock gate is not
// asserted because it is environment-sensitive).
fn main() {
    let bin = ibex_bin();
    let app = fixture_app();

    if !bin.exists() {
        eprintln!(
            "ibex binary not found at {}\nBuild it first: cargo build --bin ibex (or set IBEX_BENCH_BIN)",
            bin.display()
        );
        std::process::exit(1);
    }

    let smoke = cargo_test_invocation() || (debug_binary(&bin) && !measurement_controls_set());
    if smoke {
        let iters = env_num("BENCH_ITERS", 100_000);
        eprintln!(
            "compartment_overhead: correctness smoke (one diagnostic baseline/active pair; no performance verdict)"
        );
        eprintln!("  binary : {}", bin.display());
        eprintln!("  iters  : {iters}");
        let base = run_arm(&bin, &app, iters, false);
        let active = run_arm(&bin, &app, iters, true);
        verify_preconditions(&base, &active);
        println!(
            "PASS: diagnostic A/B produced identical results with guard false/true as expected."
        );
        return;
    }

    let iters = env_num("BENCH_ITERS", 12_000_000);
    let samples = env_num("BENCH_SAMPLES", 15).max(1) as usize;
    let warmup = env_num("BENCH_WARMUP", 3) as usize;

    eprintln!("compartment_overhead: LLP 0013 Goal 3 steady-state A/B");
    eprintln!("  binary : {}", bin.display());
    eprintln!("  iters  : {iters}   samples: {samples}   warmup: {warmup}");

    // Warmup: exercise both arms and let CPU/OS caches settle; results discarded.
    for _ in 0..warmup {
        let _ = run_arm(&bin, &app, iters, false);
        let _ = run_arm(&bin, &app, iters, true);
    }

    let mut base_wall = Vec::with_capacity(samples);
    let mut base_inner = Vec::with_capacity(samples);
    let mut act_wall = Vec::with_capacity(samples);
    let mut act_inner = Vec::with_capacity(samples);
    let mut base_result = None;
    let mut act_result = None;
    let mut base_armed_any = false;
    let mut act_armed_all = true;

    // Interleave the arms sample-by-sample so slow drift (thermal, scheduler)
    // hits both roughly equally instead of biasing one.
    for _ in 0..samples {
        let b = run_arm(&bin, &app, iters, false);
        let a = run_arm(&bin, &app, iters, true);
        base_wall.push(b.wall_ms);
        base_inner.push(b.inner_ms);
        act_wall.push(a.wall_ms);
        act_inner.push(a.inner_ms);
        base_result.get_or_insert(b.result);
        act_result.get_or_insert(a.result);
        base_armed_any |= b.armed;
        act_armed_all &= a.armed;
    }

    let bw = median(base_wall);
    let bi = median(base_inner);
    let aw = median(act_wall);
    let ai = median(act_inner);
    let wall_overhead = (aw - bw) / bw * 100.0;
    let inner_overhead = (ai - bi) / bi * 100.0;

    println!();
    println!("=== LLP 0013 Goal 3 — compartment steady-state overhead ===");
    println!("baseline (guard false): wall median {bw:8.2} ms   inner median {bi:8.2} ms");
    println!("active   (guard armed): wall median {aw:8.2} ms   inner median {ai:8.2} ms");
    println!(
        "overhead:               wall {wall_overhead:+6.2}%              inner {inner_overhead:+6.2}%"
    );
    println!();

    // Precondition (HARD): the A/B must have actually flipped the guard and both
    // arms must have computed the identical result. If not, the measurement is
    // meaningless — fail loudly rather than report a bogus ≈0% and exit 0 (which a
    // CI job keying on exit code would read as a clean pass). This also catches an
    // unpatched engine where IBEX_COMPARTMENTS is a no-op.
    if base_armed_any || !act_armed_all || base_result != act_result {
        let base = RunResult {
            wall_ms: bw,
            inner_ms: bi,
            result: base_result.unwrap_or_default(),
            armed: base_armed_any,
        };
        let active = RunResult {
            wall_ms: aw,
            inner_ms: ai,
            result: act_result.unwrap_or_default(),
            armed: act_armed_all,
        };
        verify_preconditions(&base, &active);
        std::process::exit(1);
    }

    // Report the =<1% budget informationally against the startup-free inner
    // number (the cleaner steady-state signal). Never fails the process.
    let budget = 1.0;
    if inner_overhead <= budget {
        println!("PASS (informational): inner overhead {inner_overhead:+.2}% is within the =<{budget:.0}% Goal 3 budget.");
    } else {
        println!("OVER-BUDGET (informational): inner overhead {inner_overhead:+.2}% exceeds the =<{budget:.0}% Goal 3 budget (wall-clock is noisy; re-run before drawing conclusions).");
    }
}
