//! Broad, subprocess-level runtime comparison for local Hermes shell vs Ibex.
//!
//! This is deliberately separate from `compartment_overhead`: that bench isolates
//! the LLP 0013 hot interpreter-path cost. This harness answers the coarser
//! question users ask first: "what do I pay when I run this JS through Ibex
//! instead of a Hermes shell, and what extra startup/runtime cost does the
//! explicitly diagnostic foreground audit add over production enforcement?"
//!
//! The Hermes arm uses the local `tools/hermes/hermes` by default. In this repo
//! that binary is normally produced by Ibex's Hermes install scripts, so it is a
//! useful "Hermes shell without Ibex bootstrap/host" control, not a guaranteed
//! upstream-unpatched control. Set `HERMES_BENCH_BIN` to an explicit upstream
//! Hermes shell when you need that stricter comparison.
//!
//! @ref LLP 0013#goals — broadens the runtime benchmark suite behind the
//! steady-state capsec overhead budget; `compartment_overhead` remains the
//! isolated hot-path guard measurement.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[derive(Clone, Copy)]
struct Workload {
    name: &'static str,
    file: &'static str,
    default_iters: u64,
    expect_result: bool,
}

#[derive(Clone, Copy)]
enum Runner {
    Hermes,
    IbexDefault,
    IbexAudit,
}

#[derive(Clone, Copy)]
struct Variant {
    name: &'static str,
    runner: Runner,
}

#[derive(Debug)]
struct RunResult {
    wall_ms: f64,
}

#[derive(Debug)]
struct Summary {
    median_ms: f64,
    mad_ms: f64,
}

const WORKLOADS: &[Workload] = &[
    Workload {
        name: "startup_empty",
        file: "startup_empty.js",
        default_iters: 1,
        expect_result: false,
    },
    Workload {
        name: "math_globals",
        file: "math_globals.js",
        default_iters: 4_000_000,
        expect_result: true,
    },
    Workload {
        name: "object_arrays",
        file: "object_arrays.js",
        default_iters: 280_000,
        expect_result: true,
    },
    Workload {
        name: "json_strings",
        file: "json_strings.js",
        default_iters: 18_000,
        expect_result: true,
    },
    Workload {
        name: "promise_chain",
        file: "promise_chain.js",
        default_iters: 12_000,
        expect_result: true,
    },
];

const VARIANTS: &[Variant] = &[
    Variant {
        name: "hermes-shell",
        runner: Runner::Hermes,
    },
    Variant {
        name: "ibex-default",
        runner: Runner::IbexDefault,
    },
    Variant {
        name: "ibex-audit",
        runner: Runner::IbexAudit,
    },
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_dir() -> PathBuf {
    manifest_dir()
        .join("benches")
        .join("fixtures")
        .join("runtime_compare")
}

fn ibex_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("IBEX_BENCH_BIN") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}

fn hermes_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("HERMES_BENCH_BIN") {
        return PathBuf::from(p);
    }
    manifest_dir().join("tools").join("hermes").join("hermes")
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(default)
}

fn scaled_iters(default_iters: u64, scale: f64) -> u64 {
    ((default_iters as f64 * scale).round() as u64).max(1)
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

fn wrapper_dir() -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir().join("target"));
    base.join("runtime-compare-wrappers")
}

fn wrapper_for(workload: Workload, iters: u64) -> PathBuf {
    let source_path = fixture_dir().join(workload.file);
    let source = std::fs::read_to_string(&source_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", source_path.display()));
    let dir = wrapper_dir();
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|err| panic!("failed to create {}: {err}", dir.display()));
    let path = dir.join(format!("{}-{}.js", workload.name, iters));
    let wrapped = format!("globalThis.__benchIters = {iters};\n{source}");
    std::fs::write(&path, wrapped)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
    path
}

fn clean_env(cmd: &mut Command) {
    // Keep inherited PATH/etc., but prevent an operator's security experiment
    // from silently contaminating this A/B.
    for key in [
        "IBEX_COMPARTMENTS",
        "IBEX_LOCKDOWN",
        "IBEX_PER_PACKAGE_CHUNKS",
        "IBEX_CAPSEC_ALLOW_ADVISORY",
        "IBEX_ENDOW",
        "IBEX_POLICY",
        "IBEX_NO_BYTECODE",
        "IBEX_NATIVE_LOCKDOWN",
        "EXACT_POLICY",
        "EXACT_NO_BYTECODE",
        "EXACT_NATIVE_LOCKDOWN",
    ] {
        cmd.env_remove(key);
    }
}

fn require_release_ibex(path: &Path) {
    let is_debug = path.components().any(|part| part.as_os_str() == "debug");
    let allow_debug =
        std::env::var_os("BENCH_ALLOW_DEBUG").as_deref() == Some(std::ffi::OsStr::new("1"));
    if is_debug && !allow_debug {
        eprintln!(
            "runtime_compare refuses a debug Ibex binary at {}\nBuild with `cargo build --release --bin ibex`, or set BENCH_ALLOW_DEBUG=1 for an explicitly non-comparable smoke run.",
            path.display()
        );
        std::process::exit(2);
    }
}

fn run_variant(
    variant: Variant,
    ibex: &Path,
    hermes: &Path,
    script: &Path,
    workload: Workload,
) -> RunResult {
    let (mut cmd, is_ibex) = match variant.runner {
        Runner::Hermes => {
            let mut cmd = Command::new(hermes);
            cmd.arg(script);
            (cmd, false)
        }
        Runner::IbexDefault => {
            let mut cmd = Command::new(ibex);
            cmd.arg("run").arg(script);
            (cmd, true)
        }
        Runner::IbexAudit => {
            let mut cmd = Command::new(ibex);
            cmd.args(["capsec", "audit"]).arg(script);
            (cmd, true)
        }
    };
    clean_env(&mut cmd);
    if is_ibex {
        // Hermes reparses on every invocation. Disable Ibex's persistent
        // bytecode cache so the two subprocess arms have symmetric warm-cache
        // behavior instead of measuring a cache only one runner owns.
        cmd.env("IBEX_NO_BYTECODE", "1");
    }

    let t0 = Instant::now();
    let out = cmd.output().unwrap_or_else(|err| {
        panic!(
            "failed to spawn variant={} script={}: {err}",
            variant.name,
            script.display()
        )
    });
    let wall_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let stdout = String::from_utf8_lossy(&out.stdout);

    if !out.status.success()
        || (workload.expect_result && !stdout.contains(&format!("BENCH_RESULT {}", workload.name)))
    {
        eprintln!(
            "runtime_compare failed: workload={} variant={} status={:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            workload.name,
            variant.name,
            out.status.code(),
            stdout,
            String::from_utf8_lossy(&out.stderr)
        );
        std::process::exit(1);
    }

    RunResult { wall_ms }
}

fn pct_delta(value: f64, base: f64) -> f64 {
    (value - base) / base * 100.0
}

fn main() {
    let ibex = ibex_bin();
    let hermes = hermes_bin();
    let samples = env_usize("BENCH_SAMPLES", 9).max(1);
    let warmup = env_usize("BENCH_WARMUP", 2);
    let scale = env_f64("BENCH_SCALE", 1.0);

    if !ibex.exists() {
        eprintln!(
            "ibex binary not found at {}\nBuild it first: cargo build --bin ibex (or set IBEX_BENCH_BIN)",
            ibex.display()
        );
        std::process::exit(1);
    }
    require_release_ibex(&ibex);
    if !hermes.exists() {
        eprintln!(
            "Hermes shell not found at {}\nRun scripts/download-hermes.sh, or set HERMES_BENCH_BIN to an explicit Hermes shell.",
            hermes.display()
        );
        std::process::exit(1);
    }

    eprintln!("runtime_compare: local Hermes shell vs Ibex subprocess wall-clock");
    eprintln!("  ibex   : {}", ibex.display());
    eprintln!("  hermes : {}", hermes.display());
    eprintln!("  samples: {samples}   warmup: {warmup}   scale: {scale}");

    println!();
    println!("=== Runtime Compare — Hermes shell vs Ibex ===");
    println!("medians are subprocess wall-clock; lower is better");
    println!("HERMES_BENCH_BIN can point at a true upstream-unpatched Hermes shell.");

    for workload in WORKLOADS {
        let iters = scaled_iters(workload.default_iters, scale);
        let script = wrapper_for(*workload, iters);

        for round in 0..warmup {
            for offset in 0..VARIANTS.len() {
                let variant = VARIANTS[(round + offset) % VARIANTS.len()];
                let _ = run_variant(variant, &ibex, &hermes, &script, *workload);
            }
        }

        let mut by_variant: BTreeMap<&'static str, Vec<f64>> = BTreeMap::new();
        for round in 0..samples {
            for offset in 0..VARIANTS.len() {
                let variant = VARIANTS[(warmup + round + offset) % VARIANTS.len()];
                let result = run_variant(variant, &ibex, &hermes, &script, *workload);
                by_variant
                    .entry(variant.name)
                    .or_default()
                    .push(result.wall_ms);
            }
        }

        let mut summaries = BTreeMap::new();
        for (name, xs) in by_variant {
            let median_ms = median(xs.clone());
            let mad_ms = median(xs.iter().map(|value| (value - median_ms).abs()).collect());
            summaries.insert(name, Summary { median_ms, mad_ms });
        }

        let hermes_base = summaries
            .get("hermes-shell")
            .expect("hermes-shell variant should be present")
            .median_ms;
        let ibex_base = summaries
            .get("ibex-default")
            .expect("ibex-default variant should be present")
            .median_ms;

        println!();
        println!("workload: {}  iters={}", workload.name, iters);
        println!(
            "{:<16} {:>10} {:>10} {:>14} {:>18}",
            "variant", "median ms", "MAD ms", "vs hermes", "vs ibex default"
        );
        for variant in VARIANTS {
            let summary = summaries
                .get(variant.name)
                .expect("variant should have a summary");
            let vs_hermes = pct_delta(summary.median_ms, hermes_base);
            let vs_ibex = pct_delta(summary.median_ms, ibex_base);
            println!(
                "{:<16} {:>10.2} {:>10.2} {:>+13.1}% {:>+17.1}%",
                variant.name, summary.median_ms, summary.mad_ms, vs_hermes, vs_ibex
            );
        }
    }
}
