//! Hermes-compat conformance runners, enforced through `cargo test` /
//! `scripts/run-tests.sh` (ENG-22989).
//!
//! @ref LLP 0019#the-enforced-conformance-seam — this is what makes the
//! documented two-tier split (canonical AST authority + constrained loader
//! scanner) safe: both tiers run the same corpus on every test run.
//!
//! Two runners share one corpus (`hermes-compat-corpus.mjs`) and one V8/Node
//! oracle:
//!
//! - the AST path: the canonical `fixForOfScoping` in `hermes-compat.mjs`,
//!   checked against the oracle and the standalone Hermes binary
//!   (`run-hermes-compat-corpus.mjs`);
//! - the loader path: the REAL `ibex` binary's in-process module pipeline
//!   (SWC transpile + the embedded bootstrap loader's string-scanner rewrite),
//!   with expected loader-vs-oracle divergences encoded explicitly
//!   (`run-hermes-compat-loader.mjs`).
//!
//! The JS runners are the single source of truth; these tests only spawn them
//! and fail loud on any nonzero exit or an empty/failed summary, so the
//! cross-implementation coverage cannot silently stop running (LLP 0018).
//!
//! Run with: `scripts/run-tests.sh hermes_compat` (or
//! `cargo test --test hermes_compat_conformance`).

use std::path::{Path, PathBuf};
use std::process::Command;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn scripts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("packages")
        .join("ibex-devtools")
        .join("src")
        .join("scripts")
}

/// Find a JS runner for the .mjs conformance scripts. Node is preferred; bun
/// runs the same ESM fine. No runner at all is a hard failure — silently
/// skipping would green a build whose conformance gate never ran.
fn js_runner() -> &'static str {
    for candidate in ["node", "bun"] {
        let ok = Command::new(candidate)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return candidate;
        }
    }
    panic!(
        "neither `node` nor `bun` is on PATH; the Hermes-compat conformance runners \
         cannot run. Install one (the repo already requires bun for regenerate-vendored)."
    );
}

/// Spawn a conformance runner and assert it passed with a non-empty corpus.
/// `summary_marker` is the runner's summary-line prefix; the parsed `P/T`
/// counts must be equal and greater than zero.
fn run_conformance_script(script: &str, args: &[&str], summary_marker: &str) {
    let script_path = scripts_dir().join(script);
    assert!(
        script_path.exists(),
        "conformance runner missing: {}",
        script_path.display()
    );
    let out = Command::new(js_runner())
        .arg(&script_path)
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("failed to spawn JS runner");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{script} failed (exit {:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status.code()
    );

    // Parse the "<marker>: P/T fixtures ok" summary and require P == T > 0 so
    // a runner that silently ran nothing cannot pass.
    let summary = stdout
        .lines()
        .find(|line| line.contains(summary_marker) && line.contains("fixtures ok"))
        .unwrap_or_else(|| {
            panic!("{script} printed no '{summary_marker}' summary:\n{stdout}")
        });
    let counts = summary
        .split_whitespace()
        .find(|token| token.contains('/'))
        .and_then(|token| {
            let (passed, total) = token.split_once('/')?;
            Some((passed.parse::<u32>().ok()?, total.parse::<u32>().ok()?))
        })
        .unwrap_or_else(|| panic!("{script} summary not parseable: {summary}"));
    assert!(
        counts.0 == counts.1 && counts.1 > 0,
        "{script}: expected all of a non-empty corpus to pass, got {}/{}:\n{stdout}",
        counts.0,
        counts.1
    );
}

/// AST path: canonical fixForOfScoping vs the V8/Node oracle (and standalone
/// Hermes when tools/hermes is present — the runner reports which).
#[test]
fn hermes_compat_ast_corpus_passes() {
    run_conformance_script("run-hermes-compat-corpus.mjs", &[], "hermes-compat corpus:");
}

/// Loader path: the same corpus through the actual built `ibex` binary's
/// module loader, with documented divergences pinned exactly.
#[test]
fn hermes_compat_loader_corpus_passes_against_real_binary() {
    run_conformance_script(
        "run-hermes-compat-loader.mjs",
        &["--ibex", IBEX],
        "hermes-compat loader corpus:",
    );
}
