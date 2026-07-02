//! @ref LLP 0013 — conformance + red-team suite for per-package capability
//! compartments. This is the durable asset the RFC's fork phases and every
//! future Hermes rebase are measured against: it drives the real `ibex` binary
//! against fixtures and asserts the security properties end-to-end.
//!
//! Run with: `cargo test --test llp0013_compartments`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("llp0013")
}

struct RunOutput {
    stdout: String,
    stderr: String,
    status: i32,
}

/// Run the ibex binary with the given args + extra env, returning captured
/// output. `cwd` defaults to the manifest dir.
fn run_ibex(args: &[&str], envs: &[(&str, &str)], cwd: Option<&Path>) -> RunOutput {
    let mut cmd = Command::new(IBEX);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let out = cmd.output().expect("failed to spawn ibex binary");
    RunOutput {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        status: out.status.code().unwrap_or(-1),
    }
}

fn fixture(name: &str) -> String {
    fixtures_dir().join(name).to_string_lossy().into_owned()
}

/// A unique scratch dir under the system temp dir (no external crates).
fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("ibex-llp0013-{}-{}-{}", tag, std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn have_js_runner() -> bool {
    which("bun") || which("node")
}

fn which(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Red-team suite (Mechanism 1: lockdown)
// ---------------------------------------------------------------------------

#[test]
fn redteam_all_contained_under_lockdown() {
    let out = run_ibex(&["--lockdown", "run", &fixture("redteam.js")], &[], None);
    assert!(
        !out.stdout.contains("NOT_CONTAINED"),
        "an attack was not contained under lockdown:\n{}",
        out.stdout
    );
    // Every named case must appear and be contained.
    for case in [
        "recover-real-global",
        "dynamic-code-Function",
        "dynamic-code-eval",
        "prototype-patch-Array",
        "proto-pollution",
        "generator-evaluator",
        "host-tamper-setActiveModuleId",
        "host-tamper-grantCapability",
    ] {
        assert!(
            out.stdout.contains(&format!("{case}: CONTAINED")),
            "case {case} missing/uncontained:\n{}",
            out.stdout
        );
    }
}

#[test]
fn redteam_ambient_attacks_succeed_without_lockdown() {
    // Without lockdown the ambient-authority attacks are real (NOT_CONTAINED),
    // which is exactly why lockdown is needed. This guards against the suite
    // silently passing because the attacks stopped working.
    let out = run_ibex(&["run", &fixture("redteam.js")], &[], None);
    for case in [
        "recover-real-global",
        "dynamic-code-Function",
        "prototype-patch-Array",
    ] {
        assert!(
            out.stdout.contains(&format!("{case}: NOT_CONTAINED")),
            "case {case} should be uncontained without lockdown:\n{}",
            out.stdout
        );
    }
    // The Phase 0 escape-hatch seal runs in ALL modes, so host tampering is
    // contained even without lockdown.
    assert!(
        out.stdout
            .contains("host-tamper-setActiveModuleId: CONTAINED"),
        "escape-hatch seal should hold in all modes:\n{}",
        out.stdout
    );
}

#[test]
fn lockdown_conformance_keeps_runtime_usable() {
    let out = run_ibex(
        &["--lockdown", "run", &fixture("lockdown-conformance.js")],
        &[],
        None,
    );
    for expected in [
        "lockedDown=true",
        "mapWorks=true",
        "instanceofWorks=true",
        "frozenProtoThrows=true",
        "registry=true",
    ] {
        assert!(
            out.stdout.contains(expected),
            "expected {expected} in output:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    }
}

#[test]
fn lockdown_is_off_by_default() {
    let out = run_ibex(&["run", &fixture("lockdown-conformance.js")], &[], None);
    assert!(
        out.stdout.contains("lockedDown=false"),
        "lockdown must be opt-in (off by default):\n{}",
        out.stdout
    );
}

// ---------------------------------------------------------------------------
// Compartment endowment (Mechanism 2)
// ---------------------------------------------------------------------------

#[test]
fn compartment_withholds_powerful_globals_and_honors_endowments() {
    let out = run_ibex(
        &["--lockdown", "run", &fixture("compartment-endowment.js")],
        &[("IBEX_ENDOW", "trusted-net:fetch")],
        None,
    );
    for expected in [
        "evil.process=undefined", // withheld
        "evil.fetch=undefined",   // withheld
        "evil.Object=function",   // shared intrinsic passes through
        "evil.console=object",    // shared intrinsic passes through
        "trusted.fetch=function", // endowed
    ] {
        assert!(
            out.stdout.contains(expected),
            "expected {expected}:\n{}\nstderr:\n{}",
            out.stdout,
            out.stderr
        );
    }
}

// ---------------------------------------------------------------------------
// End-to-end supply-chain containment (Mechanisms 1 + 2 via the bundler)
// ---------------------------------------------------------------------------

fn write_supply_chain_app(dir: &Path) {
    let pkg_dir = dir.join("node_modules").join("evil-pkg");
    std::fs::create_dir_all(&pkg_dir).expect("mkdir node_modules/evil-pkg");
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "evil-pkg", "version": "1.0.0", "main": "index.js" }"#,
    )
    .unwrap();
    std::fs::write(
        pkg_dir.join("index.js"),
        "module.exports = function steal() {\n\
         try { return 'STOLEN:' + process.env.SECRET_TOKEN; }\n\
         catch (e) { return 'CONTAINED:' + (e && e.name); }\n\
         };\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("app.js"),
        "const steal = require('evil-pkg');\nconsole.log('result: ' + steal());\n",
    )
    .unwrap();
}

#[test]
fn compromised_dependency_cannot_read_env_under_lockdown() {
    if !have_js_runner() {
        eprintln!("skipping: bundler (bun/node) not available; compartment rewrite needs it");
        return;
    }
    // Distinct dirs so the entry-path-keyed bundle cache never collides between
    // the locked-down and open runs.
    let locked = unique_dir("locked");
    write_supply_chain_app(&locked);
    let out = run_ibex(
        &["--lockdown", "run", locked.join("app.js").to_str().unwrap()],
        &[("SECRET_TOKEN", "hunter2")],
        None,
    );
    assert!(
        out.stdout.contains("result: CONTAINED"),
        "compromised dependency should be contained under lockdown:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    assert!(
        !out.stdout.contains("STOLEN:hunter2"),
        "secret leaked under lockdown:\n{}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&locked);
}

#[test]
fn compromised_dependency_succeeds_without_lockdown() {
    if !have_js_runner() {
        eprintln!("skipping: bundler (bun/node) not available");
        return;
    }
    let open = unique_dir("open");
    write_supply_chain_app(&open);
    let out = run_ibex(
        &["run", open.join("app.js").to_str().unwrap()],
        &[("SECRET_TOKEN", "hunter2")],
        None,
    );
    // Baseline: without compartments the attack works — proves the test setup
    // actually exercises the exfiltration path.
    assert!(
        out.stdout.contains("STOLEN:hunter2"),
        "baseline attack should succeed without lockdown:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    let _ = std::fs::remove_dir_all(&open);
}

// ---------------------------------------------------------------------------
// Audit / enforce modes (Phase 0/1)
// ---------------------------------------------------------------------------

#[test]
fn audit_mode_reports_would_deny_but_proceeds() {
    let out = run_ibex(
        &["--capsec", "audit", "run", &fixture("audit-probe.js")],
        &[],
        None,
    );
    // The operation proceeds (audit does not block)...
    assert!(
        out.stdout.contains("spawn: audit-probe-ran"),
        "audit mode must let the spawn proceed:\nstdout:\n{}\nstderr:\n{}",
        out.stdout,
        out.stderr
    );
    // ...and a would-deny report is emitted.
    assert!(
        out.stderr.contains("would-deny under enforce mode"),
        "audit mode must print a would-deny report:\n{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("process:spawn"),
        "the ungranted spawn should appear in the audit report:\n{}",
        out.stderr
    );
    // Audit never blocks, so the run exits cleanly.
    assert_eq!(
        out.status, 0,
        "audit run should exit 0; stderr:\n{}",
        out.stderr
    );
}

#[test]
fn capsec_aliases_parse() {
    // `strict` and `capability` are back-compat aliases for `enforce`.
    for mode in ["strict", "capability", "enforce", "audit", "permissive"] {
        let out = run_ibex(
            &["--capsec", mode, "run", &fixture("lockdown-conformance.js")],
            &[],
            None,
        );
        assert!(
            !out.stderr.contains("invalid value"),
            "--capsec {mode} should parse; stderr:\n{}",
            out.stderr
        );
    }
    // An unknown mode is rejected.
    let out = run_ibex(
        &[
            "--capsec",
            "bogus",
            "run",
            &fixture("lockdown-conformance.js"),
        ],
        &[],
        None,
    );
    assert!(
        out.stderr.contains("invalid value"),
        "unknown --capsec should be rejected:\n{}",
        out.stderr
    );
}
