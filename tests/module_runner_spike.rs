//! Real-Hermes execution gate for the LLP 0026 bounded Oxc producer spike.
//!
//! @ref LLP 0026#adoption-gate — canonical factories must execute on the real
//! engine; a missing Hermes binary is a failure, never a skip.

use std::path::{Path, PathBuf};
use std::process::Command;

fn hermes_binary(root: &Path) -> PathBuf {
    std::env::var_os("IBEX_HERMES_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("tools/hermes/hermes"))
}

#[test]
fn canonical_oxc_artifacts_execute_on_real_hermes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let hermes = hermes_binary(root);
    assert!(
        hermes.is_file(),
        "real Hermes is required; set IBEX_HERMES_BIN or install tools/hermes/hermes"
    );
    let node = std::env::var_os("IBEX_NODE_ORACLE_BIN").unwrap_or_else(|| "node".into());
    let output = Command::new(node)
        .arg(root.join("packages/ibex-devtools/src/scripts/run-module-runner-spike.mjs"))
        .arg("--hermes")
        .arg(&hermes)
        .current_dir(root)
        .output()
        .expect("run module-runner spike");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "module-runner spike failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let summary = stdout
        .lines()
        .find(|line| line.starts_with("module-runner spike:"))
        .expect("non-empty real-Hermes summary");
    assert!(summary.contains("12/12"), "unexpected summary: {summary}");
}

#[test]
fn predeclared_test262_threshold_passes_on_real_hermes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let hermes = hermes_binary(root);
    assert!(
        hermes.is_file(),
        "real Hermes is required; set IBEX_HERMES_BIN or install tools/hermes/hermes"
    );
    let node = std::env::var_os("IBEX_NODE_ORACLE_BIN").unwrap_or_else(|| "node".into());
    let output = Command::new(node)
        .arg(root.join("packages/ibex-devtools/src/scripts/run-module-runner-test262-spike.mjs"))
        .arg("--hermes")
        .arg(&hermes)
        .current_dir(root)
        .output()
        .expect("run module-runner test262 spike");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "module-runner test262 threshold failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let summary = stdout
        .lines()
        .find(|line| line.starts_with("module-runner test262 spike:"))
        .expect("non-empty test262 real-Hermes summary");
    assert!(
        summary.contains("20/20") && summary.contains("threshold 18/20 (met)"),
        "unexpected summary: {summary}"
    );
}
