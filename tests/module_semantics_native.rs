//! LLP 0028 Phase-0 transform corpus through the real CLI's native source and
//! prepared profiles.
//!
//! @ref LLP 0028#5-conformance-gates-telemetry-and-rollout

#![cfg(any(
    all(
        feature = "capsec-conformance-observer",
        target_os = "macos",
        target_arch = "aarch64"
    ),
    all(
        feature = "capsec-conformance-observer",
        target_os = "linux",
        target_arch = "x86_64"
    )
))]

use std::path::PathBuf;
use std::process::Command;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn node() -> &'static str {
    for candidate in ["node", "bun"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return candidate;
        }
    }
    panic!("native module-semantics conformance requires node or bun");
}

#[test]
fn transform_corpus_executes_source_and_prepared_with_receipts() {
    let script =
        repo_root().join("packages/ibex-devtools/src/scripts/run-module-semantics-native.mjs");
    let output = Command::new(node())
        .arg(script)
        .args(["--ibex", IBEX])
        .current_dir(repo_root())
        .output()
        .expect("run native module-semantics corpus");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "native module-semantics corpus failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let summary = stdout
        .lines()
        .find(|line| line.starts_with("module-semantics native:"))
        .unwrap_or_else(|| panic!("native corpus emitted no summary: {stdout}"));
    let counts = summary
        .split_whitespace()
        .find_map(|token| token.split_once('/'))
        .and_then(|(passed, total)| Some((passed.parse::<u32>().ok()?, total.parse::<u32>().ok()?)))
        .expect("native corpus summary counts");
    assert_eq!(counts.0, counts.1);
    assert!(counts.1 > 0);
}
