//! Fail-loud Phase-0 module-semantics baseline gate (ENG-25056).
//!
//! The corpus is data-only and is executed by the exact Node oracle plus the
//! real built Ibex/Hermes binary. A missing exact oracle is a hard failure;
//! using an ambient newer Node would silently change the compatibility target.

use std::path::{Path, PathBuf};
use std::process::Command;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");
const PINNED_NODE: &str = "24.13.1";

fn pinned_node() -> PathBuf {
    if let Some(path) = std::env::var_os("IBEX_NODE_ORACLE_BIN") {
        return PathBuf::from(path);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let volta = PathBuf::from(home)
            .join(".volta/tools/image/node")
            .join(PINNED_NODE)
            .join("bin/node");
        if volta.is_file() {
            return volta;
        }
    }
    panic!(
        "Node {PINNED_NODE} oracle missing; set IBEX_NODE_ORACLE_BIN or run `volta fetch node@{PINNED_NODE}`"
    );
}

#[test]
fn current_loader_baseline_matches_exact_node_and_real_hermes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = root.join("packages/ibex-devtools/src/scripts/run-module-semantics-baseline.mjs");
    let output = Command::new(pinned_node())
        .arg(script)
        .arg("--ibex")
        .arg(IBEX)
        .current_dir(root)
        .output()
        .expect("run module-semantics baseline");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "module-semantics baseline failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("module-semantics baseline: 12/12"),
        "non-empty exact count missing:\n{stdout}"
    );
}
