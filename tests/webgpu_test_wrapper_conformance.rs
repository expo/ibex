//! Enforced Node 24.13.1 versus real Ibex/Hermes conformance gate for the
//! generated test-only WebGPU wrapper (ENG-25076).
//!
//! @ref LLP 0019#the-enforced-conformance-seam
//! @ref LLP 0026#compatibility-contract-and-conformance-corpus

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
fn generated_wrapper_matches_exact_node_and_real_hermes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script =
        root.join("packages/ibex-devtools/src/scripts/run-webgpu-test-wrapper-conformance.mjs");
    let output = Command::new(pinned_node())
        .arg(script)
        .arg("--ibex")
        .arg(IBEX)
        .current_dir(root)
        .output()
        .expect("run WebGPU test-wrapper conformance");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "WebGPU test-wrapper conformance failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(
            "webgpu-test-wrapper conformance: 1/1 corpus matched Node 24.13.1 and real Ibex/Hermes"
        ),
        "non-empty exact conformance count missing:\n{stdout}"
    );
    assert!(
        stdout.contains("25 operations, 17 requestDevice terminals"),
        "operation/terminal coverage count missing:\n{stdout}"
    );
}
