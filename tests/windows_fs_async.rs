//! Windows runtime coverage for the worker-pool-backed native filesystem ABI.

#![cfg(windows)]

use std::process::Command;

#[test]
fn windows_async_fs_errno_append_fstat_and_flush_contract() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/windows_fs_async_smoke.js"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .args(["run", fixture])
        .env("IBEX_NO_BYTECODE", "1")
        .output()
        .expect("run Windows filesystem smoke");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let line = stdout
        .lines()
        .find_map(|line| line.strip_prefix("RESULT|"))
        .unwrap_or_else(|| panic!("missing RESULT line; stdout:\n{stdout}\nstderr:\n{stderr}"));
    let value: serde_json::Value = serde_json::from_str(line).expect("parse RESULT JSON");
    assert!(
        value["hooks"]
            .as_array()
            .expect("hooks array")
            .iter()
            .all(|hook| hook.as_bool() == Some(true)),
        "{value}"
    );
    assert_eq!(value["missingCode"], "ENOENT", "{value}");
    assert_eq!(value["existsCode"], "EEXIST", "{value}");
    assert_eq!(
        value["content"], "abcZ",
        "append fd reopened by path: {value}"
    );
    assert_eq!(
        value["sizeAfterRename"], 4,
        "fstat lost fd identity: {value}"
    );
}
