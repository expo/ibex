//! Negative regression for the insecure-mode `process.env` projection
//! (issues/20260724-insecure-process-env.md): in a secure build — including
//! `unadvertised-dev-arming`, which arms with every other authenticator
//! intact — a host-only sentinel must be neither readable nor enumerable
//! through `process.env`. The armed base stays explicitly empty; values exist
//! only in explicitly authorized per-principal overlays.
//!
//! This is the twin of `tests/insecure_process_env.rs` and runs under
//! `scripts/check-secure-mode.sh` (`--no-default-features --features
//! standard,unadvertised-dev-arming`), where execution routes still work.
#![cfg(all(not(feature = "insecure"), feature = "unadvertised-dev-arming"))]

use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");
const EVAL_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test]
async fn secure_process_env_never_leaks_an_inherited_host_sentinel() {
    let mut cmd = Command::new(IBEX);
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd.env("IBEX_TEST_ENV_SENTINEL", "must-not-leak");
    cmd.arg("eval").arg(concat!(
        "console.log(JSON.stringify({",
        "  direct: process.env.IBEX_TEST_ENV_SENTINEL === undefined,",
        "  enumerated: Object.keys(process.env).includes('IBEX_TEST_ENV_SENTINEL'),",
        "  keyCount: Object.keys(process.env).length,",
        "}));"
    ));
    let output = timeout(EVAL_TIMEOUT, cmd.output())
        .await
        .expect("secure eval timed out")
        .expect("spawn ibex");
    assert!(output.status.success(), "secure eval failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.starts_with('{'))
        .expect("JSON line in stdout");
    let json: serde_json::Value = serde_json::from_str(line).expect("stdout JSON parses");
    assert_eq!(json["direct"], true, "sentinel readable in secure mode");
    assert_eq!(json["enumerated"], false, "sentinel enumerable in secure mode");
    assert_eq!(json["keyCount"], 0, "secure armed base must stay empty");
}
