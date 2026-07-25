//! End-to-end coverage for the insecure-mode `process.env` projection
//! (issues/20260724-insecure-process-env.md): a default/insecure CLI build
//! exposes the host environment inherited at Ibex startup through
//! `process.env`, with Node-compatible read/write/delete/enumeration and
//! child-process semantics, on every execution route (inline eval and the
//! authenticated stdin worker). Secure builds compile none of this — see
//! `tests/secure_process_env.rs` for the negative twin.
//!
//! Run with: `cargo test --test insecure_process_env`.
#![cfg(feature = "insecure")]

use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;
use tokio::time::timeout;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");
/// Debug binaries under full-matrix load need generous deadlock bounds; this
/// is not a startup-performance assertion.
const EVAL_TIMEOUT: Duration = Duration::from_secs(120);

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn ibex_command() -> Command {
    let mut cmd = Command::new(IBEX);
    cmd.current_dir(repo_root());
    cmd.env("IBEX_TEST_ENV_SENTINEL", "from-host");
    cmd
}

fn stdout_json(output: &std::process::Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.starts_with('{'))
        .unwrap_or_else(|| {
            panic!(
                "no JSON line in stdout: {stdout:?}, stderr: {:?}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    serde_json::from_str(line).expect("stdout JSON parses")
}

/// Store-level semantics of the ambient projection, in this test binary's own
/// process (the CLI spawns in the other tests never share it). Lives here
/// rather than as a `src/` unit test so the runtime environment inventory —
/// which scans `src/` and `packages/` — does not pick up the test's own
/// `set_var`/`remove_var` calls as production surface.
#[test]
fn ambient_store_snapshots_mutates_and_deletes() {
    use ibex_runtime::host::process::*;

    std::env::set_var("IBEX_AMBIENT_TEST_SENTINEL", "inherited");
    std::env::set_var("EXACT_IPC_FD", "17");
    assert!(!insecure_ambient_environment_active());
    assert_eq!(insecure_ambient_env_get("IBEX_AMBIENT_TEST_SENTINEL"), None);

    install_insecure_ambient_environment();
    install_insecure_ambient_environment(); // idempotent
    std::env::remove_var("EXACT_IPC_FD");
    assert!(insecure_ambient_environment_active());

    // Inherited value is readable and enumerable.
    assert_eq!(
        insecure_ambient_env_get("IBEX_AMBIENT_TEST_SENTINEL").as_deref(),
        Some("inherited")
    );
    let count = insecure_ambient_env_key_count().unwrap();
    let names: Vec<String> = (0..count).filter_map(insecure_ambient_env_key_at).collect();
    assert!(names.iter().any(|n| n == "IBEX_AMBIENT_TEST_SENTINEL"));
    // The private construction handshake is not public environment.
    assert!(names.iter().all(|n| n != "EXACT_IPC_FD"));
    assert_eq!(insecure_ambient_env_get("EXACT_IPC_FD"), None);

    // Present-but-empty stays distinguishable from unset.
    insecure_ambient_env_set("IBEX_AMBIENT_TEST_EMPTY", Some(""));
    assert_eq!(
        insecure_ambient_env_get("IBEX_AMBIENT_TEST_EMPTY").as_deref(),
        Some("")
    );

    // Assignment overrides the inherited value; deletion removes it and the
    // host value does not resurface.
    insecure_ambient_env_set("IBEX_AMBIENT_TEST_SENTINEL", Some("written"));
    assert_eq!(
        insecure_ambient_env_get("IBEX_AMBIENT_TEST_SENTINEL").as_deref(),
        Some("written")
    );
    insecure_ambient_env_set("IBEX_AMBIENT_TEST_SENTINEL", None);
    assert_eq!(insecure_ambient_env_get("IBEX_AMBIENT_TEST_SENTINEL"), None);
    let count = insecure_ambient_env_key_count().unwrap();
    assert!((0..count)
        .filter_map(insecure_ambient_env_key_at)
        .all(|n| n != "IBEX_AMBIENT_TEST_SENTINEL"));

    // A JS re-set of a filtered construction name is ordinary state.
    insecure_ambient_env_set("EXACT_IPC_FD", Some("explicit"));
    assert_eq!(
        insecure_ambient_env_get("EXACT_IPC_FD").as_deref(),
        Some("explicit")
    );

    // Windows names are case-insensitive; elsewhere they are exact.
    insecure_ambient_env_set("IBEX_AMBIENT_TEST_CASE", Some("v1"));
    if cfg!(windows) {
        assert_eq!(
            insecure_ambient_env_get("ibex_ambient_test_case").as_deref(),
            Some("v1")
        );
    } else {
        assert_eq!(insecure_ambient_env_get("ibex_ambient_test_case"), None);
    }
}

#[tokio::test]
async fn insecure_eval_reads_enumerates_mutates_and_deletes_inherited_env() {
    let mut cmd = ibex_command();
    cmd.arg("eval").arg(concat!(
        "const out = {",
        "  inherited: process.env.IBEX_TEST_ENV_SENTINEL,",
        "  enumerated: Object.keys(process.env).includes('IBEX_TEST_ENV_SENTINEL'),",
        "  inOperator: 'IBEX_TEST_ENV_SENTINEL' in process.env,",
        "};",
        "process.env.IBEX_TEST_ENV_SENTINEL = 'rewritten';",
        "out.rewritten = process.env.IBEX_TEST_ENV_SENTINEL;",
        "process.env.IBEX_TEST_COERCED = 42;",
        "out.coerced = process.env.IBEX_TEST_COERCED;",
        "delete process.env.IBEX_TEST_ENV_SENTINEL;",
        "out.unsetAfterDelete = process.env.IBEX_TEST_ENV_SENTINEL === undefined;",
        "out.goneFromKeys = !Object.keys(process.env).includes('IBEX_TEST_ENV_SENTINEL');",
        "console.log(JSON.stringify(out));"
    ));
    let output = timeout(EVAL_TIMEOUT, cmd.output())
        .await
        .expect("insecure eval timed out")
        .expect("spawn ibex");
    assert!(output.status.success(), "eval failed: {output:?}");
    let json = stdout_json(&output);
    assert_eq!(json["inherited"], "from-host");
    assert_eq!(json["enumerated"], true);
    assert_eq!(json["inOperator"], true);
    assert_eq!(json["rewritten"], "rewritten");
    assert_eq!(json["coerced"], "42");
    assert_eq!(json["unsetAfterDelete"], true);
    assert_eq!(json["goneFromKeys"], true);
}

#[tokio::test]
async fn insecure_stdin_worker_route_observes_the_same_projection() {
    let mut cmd = ibex_command();
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn ibex stdin program");
    child
        .stdin
        .take()
        .expect("stdin handle")
        .write_all(b"console.log(JSON.stringify({worker: process.env.IBEX_TEST_ENV_SENTINEL}));")
        .await
        .expect("write stdin program");
    let output = timeout(EVAL_TIMEOUT, child.wait_with_output())
        .await
        .expect("stdin worker timed out")
        .expect("collect worker output");
    assert!(output.status.success(), "stdin program failed: {output:?}");
    assert_eq!(stdout_json(&output)["worker"], "from-host");
}

#[tokio::test]
async fn insecure_children_inherit_the_javascript_visible_environment() {
    let mut cmd = ibex_command();
    cmd.arg("eval").arg(concat!(
        "const cp = require('child_process');",
        "process.env.IBEX_TEST_MUTATED = 'js-set';",
        "const inherit = cp.spawnSync('/bin/sh', ['-c',",
        "  'printf \"%s|%s\" \"$IBEX_TEST_ENV_SENTINEL\" \"$IBEX_TEST_MUTATED\"']);",
        "const overlay = cp.spawnSync('/bin/sh', ['-c',",
        "  'printf \"%s|%s\" \"$IBEX_TEST_ENV_SENTINEL\" \"$IBEX_TEST_ONLY\"'],",
        "  { env: { IBEX_TEST_ONLY: 'just-this' } });",
        "console.log(JSON.stringify({",
        "  inherit: String(inherit.stdout),",
        "  overlay: String(overlay.stdout),",
        "}));"
    ));
    let output = timeout(EVAL_TIMEOUT, cmd.output())
        .await
        .expect("child inheritance eval timed out")
        .expect("spawn ibex");
    assert!(output.status.success(), "eval failed: {output:?}");
    let json = stdout_json(&output);
    // Default inheritance observes the full JavaScript-visible environment,
    // including post-startup mutations; an explicit `env` overlay replaces it.
    assert_eq!(json["inherit"], "from-host|js-set");
    assert_eq!(json["overlay"], "|just-this");
}
