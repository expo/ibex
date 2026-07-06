//! End-to-end tests for the `ibex` CLI eval/run surface, driving the real
//! binary. Ported from exact's stranded `packages/exact-cli/tests/cli_eval.rs`
//! after the LLP 0180 split orphaned that suite (ENG-22429); this repo is the
//! home of the `ibex` binary (LLP 0010), so the suite lives here now.
//!
//! Two contracts in here were interim-guarded exact-side by
//! `scripts/check-ibex-runtime-behavior.mjs` and are re-pinned properly:
//!
//!   * `cli_identity_is_node_primary_and_coherent` — LLP 0012: one identity,
//!     claimed coherently, pinned against `runtime-identity.json` (the
//!     authority file lives at this repo's root).
//!   * `cli_honors_process_exit_code_at_natural_exit` — process.exitCode set
//!     by user code is honored at natural exit for both `-e` and file runs.
//!
//! Run with: `scripts/run-tests.sh --scope test cli_` (or `cargo test --test cli_eval`).

use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn repo_root() -> PathBuf {
    // The package manifest dir IS the repo root here (unlike the exact
    // monorepo original, which had to hop two parents up).
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[tokio::test]
async fn cli_eval_one_returns_quickly() {
    let mut cmd = Command::new(IBEX);
    cmd.arg("-p").arg("1");

    let output = timeout(Duration::from_secs(5), cmd.output())
        .await
        .expect("CLI eval timed out");
    let output = output.expect("failed to spawn or read ibex process output");

    assert!(
        output.status.success(),
        "ibex eval should exit successfully"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let last_line = stdout.trim_end().lines().last().unwrap_or("");
    assert_eq!(last_line, "1");
}

#[tokio::test]
async fn cli_print_first_require_fs_promises_has_exports() {
    let mut cmd = Command::new(IBEX);
    cmd.arg("-p").arg(
        "(function(){ var mod = require('fs/promises'); return JSON.stringify({ hasReadFile: !!mod.readFile, keyCount: Object.keys(mod).length }); })()",
    );

    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("CLI print timed out");
    let output = output.expect("failed to spawn or read ibex process output");

    assert!(
        output.status.success(),
        "ibex -p should exit successfully: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = stdout.trim_end().lines().last().unwrap_or("");
    let parsed: Value = serde_json::from_str(json).expect("stdout should be valid JSON");
    assert_eq!(parsed["hasReadFile"], Value::Bool(true));
    assert!(
        parsed["keyCount"].as_u64().unwrap_or(0) > 0,
        "fs/promises should expose exports on first require: {json}"
    );
}

#[tokio::test]
async fn cli_print_waits_for_async_promise_resolution() {
    let mut cmd = Command::new(IBEX);
    cmd.arg("-p").arg(
        "(async function(){ await new Promise(function(resolve){ setTimeout(function(){ resolve(); }, 10); }); return 42; })()",
    );

    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("CLI print timed out");
    let output = output.expect("failed to spawn or read ibex process output");

    assert!(
        output.status.success(),
        "ibex -p should exit successfully: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let last_line = stdout.trim_end().lines().last().unwrap_or("");
    assert_eq!(last_line, "42");
}

#[tokio::test]
async fn cli_print_fs_promises_readfile_without_encoding_returns_buffer() {
    let readme_path = repo_root().join("README.md");
    let readme_path_json = serde_json::to_string(&readme_path.to_string_lossy().into_owned())
        .expect("path should serialize");
    let script = format!(
        "(async function(){{ var fsp = require('fs/promises'); var bytes = await fsp.readFile({readme_path_json}); return JSON.stringify({{ isBuffer: typeof Buffer === 'function' && Buffer.isBuffer(bytes), length: bytes.length }}); }})()"
    );

    let mut cmd = Command::new(IBEX);
    cmd.arg("-p").arg(script);

    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("CLI print timed out");
    let output = output.expect("failed to spawn or read ibex process output");

    assert!(
        output.status.success(),
        "ibex -p should exit successfully: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = stdout.trim_end().lines().last().unwrap_or("");
    let parsed: Value = serde_json::from_str(json).expect("stdout should be valid JSON");
    assert_eq!(parsed["isBuffer"], Value::Bool(true));
    assert!(
        parsed["length"].as_u64().unwrap_or(0) > 0,
        "fs/promises.readFile should return non-empty contents for README.md: {json}"
    );
}

#[tokio::test]
async fn cli_print_shared_runtime_installs_bootstrap_globals() {
    let mut cmd = Command::new(IBEX);
    cmd.arg("--compat").arg("bun");
    cmd.arg("-p").arg(
        r#"(function() {
            var text = globalThis.Bun.unsafe.arrayBufferToString(new Uint8Array([104, 105]));
            var bytes = globalThis.crypto.getRandomValues(new Uint8Array(4));
            var uuid = globalThis.crypto.randomUUID();
            return JSON.stringify({
              hasBunUnsafe: !!globalThis.Bun.unsafe,
              hasPeekStatus: typeof globalThis.Bun.peek.status === 'function',
              text: text,
              randomLength: bytes.length,
              uuidLength: uuid.length
            });
        })()"#,
    );

    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("CLI print timed out");
    let output = output.expect("failed to spawn or read ibex process output");

    assert!(
        output.status.success(),
        "ibex -p should exit successfully: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = stdout.trim_end().lines().last().unwrap_or("");
    let parsed: Value = serde_json::from_str(json).expect("stdout should be valid JSON");
    assert_eq!(parsed["hasBunUnsafe"], Value::Bool(true));
    assert_eq!(parsed["hasPeekStatus"], Value::Bool(true));
    assert_eq!(parsed["text"], Value::String("hi".to_string()));
    assert_eq!(
        parsed["randomLength"].as_u64(),
        Some(4),
        "crypto.getRandomValues should fill a 4-byte array: {json}"
    );
    assert_eq!(
        parsed["uuidLength"].as_u64(),
        Some(36),
        "crypto.randomUUID should produce a canonical UUID string: {json}"
    );
}

#[tokio::test]
async fn cli_print_shared_runtime_exposes_lazy_file_globals() {
    let readme_path = repo_root().join("README.md");
    let readme_path_json = serde_json::to_string(&readme_path.to_string_lossy().into_owned())
        .expect("path should serialize");
    let script = format!(
        r#"(async function() {{
            var fileTypes = {{
              bunFile: typeof globalThis.Bun.file,
              exactFile: typeof globalThis.Exact.file,
              sameObject: globalThis.Bun === globalThis.Exact
            }};
            var text = await globalThis.Bun.file({readme_path_json}).text();
            return JSON.stringify({{
              bunFile: fileTypes.bunFile,
              exactFile: fileTypes.exactFile,
              sameObject: fileTypes.sameObject,
              readLength: text.length
            }});
        }})()"#
    );

    let mut cmd = Command::new(IBEX);
    cmd.arg("--compat").arg("bun");
    cmd.arg("-p").arg(script);

    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("CLI print timed out");
    let output = output.expect("failed to spawn or read ibex process output");

    assert!(
        output.status.success(),
        "ibex -p should exit successfully: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = stdout.trim_end().lines().last().unwrap_or("");
    let parsed: Value = serde_json::from_str(json).expect("stdout should be valid JSON");
    assert_eq!(parsed["bunFile"], Value::String("function".to_string()));
    assert_eq!(parsed["exactFile"], Value::String("function".to_string()));
    assert_eq!(parsed["sameObject"], Value::Bool(true));
    assert!(
        parsed["readLength"].as_u64().unwrap_or(0) > 0,
        "Bun.file(...).text() should read README.md via the shared runtime bootstrap: {json}"
    );
}

#[tokio::test]
async fn cli_run_top_level_await_with_import_meta_url() {
    // LLP 0175 ledger item 1 (exact-side history): combining top-level await
    // with import.meta.url crashed with `ReferenceError: Property '__filename'
    // doesn't exist` because the bundler's define lowers import.meta.url to a
    // __filename-based expression that the TLA eval wrap never bound.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("tla_meta.ts");
    std::fs::write(
        &file,
        "console.log(import.meta.url);\nconst x = await Promise.resolve(7);\nconsole.log('tla-result', x);\n",
    )
    .expect("write fixture");

    let mut cmd = Command::new(IBEX);
    cmd.arg(file.to_string_lossy().as_ref());
    cmd.env("IBEX_NO_BYTECODE", "1");

    let output = timeout(Duration::from_secs(20), cmd.output())
        .await
        .expect("CLI run timed out");
    let output = output.expect("failed to spawn or read ibex process output");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ibex should run TLA + import.meta.url: status={:?}, stderr={stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains("file://"),
        "import.meta.url should resolve to a file URL: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("tla-result 7"),
        "top-level await should complete: stdout={stdout} stderr={stderr}"
    );
}

#[tokio::test]
async fn cli_console_log_prints_strings_raw() {
    // LLP 0175 ledger item 5 (exact-side history): string arguments after the
    // first were inspect-quoted (`a 'b'`); Node prints them raw (`a b`).
    let mut cmd = Command::new(IBEX);
    cmd.arg("-e").arg(r#"console.log("a", "b", 1, { x: "y" })"#);

    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("CLI eval timed out");
    let output = output.expect("failed to spawn or read ibex process output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let last_line = stdout.trim_end().lines().last().unwrap_or("");
    assert_eq!(last_line, "a b 1 { x: 'y' }");
}

#[tokio::test]
async fn cli_completion_bash_targets_ibex_not_node() {
    // LLP 0175 ledger item 4 (exact-side history): the old output was Node's
    // completion script verbatim, registering completions for `node node_g`.
    let mut cmd = Command::new(IBEX);
    cmd.arg("--completion-bash");

    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("CLI completion timed out");
    let output = output.expect("failed to spawn or read ibex process output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ibex"),
        "completion script should target ibex: {stdout}"
    );
    assert!(
        !stdout.contains("node_g"),
        "completion script must not register for node: {stdout}"
    );
}

#[tokio::test]
async fn cli_rerun_picks_up_imported_file_edits() {
    // LLP 0175 ledger item 2 (exact-side history): the bundle cache keyed on
    // the entry file only, so editing an imported module re-ran stale code.
    let dir = tempfile::tempdir().expect("tempdir");
    let entry = dir.path().join("main.ts");
    let dep = dir.path().join("util.ts");
    std::fs::write(
        &entry,
        "import { v } from './util.ts';\nconsole.log('value', v);\n",
    )
    .expect("write entry");
    std::fs::write(&dep, "export const v = 'one';\n").expect("write dep");

    let run = |entry: PathBuf| async move {
        let mut cmd = Command::new(IBEX);
        cmd.arg(entry.to_string_lossy().as_ref());
        cmd.env("IBEX_NO_BYTECODE", "1");
        let output = timeout(Duration::from_secs(20), cmd.output())
            .await
            .expect("CLI run timed out")
            .expect("failed to spawn or read ibex process output");
        assert!(
            output.status.success(),
            "run should succeed: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).to_string()
    };

    let first = run(entry.clone()).await;
    assert!(first.contains("value one"), "first run: {first}");

    std::fs::write(&dep, "export const v = 'two';\n").expect("edit dep");
    let second = run(entry).await;
    assert!(
        second.contains("value two"),
        "second run must see the imported-file edit, not stale cache: {second}"
    );
}

#[tokio::test]
async fn cli_identity_is_node_primary_and_coherent() {
    // LLP 0012 (upstream LLP 0175 §7): one identity, claimed coherently. No
    // ambient Bun global, no v8/uv/openssl/modules masquerade, truthful
    // ibex/hermes keys pinned to runtime-identity.json (the authority file at
    // this repo's root); the opt-in Bun surface sets process.versions.bun so
    // detection agrees with itself in both states.
    let identity: Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("runtime-identity.json"))
            .expect("runtime-identity.json readable"),
    )
    .expect("runtime-identity.json parses");
    let pinned_node = identity["versions"]["node"]
        .as_str()
        .expect("runtime-identity.json pins versions.node")
        .to_string();
    let pinned_ibex = identity["versions"]["ibex"]
        .as_str()
        .expect("runtime-identity.json pins versions.ibex")
        .to_string();

    let probe = r#"JSON.stringify({
        bunType: typeof Bun,
        bunVersion: (typeof process !== 'undefined' && process.versions && process.versions.bun) || null,
        node: process.versions.node || null,
        ibex: process.versions.ibex || null,
        hermes: process.versions.hermes || null,
        v8: process.versions.v8 || null,
        uv: process.versions.uv || null,
        openssl: process.versions.openssl || null,
        modules: process.versions.modules || null,
        exact: process.versions.exact || null,
        releaseName: (process.release && process.release.name) || null
    })"#;

    let mut cmd = Command::new(IBEX);
    cmd.arg("-p").arg(probe);
    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("CLI print timed out")
        .expect("failed to spawn or read ibex process output");
    assert!(
        output.status.success(),
        "default identity probe should run: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value =
        serde_json::from_str(stdout.trim_end().lines().last().unwrap_or("")).expect("json");
    assert_eq!(parsed["bunType"], "undefined", "no ambient Bun: {parsed}");
    assert_eq!(parsed["bunVersion"], Value::Null);
    assert_eq!(
        parsed["node"],
        Value::String(pinned_node),
        "process.versions.node matches runtime-identity.json: {parsed}"
    );
    assert_eq!(
        parsed["ibex"],
        Value::String(pinned_ibex),
        "process.versions.ibex matches runtime-identity.json: {parsed}"
    );
    assert!(
        parsed["hermes"].is_string(),
        "hermes version present: {parsed}"
    );
    assert_eq!(parsed["v8"], Value::Null, "no v8 masquerade: {parsed}");
    assert_eq!(parsed["uv"], Value::Null, "no uv masquerade: {parsed}");
    assert_eq!(
        parsed["openssl"],
        Value::Null,
        "no openssl masquerade: {parsed}"
    );
    assert_eq!(
        parsed["modules"],
        Value::Null,
        "no native-addon ABI claim: {parsed}"
    );
    assert_eq!(
        parsed["exact"],
        Value::Null,
        "no framework brand key: {parsed}"
    );
    assert_eq!(parsed["releaseName"], "node");

    let mut cmd = Command::new(IBEX);
    cmd.arg("--compat").arg("bun");
    cmd.arg("-p").arg(probe);
    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("CLI print timed out")
        .expect("failed to spawn or read ibex process output");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value =
        serde_json::from_str(stdout.trim_end().lines().last().unwrap_or("")).expect("json");
    assert_eq!(
        parsed["bunType"], "object",
        "--compat=bun installs Bun: {parsed}"
    );
    assert!(
        parsed["bunVersion"].is_string(),
        "--compat=bun sets versions.bun for coherent detection: {parsed}"
    );
}

#[tokio::test]
async fn cli_honors_process_exit_code_at_natural_exit() {
    // LLP 0175 §10 / ledger item 6 (exact-side history): a script that sets
    // process.exitCode and returns must exit with that code (it exited 0
    // before).
    let mut cmd = Command::new(IBEX);
    cmd.arg("-e").arg("process.exitCode = 3");
    let output = timeout(Duration::from_secs(10), cmd.output())
        .await
        .expect("CLI eval timed out")
        .expect("failed to spawn or read ibex process output");
    assert_eq!(output.status.code(), Some(3), "exitCode honored for -e");

    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("exit_code.ts");
    std::fs::write(&file, "console.log('setting'); process.exitCode = 5;\n").expect("write");
    let mut cmd = Command::new(IBEX);
    cmd.arg(file.to_string_lossy().as_ref());
    cmd.env("IBEX_NO_BYTECODE", "1");
    let output = timeout(Duration::from_secs(20), cmd.output())
        .await
        .expect("CLI run timed out")
        .expect("failed to spawn or read ibex process output");
    assert_eq!(
        output.status.code(),
        Some(5),
        "exitCode honored for file runs: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Write `source` to a temp file with `name` and run it via `ibex <file>`,
/// returning the process output. Bytecode is disabled so runs exercise the
/// plain source path deterministically.
async fn run_script(name: &str, source: &str) -> std::process::Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join(name);
    std::fs::write(&file, source).expect("write script");
    let mut cmd = Command::new(IBEX);
    cmd.arg(file.to_string_lossy().as_ref());
    cmd.env("IBEX_NO_BYTECODE", "1");
    timeout(Duration::from_secs(20), cmd.output())
        .await
        .expect("CLI run timed out")
        .expect("failed to spawn or read ibex process output")
}

#[tokio::test]
async fn cli_async_only_failures_exit_nonzero() {
    // ENG-23130: async-only failures used to complete with exit code 0,
    // reporting success to any CI/agent using the exit code as pass/fail.
    // Node exits 1 for every one of these.
    let cases: &[(&str, &str)] = &[
        (
            "floating_rejection.js",
            "Promise.reject(new Error('boom-rejection'));\n",
        ),
        (
            "throwing_next_tick.js",
            "process.nextTick(() => { throw new Error('boom-nexttick'); });\n",
        ),
        (
            // A floating rejection inside a TLA entry takes the async-IIFE
            // shim path; the rejection is not the completion value, so only
            // the unhandledrejection default action can surface it.
            "floating_rejection_tla.mjs",
            "await new Promise((resolve) => setTimeout(resolve, 10));\nPromise.reject(new Error('boom-floating-tla'));\n",
        ),
        (
            // Completion-value rejection: the engine unwraps the entry
            // promise, so this must stay nonzero too.
            "tla_rejection.mjs",
            "await Promise.reject(new Error('boom-tla'));\n",
        ),
    ];
    for (name, source) in cases {
        let output = run_script(name, source).await;
        assert_ne!(
            output.status.code(),
            Some(0),
            "{name}: async failure must not exit 0: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn cli_async_failures_consumed_by_handlers_exit_zero() {
    // ENG-23130 guard-rail: a handler that consumes the failure keeps the
    // exit green — fail-loud must not turn handled failures into failures.
    let cases: &[(&str, &str)] = &[
        (
            "handled_rejection.js",
            "process.on('unhandledRejection', (reason) => { console.log('caught:', reason && reason.message); });\nPromise.reject(new Error('handled-rejection'));\n",
        ),
        (
            "handled_next_tick.js",
            "process.on('uncaughtException', (err) => { console.log('caught:', err.message); });\nprocess.nextTick(() => { throw new Error('handled-nexttick'); });\n",
        ),
        (
            "prevented_rejection.js",
            "addEventListener('unhandledrejection', (event) => { event.preventDefault(); console.log('prevented'); });\nPromise.reject(new Error('prevented-rejection'));\n",
        ),
    ];
    for (name, source) in cases {
        let output = run_script(name, source).await;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{name}: handled async failure must exit 0: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test]
async fn cli_unhandled_rejection_preserves_user_exit_code() {
    // ENG-23130: the unhandledrejection default action only forces the exit
    // code when it is unset or 0 — a deliberate nonzero code wins.
    let output = run_script(
        "user_exit_code.js",
        "process.exitCode = 7;\nPromise.reject(new Error('user-code-preserved'));\n",
    )
    .await;
    assert_eq!(
        output.status.code(),
        Some(7),
        "user-set exitCode must survive an unhandled rejection: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn cli_legacy_env_names_warn_once() {
    // Legacy `EX_*`/`EXACT_*` env spellings keep working with a deprecation
    // warning while extracted consumers catch up (see runtime_env in
    // src/bin/ibex/main.rs).
    //
    // This must drive a FILE run: `-e` routes through eval_code and never
    // consults IBEX_NO_BYTECODE, so the previous `-e null` variant could not
    // fire the warning and its conditional assertion was dead (ENG-23131).
    // EX_STARTUP_TRACE is consulted at several trace points in one process,
    // so its warning appearing exactly once is what proves the "once" dedup.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("legacy_env.js");
    std::fs::write(&file, "console.log('legacy-env-ok');\n").expect("write");
    let mut cmd = Command::new(IBEX);
    cmd.arg(file.to_string_lossy().as_ref());
    cmd.env("EX_NO_BYTECODE", "1");
    cmd.env("EX_STARTUP_TRACE", "1");
    let output = timeout(Duration::from_secs(20), cmd.output())
        .await
        .expect("CLI run timed out")
        .expect("failed to spawn or read ibex process output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    for (legacy, ibex) in [
        ("EX_NO_BYTECODE", "IBEX_NO_BYTECODE"),
        ("EX_STARTUP_TRACE", "IBEX_STARTUP_TRACE"),
    ] {
        let warning = format!("warning: {legacy} is deprecated; use {ibex}");
        assert_eq!(
            stderr.matches(&warning).count(),
            1,
            "expected exactly one deprecation warning for {legacy}; stderr: {stderr}"
        );
    }
}
