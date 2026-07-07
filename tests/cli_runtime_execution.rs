//! End-to-end tests for the CLI runtime-execution fixes from ENG-23484,
//! driving the real `ibex` binary in an isolated environment: PATH is stripped
//! (no bun/node, so the standalone in-process pipeline runs — bundling is an
//! optimization, never a requirement) and HOME/XDG_CACHE_HOME point into the
//! test's tempdir so the runtime cache is hermetic.
//!
//! The bytecode tests need a `hermesc` under `tools/hermes` whose output the
//! linked Hermes runtime can execute; when either is missing they skip with a
//! note rather than fail (the checked-in toolchain is not present on every
//! machine).
//!
//! Run with: `scripts/run-tests.sh --scope test cli_runtime` (the filter
//! matches the `cli_runtime_` prefix every test fn here carries), or
//! `cargo test --test cli_runtime_execution`.

use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn hermesc_path() -> Option<PathBuf> {
    let tools = repo_root().join("tools").join("hermes");
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    [
        tools.join("hermesc"),
        tools.join(format!("hermesc-{}-{}", std::env::consts::OS, arch)),
    ]
    .into_iter()
    .find(|p| p.exists())
}

/// Run `ibex` with the given args, isolated: an empty PATH dir (no bun/node,
/// forcing the standalone pipeline) and HOME/XDG_CACHE_HOME inside `home` so
/// nothing leaks into the real user cache.
async fn run_ibex_isolated(home: &Path, args: &[&str]) -> std::process::Output {
    let empty_path = home.join("empty-path-dir");
    let _ = std::fs::create_dir_all(&empty_path);
    let mut cmd = Command::new(IBEX);
    cmd.args(args)
        .current_dir(home)
        .env("PATH", &empty_path)
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join("xdg-cache"))
        .env_remove("IBEX_NO_BYTECODE")
        .env_remove("EX_NO_BYTECODE")
        .env_remove("EXACT_COMPAT_TEST");
    timeout(Duration::from_secs(60), cmd.output())
        .await
        .expect("ibex run timed out")
        .expect("failed to spawn ibex")
}

async fn compile_hbc(hermesc: &Path, js: &Path, out: &Path) -> bool {
    Command::new(hermesc)
        .arg("-emit-binary")
        .arg("-out")
        .arg(out)
        .arg(js)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether the linked Hermes runtime actually executes bytecode produced by
/// the local `hermesc` (HBC versions match). Probed by planting a `.hbc`
/// compiled from DIFFERENT source next to a JS entry: if the probe output
/// comes from the `.hbc`, the bytecode path is live on this machine.
async fn engine_runs_planted_hbc(hermesc: &Path, base: &Path) -> bool {
    let probe_dir = base.join("hbc-probe");
    std::fs::create_dir_all(&probe_dir).expect("create probe dir");
    let js = probe_dir.join("probe.js");
    std::fs::write(&js, "console.log(\"from-src\");\n").expect("write probe.js");
    let alt = probe_dir.join("alt.js");
    std::fs::write(&alt, "console.log(\"from-hbc\");\n").expect("write alt.js");
    if !compile_hbc(hermesc, &alt, &probe_dir.join("probe.hbc")).await {
        return false;
    }
    let output = run_ibex_isolated(base, &["run", js.to_str().expect("utf8 path")]).await;
    String::from_utf8_lossy(&output.stdout).contains("from-hbc")
}

/// ENG-23484 finding 2 (P2): a static-import `.mjs` entry with no top-level
/// await, reaching the standalone TLA-shim path (no bun/node on PATH), lowers
/// cleanly to CJS — the "no shim needed" fast path must then evaluate the
/// LOWERED source, not re-run the raw on-disk file, which Hermes cannot parse
/// in script mode.
#[tokio::test]
async fn cli_runtime_standalone_mjs_entry_without_tla_runs_lowered_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let entry = dir.path().join("app.mjs");
    std::fs::write(
        &entry,
        "import fs from \"node:fs\";\nconsole.log(\"exists=\" + fs.existsSync(\".\"));\n",
    )
    .expect("write entry");

    let output = run_ibex_isolated(dir.path(), &[entry.to_str().expect("utf8")]).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        ".mjs entry with static imports and no TLA must run\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("exists=true"),
        "the lowered import must resolve\nstdout: {stdout}\nstderr: {stderr}"
    );
}

/// ENG-23484 finding 3 (P2): a depth-0 regex literal containing `await`
/// (`const RE = /(await)/;`) must not be detected as top-level await — the
/// false positive re-routed a valid CJS app through the ESM/TLA pipeline and
/// hard-failed it. The scanner itself is unit-tested in runtime.rs; this
/// drives the whole standalone pipeline.
#[tokio::test]
async fn cli_runtime_regex_literal_containing_await_does_not_reroute_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let entry = dir.path().join("app.js");
    std::fs::write(
        &entry,
        "import fs from \"node:fs\";\nconst RE = /(await)/;\nconsole.log(\"tla-regex=\" + RE.test(\"x\"));\n",
    )
    .expect("write entry");

    let output = run_ibex_isolated(dir.path(), &[entry.to_str().expect("utf8")]).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "an app declaring a regex containing 'await' must run\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("tla-regex=false"),
        "the program must produce its real output\nstdout: {stdout}\nstderr: {stderr}"
    );
}

/// ENG-23484 finding 4 (P3): a string literal containing
/// `//# sourceMappingURL=` must survive the TLA-shim evaluation — the eval
/// normalization used to truncate ANY line containing the marker, corrupting
/// code that generates sourcemap comments.
#[tokio::test]
async fn cli_runtime_tla_shim_preserves_sourcemap_marker_in_string_literals() {
    let dir = tempfile::tempdir().expect("tempdir");
    let entry = dir.path().join("app.js");
    std::fs::write(
        &entry,
        "const banner = \"//# sourceMappingURL=x.map\";\nawait Promise.resolve();\nconsole.log(\"len=\" + banner.length);\n",
    )
    .expect("write entry");

    let output = run_ibex_isolated(dir.path(), &[entry.to_str().expect("utf8")]).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a TLA entry with a sourcemap-marker string must run\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("len=26"),
        "the string literal must survive normalization intact\nstdout: {stdout}\nstderr: {stderr}"
    );
}

/// ENG-23484 finding 1 (P1): a runtime error thrown by a bytecode entry is an
/// EVAL failure, not a bytecode-load failure. It must propagate as-is — the
/// program's side effects must not run a second time via the JS-source
/// fallback, and the still-valid `.hbc` cache must survive (and be reused on
/// the next run).
#[tokio::test]
async fn cli_runtime_bytecode_entry_eval_throw_runs_once_and_keeps_cache() {
    let Some(hermesc) = hermesc_path() else {
        eprintln!("skipping: hermesc not found under tools/hermes");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    if !engine_runs_planted_hbc(&hermesc, dir.path()).await {
        eprintln!("skipping: runtime cannot execute local hermesc output (HBC version mismatch)");
        return;
    }

    let entry = dir.path().join("t.js");
    std::fs::write(
        &entry,
        "console.log(\"hi-eng23484\"); throw new Error(\"boom-eng23484\");\n",
    )
    .expect("write entry");
    let hbc = dir.path().join("t.hbc");
    assert!(
        compile_hbc(&hermesc, &entry, &hbc).await,
        "hermesc failed to compile the entry"
    );

    // Two runs: the first proves single execution + error propagation, the
    // second proves the surviving cache is reused instead of the pre-fix
    // compile → run → delete → re-run loop.
    for run in 0..2 {
        let output = run_ibex_isolated(dir.path(), &["run", entry.to_str().expect("utf8")]).await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stdout.matches("hi-eng23484").count(),
            1,
            "run {run}: side effects must execute exactly once\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            !output.status.success(),
            "run {run}: an eval throw must exit nonzero\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("boom-eng23484"),
            "run {run}: the thrown error must propagate\nstderr: {stderr}"
        );
        assert!(
            hbc.exists(),
            "run {run}: a valid bytecode cache must survive an eval throw"
        );
    }
}
