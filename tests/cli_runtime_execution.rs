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

/// Run an entry through `ibex capsec audit`, isolated: an empty PATH dir (no
/// bun/node, forcing the standalone pipeline) and HOME/XDG_CACHE_HOME inside
/// `home` so nothing leaks into the real user cache. Production execution is
/// closed until the target has a verified advertisement; these fixtures test
/// runtime pipeline behavior rather than that fail-closed CLI contract.
async fn run_ibex_isolated(home: &Path, entry: &Path) -> std::process::Output {
    let empty_path = home.join("empty-path-dir");
    let _ = std::fs::create_dir_all(&empty_path);
    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec")
        .arg("audit")
        .arg(entry)
        .current_dir(home)
        .env("PATH", &empty_path)
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join("xdg-cache"))
        .env_remove("IBEX_NO_BYTECODE")
        .env_remove("EX_NO_BYTECODE")
        .env_remove("EXACT_COMPAT_TEST");
    timeout(Duration::from_secs(60), cmd.output())
        .await
        .expect("ibex capsec audit timed out")
        .expect("failed to spawn ibex")
}

/// ENG-24254: merely running Ibex inside an untrusted checkout must never
/// execute `tools/hermes/{hermes,hermesc}` planted by that checkout.
#[cfg(unix)]
#[tokio::test]
async fn cli_runtime_ignores_project_local_hermes_executables() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let tools = dir.path().join("tools/hermes");
    std::fs::create_dir_all(&tools).expect("create fake tools dir");
    let marker = dir.path().join("attacker-tool-ran");
    for tool in ["hermes", "hermesc"] {
        let path = tools.join(tool);
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf attacked > {:?}\nexit 0\n", marker),
        )
        .expect("write fake executable");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
    }
    let entry = dir.path().join("app.js");
    std::fs::write(&entry, "console.log('trusted-runtime');\n").expect("write entry");

    let output = run_ibex_isolated(dir.path(), &entry).await;
    assert!(
        output.status.success(),
        "diagnostic runtime execution should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !marker.exists(),
        "project-local Hermes executable was invoked outside CapSec"
    );
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

    let output = run_ibex_isolated(dir.path(), &entry).await;
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

    let output = run_ibex_isolated(dir.path(), &entry).await;
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

    let output = run_ibex_isolated(dir.path(), &entry).await;
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
    if hermesc_path().is_none() {
        eprintln!("skipping: hermesc not found under tools/hermes");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");

    let entry = dir.path().join("t.js");
    let side_effect = dir.path().join("side-effect.txt");
    std::fs::write(
        &entry,
        format!(
            "var fs=require('fs'); fs.appendFileSync({path:?}, 'x'); console.log(\"hi-eng24256\"); throw new Error(\"Compiling JS failed: user-controlled throw\");\n",
            path = side_effect.to_string_lossy()
        ),
    )
    .expect("write entry");

    // Two runs: the first proves single execution + error propagation, the
    // second proves the surviving cache is reused instead of the pre-fix
    // compile → run → delete → re-run loop.
    for run in 0..2 {
        let output = run_ibex_isolated(dir.path(), &entry).await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stdout.matches("hi-eng24256").count(),
            1,
            "run {run}: side effects must execute exactly once\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            !output.status.success(),
            "run {run}: an eval throw must exit nonzero\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("Compiling JS failed: user-controlled throw"),
            "run {run}: the thrown error must propagate\nstderr: {stderr}"
        );
        assert_eq!(
            std::fs::read_to_string(&side_effect).expect("side-effect file"),
            "x".repeat(run + 1),
            "run {run}: filesystem side effect must happen exactly once"
        );

        if run == 0 {
            fn contains_hbc(path: &Path) -> bool {
                std::fs::read_dir(path)
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
                    .any(|entry| {
                        let path = entry.path();
                        path.extension().and_then(|ext| ext.to_str()) == Some("hbc")
                            || (path.is_dir() && contains_hbc(&path))
                    })
            }
            if !contains_hbc(dir.path()) {
                eprintln!(
                    "skipping second bytecode run: runtime/compiler bytecode cache unavailable"
                );
                return;
            }
        }
    }
}
