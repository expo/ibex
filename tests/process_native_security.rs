//! Native process security regressions for capability-gated process effects.
//!
//! Run with: `cargo test --test process_native_security`.

#![cfg(unix)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

struct AppRun {
    stdout: String,
    stderr: String,
    timed_out: bool,
}

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ibex-process-sec-{}-{}-{}",
        tag,
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_text(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dir");
    }
    std::fs::write(path, contents).expect("write test file");
}

fn run_audit_app_in(dir: &Path, timeout: Duration) -> AppRun {
    let mut child = Command::new(IBEX)
        .args(["capsec", "audit", "app.js"])
        .current_dir(dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ibex capsec audit");

    let mut out = child.stdout.take().expect("stdout pipe");
    let mut err = child.stderr.take().expect("stderr pipe");
    let out_thread = thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let err_thread = thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }

    AppRun {
        stdout: out_thread.join().unwrap_or_default(),
        stderr: err_thread.join().unwrap_or_default(),
        timed_out,
    }
}

fn result_line(run: &AppRun) -> &str {
    assert!(
        !run.timed_out,
        "app timed out\nstdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    run.stdout
        .lines()
        .find(|l| l.starts_with("RESULT|"))
        .unwrap_or_else(|| {
            panic!(
                "no RESULT line in output\nstdout:\n{}\nstderr:\n{}",
                run.stdout, run.stderr
            )
        })
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

#[test]
fn exact_exec_sync_cwd_is_child_chdir_not_shell_prefix() {
    let dir = unique_dir("execsync-cwd");
    let safe_cwd = dir.join("safe");
    std::fs::create_dir_all(&safe_cwd).expect("create safe cwd");
    let marker = dir.join("pwned");
    let malicious_cwd = format!("{}; touch {}", safe_cwd.display(), marker.display());
    let app = format!(
        r#"
if (typeof __exactEnsureChildProcess === 'function') __exactEnsureChildProcess();
var result = JSON.parse(String(__exactExecSync('printf SAFE', JSON.stringify({{ cwd: {cwd} }}))));
console.log('RESULT|status=' + result.status + '|stdout=' + result.stdout);
"#,
        cwd = json_string(&malicious_cwd)
    );
    write_text(&dir.join("app.js"), &app);

    let run = run_audit_app_in(&dir, Duration::from_secs(20));
    let _line = result_line(&run);
    assert!(
        !marker.exists(),
        "__exactExecSync interpreted cwd as shell text and created {}\nstdout:\n{}\nstderr:\n{}",
        marker.display(),
        run.stdout,
        run.stderr
    );
}
