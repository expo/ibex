//! Native child_process option JSON parser regressions (ENG-23886).
//!
//! Run with: `cargo test --test child_process_option_parse`.

#![cfg(unix)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

// `capsec audit` authenticates and hashes the complete lowering/bundling
// toolchain before each option-parser fixture runs. Shared-host full-matrix
// load can exhaust shorter deadlines before the probe executes. This is a
// deadlock bound, not a startup-performance assertion.
const DIAGNOSTIC_AUDIT_TIMEOUT: Duration = Duration::from_secs(120);

struct AppRun {
    stdout: String,
    stderr: String,
    timed_out: bool,
}

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("ibex-cp-opts-{}-{}-{}", tag, std::process::id(), n));
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

fn run_app_in(dir: &Path, app: &str, timeout: Duration) -> AppRun {
    static APP_RUN_LOCK: Mutex<()> = Mutex::new(());
    let _guard = APP_RUN_LOCK.lock().expect("lock app runner");

    write_text(&dir.join("app.js"), app);
    let mut child = Command::new(IBEX)
        .arg("capsec")
        .arg("audit")
        .arg("app.js")
        .current_dir(dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ibex binary");

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

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split('|').find_map(|kv| kv.strip_prefix(key))
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
fn spawn_sync_honors_spaced_shell_true() {
    let app = r#"
if (typeof __exactEnsureChildProcess === 'function') __exactEnsureChildProcess();
var result = JSON.parse(String(__exactSpawnSync('printf PARSED', '[]', '{"shell": true, "stdio": "pipe"}')));
console.log('RESULT|status=' + result.status + '|stdout=' + result.stdout);
"#;
    let run = run_app_in(&unique_dir("spaced-shell"), app, DIAGNOSTIC_AUDIT_TIMEOUT);
    let line = result_line(&run);
    assert_eq!(
        field(line, "status="),
        Some("0"),
        "spaced shell:true was not honored: {line}"
    );
    assert_eq!(
        field(line, "stdout="),
        Some("UEFSU0VE"),
        "shell:true with whitespace did not run through the shell: {line}"
    );
}

#[test]
fn spawn_sync_ignores_nested_shell_true_property() {
    let app = r#"
if (typeof __exactEnsureChildProcess === 'function') __exactEnsureChildProcess();
var opts = '{"nested":{"shell":true},"stdio":"pipe"}';
var result = JSON.parse(String(__exactSpawnSync('printf SHOULD_NOT_RUN', '[]', opts)));
console.log('RESULT|status=' + result.status + '|stdout=' + result.stdout + '|error=' + (result.error || ''));
"#;
    let run = run_app_in(&unique_dir("env-shell"), app, DIAGNOSTIC_AUDIT_TIMEOUT);
    let line = result_line(&run);
    assert_ne!(
        field(line, "stdout="),
        Some("U0hPVUxEX05PVF9SVU4="),
        "nested shell property falsely enabled shell mode: {line}"
    );
    assert_ne!(
        field(line, "status="),
        Some("0"),
        "nested shell property falsely enabled shell mode: {line}"
    );
}

#[test]
fn spawn_async_ignores_nested_shell_true_property() {
    let app = r#"
if (typeof __exactEnsureChildProcess === 'function') __exactEnsureChildProcess();
var opts = '{"nested":{"shell":true},"stdio":["ignore","pipe","pipe"]}';
var started = JSON.parse(String(__exactSpawn('printf ASYNC_SHOULD_NOT_RUN', '[]', opts)));
if (started.error) {
  console.log('RESULT|startError=' + started.error + '|out=');
} else {
  var out = '';
  function drain() {
    var bytes = __exactSpawnRead(started.handle, 'stdout');
    for (var i = 0; bytes && i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  }
  function poll() {
    drain();
    var st = JSON.parse(String(__exactSpawnPoll(started.handle)));
    if (st.exited) {
      drain();
      if (typeof __exactSpawnDispose === 'function') __exactSpawnDispose(started.handle);
      console.log('RESULT|startError=|out=' + out.trim());
      return;
    }
    setTimeout(poll, 20);
  }
  poll();
}
"#;
    let run = run_app_in(
        &unique_dir("async-nested-shell"),
        app,
        DIAGNOSTIC_AUDIT_TIMEOUT,
    );
    let line = result_line(&run);
    assert_ne!(
        field(line, "out="),
        Some("ASYNC_SHOULD_NOT_RUN"),
        "nested shell property falsely enabled async shell mode: {line}"
    );
    assert_eq!(
        field(line, "startError="),
        Some("ENOENT"),
        "async spawn should treat the spaced command as a literal path: {line}"
    );
}

#[test]
fn spawn_sync_custom_shell_path_allows_escaped_quote() {
    let dir = unique_dir("quoted-shell");
    let shell = dir.join("my\"sh");
    std::os::unix::fs::symlink("/bin/sh", &shell).expect("create quoted shell symlink");

    let app = format!(
        r#"
const cp = require('child_process');
const r = cp.spawnSync('echo QUOTED_SHELL_RAN', [], {{ shell: {shell}, encoding: 'utf8' }});
console.log('RESULT|status=' + r.status + '|stdout=' + String(r.stdout || '').trim() + '|error=' + (r.error && (r.error.code || r.error.message) || ''));
"#,
        shell = json_string(&shell.to_string_lossy())
    );
    let run = run_app_in(&dir, &app, DIAGNOSTIC_AUDIT_TIMEOUT);
    let line = result_line(&run);
    assert_eq!(
        field(line, "stdout="),
        Some("QUOTED_SHELL_RAN"),
        "custom shell path with escaped quote was not parsed correctly: {line}\nstderr:\n{}",
        run.stderr
    );
}
