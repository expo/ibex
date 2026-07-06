//! End-to-end tests for the native child_process bridge, driving the real
//! `ibex` binary against small JS apps. These cover resource-management and
//! Node-parity properties that can only be observed by actually forking/execing
//! children:
//!
//!   * ENG-23023 — async spawn must free its parent-side stdio fds and drop its
//!     process-table entry once the child closes (else repeated spawns EMFILE).
//!   * ENG-23025 — spawnSync/execSync must multiplex stdin/stdout/stderr so a
//!     child that fills a pipe the parent isn't draining does not deadlock.
//!   * ENG-23032 — `detached` must start a new process group (setsid); a custom
//!     `shell` binary must actually be exec'd.
//!
//! Run with: `cargo test --test child_process_native`.

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

/// A unique scratch dir under the system temp dir (no external crates).
fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ibex-cp-{}-{}-{}", tag, std::process::id(), n));
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

/// Run `ibex run app.js` (allow-all default) with `app` as the program body,
/// enforcing a wall-clock timeout so a regressed deadlock fails the test instead
/// of hanging the suite forever. Extra files can be pre-written into `dir`.
fn run_app_in(dir: &Path, app: &str, timeout: Duration) -> AppRun {
    write_text(&dir.join("app.js"), app);
    let mut child = Command::new(IBEX)
        .arg("run")
        .arg("app.js")
        .current_dir(dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ibex binary");

    // Drain both pipes on dedicated threads so a chatty child can never fill a
    // pipe and wedge our wait loop.
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

fn run_app(tag: &str, app: &str, timeout: Duration) -> AppRun {
    let dir = unique_dir(tag);
    run_app_in(&dir, app, timeout)
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split('|').find_map(|kv| kv.strip_prefix(key))
}

fn result_line<'a>(run: &'a AppRun) -> &'a str {
    assert!(
        !run.timed_out,
        "app timed out (likely a deadlock regression)\nstdout:\n{}\nstderr:\n{}",
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

// ENG-23023 -----------------------------------------------------------------

/// Each async `spawn` captures the parent ends of the child's stdin/stdout/
/// stderr pipes. Before the fix nothing ever closed them or erased the native
/// `s_spawnedProcesses` entry (the JS `__exactSpawnDispose` was a no-op stub),
/// so ~3 fds leaked per child and a spawn loop marched to EMFILE. After the fix
/// the native `__exactSpawnDispose` reclaims them on `close`, so the process's
/// open-fd count stays flat across many spawns.
#[test]
fn async_spawn_does_not_leak_parent_fds() {
    let app = r#"
const cp = require('child_process');
const fs = require('fs');
function fdCount() { try { return fs.readdirSync('/dev/fd').length; } catch (e) { return -1; } }
const N = 60;
let done = 0;
const baseline = fdCount();
function finish() {
  // Let the queued __exactSpawnDispose timeouts run before measuring.
  setTimeout(function () {
    const after = fdCount();
    console.log('RESULT|done=' + done + '|baseline=' + baseline + '|after=' + after + '|delta=' + (after - baseline));
  }, 80);
}
function next(i) {
  if (i >= N) { finish(); return; }
  let c;
  try { c = cp.spawn('true', []); }
  catch (e) { console.log('RESULT|done=' + done + '|spawn_threw=' + (e && e.message)); return; }
  let advanced = false;
  function advance() { if (advanced) return; advanced = true; done++; next(i + 1); }
  c.on('close', advance);
  c.on('error', function (e) { console.log('CHILD_ERR|' + (e && (e.code || e.message))); advance(); });
}
next(0);
"#;
    let run = run_app("fdleak", app, Duration::from_secs(30));
    let line = result_line(&run);
    let done: i64 = field(line, "done=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1);
    let delta: i64 = field(line, "delta=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(i64::MAX);
    assert_eq!(done, 60, "not all children reached close: {line}");
    // Fixed: delta ~= 0. Broken: ~3 fds/child => ~180.
    assert!(
        delta < 20,
        "parent fd count grew by {delta} across 60 async spawns — fd leak regressed: {line}"
    );
}

// ENG-23025 -----------------------------------------------------------------

/// The child writes 100_000 bytes to stderr (past the ~64KB pipe buffer) and
/// then `echo done` to stdout. The old spawnSync drained stdout to EOF *before*
/// touching stderr, so the child blocked writing stderr while the parent blocked
/// reading stdout — a permanent deadlock. The poll()-multiplexed path drains
/// both, so execSync returns `done`. The run timeout turns a regression into a
/// failed assertion instead of a hung suite.
#[test]
fn spawn_sync_does_not_deadlock_on_full_stderr() {
    let app = r#"
const cp = require('child_process');
try {
  const r = cp.execSync("yes X | head -c 100000 >&2; echo done", { maxBuffer: 10 * 1024 * 1024 });
  console.log('RESULT|stdout=' + JSON.stringify(String(r)));
} catch (e) {
  console.log('RESULT|error=' + (e && e.message));
}
"#;
    let run = run_app("stderrfill", app, Duration::from_secs(20));
    let line = result_line(&run);
    let stdout = field(line, "stdout=").unwrap_or("");
    assert!(
        stdout.contains("done"),
        "execSync did not return child stdout (deadlock/regression): {line}"
    );
}

/// `cat` echoes its 200_000-byte stdin back to stdout. The old spawnSync wrote
/// all of stdin with blocking writes before reading any stdout, so once `cat`
/// blocked writing >64KB of stdout the parent hadn't begun draining, both sides
/// wedged. The multiplexed path interleaves the stdin write with the stdout
/// read, so the full payload round-trips.
#[test]
fn spawn_sync_does_not_deadlock_on_large_stdin() {
    let app = r#"
const cp = require('child_process');
try {
  const out = cp.spawnSync('cat', [], { input: Buffer.alloc(200000, 65), maxBuffer: 10 * 1024 * 1024 });
  const len = out.stdout ? out.stdout.length : -1;
  console.log('RESULT|len=' + len + '|status=' + out.status);
} catch (e) {
  console.log('RESULT|error=' + (e && e.message));
}
"#;
    let run = run_app("stdinfill", app, Duration::from_secs(20));
    let line = result_line(&run);
    let len: i64 = field(line, "len=").and_then(|v| v.parse().ok()).unwrap_or(-1);
    assert_eq!(
        len, 200000,
        "spawnSync stdin/stdout round-trip wrong length (deadlock/regression): {line}"
    );
}

/// Array-form stdio was ignored by the native spawnSync parser, which read only
/// the string form and left every fd at the default `pipe`. With
/// `stdio: ['ignore','inherit','inherit']` the child's stdout must reach the
/// inherited terminal (this process's stdout) and NOT be captured into
/// `result.stdout`.
#[test]
fn spawn_sync_honors_array_form_stdio() {
    let app = r#"
const cp = require('child_process');
const r = cp.spawnSync('sh', ['-c', 'echo INHERITED_LINE'], { stdio: ['ignore', 'inherit', 'inherit'] });
const captured = r.stdout ? r.stdout.length : 0;
console.log('RESULT|captured=' + captured);
"#;
    let run = run_app("arraystdio", app, Duration::from_secs(20));
    let line = run
        .stdout
        .lines()
        .find(|l| l.starts_with("RESULT|"))
        .unwrap_or_else(|| panic!("no RESULT line\nstdout:\n{}\nstderr:\n{}", run.stdout, run.stderr));
    assert!(!run.timed_out, "app timed out");
    let captured: i64 = field(line, "captured=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1);
    assert_eq!(
        captured, 0,
        "array-form stdio ignored: child stdout was captured instead of inherited: {line}"
    );
    // The inherited child stdout must appear on the parent's stdout.
    assert!(
        run.stdout.contains("INHERITED_LINE"),
        "inherited child stdout did not reach the parent terminal\nstdout:\n{}",
        run.stdout
    );
}
