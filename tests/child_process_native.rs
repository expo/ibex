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

fn result_line(run: &AppRun) -> &str {
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

// ENG-23113 ------------------------------------------------------------------

/// The async exec-failure branch (spawning a MISSING binary -> ENOENT) closed
/// only the parent-retained pipe ends and leaked the child-side ends the parent
/// still held; no `s_spawnedProcesses` entry is stored on failure, so there is no
/// `__exactSpawnDispose` to reclaim them — ~3 fds leaked per failed spawn. A
/// process probing for optional/missing binaries marched to EMFILE. After the fix
/// the exec-failure branch closes every fd, so the open-fd count stays flat across
/// many failed spawns.
#[test]
fn async_spawn_exec_failure_does_not_leak_fds() {
    let app = r#"
const cp = require('child_process');
const fs = require('fs');
function fdCount() { try { return fs.readdirSync('/dev/fd').length; } catch (e) { return -1; } }
const N = 60;
let done = 0;
let badCode = '';
const baseline = fdCount();
function finish() {
  const after = fdCount();
  console.log('RESULT|done=' + done + '|badCode=' + badCode + '|baseline=' + baseline + '|after=' + after + '|delta=' + (after - baseline));
}
function next(i) {
  if (i >= N) { finish(); return; }
  let c;
  try { c = cp.spawn('definitely-does-not-exist-ibex-xyz', []); }
  catch (e) { console.log('RESULT|spawn_threw=' + (e && e.message) + '|at=' + i); return; }
  let advanced = false;
  function advance() { if (advanced) return; advanced = true; done++; next(i + 1); }
  c.on('error', function (e) {
    // Every failed spawn should report ENOENT; an EMFILE here means fds leaked.
    if (e && e.code && e.code !== 'ENOENT' && !badCode) badCode = String(e.code) + '@' + i;
    advance();
  });
  c.on('close', advance);
}
next(0);
"#;
    let run = run_app("fdleak_fail", app, Duration::from_secs(30));
    let line = result_line(&run);
    let done: i64 = field(line, "done=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1);
    let delta: i64 = field(line, "delta=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(i64::MAX);
    assert_eq!(done, 60, "not all failed spawns completed: {line}");
    assert_eq!(
        field(line, "badCode="),
        Some(""),
        "a failed spawn reported a non-ENOENT error (likely EMFILE from leaked fds): {line}"
    );
    // Fixed: delta ~= 0. Broken: ~3 fds/failed-spawn => ~180.
    assert!(
        delta < 20,
        "parent fd count grew by {delta} across 60 failed spawns — exec-failure fd leak regressed: {line}"
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
    let len: i64 = field(line, "len=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1);
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
        .unwrap_or_else(|| {
            panic!(
                "no RESULT line\nstdout:\n{}\nstderr:\n{}",
                run.stdout, run.stderr
            )
        });
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

// ENG-23032 -----------------------------------------------------------------

/// `detached: true` was a no-op in native (grep: no setsid/setpgid), so the
/// child stayed in the parent's process group. With the fix the child calls
/// setsid() and becomes the leader of its own group (pgid == pid), which we
/// observe via process.kill(-pid, 0): a process group whose id equals the
/// child's pid exists only when the child made itself leader.
#[test]
fn spawn_detached_starts_new_process_group() {
    let app = r#"
const cp = require('child_process');
const c = cp.spawn('sleep', ['30'], { detached: true, stdio: 'ignore' });
const pid = c.pid;
setTimeout(function () {
  let groupExists;
  try { process.kill(-pid, 0); groupExists = true; }
  catch (e) { groupExists = false; }
  console.log('RESULT|groupExists=' + groupExists);
  // Clean up: reap the detached group (and the child) so no sleep lingers.
  try { process.kill(-pid, 'SIGKILL'); } catch (e) {}
  try { process.kill(pid, 'SIGKILL'); } catch (e) {}
}, 300);
"#;
    let run = run_app("detached", app, Duration::from_secs(15));
    let line = result_line(&run);
    assert_eq!(
        field(line, "groupExists="),
        Some("true"),
        "detached child did not become its own process-group leader (setsid missing): {line}"
    );
}

/// ENG-23113: spawnSync/execSync with a `timeout` armed a DETACHED watchdog thread
/// capturing stack `std::atomic<bool>`s by reference; on a fast child it woke after
/// the host function returned and dereferenced the freed frame (and could SIGKILL a
/// recycled PID). The fix holds the watchdog state in a self-joining object that is
/// cancelled + JOINED once the child is reaped, so no thread outlives the frame.
/// The UAF itself is a non-deterministic latent crash (best caught under ASan, not
/// wired into this suite); this is the deterministic functional regression — the
/// refactored watchdog still (a) lets a fast command under a long timeout succeed
/// (watchdog cancelled, not fired) across many iterations without hanging on the
/// join, and (b) kills a slow command under a short timeout.
#[test]
fn spawn_sync_timeout_watchdog_joins_and_still_enforces() {
    let app = r#"
const cp = require('child_process');
// (A) Fast command, long timeout: must succeed, never reported as timed out.
// Looped to exercise the cancel+join path repeatedly (a join deadlock would hang
// the run and trip the harness timeout).
let okCount = 0;
for (let i = 0; i < 20; i++) {
  const r = cp.spawnSync('echo', ['hi'], { timeout: 30000, encoding: 'utf8' });
  if (r.status === 0 && !r.error && String(r.stdout).indexOf('hi') !== -1) okCount++;
}
// (B) Slow command, short timeout: must be killed and reported as ETIMEDOUT.
const slow = cp.spawnSync('sleep', ['5'], { timeout: 200 });
const timedOut = !!(slow.error && slow.error.code === 'ETIMEDOUT');
console.log('RESULT|okCount=' + okCount + '|timedOut=' + timedOut);
"#;
    let run = run_app("watchdog", app, Duration::from_secs(30));
    let line = result_line(&run);
    assert_eq!(
        field(line, "okCount="),
        Some("20"),
        "fast spawnSync under a long timeout should always succeed (watchdog cancelled): {line}"
    );
    assert_eq!(
        field(line, "timedOut="),
        Some("true"),
        "slow spawnSync under a short timeout should be killed (ETIMEDOUT): {line}"
    );
}

/// ENG-23113: `spawn(cmd, { detached: true })` must NOT auto-unref. Node unrefs
/// only on an explicit `child.unref()`; otherwise the parent waits for the child
/// and its `exit`/`close` handlers fire. Ibex auto-unref'd on `detached`, so with
/// the child as the only pending work the parent's event loop drained and exited
/// before a short-lived detached child finished, skipping its handlers. Here the
/// ONLY pending work is a ~300ms detached child with no explicit unref; with the
/// fix the parent stays alive until it exits and the `exit` handler runs.
#[test]
fn detached_spawn_does_not_auto_unref() {
    let app = r#"
const cp = require('child_process');
// Short-lived detached child, no explicit unref, no other keep-alive.
const c = cp.spawn('sleep', ['0.3'], { detached: true, stdio: 'ignore' });
c.on('exit', function (code) { console.log('RESULT|exit=fired|code=' + code); });
"#;
    let run = run_app("detached_ref", app, Duration::from_secs(15));
    let line = result_line(&run);
    assert_eq!(
        field(line, "exit="),
        Some("fired"),
        "detached child's exit handler did not fire — parent auto-unref'd and exited early: {line}"
    );
}

/// The native spawn hardcoded `execl("/bin/sh", ...)` and ignored the `shell`
/// string. With the fix a custom shell binary is exec'd. The helper shell script
/// ignores its `-c` argument and prints a sentinel, so the sentinel appears only
/// when the requested shell actually ran (cross-platform, not dialect-dependent).
#[test]
fn spawn_honors_custom_shell_binary() {
    let dir = unique_dir("customshell");
    let shell = dir.join("myshell.sh");
    write_text(&shell, "#!/bin/sh\necho MYSHELL_RAN\n");
    let mut perms = std::fs::metadata(&shell).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&shell, perms).unwrap();

    let app = format!(
        r#"
const cp = require('child_process');
const c = cp.spawn('echo', ['ignored'], {{ shell: {shell_json}, stdio: ['ignore', 'pipe', 'ignore'] }});
let out = '';
c.stdout.on('data', function (d) {{ out += d; }});
c.on('close', function () {{ console.log('RESULT|out=' + out.trim()); }});
c.on('error', function (e) {{ console.log('RESULT|error=' + (e && e.message)); }});
"#,
        shell_json = serde_json_string(&shell.to_string_lossy())
    );
    let run = run_app_in(&dir, &app, Duration::from_secs(15));
    let line = result_line(&run);
    assert_eq!(
        field(line, "out="),
        Some("MYSHELL_RAN"),
        "custom shell binary was not exec'd (fell back to /bin/sh): {line}"
    );
}

/// Exit-signal names must be sourced from the running platform's signal numbers.
/// A child that raises SIGUSR1 exits with WTERMSIG = 30 on Darwin but 10 on
/// Linux; the old fixed Darwin table reported signal 10 as 'SIGBUS' on Linux.
/// The platform-branched table reports 'SIGUSR1' on both.
#[test]
fn spawn_reports_platform_correct_exit_signal() {
    let app = r#"
const cp = require('child_process');
const c = cp.spawn('sh', ['-c', 'kill -USR1 $$']);
c.on('close', function (code, signal) { console.log('RESULT|code=' + code + '|signal=' + signal); });
c.on('error', function (e) { console.log('RESULT|error=' + (e && e.message)); });
"#;
    let run = run_app("signal", app, Duration::from_secs(15));
    let line = result_line(&run);
    assert_eq!(
        field(line, "signal="),
        Some("SIGUSR1"),
        "child killed by SIGUSR1 was not reported as SIGUSR1 (platform signal table wrong): {line}"
    );
}

/// A child that emits its output only after an idle gap must still be captured
/// once the poller has backed off — proving the ENG-23032 idle backoff stays
/// responsive when bytes finally flow.
#[test]
fn spawn_backoff_still_captures_delayed_output() {
    let app = r#"
const cp = require('child_process');
const c = cp.spawn('sh', ['-c', 'sleep 0.3; echo LATE_OUTPUT']);
let out = '';
c.stdout.on('data', function (d) { out += d; });
c.on('close', function () { console.log('RESULT|out=' + out.trim()); });
"#;
    let run = run_app("backoff", app, Duration::from_secs(15));
    let line = result_line(&run);
    assert_eq!(
        field(line, "out="),
        Some("LATE_OUTPUT"),
        "delayed child output lost after idle poll backoff: {line}"
    );
}

// ENG-23485 -----------------------------------------------------------------

/// execSync must honor options.stdio (previously dropped by an option
/// allowlist, so stdio:'inherit' captured output invisibly instead of
/// streaming it), return null for a non-piped stdout like Node, and — when no
/// stdio is given — pass the captured child stderr through to the parent's
/// stderr (Node's sync-exec-family default).
#[test]
fn exec_sync_honors_stdio_and_passes_stderr_through() {
    let app = r#"
const cp = require('child_process');
const inherited = cp.execSync('echo INHERITED_EXEC_LINE', { stdio: 'inherit' });
console.log('RESULT|inheritReturn=' + inherited);
const captured = cp.execSync('echo EXEC_STDERR_LINE 1>&2; echo captured-out', { encoding: 'utf8' });
console.log('RESULT2|captured=' + captured.trim());
cp.execFileSync('sh', ['-c', 'echo EXECFILE_STDERR_LINE 1>&2']);
"#;
    let run = run_app("execsyncstdio", app, Duration::from_secs(20));
    let line = result_line(&run);
    assert_eq!(
        field(line, "inheritReturn="),
        Some("null"),
        "execSync(stdio:'inherit') must return null (stdout not piped): {line}"
    );
    assert!(
        run.stdout.contains("INHERITED_EXEC_LINE"),
        "execSync stdio:'inherit' output did not reach the parent terminal\nstdout:\n{}",
        run.stdout
    );
    let line2 = run
        .stdout
        .lines()
        .find(|l| l.starts_with("RESULT2|"))
        .expect("RESULT2 line");
    assert_eq!(
        field(line2, "captured="),
        Some("captured-out"),
        "default execSync must still capture stdout: {line2}"
    );
    assert!(
        run.stderr.contains("EXEC_STDERR_LINE"),
        "execSync must pass child stderr through to the parent's stderr by default\nstderr:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("EXECFILE_STDERR_LINE"),
        "execFileSync must pass child stderr through to the parent's stderr by default\nstderr:\n{}",
        run.stderr
    );
}

/// Numeric stdio entries mean "share this parent fd" (Node contract:
/// stdio:[0,1,2] === 'inherit'). The old mapping turned 0 into 'ignore' and
/// 1 into 'pipe', so spawn(..., {stdio:[0,1,2]}) printed nothing.
#[test]
fn numeric_stdio_shares_parent_fds() {
    let app = r#"
const cp = require('child_process');
const r = cp.spawnSync('sh', ['-c', 'echo SYNC_NUMERIC_LINE'], { stdio: [0, 1, 2] });
console.log('RESULT|syncStdout=' + r.stdout + '|status=' + r.status);
const c = cp.spawn('sh', ['-c', 'echo ASYNC_NUMERIC_LINE'], { stdio: [0, 1, 2] });
console.log('RESULT2|childStdoutNull=' + (c.stdout === null));
c.on('close', function (code) { console.log('RESULT3|asyncExit=' + code); });
"#;
    let run = run_app("numericstdio", app, Duration::from_secs(20));
    let line = result_line(&run);
    assert_eq!(
        field(line, "syncStdout="),
        Some("null"),
        "spawnSync stdio:[0,1,2] must not capture stdout (Node returns null): {line}"
    );
    assert_eq!(field(line, "status="), Some("0"), "child failed: {line}");
    assert!(
        run.stdout.contains("SYNC_NUMERIC_LINE") && run.stdout.contains("ASYNC_NUMERIC_LINE"),
        "numeric stdio output did not reach the parent terminal\nstdout:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("RESULT2|childStdoutNull=true"),
        "spawn stdio:[0,1,2] must not create a stdout pipe\nstdout:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("RESULT3|asyncExit=0"),
        "async numeric-stdio child did not exit cleanly\nstdout:\n{}",
        run.stdout
    );
}

/// options.uid/options.gid must actually be applied in the child (previously
/// validated, then silently discarded). Running as non-root we can only prove
/// the plumbing end-to-end with the caller's own uid/gid (the setgid/setuid
/// syscalls run and succeed) and that a foreign uid fails with EPERM instead
/// of silently running as the parent's user.
#[test]
fn spawn_sync_applies_uid_gid() {
    let app = r#"
const cp = require('child_process');
const uid = process.getuid();
const gid = process.getgid();
const same = cp.spawnSync('id', ['-u'], { uid: uid, gid: gid, encoding: 'utf8' });
console.log('RESULT|status=' + same.status + '|out=' + String(same.stdout).trim() + '|uid=' + uid);
if (uid !== 0) {
  const cross = cp.spawnSync('id', [], { uid: 0 });
  console.log('RESULT2|crossCode=' + (cross.error && cross.error.code));
} else {
  console.log('RESULT2|crossCode=EPERM'); // running as root: cross-uid would legitimately succeed
}
"#;
    let run = run_app("uidgid", app, Duration::from_secs(20));
    let line = result_line(&run);
    assert_eq!(
        field(line, "status="),
        Some("0"),
        "same-uid spawn failed: {line}"
    );
    let uid = field(line, "uid=").expect("uid field");
    assert_eq!(
        field(line, "out="),
        Some(uid),
        "child did not run with the requested uid: {line}"
    );
    assert!(
        run.stdout.contains("RESULT2|crossCode=EPERM"),
        "cross-uid spawnSync as non-root must surface EPERM, not silently keep parent credentials\nstdout:\n{}",
        run.stdout
    );
}

/// unref() followed by ref() must resume polling: the old ref() fired the
/// pump exactly once, left the fired timer id in _pollTimer (so later ref()s
/// were no-ops), and stdout/'exit'/'close' never arrived.
#[test]
fn unref_then_ref_resumes_child_events() {
    let app = r#"
const cp = require('child_process');
const c = cp.spawn('sh', ['-c', 'sleep 1; echo HI_AFTER_REF']);
let out = '';
c.stdout.on('data', function (d) { out += d; });
c.unref();
setTimeout(function () { c.ref(); }, 100);
let exited = false;
c.on('exit', function (code) { exited = true; console.log('RESULT|exit=' + code + '|out=' + out.trim()); });
c.on('close', function () { console.log('RESULT2|close=1'); });
setTimeout(function () {
  if (!exited) { console.log('RESULT|exit=NEVER|out='); process.exit(1); }
}, 10000);
"#;
    let run = run_app("unrefref", app, Duration::from_secs(25));
    let line = result_line(&run);
    assert_eq!(
        field(line, "exit="),
        Some("0"),
        "child 'exit' never fired after unref()+ref(): {line}"
    );
    assert_eq!(
        field(line, "out="),
        Some("HI_AFTER_REF"),
        "child output lost after unref()+ref(): {line}"
    );
    assert!(
        run.stdout.contains("RESULT2|close=1"),
        "'close' never fired after unref()+ref()\nstdout:\n{}",
        run.stdout
    );
}

/// Parent-side IPC receive must survive a multibyte UTF-8 sequence split
/// across recvmsg chunks (the 64KB native read guarantees splits for a 360KB
/// payload of 3-byte chars). Previously the native bridge stringified each
/// chunk with createFromUtf8 (U+FFFD at both cut ends) and the corrupted JSON
/// line was silently dropped — the parent's 'message' never fired. Companion
/// to the child-side test in bootstrap_ipc.rs (ENG-23132).
#[test]
fn parent_ipc_decode_survives_multibyte_split_across_reads() {
    let dir = unique_dir("parentdecode");
    write_text(
        &dir.join("child.js"),
        r#"
process.send({ type: 'blob', payload: '€'.repeat(120000) });
setTimeout(function () { process.exit(0); }, 5000);
"#,
    );
    let app = r#"
const cp = require('child_process');
const c = cp.fork(__dirname + '/child.js');
let done = false;
c.on('message', function (m) {
  if (!m || m.type !== 'blob') return;
  done = true;
  let replacements = 0;
  for (const ch of m.payload) if (ch === '�') replacements++;
  const ok = m.payload === '€'.repeat(120000);
  console.log('RESULT|ok=' + ok + '|replacements=' + replacements + '|len=' + m.payload.length);
  c.kill();
});
setTimeout(function () {
  if (!done) { console.log('RESULT|ok=timeout|replacements=-1|len=-1'); try { c.kill(); } catch (e) {} process.exit(1); }
}, 20000);
"#;
    let run = run_app_in(&dir, app, Duration::from_secs(40));
    let line = result_line(&run);
    assert_eq!(
        field(line, "ok="),
        Some("true"),
        "large multibyte IPC message corrupted or dropped on the parent side: {line}"
    );
    assert_eq!(
        field(line, "replacements="),
        Some("0"),
        "U+FFFD replacement characters leaked into the delivered payload: {line}"
    );
}

/// Minimal JSON string encoder (avoids pulling serde into this test).
fn serde_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}
