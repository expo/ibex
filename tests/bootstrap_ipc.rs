//! End-to-end tests for the bootstrap IPC layer (ENG-23132, ENG-23231),
//! driving the real `ibex` binary:
//!
//!   * Fork-child `process.send` must queue on socket backpressure instead of
//!     abandoning partially written packets (which corrupted the parent's
//!     newline framing and silently dropped messages).
//!   * The parent-side mirror (ENG-23231): `child.send()` must queue the
//!     unsent tail on partial writes/EAGAIN instead of silently dropping
//!     packets larger than the AF_UNIX send buffer (~16KB), preserve order,
//!     and fire the send callback on actual delivery.
//!   * The child's IPC receive path must decode UTF-8 with a persistent
//!     streaming decoder so a multibyte sequence split across two reads does
//!     not turn into U+FFFD on both sides.
//!   * A throwing user 'message' listener must not permanently kill IPC
//!     polling (uncaughtException semantics preserved, channel stays live).
//!   * Runtime-bundle compatibility fixes, run through the explicitly
//!     diagnostic `ibex capsec audit` command because production execution is
//!     unavailable until this exact target has a verified advertisement:
//!     WebCrypto preserves binary hash/HMAC input and storage/stdin data stays
//!     byte-exact.
//!
//! Run with: `scripts/run-tests.sh --scope test bootstrap_ipc`.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

// Diagnostic `.js` entries authenticate the selected bundler before project
// code starts. Authenticated fork fixtures perform another cold child startup
// after the audit parent is ready, so shared-host full-matrix load can consume
// nearly the old 60s process bound. Serialize the real-binary runs, matching
// the established `cli_eval` harness contract. This is a deadlock bound, not a
// startup-performance assertion.
const DIAGNOSTIC_AUDIT_TIMEOUT: Duration = Duration::from_secs(120);
// The three high-volume IPC probes include cold authenticated startup for a
// forked debug-build child before they can finish draining their queues. Keep
// their semantic watchdog below an independent process-group bound, while
// leaving payload, ordering, and delivery-callback assertions exact.
const IPC_BACKPRESSURE_HARNESS_TIMEOUT: Duration = Duration::from_secs(150);
static AUDIT_RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serialize_audit_run() -> std::sync::MutexGuard<'static, ()> {
    AUDIT_RUN_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct AppRun {
    stdout: String,
    stderr: String,
    timed_out: bool,
    status: Option<ExitStatus>,
}

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ibex-ipc-{}-{}-{}", tag, std::process::id(), n));
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

fn isolate_process_group(cmd: &mut Command) {
    // Fork fixtures inherit the audit process's output pipes. A separate
    // process group lets the harness close every descendant before joining
    // the pipe readers, including when the fixture's parent wedges or exits
    // without reaping its child.
    cmd.process_group(0);
}

fn kill_process_group(child: &mut Child) {
    let Ok(group) = i32::try_from(child.id()) else {
        let _ = child.kill();
        return;
    };
    // SAFETY: `isolate_process_group` makes the spawned child's pid its pgid;
    // a negative pid targets only that group. ESRCH just means it is empty.
    let _ = unsafe { libc::kill(-group, libc::SIGKILL) };
    let _ = child.kill();
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> (Option<ExitStatus>, bool) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // The top-level process is reaped, but a forked descendant can
                // still own the captured pipes. Close the rest of the group.
                kill_process_group(child);
                return (Some(status), false);
            }
            Ok(None) if Instant::now() >= deadline => {
                kill_process_group(child);
                return (child.wait().ok(), true);
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                kill_process_group(child);
                return (child.wait().ok(), false);
            }
        }
    }
}

fn capture_bounded_output(child: &mut Child, timeout: Duration) -> AppRun {
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

    let (status, timed_out) = wait_bounded(child, timeout);
    AppRun {
        stdout: out_thread.join().unwrap_or_default(),
        stderr: err_thread.join().unwrap_or_default(),
        timed_out,
        status,
    }
}

/// Run `ibex capsec audit app.js` with a wall-clock timeout. These compatibility
/// checks intentionally need the diagnostic runtime: production execution must
/// refuse an unadvertised target before observing project code. Extra env vars
/// are applied to the parent (and inherited by forked children).
fn run_app_env(tag: &str, app: &str, env: &[(&str, &str)], timeout: Duration) -> AppRun {
    run_app_env_with_files(tag, app, &[], env, timeout)
}

fn run_app_env_with_files(
    tag: &str,
    app: &str,
    files: &[(&str, &str)],
    env: &[(&str, &str)],
    timeout: Duration,
) -> AppRun {
    let _audit_run = serialize_audit_run();
    let dir = unique_dir(tag);
    write_text(&dir.join("app.js"), app);
    for (path, contents) in files {
        write_text(&dir.join(path), contents);
    }
    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec")
        .arg("audit")
        .arg("app.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    isolate_process_group(&mut cmd);
    let mut child = cmd.spawn().expect("spawn ibex binary");
    capture_bounded_output(&mut child, timeout)
}

fn run_app_env_stdin(
    tag: &str,
    app: &str,
    stdin_bytes: Vec<u8>,
    env: &[(&str, &str)],
    timeout: Duration,
) -> AppRun {
    let _audit_run = serialize_audit_run();
    let dir = unique_dir(tag);
    write_text(&dir.join("app.js"), app);
    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec")
        .arg("audit")
        .arg("app.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    isolate_process_group(&mut cmd);
    let mut child = cmd.spawn().expect("spawn ibex binary");

    let mut child_stdin = child.stdin.take().expect("stdin pipe");
    let writer = thread::spawn(move || {
        let _ = child_stdin.write_all(&stdin_bytes);
    });
    let run = capture_bounded_output(&mut child, timeout);
    let _ = writer.join();
    run
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

// ---------------------------------------------------------------------------
// Fork-child send backpressure (H)
// ---------------------------------------------------------------------------

/// The child bursts 300 x ~2KB messages plus one 300KB multibyte message.
/// Before the queue fix the AF_UNIX send buffer filled, a mid-packet EAGAIN
/// abandoned the packet tail, the parent glued the headless fragment to the
/// next packet, and everything from ~message 35 on was silently lost.
const BURST_PARENT: &str = r#"
const { fork } = require('child_process');
const child = fork(__dirname + '/child.js');
let count = 0, bad = 0, gotBig = false, bigOk = false;
child.on('message', (m) => {
  if (m && m.type === 'seq') {
    count++;
    if (m.payload !== 'x'.repeat(2000) + '-' + m.i) bad++;
  } else if (m && m.type === 'big') {
    gotBig = true;
    bigOk = (m.payload === 'é'.repeat(150000) + 'a'.repeat(150000));
  } else if (m && m.type === 'done') {
    console.log(`RESULT|seq=${count}|bad=${bad}|gotBig=${gotBig}|bigOk=${bigOk}`);
    child.kill();
    process.exit(0);
  }
});
child.send('go');
setTimeout(() => {
  console.log(`RESULT|timeout|seq=${count}|bad=${bad}|gotBig=${gotBig}`);
  child.kill();
  process.exit(1);
}, 120000);
"#;

const BURST_CHILD: &str = r#"
process.on('message', () => {
  for (let i = 0; i < 300; i++) {
    process.send({ type: 'seq', i, payload: 'x'.repeat(2000) + '-' + i });
  }
  process.send({ type: 'big', payload: 'é'.repeat(150000) + 'a'.repeat(150000) });
  process.send({ type: 'done' });
});
"#;

fn assert_burst_delivered(tag: &str, env: &[(&str, &str)]) {
    let _audit_run = serialize_audit_run();
    let dir = unique_dir(tag);
    write_text(&dir.join("child.js"), BURST_CHILD);
    write_text(&dir.join("app.js"), BURST_PARENT);
    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec")
        .arg("audit")
        .arg("app.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    isolate_process_group(&mut cmd);
    let mut child = cmd.spawn().expect("spawn ibex");
    let run = capture_bounded_output(&mut child, IPC_BACKPRESSURE_HARNESS_TIMEOUT);
    assert!(
        !run.timed_out,
        "burst fixture timed out\nstdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
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
    assert_eq!(
        line, "RESULT|seq=300|bad=0|gotBig=true|bigOk=true",
        "burst was corrupted or truncated\nstdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
}

#[test]
fn fork_child_send_burst_survives_backpressure() {
    assert_burst_delivered("burst", &[]);
}

// ---------------------------------------------------------------------------
// Parent-side send backpressure (ENG-23231): parent → child direction
// ---------------------------------------------------------------------------

fn run_parent_child(
    tag: &str,
    parent_src: &str,
    child_src: &str,
    env: &[(&str, &str)],
    timeout: Duration,
) -> (String, String) {
    let _audit_run = serialize_audit_run();
    let dir = unique_dir(tag);
    write_text(&dir.join("child.js"), child_src);
    write_text(&dir.join("app.js"), parent_src);
    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec")
        .arg("audit")
        .arg("app.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    isolate_process_group(&mut cmd);
    let mut child = cmd.spawn().expect("spawn ibex");
    let run = capture_bounded_output(&mut child, timeout);
    assert!(
        !run.timed_out,
        "parent/child fixture timed out\nstdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    (run.stdout, run.stderr)
}

/// A single parent→child message whose framed packet (~300KB, multibyte)
/// far exceeds the AF_UNIX send buffer. Before the parent-side queue fix the
/// packet's tail was dropped on the first EAGAIN and the message never
/// arrived (the ticket's repro table: everything >= 16000 ascii chars was
/// lost). `cbDelivered` also proves the send callback fired by the time the
/// child's echo arrived, i.e. on actual delivery, not on write attempt.
const SINGLE_BIG_PARENT: &str = r#"
const { fork } = require('child_process');
const child = fork(__dirname + '/child.js');
let delivered = false;
child.on('message', (m) => {
  console.log(`RESULT|len=${m.len}|ok=${m.ok}|cbDelivered=${delivered}`);
  child.kill();
  process.exit(0);
});
child.send({ type: 'blob', payload: 'é'.repeat(150000) + 'a'.repeat(150000) }, (err) => {
  if (err) {
    console.log('RESULT|cb-error|' + (err.code || err.message));
    child.kill();
    process.exit(1);
  }
  delivered = true;
});
setTimeout(() => {
  console.log('RESULT|timeout');
  child.kill();
  process.exit(1);
}, 120000);
"#;

const SINGLE_BIG_CHILD: &str = r#"
process.on('message', (m) => {
  const ok = m && m.type === 'blob' && m.payload === 'é'.repeat(150000) + 'a'.repeat(150000);
  process.send({ len: m && m.payload ? m.payload.length : -1, ok: ok });
});
"#;

fn assert_parent_single_big_delivered(tag: &str, env: &[(&str, &str)]) {
    let (stdout, stderr) = run_parent_child(
        tag,
        SINGLE_BIG_PARENT,
        SINGLE_BIG_CHILD,
        env,
        IPC_BACKPRESSURE_HARNESS_TIMEOUT,
    );
    let line = stdout
        .lines()
        .find(|l| l.starts_with("RESULT|"))
        .unwrap_or_else(|| panic!("no RESULT line\nstdout:\n{}\nstderr:\n{}", stdout, stderr));
    assert_eq!(
        line, "RESULT|len=300000|ok=true|cbDelivered=true",
        "large parent->child message was dropped or corrupted\nstdout:\n{}\nstderr:\n{}",
        stdout, stderr
    );
}

#[test]
fn parent_send_single_large_message_survives_backpressure() {
    assert_parent_single_big_delivered("parent-big", &[]);
}

/// The parent bursts 300 x ~2KB sequenced messages, one ~300KB multibyte
/// message, then 'done', all with delivery callbacks on the last two. The
/// child verifies payload integrity and arrival order and reports a verdict.
const PARENT_BURST_PARENT: &str = r#"
const { fork } = require('child_process');
const child = fork(__dirname + '/child.js');
let cbFired = 0, cbErrs = 0;
const cb = (err) => { cbFired++; if (err) cbErrs++; };
child.on('message', (m) => {
  if (m && m.type === 'verdict') {
    console.log(`RESULT|seq=${m.seq}|bad=${m.bad}|outOfOrder=${m.outOfOrder}|gotBig=${m.gotBig}|bigOk=${m.bigOk}|cbFired=${cbFired}|cbErrs=${cbErrs}`);
    child.kill();
    process.exit(0);
  }
});
for (let i = 0; i < 300; i++) {
  child.send({ type: 'seq', i, payload: 'x'.repeat(2000) + '-' + i });
}
child.send({ type: 'big', payload: 'é'.repeat(150000) + 'a'.repeat(150000) }, cb);
child.send({ type: 'done' }, cb);
setTimeout(() => {
  console.log(`RESULT|timeout|cbFired=${cbFired}|cbErrs=${cbErrs}`);
  child.kill();
  process.exit(1);
}, 120000);
"#;

const PARENT_BURST_CHILD: &str = r#"
let seq = 0, bad = 0, outOfOrder = 0, gotBig = false, bigOk = false;
process.on('message', (m) => {
  if (!m) return;
  if (m.type === 'seq') {
    if (m.i !== seq) outOfOrder++;
    seq++;
    if (m.payload !== 'x'.repeat(2000) + '-' + m.i) bad++;
  } else if (m.type === 'big') {
    if (!gotBig) {
      gotBig = true;
      bigOk = (m.payload === 'é'.repeat(150000) + 'a'.repeat(150000));
    }
  } else if (m.type === 'done') {
    process.send({ type: 'verdict', seq: seq, bad: bad, outOfOrder: outOfOrder, gotBig: gotBig, bigOk: bigOk });
  }
});
"#;

fn assert_parent_burst_delivered(tag: &str, env: &[(&str, &str)]) {
    let (stdout, stderr) = run_parent_child(
        tag,
        PARENT_BURST_PARENT,
        PARENT_BURST_CHILD,
        env,
        IPC_BACKPRESSURE_HARNESS_TIMEOUT,
    );
    let line = stdout
        .lines()
        .find(|l| l.starts_with("RESULT|"))
        .unwrap_or_else(|| panic!("no RESULT line\nstdout:\n{}\nstderr:\n{}", stdout, stderr));
    assert_eq!(
        line, "RESULT|seq=300|bad=0|outOfOrder=0|gotBig=true|bigOk=true|cbFired=2|cbErrs=0",
        "parent->child burst was corrupted, reordered or truncated\nstdout:\n{}\nstderr:\n{}",
        stdout, stderr
    );
}

#[test]
fn parent_send_burst_survives_backpressure() {
    assert_parent_burst_delivered("parent-burst", &[]);
}

// ---------------------------------------------------------------------------
// Throwing 'message' listener must not kill polling (M)
// ---------------------------------------------------------------------------

const THROWING_LISTENER_PARENT: &str = r#"
const { fork } = require('child_process');
const child = fork(__dirname + '/child.js');
let got = [];
let semanticTimeout = null;
const startupTimeout = setTimeout(() => {
  console.log('RESULT|startup-timeout|' + JSON.stringify(got));
  child.kill();
  process.exit(1);
}, 60000);
child.on('message', (m) => {
  if (m === 'listener-ready') {
    clearTimeout(startupTimeout);
    child.send('first');
    semanticTimeout = setTimeout(() => {
      console.log('RESULT|timeout|' + JSON.stringify(got));
      child.kill();
      process.exit(1);
    }, 20000);
    return;
  }
  got.push(m);
  if (m === 'caught:listener-boom') {
    child.send('second');
  }
  if (m === 'second-received') {
    clearTimeout(semanticTimeout);
    console.log('RESULT|' + JSON.stringify(got));
    child.kill();
    process.exit(0);
  }
});
"#;

const THROWING_LISTENER_CHILD: &str = r#"
process.on('uncaughtException', (e) => {
  process.send('caught:' + e.message);
});
process.on('message', (m) => {
  if (m === 'first') throw new Error('listener-boom');
  if (m === 'second') process.send('second-received');
});
// `fork()` propagates the authenticated diagnostic route, whose cold startup
// can exceed the listener test's semantic deadline. Start that deadline only
// after this child has installed both handlers.
process.send('listener-ready');
"#;

fn assert_channel_survives_throwing_listener(tag: &str, env: &[(&str, &str)]) {
    let run = run_app_env_with_files(
        tag,
        THROWING_LISTENER_PARENT,
        &[("child.js", THROWING_LISTENER_CHILD)],
        env,
        Duration::from_secs(140),
    );
    let line = result_line(&run);
    assert_eq!(
        line, r#"RESULT|["caught:listener-boom","second-received"]"#,
        "channel went deaf after a throwing listener\nstderr:\n{}",
        run.stderr,
    );
}

#[test]
fn throwing_message_listener_does_not_kill_ipc_polling() {
    assert_channel_survives_throwing_listener("throwing-listener", &[]);
}

// ---------------------------------------------------------------------------
// Multibyte split across two reads must not corrupt (M)
// ---------------------------------------------------------------------------

const DECODE_CHILD: &str = r#"
function ipcCarrierHidden() {
  if (typeof Reflect !== 'object' ||
      typeof Reflect.ownKeys !== 'function') return false;
  const spread = { ...globalThis };
  const ownKeys = Reflect.ownKeys(globalThis);
  const keys = ['__exactCompatModes', '__exactProcessIpcBootstrap'];
  for (const key of keys) {
    if (globalThis[key] !== undefined || ownKeys.indexOf(key) !== -1 ||
        spread[key] !== undefined ||
        Object.getOwnPropertyDescriptor(globalThis, key) !== undefined) return false;
  }
  return true;
}
process.on('message', (m) => {
  if (!m || m.type !== 'blob') return;
  let replacements = 0;
  for (const ch of m.payload) if (ch === '�') replacements++;
  const ok = m.payload === 'π'.repeat(50000);
  const ipcEnvHidden = process.env.EXACT_IPC_FD === undefined &&
    process.env.EXACT_IPC_SERIALIZATION === undefined;
  process.send({
    type: 'verdict',
    len: m.payload.length,
    ok: ok,
    replacements: replacements,
    ipcEnvHidden: ipcEnvHidden,
    ipcCarrierHidden: ipcCarrierHidden()
  });
});
"#;

/// Drives the child's IPC receive path directly over a socketpair so the test
/// controls exactly where the byte stream is split: the packet is written in
/// two halves with a pause, cut in the middle of a two-byte UTF-8 'π'
/// (0xCF 0x80). With a fresh TextDecoder per chunk both halves decoded to
/// U+FFFD; the persistent streaming decoder reassembles them.
fn assert_split_multibyte_decodes(tag: &str, env: &[(&str, &str)]) {
    let _audit_run = serialize_audit_run();
    let dir = unique_dir(tag);
    write_text(&dir.join("child.js"), DECODE_CHILD);

    let (parent_sock, child_sock) = UnixStream::pair().expect("socketpair");
    let child_fd = child_sock.as_raw_fd();

    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec")
        .arg("audit")
        .arg("child.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .env("EXACT_IPC_FD", "3")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            // dup2 clears CLOEXEC on the destination fd.
            if libc::dup2(child_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    isolate_process_group(&mut cmd);
    let mut child = cmd.spawn().expect("spawn ibex child");
    drop(child_sock);

    // Build the framed packet: {"__exactIpc":true,"type":"message","data":{"type":"blob","payload":"πππ..."}}\n
    let payload = "\u{03C0}".repeat(50000);
    let packet = format!(
        "{{\"__exactIpc\":true,\"type\":\"message\",\"data\":{{\"type\":\"blob\",\"payload\":\"{}\"}}}}\n",
        payload
    );
    let bytes = packet.as_bytes();
    // Split in the middle of a 'π' (0xCF 0x80): find a 0xCF around the middle
    // and cut right after it.
    let mid = bytes.len() / 2;
    let split = (mid..bytes.len())
        .find(|&i| bytes[i] == 0xCF)
        .expect("multibyte lead byte in payload")
        + 1;

    let mut writer = parent_sock.try_clone().expect("clone socket");
    writer
        .set_write_timeout(Some(DIAGNOSTIC_AUDIT_TIMEOUT))
        .expect("set write timeout");
    writer.write_all(&bytes[..split]).expect("write first half");
    writer.flush().ok();
    // Give the child time to boot and poll the first half on its own read.
    thread::sleep(Duration::from_millis(1500));
    writer
        .write_all(&bytes[split..])
        .expect("write second half");
    writer.flush().ok();

    // Read the child's framed verdict.
    let mut reader = parent_sock;
    reader
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set read timeout");
    let mut acc = Vec::new();
    let deadline = Instant::now() + DIAGNOSTIC_AUDIT_TIMEOUT;
    let verdict = loop {
        if Instant::now() >= deadline {
            break None;
        }
        let mut buf = [0u8; 65536];
        match reader.read(&mut buf) {
            Ok(0) => break None,
            Ok(n) => {
                acc.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&acc);
                if let Some(line) = text.lines().find(|l| l.contains("\"verdict\"")) {
                    break Some(line.to_string());
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break None,
        }
    };

    kill_process_group(&mut child);
    let _ = child.wait();
    let mut child_out = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut child_out);
    }
    let mut child_err = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut child_err);
    }
    let verdict = verdict.unwrap_or_else(|| {
        panic!(
            "no verdict from child ({})\nchild stdout:\n{}\nchild stderr:\n{}",
            tag, child_out, child_err
        )
    });
    assert!(
        verdict.contains("\"ok\":true")
            && verdict.contains("\"replacements\":0")
            && verdict.contains("\"ipcEnvHidden\":true")
            && verdict.contains("\"ipcCarrierHidden\":true"),
        "multibyte split corrupted the payload or disclosed private IPC bootstrap state ({}): {}",
        tag,
        verdict
    );
}

#[test]
fn child_ipc_decode_survives_multibyte_split_across_reads() {
    assert_split_multibyte_decodes("decode-split", &[]);
}

#[test]
fn child_ipc_bootstrap_rejects_non_socket_descriptor_before_project_code() {
    let _audit_run = serialize_audit_run();
    let dir = unique_dir("ipc-nonsocket");
    let marker = dir.join("project-ran");
    write_text(
        &dir.join("child.js"),
        "require('fs').writeFileSync(__dirname + '/project-ran', 'yes');\n",
    );
    let regular_path = dir.join("not-a-socket");
    let regular = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&regular_path)
        .expect("open regular fd fixture");
    let regular_fd = regular.as_raw_fd();

    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec")
        .arg("audit")
        .arg("child.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .env("IBEX_NO_BYTECODE", "1")
        .env("EXACT_IPC_FD", "3")
        .env("EXACT_IPC_SERIALIZATION", "advanced")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            if libc::dup2(regular_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    isolate_process_group(&mut cmd);
    let mut child = cmd.spawn().expect("run child with non-socket IPC fd");
    let run = capture_bounded_output(&mut child, DIAGNOSTIC_AUDIT_TIMEOUT);

    assert!(
        !run.timed_out,
        "runtime did not finish rejecting a regular-file IPC channel\nstdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    assert!(
        run.status.is_some_and(|status| !status.success()),
        "runtime accepted a regular file as the process IPC channel\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    assert!(
        !marker.exists(),
        "project code ran after non-socket IPC bootstrap should have failed closed"
    );
    assert!(
        run.stderr
            .contains("invalid or unprotectable child-process IPC descriptor"),
        "startup refusal did not identify the invalid IPC descriptor\nstderr:\n{}",
        run.stderr
    );
}

// ---------------------------------------------------------------------------
// removeListener of a never-registered function must not stop delivery
// (ENG-23481 #2)
// ---------------------------------------------------------------------------

const REMOVE_MISCOUNT_PARENT: &str = r#"
const { fork } = require('child_process');
const child = fork(__dirname + '/child.js');
let got = [];
let semanticTimeout = null;
child.on('message', (m) => {
  got.push(m);
  if (m === 'ready') {
    semanticTimeout = setTimeout(() => {
      console.log('RESULT|timeout|' + JSON.stringify(got));
      child.kill();
      process.exit(1);
    }, 20000);
  }
  if (String(m).indexOf('removed-nothing') === 0) child.send('after-remove');
  if (String(m).indexOf('after-remove-received') === 0) {
    clearTimeout(semanticTimeout);
    console.log('RESULT|' + JSON.stringify(got));
    child.kill();
    process.exit(0);
  }
});
"#;

const REMOVE_MISCOUNT_CHILD: &str = r#"
function nope() {}
process.on('message', (m) => {
  if (m === 'after-remove') {
    process.send('after-remove-received:count=' + process.listenerCount('message'));
  }
});
process.send('ready');
process.removeListener('message', nope);
process.send('removed-nothing:count=' + process.listenerCount('message'));
"#;

/// The async IPC listener patch keeps a shadow listener count. It used to
/// decrement on every removeListener('message', fn) even when the emitter
/// removed nothing, driving the tracked count to 0 while a live listener
/// existed — the channel was unref'd (readStop) and later parent messages
/// were never delivered, and listenerCount answered from the drifted count.
#[test]
fn remove_listener_of_unregistered_fn_does_not_stop_delivery() {
    let _audit_run = serialize_audit_run();
    let dir = unique_dir("remove-miscount");
    write_text(&dir.join("child.js"), REMOVE_MISCOUNT_CHILD);
    write_text(&dir.join("app.js"), REMOVE_MISCOUNT_PARENT);
    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec")
        .arg("audit")
        .arg("app.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    isolate_process_group(&mut cmd);
    let mut child = cmd.spawn().expect("run ibex");
    let run = capture_bounded_output(&mut child, DIAGNOSTIC_AUDIT_TIMEOUT);
    assert!(
        !run.timed_out,
        "remove-listener fixture timed out\nstdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
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
    assert!(
        line.contains("removed-nothing:count=1") && line.contains("after-remove-received:count=1"),
        "delivery stopped (or listenerCount drifted) after removing a \
        never-registered listener: {}\nstderr:\n{}",
        line,
        run.stderr
    );
}

// ---------------------------------------------------------------------------
// Runtime-bundle compatibility regressions.
// ---------------------------------------------------------------------------

const DIAGNOSTIC_ENV: &[(&str, &str)] = &[];

/// WebCrypto must keep algorithm metadata and hash raw bytes, not a
/// UTF-8-reencoded binary string.
#[test]
fn web_crypto_preserves_hmac_params_and_binary_hashes() {
    let app = r#"
(async function() {
  const data = new Uint8Array([0xff, 0x80, 0x01]);
  const keyBytes = new Uint8Array([0xff, 0x80, 0x01, 0x02]);
  const digestHex = Buffer.from(await crypto.subtle.digest('SHA-256', data)).toString('hex');
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: { name: 'SHA-256' } },
    true,
    ['sign', 'verify']
  );
  const sigHex = Buffer.from(await crypto.subtle.sign({ name: 'HMAC' }, key, data)).toString('hex');
  const generated = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-512' },
    true,
    ['sign', 'verify']
  );
  console.log('RESULT|' + [
    digestHex,
    sigHex,
    key.algorithm.hash.name,
    key.algorithm.length,
    generated.algorithm.hash.name,
    generated.algorithm.length
  ].join('|'));
  process.exit(0);
})().catch((err) => {
  console.log('RESULT|error|' + (err && (err.name + ':' + err.message)));
  process.exit(1);
});
"#;
    let run = run_app_env("web-crypto", app, DIAGNOSTIC_ENV, DIAGNOSTIC_AUDIT_TIMEOUT);
    assert_eq!(
        result_line(&run),
        "RESULT|1b28450642394cac2cd61bbfb2b88c6325ac0c94944091bfd1ffdd8fad6571f9|32a877ecf1da16c451665baf2bae55e3792573b48f3c9d6d4df704c53dcc5f85|SHA-256|32|SHA-512|1024",
        "web crypto did not preserve HMAC metadata/raw bytes\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn web_storage_persists_utf8_values() {
    let home = unique_dir("storage-home");
    let home_str = home.to_str().expect("utf8 temp path");
    let env = [("HOME", home_str)];

    let writer = r#"
localStorage.setItem('k', 'Ģ and π');
console.log('RESULT|write|' + localStorage.length);
process.exit(0);
"#;
    let write_run = run_app_env("storage-write", writer, &env, DIAGNOSTIC_AUDIT_TIMEOUT);
    assert_eq!(
        result_line(&write_run),
        "RESULT|write|1",
        "localStorage write failed\nstdout:\n{}\nstderr:\n{}",
        write_run.stdout,
        write_run.stderr
    );

    let reader = r#"
console.log('RESULT|read|' + localStorage.length + '|' + localStorage.getItem('k'));
process.exit(0);
"#;
    let read_run = run_app_env("storage-read", reader, &env, DIAGNOSTIC_AUDIT_TIMEOUT);
    assert_eq!(
        result_line(&read_run),
        "RESULT|read|1|Ģ and π",
        "localStorage UTF-8 value did not round-trip\nstdout:\n{}\nstderr:\n{}",
        read_run.stdout,
        read_run.stderr
    );
}

#[test]
fn stdin_data_chunks_are_buffers_with_raw_bytes() {
    let app = r#"
const chunks = [];
process.stdin.on('data', (chunk) => {
  chunks.push([
    Buffer.isBuffer(chunk),
    typeof chunk,
    Buffer.from(chunk).toString('hex')
  ].join(':'));
});
process.stdin.on('end', () => {
  console.log('RESULT|' + chunks.join(','));
  process.exit(0);
});
process.stdin.resume();
"#;
    let run = run_app_env_stdin(
        "stdin-buffer",
        app,
        vec![0x80, 0xff, 0x61],
        DIAGNOSTIC_ENV,
        DIAGNOSTIC_AUDIT_TIMEOUT,
    );
    assert_eq!(
        result_line(&run),
        "RESULT|true:object:80ff61",
        "stdin did not emit byte-exact Buffer chunks\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn stdin_set_encoding_stream_decodes_split_utf8() {
    let app = r#"
let text = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { text += chunk; });
process.stdin.on('end', () => {
  let replacements = 0;
  for (const ch of text) if (ch === '�') replacements++;
  console.log('RESULT|' + text.length + '|' + text.slice(-1) + '|repl=' + replacements);
  process.exit(0);
});
process.stdin.resume();
"#;
    let mut input = vec![b'a'; 262143];
    input.push(0xcf);
    input.push(0x80);
    let run = run_app_env_stdin(
        "stdin-utf8-split",
        app,
        input,
        DIAGNOSTIC_ENV,
        DIAGNOSTIC_AUDIT_TIMEOUT,
    );
    assert_eq!(
        result_line(&run),
        "RESULT|262144|π|repl=0",
        "stdin setEncoding('utf8') corrupted a split multibyte sequence\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn web_streams_polyfill_exports_install_when_enabled() {
    let env = [("EX_WEB_STREAMS_POLYFILL", "1")];
    let app = r#"
console.log('RESULT|' + [
  typeof WebStreamsPolyfill,
  typeof WebStreamsPolyfill.ReadableStream,
  typeof ReadableStream,
  typeof TransformStream,
  typeof WritableStream
].join('|'));
process.exit(0);
"#;
    let run = run_app_env("web-streams-polyfill", app, &env, DIAGNOSTIC_AUDIT_TIMEOUT);
    assert_eq!(
        result_line(&run),
        "RESULT|object|function|function|function|function",
        "web streams polyfill did not expose expected globals\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
}
