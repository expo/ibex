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
//!   * Legacy (EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE=1) bootstrap fixes:
//!     global `setTimeout().refresh()` re-arms fired timers (ENG-22970
//!     parity), `Bun.serve({unix})` returns a disposable server instead of
//!     throwing ReferenceError, and Bun's binary hash helpers hash raw bytes.
//!
//! Run with: `scripts/run-tests.sh --scope test bootstrap_ipc`.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
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

/// Run `ibex run app.js` with a wall-clock timeout. Extra env vars are applied
/// to the parent (and inherited by forked children).
fn run_app_env(tag: &str, app: &str, env: &[(&str, &str)], timeout: Duration) -> AppRun {
    let dir = unique_dir(tag);
    write_text(&dir.join("app.js"), app);
    let mut cmd = Command::new(IBEX);
    cmd.arg("run")
        .arg("app.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn ibex binary");

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

fn result_line<'a>(run: &'a AppRun) -> &'a str {
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
const legacy = process.env.IPC_TEST_LEGACY === '1';
const child = fork(__dirname + '/child.js', [], legacy
  ? { env: Object.assign({}, process.env, { EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE: '1' }) }
  : {});
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
}, 45000);
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
    let dir = unique_dir(tag);
    write_text(&dir.join("child.js"), BURST_CHILD);
    write_text(&dir.join("app.js"), BURST_PARENT);
    let mut cmd = Command::new(IBEX);
    cmd.arg("run")
        .arg("app.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = {
        let mut child = cmd.spawn().expect("spawn ibex");
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
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
        (
            out_thread.join().unwrap_or_default(),
            err_thread.join().unwrap_or_default(),
        )
    };
    let line = output
        .0
        .lines()
        .find(|l| l.starts_with("RESULT|"))
        .unwrap_or_else(|| {
            panic!(
                "no RESULT line\nstdout:\n{}\nstderr:\n{}",
                output.0, output.1
            )
        });
    assert_eq!(
        line, "RESULT|seq=300|bad=0|gotBig=true|bigOk=true",
        "burst was corrupted or truncated\nstdout:\n{}\nstderr:\n{}",
        output.0, output.1
    );
}

#[test]
fn fork_child_send_burst_survives_backpressure() {
    assert_burst_delivered("burst", &[]);
}

#[test]
fn fork_child_send_burst_survives_backpressure_legacy_ipc() {
    // Forces the child onto the legacy compat-polyfills IPC bootstrap
    // (process.__exactProcessIpcBootstrapInstalled), which has its own send
    // queue implementation.
    assert_burst_delivered("burst-legacy", &[("IPC_TEST_LEGACY", "1")]);
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
    let dir = unique_dir(tag);
    write_text(&dir.join("child.js"), child_src);
    write_text(&dir.join("app.js"), parent_src);
    let mut cmd = Command::new(IBEX);
    cmd.arg("run")
        .arg("app.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn ibex");
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
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    (
        out_thread.join().unwrap_or_default(),
        err_thread.join().unwrap_or_default(),
    )
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
}, 30000);
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
        Duration::from_secs(60),
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
}, 45000);
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
        Duration::from_secs(60),
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

#[test]
fn parent_send_burst_survives_backpressure_legacy_ipc() {
    // Runs the PARENT on the legacy bootstrap too (the child inherits the
    // env via fork), covering the legacy-parent flavor of the send path.
    assert_parent_burst_delivered(
        "parent-burst-legacy",
        &[("EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE", "1")],
    );
}

// ---------------------------------------------------------------------------
// Throwing 'message' listener must not kill polling (M)
// ---------------------------------------------------------------------------

const THROWING_LISTENER_PARENT: &str = r#"
const { fork } = require('child_process');
const legacy = process.env.IPC_TEST_LEGACY === '1';
const child = fork(__dirname + '/child.js', [], legacy
  ? { env: Object.assign({}, process.env, { EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE: '1' }) }
  : {});
let got = [];
child.on('message', (m) => {
  got.push(m);
  if (m === 'second-received') {
    console.log('RESULT|' + JSON.stringify(got));
    child.kill();
    process.exit(0);
  }
});
child.send('first');
setTimeout(() => child.send('second'), 400);
setTimeout(() => {
  console.log('RESULT|timeout|' + JSON.stringify(got));
  child.kill();
  process.exit(1);
}, 20000);
"#;

const THROWING_LISTENER_CHILD: &str = r#"
process.on('uncaughtException', (e) => {
  process.send('caught:' + e.message);
});
process.on('message', (m) => {
  if (m === 'first') throw new Error('listener-boom');
  if (m === 'second') process.send('second-received');
});
"#;

fn assert_channel_survives_throwing_listener(tag: &str, env: &[(&str, &str)]) {
    let dir = unique_dir(tag);
    write_text(&dir.join("child.js"), THROWING_LISTENER_CHILD);
    let app = THROWING_LISTENER_PARENT;
    write_text(&dir.join("app.js"), app);
    let mut cmd = Command::new(IBEX);
    cmd.arg("run")
        .arg("app.js")
        .current_dir(&dir)
        .env("IBEX_SKIP_AGENT_SKILLS_SYNC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("run ibex");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("RESULT|"))
        .unwrap_or_else(|| {
            panic!(
                "no RESULT line\nstdout:\n{}\nstderr:\n{}",
                stdout,
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert!(
        line.contains("caught:listener-boom") && line.contains("second-received"),
        "channel went deaf after a throwing listener: {}\nstderr:\n{}",
        line,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn throwing_message_listener_does_not_kill_ipc_polling() {
    assert_channel_survives_throwing_listener("throwing-listener", &[]);
}

#[test]
fn throwing_message_listener_does_not_kill_ipc_polling_legacy_ipc() {
    assert_channel_survives_throwing_listener(
        "throwing-listener-legacy",
        &[("IPC_TEST_LEGACY", "1")],
    );
}

// ---------------------------------------------------------------------------
// Multibyte split across two reads must not corrupt (M)
// ---------------------------------------------------------------------------

const DECODE_CHILD: &str = r#"
process.on('message', (m) => {
  if (!m || m.type !== 'blob') return;
  let replacements = 0;
  for (const ch of m.payload) if (ch === '�') replacements++;
  const ok = m.payload === 'π'.repeat(50000);
  process.send({ type: 'verdict', len: m.payload.length, ok: ok, replacements: replacements });
});
"#;

/// Drives the child's IPC receive path directly over a socketpair so the test
/// controls exactly where the byte stream is split: the packet is written in
/// two halves with a pause, cut in the middle of a two-byte UTF-8 'π'
/// (0xCF 0x80). With a fresh TextDecoder per chunk both halves decoded to
/// U+FFFD; the persistent streaming decoder reassembles them.
fn assert_split_multibyte_decodes(tag: &str, env: &[(&str, &str)]) {
    let dir = unique_dir(tag);
    write_text(&dir.join("child.js"), DECODE_CHILD);

    let (parent_sock, child_sock) = UnixStream::pair().expect("socketpair");
    let child_fd = child_sock.as_raw_fd();

    let mut cmd = Command::new(IBEX);
    cmd.arg("run")
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
        .set_write_timeout(Some(Duration::from_secs(30)))
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
    let deadline = Instant::now() + Duration::from_secs(30);
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

    let _ = child.kill();
    let mut child_out = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut child_out);
    }
    let mut child_err = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut child_err);
    }
    let _ = child.wait();

    let verdict = verdict.unwrap_or_else(|| {
        panic!(
            "no verdict from child ({})\nchild stdout:\n{}\nchild stderr:\n{}",
            tag, child_out, child_err
        )
    });
    assert!(
        verdict.contains("\"ok\":true") && verdict.contains("\"replacements\":0"),
        "multibyte split corrupted the payload ({}): {}",
        tag,
        verdict
    );
}

#[test]
fn child_ipc_decode_survives_multibyte_split_across_reads() {
    assert_split_multibyte_decodes("decode-split", &[]);
}

#[test]
fn child_ipc_decode_survives_multibyte_split_across_reads_legacy_ipc() {
    assert_split_multibyte_decodes(
        "decode-split-legacy",
        &[("EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE", "1")],
    );
}

// ---------------------------------------------------------------------------
// Legacy bootstrap misc fixes (only reachable without the startup shared
// runtime bundle; these run the bootstrap-globals / exact-global paths)
// ---------------------------------------------------------------------------

const LEGACY_ENV: &[(&str, &str)] = &[("EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE", "1")];

/// ENG-22970 parity for the bootstrap-globals global timer wrapper:
/// refresh() must re-arm a fired one-shot; a cleared timer must stay dead.
#[test]
fn global_timeout_refresh_rearms_after_fire() {
    let app = r#"
let fires = 0;
const t = setTimeout(() => { fires++; }, 30);
setTimeout(() => { t.refresh(); }, 150);
setTimeout(() => {
  const t2 = setTimeout(() => { fires += 100; }, 10);
  clearTimeout(t2);
  t2.refresh();
  setTimeout(() => {
    console.log('RESULT|fires=' + fires);
    process.exit(0);
  }, 100);
}, 320);
"#;
    let run = run_app_env("refresh", app, LEGACY_ENV, Duration::from_secs(30));
    assert_eq!(
        result_line(&run),
        "RESULT|fires=2",
        "refresh() did not re-arm exactly once\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
}

/// Bun.serve({ unix }) used to throw `ReferenceError: defineDisposable is not
/// defined` after the server had already started listening.
#[test]
fn bun_serve_unix_returns_disposable_server() {
    let app = r#"
const sock = '/tmp/ibex-eng23132-test-' + process.pid + '.sock';
const server = Bun.serve({ unix: sock, fetch() { return new Response('ok'); } });
const hasDispose = typeof server[Symbol.dispose] === 'function';
server.stop(true);
console.log('RESULT|serve-ok|dispose=' + hasDispose);
process.exit(0);
"#;
    let run = run_app_env("bun-serve", app, LEGACY_ENV, Duration::from_secs(30));
    assert_eq!(
        result_line(&run),
        "RESULT|serve-ok|dispose=true",
        "Bun.serve({{unix}}) failed\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
}

/// Bun.sha / Bun.CryptoHasher must hash raw bytes (previously Uint8Array
/// input hashed '' and bytes >= 0x80 were mangled through a latin1/UTF-8
/// round-trip), and Bun.peek must return the value/promise itself.
#[test]
fn bun_binary_hash_and_peek_are_correct() {
    // printf '\xff\x80\x01' | openssl dgst -sha512 / -sha256
    let app = r#"
const shaBytes = Bun.sha(new Uint8Array([0xff, 0x80, 0x01]), 'hex');
const hasherBytes = new Bun.CryptoHasher('sha256').update(new Uint8Array([0xff, 0x80, 0x01])).digest('hex');
const hasherString = new Bun.CryptoHasher('sha256').update('hello').digest('hex');
const p = Promise.resolve(1);
const peekOk = (Bun.peek(42) === 42) && (Bun.peek(p) === p);
console.log('RESULT|' + [
  shaBytes === 'f72ac708801b73cf865f18a675f1f1c765390f71e25aa77388bfed93267038d4e648111bad6e7db6f303cad5584e6134f547cee1b19198b21cc9d39ec163e12d',
  hasherBytes === '1b28450642394cac2cd61bbfb2b88c6325ac0c94944091bfd1ffdd8fad6571f9',
  hasherString === '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
  peekOk
].join('|'));
process.exit(0);
"#;
    let run = run_app_env("bun-hash", app, LEGACY_ENV, Duration::from_secs(30));
    assert_eq!(
        result_line(&run),
        "RESULT|true|true|true|true",
        "Bun binary hash/peek helpers wrong\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
}
