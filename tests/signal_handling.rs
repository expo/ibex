//! End-to-end Node-style signal handling tests (ENG-23234), driving the real
//! `ibex` binary and delivering REAL signals from outside the process:
//!
//!   * `process.on('SIGINT', h)` + external `kill -INT` must run the handler
//!     (and the process survives until it chooses to exit) — previously the
//!     trap pipeline was dormant and the handler never fired.
//!   * With NO handler registered, an external SIGINT must kill the process
//!     with the default disposition.
//!   * `process.kill(process.pid, 'SIGUSR2')` must deliver to a registered
//!     handler — previously the shared-bundle shim's hardcoded `pid = 1`
//!     made self-signaling a silent no-op.
//!   * Removing the last handler must restore the default disposition.
//!   * A signal listener must not keep an otherwise-finished process alive.
//!
//! Dispatch rides the event-loop wake path (native trap -> pending queue ->
//! pushed runtime callback), so these tests also cover the default-profile
//! wake hook: a runtime parked on a long timer must dispatch immediately,
//! not at the next timer expiry.
//!
//! Run with: `scripts/run-tests.sh --scope test sigint` (plus `sigusr2` and
//! `signal_listener` for the remaining cases).

#![cfg(unix)]

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("ibex-sig-{}-{}-{}", tag, std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_text(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write test file");
}

struct SignalRun {
    /// Exit code, if the process exited normally.
    code: Option<i32>,
    /// Terminating signal number, if killed by a signal.
    signal: Option<i32>,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

/// Spawn `ibex run app.js`, wait for a READY line on stdout, then deliver
/// `signals` (signal number, delay-after-previous) to the process with real
/// `libc::kill` from this (outside) process. Returns how it terminated.
fn run_with_signals(
    tag: &str,
    app: &str,
    env: &[(&str, &str)],
    signals: &[(i32, Duration)],
    timeout: Duration,
) -> SignalRun {
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
    let mut child: Child = cmd.spawn().expect("spawn ibex binary");
    let pid = child.id() as i32;

    // Stream stdout so we can synchronize on READY before signaling.
    let mut out = child.stdout.take().expect("stdout pipe");
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let out_thread = thread::spawn(move || {
        let mut acc = String::new();
        let mut buf = [0u8; 4096];
        let mut announced = false;
        loop {
            match out.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if !announced && acc.contains("READY") {
                        announced = true;
                        let _ = ready_tx.send(());
                    }
                }
                Err(_) => break,
            }
        }
        acc
    });
    let mut err = child.stderr.take().expect("stderr pipe");
    let err_thread = thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });

    if !signals.is_empty() {
        // Wait for READY (bounded) so the JS handler is registered before we
        // signal; a process that dies first drops the channel.
        let _ = ready_rx.recv_timeout(Duration::from_secs(20));
        for (sig, delay) in signals {
            thread::sleep(*delay);
            unsafe {
                libc::kill(pid, *sig);
            }
        }
    }

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break None,
        }
    };

    SignalRun {
        code: status.and_then(|s| s.code()),
        signal: status.and_then(|s| s.signal()),
        stdout: out_thread.join().unwrap_or_default(),
        stderr: err_thread.join().unwrap_or_default(),
        timed_out,
    }
}

const SIGINT_HANDLER_APP: &str = r#"
process.on('SIGINT', (name) => {
  console.log('HANDLER-RAN name=' + name);
  process.exit(42);
});
console.log('READY pid=' + process.pid);
setTimeout(() => { console.log('TIMEOUT-NO-SIGNAL'); process.exit(3); }, 15000);
"#;

fn assert_sigint_handler_runs(tag: &str, env: &[(&str, &str)]) {
    let run = run_with_signals(
        tag,
        SIGINT_HANDLER_APP,
        env,
        &[(libc::SIGINT, Duration::from_millis(300))],
        Duration::from_secs(30),
    );
    assert!(
        !run.timed_out,
        "process hung\nstdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    assert!(
        run.stdout.contains("HANDLER-RAN name=SIGINT"),
        "SIGINT handler never ran\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    assert_eq!(
        run.code,
        Some(42),
        "expected the handler's exit code (survived + chose to exit), got code={:?} signal={:?}\nstdout:\n{}\nstderr:\n{}",
        run.code,
        run.signal,
        run.stdout,
        run.stderr
    );
}

/// External SIGINT with a registered handler: the handler runs and the
/// process survives long enough to exit on its own terms. The 15s fallback
/// timer also proves dispatch happens on signal arrival (event-loop wake),
/// not when the parked timer expires.
#[test]
fn external_sigint_dispatches_to_js_handler() {
    assert_sigint_handler_runs("sigint-handler", &[]);
}

#[test]
fn external_sigint_dispatches_to_js_handler_legacy_bootstrap() {
    assert_sigint_handler_runs(
        "sigint-handler-legacy",
        &[("EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE", "1")],
    );
}

/// No handler registered: external SIGINT must kill the process via the
/// default disposition (nothing may trap/swallow it).
#[test]
fn external_sigint_kills_process_without_handler() {
    let app = r#"
console.log('READY pid=' + process.pid);
setTimeout(() => { console.log('STILL-ALIVE'); process.exit(3); }, 15000);
"#;
    let run = run_with_signals(
        "sigint-default",
        app,
        &[],
        &[(libc::SIGINT, Duration::from_millis(300))],
        Duration::from_secs(30),
    );
    assert!(
        !run.timed_out && !run.stdout.contains("STILL-ALIVE"),
        "process ignored SIGINT with no handler registered\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    assert_eq!(
        run.signal,
        Some(libc::SIGINT),
        "expected death by SIGINT, got code={:?} signal={:?}\nstdout:\n{}\nstderr:\n{}",
        run.code,
        run.signal,
        run.stdout,
        run.stderr
    );
}

const SELF_USR2_APP: &str = r#"
let delivered = false;
process.on('SIGUSR2', () => {
  delivered = true;
  console.log('USR2-DELIVERED');
  process.exit(0);
});
process.kill(process.pid, 'SIGUSR2');
setTimeout(() => { console.log('delivered=' + delivered); process.exit(delivered ? 0 : 1); }, 5000);
"#;

fn assert_self_usr2_delivers(tag: &str, env: &[(&str, &str)]) {
    let run = run_with_signals(tag, SELF_USR2_APP, env, &[], Duration::from_secs(30));
    assert!(
        run.stdout.contains("USR2-DELIVERED") && run.code == Some(0),
        "self process.kill(process.pid, 'SIGUSR2') was not delivered (code={:?})\nstdout:\n{}\nstderr:\n{}",
        run.code,
        run.stdout,
        run.stderr
    );
}

/// Self-signaling: process.kill(process.pid, 'SIGUSR2') must reach the JS
/// handler. Covers both the real process.pid (shim used to hardcode 1) and
/// the Darwin-correct SIGUSR2 number (Linux-numbered tables sent SIGSYS).
#[test]
fn self_kill_sigusr2_delivers_to_handler() {
    assert_self_usr2_delivers("usr2-self", &[]);
}

#[test]
fn self_kill_sigusr2_delivers_to_handler_legacy_bootstrap() {
    assert_self_usr2_delivers(
        "usr2-self-legacy",
        &[("EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE", "1")],
    );
}

/// Removing the last listener restores the default disposition: two SIGINTs
/// run the handler (which removes itself on the second), the third kills.
#[test]
fn removing_last_sigint_handler_restores_default_disposition() {
    let app = r#"
let count = 0;
const h = () => {
  count++;
  console.log('GOT-' + count);
  if (count === 2) {
    process.removeListener('SIGINT', h);
    console.log('REMOVED');
  }
};
process.on('SIGINT', h);
console.log('READY pid=' + process.pid);
setTimeout(() => { console.log('TIMEOUT count=' + count); process.exit(3); }, 15000);
"#;
    let run = run_with_signals(
        "sigint-remove",
        app,
        &[],
        &[
            (libc::SIGINT, Duration::from_millis(300)),
            (libc::SIGINT, Duration::from_millis(500)),
            (libc::SIGINT, Duration::from_millis(500)),
        ],
        Duration::from_secs(30),
    );
    assert!(
        run.stdout.contains("GOT-1")
            && run.stdout.contains("GOT-2")
            && run.stdout.contains("REMOVED"),
        "handler did not run twice + remove itself\nstdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    assert_eq!(
        run.signal,
        Some(libc::SIGINT),
        "third SIGINT after removal should kill via default disposition, got code={:?} signal={:?}\nstdout:\n{}\nstderr:\n{}",
        run.code,
        run.signal,
        run.stdout,
        run.stderr
    );
}

/// A signal listener must not keep the event loop alive (Node semantics,
/// ENG-23132): with no other work the process exits immediately.
#[test]
fn signal_listener_does_not_keep_process_alive() {
    let app = r#"
process.on('SIGINT', () => {});
console.log('DONE');
"#;
    let start = Instant::now();
    let run = run_with_signals("sigint-noref", app, &[], &[], Duration::from_secs(20));
    let elapsed = start.elapsed();
    assert!(
        run.stdout.contains("DONE") && run.code == Some(0),
        "process did not exit cleanly (code={:?})\nstdout:\n{}\nstderr:\n{}",
        run.code,
        run.stdout,
        run.stderr
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "signal listener kept the process alive ({}ms)",
        elapsed.as_millis()
    );
}
