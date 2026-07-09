//! ENG-23731: JS exceptions escaping drained async callbacks must never
//! unwind through `ex_hermes_poll`'s extern "C" boundary (std::terminate →
//! SIGABRT in the host). The CLI keeps the ENG-23130 contract — an unconsumed
//! async throw reports and the run exits nonzero — but it must be a *clean*
//! nonzero exit, never a signal death. (Embedded hosts opt into
//! ex_hermes_set_keep_alive_on_async_error(), covered by exact's
//! ExactRuntimeEngineTests; these tests pin the default policy and the
//! no-escape guarantee, which are shared by both modes.)
//!
//! Run with: `cargo test --test poll_async_throw_eng23731`.

use std::process::Command;
use std::time::{Duration, Instant};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn run_with_timeout(source: &str) -> std::process::Output {
    let start = Instant::now();
    let child = Command::new(IBEX)
        .arg("-e")
        .arg(source)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn ibex");
    // Bounded wait: these programs finish in well under a second; a wedge is
    // itself a failure mode this suite exists to catch.
    let mut child = child;
    loop {
        if let Some(_status) = child.try_wait().expect("try_wait failed") {
            return child.wait_with_output().expect("wait_with_output failed");
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            panic!("ibex did not exit within 10s (runtime wedged?)");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// ENG-23130 contract, unchanged by ENG-23731: a synchronous throw escaping a
/// timer callback with no uncaughtException handler reports and exits nonzero.
#[test]
fn timer_throw_reports_and_exits_nonzero() {
    let output = run_with_timeout("setTimeout(function () { var f = null; f(); }, 10);");
    let code = output
        .status
        .code()
        .expect("process died by signal instead of exiting (ENG-23731 regression)");
    assert_ne!(code, 0, "throwing timer must fail the run (ENG-23130)");
    let text = combined_output(&output);
    assert!(
        text.contains("null is not a function"),
        "error must be reported, got: {text}"
    );
}

/// ENG-23731 leg 1 at the CLI: a microtask queued by a cross-thread callback
/// (async fs completion) throws during the top-of-poll microtask drain.
/// Pre-fix this escaped `ex_hermes_poll` as a C++ exception and the process
/// died by SIGABRT (status.code() == None on unix). It must be a clean
/// nonzero exit with the error reported.
#[test]
fn cross_thread_microtask_throw_is_reported_not_sigabrt() {
    let source = r#"
        var fs = require('fs');
        fs.readFile(process.argv[0] || '/etc/hosts', function () {
            queueMicrotask(function () { var f = null; f(); });
        });
        // Keep a referenced timer pending so the loop is alive when the fs
        // completion arrives via the cross-thread callback queue.
        setTimeout(function () {}, 2000);
    "#;
    let output = run_with_timeout(source);
    let code = output.status.code().expect(
        "process died by signal — throwing microtask escaped ex_hermes_poll (ENG-23731 regression)",
    );
    assert_ne!(
        code, 0,
        "unconsumed microtask throw must fail the run (ENG-23130)"
    );
    let text = combined_output(&output);
    assert!(
        text.contains("null is not a function"),
        "error must be reported, got: {text}"
    );
}

/// A consumed microtask throw (handler returns true) must not strand the rest
/// of the microtask queue: draining resumes after the throwing job.
#[test]
fn handled_microtask_throw_keeps_draining_queue() {
    let source = r#"
        globalThis.__exactUncaughtExceptionHandler = function () { return true; };
        setTimeout(function () {
            queueMicrotask(function () { var f = null; f(); });
            queueMicrotask(function () { console.log('SECOND_JOB_RAN'); });
        }, 10);
        setTimeout(function () { console.log('LATER_TIMER_RAN'); process.exit(0); }, 60);
    "#;
    let output = run_with_timeout(source);
    let code = output.status.code().expect("process died by signal");
    assert_eq!(code, 0, "handled throw must not fail the run");
    let text = combined_output(&output);
    assert!(
        text.contains("SECOND_JOB_RAN"),
        "queue must keep draining after a consumed throw, got: {text}"
    );
    assert!(
        text.contains("LATER_TIMER_RAN"),
        "event loop must stay alive after a consumed throw, got: {text}"
    );
}
