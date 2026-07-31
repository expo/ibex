//! Operator EOF after a ready prompt must exit the secure-dev REPL cleanly.
//!
//! Regression for issues/closed/20260726-secure-repl-operator-exit-denied.md:
//! an `unadvertised-dev-arming` build published the REPL prompt but denied the
//! operator's own Ctrl-D at the root-authority-ceiling stratum (`exit 1`,
//! "operator exit was denied by the typed lifecycle route"), because the
//! synthesized dev ceiling carried no `lifecycle:exit` row. LLP 0025 §8 pins
//! orderly shutdown (Ctrl+D at an empty prompt, `.exit`) as an authorized
//! root lifecycle route in every mode.
//!
//! The interactive route only exists on a controlling terminal, so this test
//! runs the product binary on a real PTY rather than a pipe. It compiles only
//! into secure dev-arming builds; run it through the harness as:
//!   scripts/run-tests.sh --secure --features unadvertised-dev-arming \
//!     --test secure_repl_operator_eof
//! @ref LLP 0025#8-exit-and-lifecycle
//! @ref LLP 0038#2-root-authority-ceiling-raised-to-the-project-subtree
#![cfg(all(unix, not(feature = "insecure"), feature = "unadvertised-dev-arming"))]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");
/// The ready-prompt glyph published by the prompt witness ("➤").
const PROMPT: &[u8] = "\u{27a4}".as_bytes();
const DENIAL: &str = "operator exit was denied";
/// Generous: an armed debug-profile startup is the slow path being tested.
const DEADLINE: Duration = Duration::from_secs(180);

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn operator_eof_after_ready_prompt_exits_zero() {
    let project = tempfile::tempdir().expect("temporary project");
    std::fs::write(
        project.path().join("package.json"),
        "{\"name\":\"secure-repl-eof-fixture\",\"private\":true}\n",
    )
    .expect("package manifest");

    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let mut winsize = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut winsize,
        )
    };
    assert_eq!(
        opened,
        0,
        "openpty failed: {}",
        std::io::Error::last_os_error()
    );

    let slave_stdio = || {
        let duplicated = unsafe { libc::dup(slave) };
        assert!(
            duplicated >= 0,
            "dup(slave) failed: {}",
            std::io::Error::last_os_error()
        );
        unsafe { <Stdio as std::os::fd::FromRawFd>::from_raw_fd(duplicated) }
    };
    let mut command = Command::new(IBEX);
    command
        .arg("--project-root")
        .arg(project.path())
        .arg("repl")
        .stdin(slave_stdio())
        .stdout(slave_stdio())
        .stderr(slave_stdio());
    // The interactive editor requires a *controlling* terminal, not merely a
    // tty on stdio: make the slave this child's controlling terminal in a
    // fresh session, as `script(1)` does for the ticket's reproduction.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("spawn secure-dev ibex repl on pty");
    unsafe { libc::close(slave) };

    let deadline = Instant::now() + DEADLINE;
    let mut transcript: Vec<u8> = Vec::new();
    let mut sent_eof = false;
    let mut buffer = [0u8; 4096];
    loop {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the secure-dev REPL (eof sent: {sent_eof});\ntranscript:\n{}",
            String::from_utf8_lossy(&transcript)
        );
        let mut fds = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut fds, 1, 200) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::Interrupted,
                "poll(master) failed: {error}"
            );
            continue;
        }
        if ready > 0 {
            let read = unsafe {
                libc::read(
                    master,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                )
            };
            if read > 0 {
                transcript.extend_from_slice(&buffer[..read as usize]);
            } else {
                // 0 on macOS, -1/EIO on Linux: the session closed its side.
                break;
            }
        }
        if !sent_eof && contains(&transcript, PROMPT) {
            // Ctrl-D on the empty edit buffer, only after the ready prompt.
            let wrote = unsafe { libc::write(master, [0x04u8].as_ptr() as *const libc::c_void, 1) };
            assert_eq!(wrote, 1, "write EOF byte to pty master");
            sent_eof = true;
        }
        if ready == 0 && child.try_wait().expect("try_wait child").is_some() {
            break;
        }
    }
    unsafe { libc::close(master) };
    let status = child.wait().expect("wait for secure-dev ibex repl");

    let text = String::from_utf8_lossy(&transcript);
    assert!(
        sent_eof,
        "the REPL never published a ready prompt;\ntranscript:\n{text}"
    );
    assert!(
        !text.contains(DENIAL),
        "operator EOF was denied by the typed lifecycle route;\ntranscript:\n{text}"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "operator EOF must terminate the secure-dev REPL orderly (status {status:?});\ntranscript:\n{text}"
    );
}
