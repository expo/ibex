//! Real OS fixtures for the engine-free process capability.
#![cfg(any(target_os = "macos", target_os = "linux"))]

use ibex2::boundary::HostError;
use ibex2::grant::{Grant, GrantSet};
use ibex2::host::Host;
use ibex2::stdlib::abort::{AbortController, AbortSignal};
use ibex2::stdlib::process::{Command, PtySize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::mpsc;
use std::time::Duration;

fn app(grants: &str) -> ibex2::host::Bindings {
    Host::new()
        .with_process_support()
        .endow(GrantSet::parse(grants).unwrap())
}

fn command(executable: &str, args: &[&str]) -> Command {
    Command {
        executable: executable.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        cwd: std::env::temp_dir().to_str().unwrap().into(),
        env: BTreeMap::new(),
    }
}

// A failed test must not leave a blocked reader/writer or a thirty-second child.
struct Deadline(Option<mpsc::Sender<()>>);
impl Deadline {
    fn new(controller: AbortController) -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            if rx.recv_timeout(Duration::from_secs(5)).is_err() {
                controller.abort();
            }
        });
        Self(Some(tx))
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        let _ = self.0.take().unwrap().send(());
    }
}

fn assert_reaped(pid: u32) {
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn authority_and_validation_refuse_before_execution() {
    let marker = std::env::temp_dir().join(format!("ibex-process-denied-{}", std::process::id()));
    let mut request = command("/bin/sh", &["-c", "printf ran > \"$MARKER\""]);
    request
        .env
        .insert("MARKER".into(), marker.to_str().unwrap().into());
    let signal = AbortSignal::default();
    let disabled = Host::new().endow(GrantSet::parse("process.spawn /bin/sh").unwrap());
    assert!(matches!(
        disabled.process.spawn(request.clone(), &signal),
        Err(HostError::Denied { .. })
    ));
    for grants in [
        "",
        "fs.read /",
        "process.pty /bin/sh",
        "process.spawn /bin",
        "process.spawn /bin/sh-other",
    ] {
        assert!(matches!(
            app(grants).process.spawn(request.clone(), &signal),
            Err(HostError::Denied { .. })
        ));
    }
    for grant in [
        "process.spawn",
        "process.spawn sh",
        "process.spawn /bin/../bin/sh",
        "process.pty /bin/sh extra",
        "process.spawn /bin/sh\0",
    ] {
        assert!(GrantSet::parse(grant).is_err(), "{grant:?}");
    }
    let granted = app("process.spawn /bin/sh");
    for bad in 0..4 {
        let mut malformed = request.clone();
        match bad {
            0 => malformed.cwd = "relative".into(),
            1 => malformed.args.push("bad\0arg".into()),
            2 => {
                malformed.env.insert("BAD=KEY".into(), "value".into());
            }
            _ => {
                malformed.env.insert("BAD".into(), "value\0".into());
            }
        }
        assert!(matches!(
            granted.process.spawn(malformed, &signal),
            Err(HostError::InvalidArgument(_))
        ));
    }
    let malformed = Host::new()
        .with_process_support()
        .endow(GrantSet::none().with(Grant::ProcessSpawn("sh".into())));
    assert!(malformed
        .process
        .spawn(command("sh", &[]), &signal)
        .is_err());
    let aborted = AbortController::new();
    aborted.abort();
    assert!(granted.process.spawn(request, &aborted.signal()).is_err());
    assert!(!marker.exists(), "refused request executed");
}

#[test]
fn literal_argv_explicit_cwd_env_and_exit_status() {
    let ctl = AbortController::new();
    let _deadline = Deadline::new(ctl.clone());
    let bindings = app("process.spawn /bin/sh\nprocess.spawn /usr/bin/env");
    let mut request = command(
        "/bin/sh",
        &[
            "-c",
            "printf '%s' \"$1\"; printf '%s' \"$PWD\" >&2; exit 23",
            "fixture",
            "$(touch nope); * \" ' \n",
        ],
    );
    request.cwd = "/".into();
    let mut child = bindings.process.spawn(request, &ctl.signal()).unwrap();
    drop(child.stdin.take());
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(output, "$(touch nope); * \" ' \n");
    output.clear();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(output, "/");
    let status = child.wait().unwrap();
    assert_eq!(status.code, Some(23));
    assert_eq!(status.signal, None);
    assert!(!status.success());
    assert_eq!(child.try_wait().unwrap(), Some(status));
    assert_reaped(child.id());
    let mut request = command("/usr/bin/env", &[]);
    request
        .env
        .insert("ONLY_THIS".into(), "literal=value".into());
    let mut child = bindings.process.spawn(request, &ctl.signal()).unwrap();
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(output, "ONLY_THIS=literal=value\n");
    assert!(child.wait().unwrap().success());
}

#[test]
fn piped_binary_roundtrip_and_stdin_eof() {
    let ctl = AbortController::new();
    let _deadline = Deadline::new(ctl.clone());
    let mut child = app("process.spawn /bin/cat")
        .process
        .spawn(command("/bin/cat", &[]), &ctl.signal())
        .unwrap();
    let bytes: Vec<u8> = (0..1_048_576).map(|n| n as u8).collect();
    let expected = bytes.clone();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&bytes).unwrap());
    let mut received = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut received)
        .unwrap();
    writer.join().unwrap();
    assert_eq!(received, expected);
    assert!(child.wait().unwrap().success());
}

#[test]
fn unread_output_backpressures_child() {
    let ctl = AbortController::new();
    let _deadline = Deadline::new(ctl.clone());
    let marker = std::env::temp_dir().join(format!("ibex-process-pressure-{}", std::process::id()));
    let mut request = command(
        "/bin/sh",
        &[
            "-c",
            "/bin/dd if=/dev/zero bs=65536 count=128 2>/dev/null; printf done > \"$MARKER\"",
        ],
    );
    request
        .env
        .insert("MARKER".into(), marker.to_str().unwrap().into());
    let mut child = app("process.spawn /bin/sh")
        .process
        .spawn(request, &ctl.signal())
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        !marker.exists(),
        "stdout was drained into an unbounded queue"
    );
    assert_eq!(child.try_wait().unwrap(), None);
    let mut stdout = child.stdout.take().unwrap();
    assert_eq!(
        std::io::copy(&mut stdout, &mut std::io::sink()).unwrap(),
        8 * 1_048_576
    );
    assert!(child.wait().unwrap().success());
    assert_eq!(std::fs::read(&marker).unwrap(), b"done");
    std::fs::remove_file(marker).unwrap();
}

#[test]
fn abort_interrupts_blocked_reads_writes_and_wait() {
    for write in [false, true] {
        let ctl = AbortController::new();
        let _deadline = Deadline::new(ctl.clone());
        let mut child = app("process.spawn /bin/sleep")
            .process
            .spawn(command("/bin/sleep", &["30"]), &ctl.signal())
            .unwrap();
        let pid = child.id();
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let io = std::thread::spawn(move || {
            if write {
                stdin.write_all(&vec![0; 1_048_576])
            } else {
                stdout.read(&mut [0; 1]).map(|_| ())
            }
        });
        let wait = std::thread::spawn(move || child.wait());
        std::thread::sleep(Duration::from_millis(30));
        ctl.abort();
        assert!(io.join().unwrap().is_err());
        assert_eq!(wait.join().unwrap().unwrap().signal, Some(libc::SIGKILL));
        assert_reaped(pid);
    }
}

#[test]
fn drop_cancels_group_and_reaps_even_with_retained_streams() {
    let ctl = AbortController::new();
    let _deadline = Deadline::new(ctl.clone());
    let mut child = app("process.spawn /bin/sh")
        .process
        .spawn(
            command(
                "/bin/sh",
                &["-c", "/bin/sleep 30 & printf '%s\\n' \"$!\"; wait"],
            ),
            &ctl.signal(),
        )
        .unwrap();
    let pid = child.id();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let descendant: i32 = line.trim().parse().unwrap();
    drop(child);
    assert_reaped(pid);
    assert!(output.read(&mut [0; 1]).is_err());
    // A killed grandchild may briefly be a zombie awaiting its OS parent.
    for _ in 0..100 {
        if unsafe { libc::kill(descendant, 0) } == -1 {
            return;
        }
        #[cfg(target_os = "linux")]
        if std::fs::read_to_string(format!("/proc/{descendant}/stat"))
            .is_ok_and(|s| s.contains(") Z "))
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("process-group descendant {descendant} survived drop");
}

#[test]
fn normal_exit_cleans_background_group_and_late_abort_keeps_status() {
    let ctl = AbortController::new();
    let _deadline = Deadline::new(ctl.clone());
    let mut child = app("process.spawn /bin/sh")
        .process
        .spawn(
            command("/bin/sh", &["-c", "/bin/sleep 30 & printf ready; exit 17"]),
            &ctl.signal(),
        )
        .unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut ready = [0; 5];
    output.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready");
    let status = child.wait().unwrap();
    assert_eq!(status.code, Some(17));
    // The sleeping descendant inherited stdout. EOF proves the remaining
    // process group was cleaned before the leader's PID became reusable.
    assert_eq!(output.read(&mut [0; 1]).unwrap(), 0);
    assert_reaped(child.id());
    ctl.abort();
    assert_eq!(child.wait().unwrap(), status);
}

#[test]
fn failed_exec_and_closed_stdin_report_errors() {
    let ctl = AbortController::new();
    let _deadline = Deadline::new(ctl.clone());
    let bindings = app("process.spawn /ibex-no-such-executable\nprocess.pty /ibex-no-such-executable\nprocess.spawn /bin/sh");
    for _ in 0..24 {
        assert!(matches!(
            bindings
                .process
                .spawn(command("/ibex-no-such-executable", &[]), &ctl.signal()),
            Err(HostError::Failed(_))
        ));
        assert!(matches!(
            bindings.process.pty(
                command("/ibex-no-such-executable", &[]),
                PtySize { rows: 24, cols: 80 },
                &ctl.signal()
            ),
            Err(HostError::Failed(_))
        ));
    }
    let mut child = bindings
        .process
        .spawn(
            command(
                "/bin/sh",
                &["-c", "exec 0<&-; printf closed; /bin/sleep 30"],
            ),
            &ctl.signal(),
        )
        .unwrap();
    let mut ready = [0; 6];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .unwrap();
    assert_eq!(&ready, b"closed");
    assert_eq!(
        child
            .stdin
            .as_mut()
            .unwrap()
            .write(b"data")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );
    assert_eq!(child.cancel().unwrap().signal, Some(libc::SIGKILL));
}

#[test]
fn pty_abort_wakes_retained_read_and_wait() {
    let ctl = AbortController::new();
    let _deadline = Deadline::new(ctl.clone());
    let mut pty = app("process.pty /bin/cat")
        .process
        .pty(
            command("/bin/cat", &[]),
            PtySize { rows: 24, cols: 80 },
            &ctl.signal(),
        )
        .unwrap();
    let pid = pty.id();
    let mut output = pty.output.take().unwrap();
    let reader = std::thread::spawn(move || output.read(&mut [0; 1]));
    let waiter = std::thread::spawn(move || pty.wait());
    ctl.abort();
    assert!(reader.join().unwrap().is_err());
    assert_eq!(waiter.join().unwrap().unwrap().signal, Some(libc::SIGKILL));
    assert_reaped(pid);
}

#[test]
fn pty_is_a_raw_controlling_terminal_with_resize_and_close() {
    let ctl = AbortController::new();
    let _deadline = Deadline::new(ctl.clone());
    let bindings = app("process.pty /bin/sh\nprocess.pty /bin/cat");
    let size = PtySize { rows: 24, cols: 80 };
    assert!(app("process.spawn /bin/cat")
        .process
        .pty(command("/bin/cat", &[]), size, &ctl.signal())
        .is_err());
    assert!(bindings
        .process
        .pty(
            command("/bin/cat", &[]),
            PtySize { rows: 0, cols: 80 },
            &ctl.signal()
        )
        .is_err());
    let mut pty = bindings.process.pty(command("/bin/sh", &["-c", "test -t 0 && test -t 1 && test -t 2 && exec 3</dev/tty && printf ready; read answer; /bin/stty size"]), size, &ctl.signal()).unwrap();
    let mut output = pty.output.take().unwrap();
    let mut ready = [0; 5];
    output.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready");
    pty.resize(PtySize {
        rows: 43,
        cols: 121,
    })
    .unwrap();
    pty.input.as_mut().unwrap().write_all(b"go\n").unwrap();
    let mut rest = String::new();
    output.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "43 121\n");
    assert!(pty.wait().unwrap().success());
    let mut pty = bindings
        .process
        .pty(command("/bin/cat", &[]), size, &ctl.signal())
        .unwrap();
    let pid = pty.id();
    let mut output = pty.output.take().unwrap();
    let bytes = b"\0\x03\x04\x1b[31m\xff\r\n";
    pty.input.as_mut().unwrap().write_all(bytes).unwrap();
    let mut received = vec![0; bytes.len()];
    output.read_exact(&mut received).unwrap();
    assert_eq!(received, bytes);
    assert_eq!(pty.close().unwrap().signal, Some(libc::SIGKILL));
    assert_eq!(pty.close().unwrap().signal, Some(libc::SIGKILL));
    assert!(output.read(&mut [0; 1]).is_err());
    assert_reaped(pid);
}
