//! Unix launcher SIGINT mediation for package-script and watch controllers.
//!
//! These routes do not construct an armed runtime, so the fixtures remain
//! executable before a production CapSec target advertisement exists.
//! @ref LLP 0025#1-modes-descriptors-and-topology

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::ops::{Deref, DerefMut};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use tempfile::TempDir;

struct FixtureProcessGroup(Child);

impl FixtureProcessGroup {
    fn new(child: Child) -> Self {
        Self(child)
    }
}

impl Deref for FixtureProcessGroup {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FixtureProcessGroup {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for FixtureProcessGroup {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(None)) {
            return;
        }
        // Every product fixture owns a fresh process group. A failed assertion
        // must not leave its launcher or any child shell/runtime behind.
        let _ = unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
        let _ = self.0.wait();
    }
}

fn project() -> TempDir {
    let project = tempfile::tempdir().expect("temporary launcher project");
    std::fs::write(
        project.path().join("package.json"),
        r#"{
  "name": "launcher-signal-fixture",
  "private": true,
  "scripts": {
    "dev": "printf '%s' \"$$\" > child.pid; trap 'exit 130' INT; while :; do sleep 1; done",
    "count-interrupts": "printf '%s' \"$$\" > child.pid; trap 'printf x >> signal.count' INT; while :; do sleep 0.05; done"
  }
}
"#,
    )
    .expect("package manifest");
    project
}

fn product(project: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ibex"));
    command
        .arg("--project-root")
        .arg(project)
        .current_dir(project)
        // Give the fixture its own foreground-like process group. Sending the
        // group SIGINT then models the kernel delivery caused by terminal
        // Ctrl+C without signaling the test harness itself.
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

fn wait_for_file(path: &Path, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(value) = std::fs::read_to_string(path) {
            if !value.trim().is_empty() {
                return value;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll launcher") {
            return status;
        }
        assert!(Instant::now() < deadline, "launcher did not exit in time");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn interrupt_group(child: &Child) {
    let result = unsafe { libc::kill(-(child.id() as i32), libc::SIGINT) };
    assert_eq!(result, 0, "send SIGINT to launcher process group");
}

#[test]
fn package_script_parent_survives_group_sigint_reaps_child_and_exits_130() {
    let project = project();
    let mut command = product(project.path());
    command.args(["run", "dev"]);
    let mut launcher =
        FixtureProcessGroup::new(command.spawn().expect("spawn package-script launcher"));

    let child_pid: i32 = wait_for_file(&project.path().join("child.pid"), Duration::from_secs(10))
        .trim()
        .parse()
        .expect("shell child pid");
    interrupt_group(&launcher);
    let status = wait_for_exit(&mut launcher, Duration::from_secs(10));

    assert_eq!(status.code(), Some(128 + libc::SIGINT));
    assert_eq!(status.signal(), None, "launcher itself must hold SIGINT");
    let still_exists = unsafe { libc::kill(child_pid, 0) } == 0;
    assert!(!still_exists, "package-script shell child was not reaped");
}

#[test]
fn package_script_child_observes_one_sigint_per_group_interrupt() {
    let project = project();
    let mut command = product(project.path());
    command.args(["run", "count-interrupts"]);
    let mut launcher =
        FixtureProcessGroup::new(command.spawn().expect("spawn package-script launcher"));

    let child_pid: i32 = wait_for_file(&project.path().join("child.pid"), Duration::from_secs(10))
        .trim()
        .parse()
        .expect("shell child pid");
    interrupt_group(&launcher);
    let status = wait_for_exit(&mut launcher, Duration::from_secs(10));

    assert_eq!(status.code(), Some(128 + libc::SIGINT));
    assert_eq!(status.signal(), None, "launcher itself must hold SIGINT");
    assert_eq!(
        std::fs::read(project.path().join("signal.count")).expect("signal count"),
        b"x",
        "the launcher must not duplicate the foreground process-group SIGINT"
    );
    let still_exists = unsafe { libc::kill(child_pid, 0) } == 0;
    assert!(!still_exists, "package-script shell child was not reaped");
}

#[test]
fn watch_controller_holds_group_sigint_cleans_up_and_exits_130() {
    let project = project();
    const READY: &str = "watching for changes";
    std::fs::write(project.path().join("entry.mjs"), "while (true) {}\n").expect("watch entry");
    let mut command = product(project.path());
    command.args(["--watch", "entry.mjs"]);
    let mut launcher = FixtureProcessGroup::new(command.spawn().expect("spawn watch controller"));
    let stderr = launcher.stderr.take().expect("watch stderr");
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let stderr_thread = std::thread::spawn(move || {
        let mut observed = Vec::new();
        for line in BufReader::new(stderr).lines() {
            let line = line.expect("read watch diagnostic");
            if line.contains(READY) {
                let _ = ready_tx.try_send(line.clone());
            }
            observed.push(line);
        }
        observed
    });
    ready_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("watch controller did not publish its mediated readiness banner");

    interrupt_group(&launcher);
    let status = wait_for_exit(&mut launcher, Duration::from_secs(10));
    let diagnostics = stderr_thread
        .join()
        .expect("join watch diagnostic reader")
        .join("\n");
    assert_eq!(
        status.code(),
        Some(128 + libc::SIGINT),
        "watch diagnostics:\n{diagnostics}"
    );
    assert_eq!(
        status.signal(),
        None,
        "watch controller itself must hold SIGINT"
    );
    assert!(
        diagnostics.contains("watching for changes"),
        "{diagnostics}"
    );
    assert_eq!(
        diagnostics.matches(READY).count(),
        1,
        "watch readiness must be emitted exactly once: {diagnostics}"
    );
}
