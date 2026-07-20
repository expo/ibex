//! Bounded, contract-driven execution for an authenticated portable host tool.
//!
//! Legacy build tools do not use this runner. A portable invocation starts
//! from an empty environment, receives only the reviewed variables, runs with
//! empty stdin in a fresh private directory, and is killed on any time or byte
//! bound violation.
//!
//! @ref LLP 0035#build-consumption-and-post-link-contracts — a selected host
//! tool remains authoritative only under its digest-bound execution contract.

use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableHostToolContract {
    pub compatibility_digest: String,
    pub environment: Vec<(String, String)>,
    pub timeout_ms: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_output_bytes: u64,
}

#[derive(Debug)]
pub struct PortableHostToolOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PortableHostToolRunner {
    tool_path: PathBuf,
    contract: PortableHostToolContract,
    workspace_parent: PathBuf,
}

static WORKSPACE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct FreshWorkspace {
    path: PathBuf,
    cleaned: bool,
}

#[cfg(unix)]
struct ProcessGroupGuard {
    pgid: libc::pid_t,
    armed: bool,
}

#[cfg(unix)]
impl ProcessGroupGuard {
    fn new(pgid: libc::pid_t) -> Self {
        Self { pgid, armed: true }
    }

    fn signal(&self, signal: libc::c_int) -> Result<(), String> {
        // Negative PID selects the whole process group. The child creates the
        // group in `pre_exec`, before any reviewed tool byte can run.
        let result = unsafe { libc::kill(-self.pgid, signal) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!(
                "signal portable host-tool process group {}: {error}",
                self.pgid
            ))
        }
    }

    fn alive(&self) -> Result<bool, String> {
        let result = unsafe { libc::kill(-self.pgid, 0) };
        if result == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            // We created the group under the same effective UID. EPERM is not
            // treated as quiescence if that premise is unexpectedly lost.
            _ => Err(format!(
                "inspect portable host-tool process group {}: {error}",
                self.pgid
            )),
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.signal(libc::SIGKILL);
        }
    }
}

struct OutputCleanup {
    paths: Vec<PathBuf>,
    armed: bool,
}

impl OutputCleanup {
    fn new(paths: &[PathBuf]) -> Self {
        Self {
            paths: paths.to_vec(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for OutputCleanup {
    fn drop(&mut self) {
        if self.armed {
            cleanup_outputs(&self.paths);
        }
    }
}

impl FreshWorkspace {
    fn create(parent: &Path) -> Result<Self, String> {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create portable host-tool workspace parent {}: {error}",
                parent.display()
            )
        })?;
        for _ in 0..1024 {
            let sequence = WORKSPACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("invocation-{}-{sequence}", std::process::id()));
            #[cfg(unix)]
            let created = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700).create(&path)
            };
            #[cfg(not(unix))]
            let created = fs::create_dir(&path);
            match created {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(
                            |error| {
                                format!(
                                    "make portable host-tool workspace private {}: {error}",
                                    path.display()
                                )
                            },
                        )?;
                    }
                    return Ok(Self {
                        path,
                        cleaned: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "create portable host-tool workspace under {}: {error}",
                        parent.display()
                    ));
                }
            }
        }
        Err("could not allocate a unique portable host-tool workspace".to_owned())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if self.cleaned {
            return Ok(());
        }
        fs::remove_dir_all(&self.path).map_err(|error| {
            format!(
                "clean portable host-tool workspace {}: {error}",
                self.path.display()
            )
        })?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for FreshWorkspace {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn read_bounded(
    mut stream: impl Read,
    maximum: u64,
    label: &'static str,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("read portable host-tool {label}: {error}"))?;
        if count == 0 {
            return Ok(bytes);
        }
        let next = (bytes.len() as u64)
            .checked_add(count as u64)
            .ok_or_else(|| format!("portable host-tool {label} size overflow"))?;
        if next > maximum {
            return Err(format!(
                "portable host-tool {label} exceeded {maximum} bytes"
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

fn cleanup_outputs(paths: &[PathBuf]) {
    for path in paths {
        if let Err(error) = fs::remove_file(path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                // The primary invocation error remains more useful; a
                // surviving output is still made visible in that error.
                eprintln!(
                    "portable host-tool cleanup could not remove {}: {error}",
                    path.display()
                );
            }
        }
    }
}

#[cfg(unix)]
fn same_output_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_output_object(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len()
}

fn deadline_remaining(deadline: Instant, label: &str) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| format!("portable host tool exceeded its deadline while {label}"))
}

fn validate_outputs(
    paths: &[PathBuf],
    maximum: u64,
    deadline: Instant,
) -> Result<Vec<File>, String> {
    let mut output_size = 0u64;
    let mut pinned = Vec::with_capacity(paths.len());
    for path in paths {
        deadline_remaining(deadline, "pinning declared outputs")?;
        let before = fs::symlink_metadata(path).map_err(|error| {
            format!(
                "inspect portable host-tool output {}: {error}",
                path.display()
            )
        })?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(format!(
                "portable host-tool output {} is redirected or not regular",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            if before.uid() != unsafe { libc::geteuid() } {
                return Err(format!(
                    "portable host-tool output {} is not effective-UID-owned",
                    path.display()
                ));
            }
            if before.nlink() != 1 {
                return Err(format!(
                    "portable host-tool output {} is hard-linked",
                    path.display()
                ));
            }
            let mut options = OpenOptions::new();
            options.read(true).custom_flags(libc::O_NOFOLLOW);
            let mut file = options.open(path).map_err(|error| {
                format!(
                    "open portable host-tool output without following {}: {error}",
                    path.display()
                )
            })?;
            let opened = file.metadata().map_err(|error| {
                format!(
                    "inspect pinned portable host-tool output {}: {error}",
                    path.display()
                )
            })?;
            if !same_output_object(&before, &opened) {
                return Err(format!(
                    "portable host-tool output {} changed while it was pinned",
                    path.display()
                ));
            }
            let mut buffer = [0u8; 16 * 1024];
            let mut observed = 0u64;
            loop {
                deadline_remaining(deadline, "reading declared outputs")?;
                let count = file.read(&mut buffer).map_err(|error| {
                    format!(
                        "read pinned portable host-tool output {}: {error}",
                        path.display()
                    )
                })?;
                if count == 0 {
                    break;
                }
                observed = observed
                    .checked_add(count as u64)
                    .ok_or_else(|| "portable host-tool output size overflow".to_owned())?;
                if output_size
                    .checked_add(observed)
                    .is_none_or(|total| total > maximum)
                {
                    return Err(format!(
                        "portable host-tool outputs exceeded {maximum} bytes"
                    ));
                }
            }
            let after = file.metadata().map_err(|error| {
                format!(
                    "reinspect pinned portable host-tool output {}: {error}",
                    path.display()
                )
            })?;
            let path_after = fs::symlink_metadata(path).map_err(|error| {
                format!(
                    "reinspect portable host-tool output {}: {error}",
                    path.display()
                )
            })?;
            if observed != before.len()
                || !same_output_object(&before, &after)
                || !same_output_object(&before, &path_after)
            {
                return Err(format!(
                    "portable host-tool output {} changed during final validation",
                    path.display()
                ));
            }
            output_size += observed;
            pinned.push(file);
            continue;
        }
        #[cfg(not(unix))]
        {
            output_size = output_size
                .checked_add(before.len())
                .ok_or_else(|| "portable host-tool output size overflow".to_owned())?;
        }
    }
    if output_size > maximum {
        Err(format!(
            "portable host-tool outputs exceeded {maximum} bytes"
        ))
    } else {
        Ok(pinned)
    }
}

enum ChildEvent {
    Status(Result<ExitStatus, String>),
    Stdout(Result<Vec<u8>, String>),
    Stderr(Result<Vec<u8>, String>),
}

impl PortableHostToolRunner {
    pub fn new(
        tool_path: PathBuf,
        contract: PortableHostToolContract,
        workspace_parent: PathBuf,
    ) -> Self {
        Self {
            tool_path,
            contract,
            workspace_parent,
        }
    }

    pub fn compatibility_digest(&self) -> &str {
        &self.contract.compatibility_digest
    }

    pub fn max_output_bytes(&self) -> u64 {
        self.contract.max_output_bytes
    }

    pub fn run(
        &self,
        args: &[OsString],
        output_files: &[PathBuf],
    ) -> Result<PortableHostToolOutput, String> {
        if !self.tool_path.is_absolute() || !self.workspace_parent.is_absolute() {
            return Err("portable host-tool path and workspace parent must be absolute".to_owned());
        }
        if self.contract.timeout_ms == 0 {
            return Err("portable host-tool timeout must be positive".to_owned());
        }
        let mut unique_outputs = std::collections::BTreeSet::new();
        for path in output_files {
            if !path.is_absolute() || !unique_outputs.insert(path) {
                return Err(
                    "portable host-tool output paths must be absolute and unique".to_owned(),
                );
            }
            match fs::symlink_metadata(path) {
                Ok(_) => {
                    return Err(format!(
                        "portable host-tool output path existed before the fresh invocation: {}",
                        path.display()
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "inspect portable host-tool output path {}: {error}",
                        path.display()
                    ));
                }
            }
        }

        let mut output_cleanup = OutputCleanup::new(output_files);
        let mut workspace = FreshWorkspace::create(&self.workspace_parent)?;
        let mut command = Command::new(&self.tool_path);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.arg0(self.tool_path.as_os_str());
            // SAFETY: `setpgid` is async-signal-safe and touches no Rust state.
            // The child becomes leader of a fresh process group before exec,
            // so every ordinary descendant remains inside the containment
            // boundary even if the direct child exits first.
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });
            }
        }
        command
            .args(args)
            .env_clear()
            .envs(self.contract.environment.iter().cloned())
            .current_dir(&workspace.path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = Instant::now();
        let timeout = Duration::from_millis(self.contract.timeout_ms);
        let deadline = started
            .checked_add(timeout)
            .ok_or_else(|| "portable host-tool deadline overflow".to_owned())?;
        // Reserve a small portion of the reviewed upper bound for mandatory
        // group shutdown, pipe drain, and output pinning. One absolute
        // deadline governs all of them; direct-child exit never stops it.
        let shutdown_reserve = std::cmp::min(
            Duration::from_millis(25),
            std::cmp::max(Duration::from_millis(1), timeout / 10),
        );
        let execution_deadline = deadline.checked_sub(shutdown_reserve).unwrap_or(deadline);

        let mut child = command.spawn().map_err(|error| {
            format!(
                "spawn portable host tool {}: {error}",
                self.tool_path.display()
            )
        })?;
        #[cfg(unix)]
        let mut process_group = ProcessGroupGuard::new(child.id() as libc::pid_t);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "portable host tool has no captured stdout".to_owned())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "portable host tool has no captured stderr".to_owned())?;
        let (event_sender, event_receiver) = mpsc::channel();
        let status_sender = event_sender.clone();
        let status_thread = thread::spawn(move || {
            let result = child
                .wait()
                .map_err(|error| format!("wait for portable host tool: {error}"));
            let _ = status_sender.send(ChildEvent::Status(result));
        });
        let stdout_sender = event_sender.clone();
        let max_stdout = self.contract.max_stdout_bytes;
        let stdout_thread = thread::spawn(move || {
            let result = read_bounded(stdout, max_stdout, "stdout");
            let _ = stdout_sender.send(ChildEvent::Stdout(result));
        });
        let max_stderr = self.contract.max_stderr_bytes;
        let stderr_thread = thread::spawn(move || {
            let result = read_bounded(stderr, max_stderr, "stderr");
            let _ = event_sender.send(ChildEvent::Stderr(result));
        });

        let mut status = None;
        let mut stdout = None;
        let mut stderr = None;
        let mut forced_error = None;
        while status.is_none() && forced_error.is_none() {
            let now = Instant::now();
            if now >= execution_deadline {
                forced_error = Some(format!(
                    "portable host tool exceeded {} ms",
                    self.contract.timeout_ms
                ));
                break;
            }
            let wait = std::cmp::min(
                Duration::from_millis(2),
                execution_deadline.duration_since(now),
            );
            match event_receiver.recv_timeout(wait) {
                Ok(ChildEvent::Status(result)) => status = Some(result),
                Ok(ChildEvent::Stdout(result)) => {
                    if let Err(error) = &result {
                        forced_error = Some(error.clone());
                    }
                    stdout = Some(result);
                }
                Ok(ChildEvent::Stderr(result)) => {
                    if let Err(error) = &result {
                        forced_error = Some(error.clone());
                    }
                    stderr = Some(result);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    forced_error =
                        Some("portable host-tool supervision channel disconnected".to_owned());
                }
            }
        }

        // Every terminal path closes the process group. In particular, a
        // successful direct-child exit is not success while a descendant can
        // retain a pipe or mutate a declared output.
        #[cfg(unix)]
        {
            if forced_error.is_none() && status.as_ref().is_some_and(Result::is_ok) {
                match process_group.alive() {
                    Ok(true) => {
                        forced_error = Some(
                            "portable host tool left live descendants after its direct child exited"
                                .to_owned(),
                        );
                    }
                    Ok(false) => {}
                    Err(error) => forced_error = Some(error),
                }
            }
            let _ = process_group.signal(libc::SIGTERM);
            let grace_end = std::cmp::min(
                deadline,
                Instant::now()
                    .checked_add(Duration::from_millis(5))
                    .unwrap_or(deadline),
            );
            while Instant::now() < grace_end {
                match process_group.alive() {
                    Ok(false) => break,
                    Ok(true) => thread::sleep(Duration::from_millis(1)),
                    Err(error) => {
                        forced_error.get_or_insert(error);
                        break;
                    }
                }
            }
            let _ = process_group.signal(libc::SIGKILL);
        }

        while (status.is_none() || stdout.is_none() || stderr.is_none())
            && Instant::now() < deadline
        {
            let remaining = deadline_remaining(deadline, "draining supervised child state")?;
            match event_receiver.recv_timeout(remaining) {
                Ok(ChildEvent::Status(result)) => status = Some(result),
                Ok(ChildEvent::Stdout(result)) => stdout = Some(result),
                Ok(ChildEvent::Stderr(result)) => stderr = Some(result),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        #[cfg(unix)]
        {
            while Instant::now() < deadline {
                match process_group.alive() {
                    Ok(false) => {
                        process_group.disarm();
                        break;
                    }
                    Ok(true) => {
                        let _ = process_group.signal(libc::SIGKILL);
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => {
                        forced_error.get_or_insert(error);
                        break;
                    }
                }
            }
            if process_group.armed {
                forced_error.get_or_insert_with(|| {
                    "portable host-tool process group did not quiesce before its deadline"
                        .to_owned()
                });
            }
        }

        let threads_complete = status.is_some() && stdout.is_some() && stderr.is_some();
        if threads_complete && Instant::now() < deadline {
            if status_thread.join().is_err() {
                forced_error
                    .get_or_insert_with(|| "portable host-tool status waiter panicked".to_owned());
            }
            if stdout_thread.join().is_err() {
                forced_error
                    .get_or_insert_with(|| "portable host-tool stdout reader panicked".to_owned());
            }
            if stderr_thread.join().is_err() {
                forced_error
                    .get_or_insert_with(|| "portable host-tool stderr reader panicked".to_owned());
            }
        } else {
            forced_error.get_or_insert_with(|| {
                "portable host tool exceeded its deadline while draining descendants".to_owned()
            });
            // Dropping an unfinished JoinHandle detaches rather than blocking;
            // the process-group guard has already issued SIGKILL.
            drop(status_thread);
            drop(stdout_thread);
            drop(stderr_thread);
        }

        let mut result = match (forced_error, status, stdout, stderr) {
            (Some(error), _, _, _) => Err(error),
            (None, Some(Err(error)), _, _) => Err(error),
            (None, Some(Ok(_)), Some(Err(error)), _) | (None, Some(Ok(_)), _, Some(Err(error))) => {
                Err(error)
            }
            (None, Some(Ok(status)), Some(Ok(_stdout)), Some(Ok(stderr))) if !status.success() => {
                Err(format!(
                    "portable host tool exited with {status}: {}",
                    String::from_utf8_lossy(&stderr)
                ))
            }
            (None, Some(Ok(_)), Some(Ok(stdout)), Some(Ok(stderr))) => {
                validate_outputs(output_files, self.contract.max_output_bytes, deadline)
                    .map(|_pinned_outputs| PortableHostToolOutput { stdout, stderr })
            }
            _ => Err("portable host-tool supervision ended without complete state".to_owned()),
        };

        if result.is_ok() && Instant::now() >= deadline {
            result = Err(
                "portable host tool exceeded its deadline during final output validation"
                    .to_owned(),
            );
        }

        if let Err(cleanup_error) = workspace.cleanup() {
            result = Err(match result {
                Ok(_) => cleanup_error,
                Err(error) => format!("{error}; {cleanup_error}"),
            });
        }
        if result.is_ok() {
            output_cleanup.disarm();
        }
        result
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn contract() -> PortableHostToolContract {
        PortableHostToolContract {
            compatibility_digest: "sha256-fixture".to_owned(),
            environment: vec![("REVIEWED_MARKER".to_owned(), "present".to_owned())],
            timeout_ms: 1_000,
            max_stdout_bytes: 4_096,
            max_stderr_bytes: 4_096,
            max_output_bytes: 128,
        }
    }

    fn runner(temporary: &TempDir, contract: PortableHostToolContract) -> PortableHostToolRunner {
        runner_with_tool(temporary, contract, PathBuf::from("/bin/sh"))
    }

    fn runner_with_tool(
        temporary: &TempDir,
        contract: PortableHostToolContract,
        tool_path: PathBuf,
    ) -> PortableHostToolRunner {
        PortableHostToolRunner::new(tool_path, contract, temporary.path().join("workspaces"))
    }

    fn shell_args(script: &str, extra: &[&Path]) -> Vec<OsString> {
        let mut args = vec![OsString::from("-c"), OsString::from(script)];
        args.extend(extra.iter().map(|path| path.as_os_str().to_owned()));
        args
    }

    #[test]
    #[ignore]
    fn child_environment_probe() {
        if std::env::var("IBEX_PORTABLE_RUNNER_CHILD").as_deref() != Ok("1") {
            return;
        }
        let mut stdin = String::new();
        std::io::stdin().read_to_string(&mut stdin).unwrap();
        println!(
            "PROBE_ARGV0={}",
            std::env::args_os().next().unwrap().to_string_lossy()
        );
        println!("PROBE_HOME={}", std::env::var_os("HOME").is_some());
        println!("PROBE_PATH={}", std::env::var_os("PATH").is_some());
        println!(
            "PROBE_MARKER={}",
            std::env::var("REVIEWED_MARKER").unwrap_or_else(|_| "unset".to_owned())
        );
        let mut environment_keys = std::env::vars_os()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        environment_keys.sort();
        println!("PROBE_ENV_KEYS={}", environment_keys.join(","));
        println!("PROBE_CWD={}", std::env::current_dir().unwrap().display());
        println!("PROBE_STDIN_BYTES={}", stdin.len());
    }

    #[test]
    fn clears_ambient_environment_uses_empty_stdin_exact_argv0_and_fresh_cwd() {
        let temporary = TempDir::new().unwrap();
        let ambient_cwd = std::env::current_dir().unwrap();
        let tool_path = std::env::current_exe().unwrap();
        let mut exact_contract = contract();
        exact_contract
            .environment
            .insert(0, ("IBEX_PORTABLE_RUNNER_CHILD".to_owned(), "1".to_owned()));
        let runner = runner_with_tool(&temporary, exact_contract, tool_path.clone());
        let output = runner
            .run(
                &[
                    OsString::from("--exact"),
                    OsString::from("portable_host_tool_runner::tests::child_environment_probe"),
                    OsString::from("--ignored"),
                    OsString::from("--nocapture"),
                ],
                &[],
            )
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(&format!("PROBE_ARGV0={}\n", tool_path.display())));
        assert!(stdout.contains("PROBE_HOME=false\n"));
        assert!(stdout.contains("PROBE_PATH=false\n"));
        assert!(stdout.contains("PROBE_MARKER=present\n"));
        assert!(stdout.contains("PROBE_ENV_KEYS=IBEX_PORTABLE_RUNNER_CHILD,REVIEWED_MARKER\n"));
        assert!(stdout.contains("PROBE_STDIN_BYTES=0\n"));
        let cwd = stdout
            .lines()
            .find_map(|line| line.strip_prefix("PROBE_CWD="))
            .unwrap();
        assert_ne!(Path::new(cwd), ambient_cwd);
        assert!(Path::new(cwd).starts_with(fs::canonicalize(temporary.path()).unwrap()));
        assert!(output.stderr.is_empty());
        assert_eq!(
            fs::read_dir(temporary.path().join("workspaces"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn refuses_failure_timeout_and_stream_oversize_and_cleans_workspaces() {
        let temporary = TempDir::new().unwrap();
        let base = contract();
        let error = runner(&temporary, base.clone())
            .run(&shell_args("exit 7", &[]), &[])
            .unwrap_err();
        assert!(error.contains("exited with"));

        let mut timeout = base.clone();
        timeout.timeout_ms = 25;
        let error = runner(&temporary, timeout)
            .run(&shell_args("while :; do :; done", &[]), &[])
            .unwrap_err();
        assert!(error.contains("exceeded 25 ms"));

        let mut oversize = base;
        oversize.max_stdout_bytes = 16;
        let error = runner(&temporary, oversize)
            .run(
                &shell_args("printf '0123456789012345678901234567890123456789'", &[]),
                &[],
            )
            .unwrap_err();
        assert!(error.contains("stdout exceeded 16 bytes"));

        let mut stderr_oversize = contract();
        stderr_oversize.max_stderr_bytes = 16;
        let error = runner(&temporary, stderr_oversize)
            .run(
                &shell_args("printf '0123456789012345678901234567890123456789' >&2", &[]),
                &[],
            )
            .unwrap_err();
        assert!(error.contains("stderr exceeded 16 bytes"));
        assert_eq!(
            fs::read_dir(temporary.path().join("workspaces"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn refuses_oversize_declared_outputs_and_removes_them() {
        let temporary = TempDir::new().unwrap();
        let exact_path = temporary.path().join("exact-bound.hbc");
        let mut bounded = contract();
        bounded.max_output_bytes = 4;
        runner(&temporary, bounded.clone())
            .run(
                &shell_args("printf '1234' > \"$0\"", &[&exact_path]),
                std::slice::from_ref(&exact_path),
            )
            .unwrap();
        assert_eq!(fs::read(&exact_path).unwrap(), b"1234");
        fs::remove_file(&exact_path).unwrap();

        let output_path = temporary.path().join("over-bound.hbc");
        let error = runner(&temporary, bounded)
            .run(
                &shell_args("printf '12345' > \"$0\"", &[&output_path]),
                std::slice::from_ref(&output_path),
            )
            .unwrap_err();
        assert!(error.contains("outputs exceeded 4 bytes"));
        assert!(!output_path.exists());
        assert_eq!(
            fs::read_dir(temporary.path().join("workspaces"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn kills_inherited_pipe_descendant_after_direct_child_exit() {
        let temporary = TempDir::new().unwrap();
        let mut bounded = contract();
        bounded.timeout_ms = 500;
        let started = Instant::now();
        let error = runner(&temporary, bounded)
            .run(
                &shell_args(
                    "(trap '' TERM; while :; do sleep 1; done) & printf parent-exited",
                    &[],
                ),
                &[],
            )
            .unwrap_err();
        assert!(error.contains("left live descendants"));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "an inherited descendant pipe held the runner to its deadline"
        );
        assert_eq!(
            fs::read_dir(temporary.path().join("workspaces"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn kills_delayed_descendant_before_pinning_declared_output() {
        let temporary = TempDir::new().unwrap();
        let output_path = temporary.path().join("stable.hbc");
        let marker_path = temporary.path().join("late-marker");
        let args = shell_args(
            "printf stable > \"$0\"; (trap '' TERM; sleep 0.10; printf mutated > \"$0\"; printf late > \"$1\") &",
            &[&output_path, &marker_path],
        );
        let error = runner(&temporary, contract())
            .run(&args, std::slice::from_ref(&output_path))
            .unwrap_err();
        assert!(error.contains("left live descendants"));
        assert!(!output_path.exists());
        thread::sleep(Duration::from_millis(175));
        assert!(!output_path.exists());
        assert!(!marker_path.exists());
    }
}
