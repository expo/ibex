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
use std::fs;
use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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

struct ReapedChild(Child);

impl Deref for ReapedChild {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ReapedChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ReapedChild {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
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
    failed: mpsc::Sender<String>,
) -> Result<Vec<u8>, String> {
    let result = (|| {
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
    })();
    if let Err(error) = &result {
        let _ = failed.send(error.clone());
    }
    result
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

fn validate_outputs(paths: &[PathBuf], maximum: u64) -> Result<(), String> {
    let mut output_size = 0u64;
    for path in paths {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            format!(
                "inspect portable host-tool output {}: {error}",
                path.display()
            )
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "portable host-tool output {} is redirected or not regular",
                path.display()
            ));
        }
        output_size = output_size
            .checked_add(metadata.len())
            .ok_or_else(|| "portable host-tool output size overflow".to_owned())?;
    }
    if output_size > maximum {
        Err(format!(
            "portable host-tool outputs exceeded {maximum} bytes"
        ))
    } else {
        Ok(())
    }
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
        }
        command
            .args(args)
            .env_clear()
            .envs(self.contract.environment.iter().cloned())
            .current_dir(&workspace.path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = ReapedChild(command.spawn().map_err(|error| {
            format!(
                "spawn portable host tool {}: {error}",
                self.tool_path.display()
            )
        })?);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "portable host tool has no captured stdout".to_owned())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "portable host tool has no captured stderr".to_owned())?;
        let (exceeded_sender, exceeded_receiver) = mpsc::channel();
        let stdout_sender = exceeded_sender.clone();
        let max_stdout = self.contract.max_stdout_bytes;
        let stdout_thread =
            thread::spawn(move || read_bounded(stdout, max_stdout, "stdout", stdout_sender));
        let max_stderr = self.contract.max_stderr_bytes;
        let stderr_thread =
            thread::spawn(move || read_bounded(stderr, max_stderr, "stderr", exceeded_sender));

        let started = Instant::now();
        let timeout = Duration::from_millis(self.contract.timeout_ms);
        let mut forced_error = None;
        let status = loop {
            if let Ok(error) = exceeded_receiver.try_recv() {
                forced_error = Some(error);
                let _ = child.kill();
                break child.wait().map_err(|wait_error| {
                    format!("wait after portable host-tool output refusal: {wait_error}")
                });
            }
            if started.elapsed() >= timeout {
                forced_error = Some(format!(
                    "portable host tool exceeded {} ms",
                    self.contract.timeout_ms
                ));
                let _ = child.kill();
                break child.wait().map_err(|wait_error| {
                    format!("wait after portable host-tool timeout: {wait_error}")
                });
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {}
                Err(error) => {
                    forced_error = Some(format!("poll portable host tool: {error}"));
                    let _ = child.kill();
                    break child.wait().map_err(|wait_error| {
                        format!("wait after portable host-tool poll failure: {wait_error}")
                    });
                }
            }
            thread::sleep(Duration::from_millis(2));
        };

        let stdout = stdout_thread
            .join()
            .map_err(|_| "portable host-tool stdout reader panicked".to_owned())
            .and_then(|result| result);
        let stderr = stderr_thread
            .join()
            .map_err(|_| "portable host-tool stderr reader panicked".to_owned())
            .and_then(|result| result);

        let mut result = match (forced_error, status, stdout, stderr) {
            (Some(error), _, _, _) => Err(error),
            (None, Err(error), _, _) => Err(error),
            (None, Ok(_), Err(error), _) | (None, Ok(_), _, Err(error)) => Err(error),
            (None, Ok(status), Ok(stdout), Ok(stderr)) if !status.success() => Err(format!(
                "portable host tool exited with {status}: {}",
                String::from_utf8_lossy(&stderr)
            )),
            (None, Ok(_), Ok(stdout), Ok(stderr)) => {
                validate_outputs(output_files, self.contract.max_output_bytes)
                    .map(|()| PortableHostToolOutput { stdout, stderr })
            }
        };

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
}
