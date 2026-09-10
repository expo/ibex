//! Native subprocesses for Rust consumers; no engine, executor, shell parser,
//! output collector, or event queue. Put blocking operations on caller workers.
//! @ref LLP 0068#21-native-processes-and-ptys — Fleet's host-authorized process capability

use crate::boundary::{admit, HostError};
use crate::grant::{GrantSet, Operation};
use crate::stdlib::abort::AbortSignal;
use std::collections::BTreeMap;
use std::sync::Arc;

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[path = "process_unix.rs"]
mod platform;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[path = "process_unsupported.rs"]
mod platform;
pub use platform::{Input, Output, Process, Pty};

/// All launch inputs are explicit. `executable` and `cwd` must be absolute
/// native paths. Arguments are literal, and the child inherits no environment
/// variables: `env` replaces the environment. Nothing searches the host PATH.
/// A granted interpreter can of course interpret the arguments it receives.
#[derive(Clone, Debug)]
pub struct Command {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
}

/// Character-cell dimensions. Zero in either dimension is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
}
impl PtySize {
    pub(crate) fn validate(self) -> Result<(), HostError> {
        if self.rows == 0 || self.cols == 0 {
            return Err(HostError::InvalidArgument(
                "PTY rows and cols must be nonzero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitStatus {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}
impl ExitStatus {
    pub fn success(self) -> bool {
        self.code == Some(0)
    }
}

/// A binding carrying the endowing host's authority. Only Host constructs it.
/// Granting an executable permits arbitrary argv/cwd/env for that executable,
/// with the host's OS privileges. It does not restrict the child's own effects.
#[derive(Clone)]
pub struct Processes {
    grants: Arc<GrantSet>,
    enabled: bool,
}
impl Processes {
    pub(crate) fn new(grants: Arc<GrantSet>, enabled: bool) -> Self {
        Self { grants, enabled }
    }

    pub(crate) fn check(
        &self,
        command: &Command,
        pty: bool,
        signal: &AbortSignal,
    ) -> Result<(), HostError> {
        let operation = if pty {
            Operation::ProcessPty {
                executable: command.executable.clone(),
            }
        } else {
            Operation::ProcessSpawn {
                executable: command.executable.clone(),
            }
        };
        admit(&self.grants, &operation)?;
        if !self.enabled {
            return Err(HostError::Denied {
                capability: if pty { "process.pty" } else { "process.spawn" },
            });
        }
        if !valid_executable(&command.executable)
            || !(command.cwd == "/" || valid_executable(&command.cwd))
            || command.args.iter().any(|v| v.contains('\0'))
            || command
                .env
                .iter()
                .any(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0'))
        {
            return Err(HostError::InvalidArgument("process requires absolute paths and NUL-free argv/env with nonempty env names without '='".into()));
        }
        signal.check()
    }

    /// Three OS pipes, with demand-driven Read/Write and kernel backpressure.
    /// Drop stdin to send EOF; drain stdout and stderr concurrently when needed.
    /// Waiting does not drain output, and can block behind a full pipe.
    pub fn spawn(&self, command: Command, signal: &AbortSignal) -> Result<Process, HostError> {
        self.check(&command, false, signal)?;
        platform::spawn(command, signal)
    }

    /// A new session with a controlling terminal, initially in raw mode.
    /// stdout/stderr are merged; input and output preserve bytes, including NUL
    /// and invalid UTF-8. The child may subsequently change its terminal mode.
    pub fn pty(
        &self,
        command: Command,
        size: PtySize,
        signal: &AbortSignal,
    ) -> Result<Pty, HostError> {
        self.check(&command, true, signal)?;
        size.validate()?;
        platform::pty(command, size, signal)
    }
}

pub(crate) fn valid_executable(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains('\0')
        && !path.split('/').any(|p| p == "." || p == "..")
        && path.split('/').any(|p| !p.is_empty())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn failed(error: std::io::Error) -> HostError {
    HostError::Failed(format!("process: {error}"))
}
