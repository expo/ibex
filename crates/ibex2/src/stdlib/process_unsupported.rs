//! Keep the Rust surface present and refusing on targets without this backend.
use super::{Command, ExitStatus, HostError, PtySize};
use crate::stdlib::abort::AbortSignal;
use std::io::{self, Read, Write};

fn unavailable() -> HostError {
    HostError::Failed("native processes require macOS or Linux".into())
}
pub struct Input;
pub struct Output;
impl Write for Input {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
impl Read for Output {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
pub struct Process {
    pub stdin: Option<Input>,
    pub stdout: Option<Output>,
    pub stderr: Option<Output>,
}
pub struct Pty {
    pub input: Option<Input>,
    pub output: Option<Output>,
}
macro_rules! methods {
    ($ty:ty) => {
        impl $ty {
            pub fn id(&self) -> u32 {
                0
            }
            pub fn wait(&self) -> Result<ExitStatus, HostError> {
                Err(unavailable())
            }
            pub fn try_wait(&self) -> Result<Option<ExitStatus>, HostError> {
                Err(unavailable())
            }
            pub fn cancel(&self) -> Result<ExitStatus, HostError> {
                Err(unavailable())
            }
        }
    };
}
methods!(Process);
methods!(Pty);
impl Pty {
    pub fn resize(&self, _: PtySize) -> Result<(), HostError> {
        Err(unavailable())
    }
    pub fn close(&mut self) -> Result<ExitStatus, HostError> {
        Err(unavailable())
    }
}
pub(super) fn spawn(_: Command, _: &AbortSignal) -> Result<Process, HostError> {
    Err(unavailable())
}
pub(super) fn pty(_: Command, _: PtySize, _: &AbortSignal) -> Result<Pty, HostError> {
    Err(unavailable())
}
