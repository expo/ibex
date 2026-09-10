//! POSIX transport. Ownership and cancellation stay here, outside any executor.
//! @ref LLP 0068#21-native-processes-and-ptys — bounded I/O and group lifetime

use super::{failed, Command, ExitStatus, PtySize};
use crate::boundary::HostError;
use crate::stdlib::abort::{AbortRegistration, AbortSignal};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};
use std::time::Duration;

type IoFile = Arc<Mutex<Option<File>>>;

struct Stop {
    cancelled: AtomicBool,
    reader: RwLock<Option<UnixStream>>,
    writer: Mutex<Option<UnixStream>>,
    files: Mutex<Vec<Weak<Mutex<Option<File>>>>>,
}
impl Stop {
    fn new() -> io::Result<Arc<Self>> {
        let (reader, writer) = UnixStream::pair()?;
        Ok(Arc::new(Self {
            cancelled: AtomicBool::new(false),
            reader: RwLock::new(Some(reader)),
            writer: Mutex::new(Some(writer)),
            files: Mutex::new(Vec::new()),
        }))
    }
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // Readable EOF wakes every poll without any queued notifications.
        if let Some(writer) = self.writer.lock().unwrap().as_ref() {
            let _ = writer.shutdown(Shutdown::Both);
        }
    }
    fn own(&self, file: File) -> IoFile {
        let file = Arc::new(Mutex::new(Some(file)));
        self.files.lock().unwrap().push(Arc::downgrade(&file));
        file
    }
    fn close_files(&self) {
        // At most three data descriptors per child. Weak references preserve
        // stdin EOF on drop. Cancellation has already woken blocked polls;
        // locking each file prevents close/reuse racing an in-flight syscall.
        for file in self.files.lock().unwrap().iter().filter_map(Weak::upgrade) {
            file.lock().unwrap().take();
        }
        // Retained inert streams keep only cancelled state. The reader guard
        // prevents closing/reusing a wake FD while any poll still holds it.
        self.reader.write().unwrap().take();
        self.writer.lock().unwrap().take();
    }
    fn check(&self) -> io::Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "process I/O cancelled",
            ))
        } else {
            Ok(())
        }
    }
    fn ready(&self, fd: RawFd, events: i16) -> io::Result<()> {
        let reader = self.reader.read().unwrap();
        self.check()?;
        let reader = reader.as_ref().ok_or(io::ErrorKind::ConnectionAborted)?;
        loop {
            self.check()?;
            let mut fds = [
                libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                },
                libc::pollfd {
                    fd: reader.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) };
            self.check()?;
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if fds[0].revents != 0 {
                return Ok(());
            }
        }
    }
}

/// A single byte writer. No buffering: OS capacity applies backpressure.
/// Dropping a pipe writer sends EOF; a PTY has no independent input half-close.
pub struct Input {
    file: IoFile,
    stop: Arc<Stop>,
}
impl Write for Input {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let file = self.file.lock().unwrap();
        self.stop.check()?;
        let file = file.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        loop {
            self.stop.ready(file.as_raw_fd(), libc::POLLOUT)?;
            match write_without_sigpipe(file.as_raw_fd(), bytes) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue
                }
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stop.check()
    }
}

/// A demand-driven byte reader. No worker drains it in the background.
pub struct Output {
    file: IoFile,
    stop: Arc<Stop>,
    pty: bool,
}
impl Read for Output {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut file = self.file.lock().unwrap();
        self.stop.check()?;
        let file = file.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        loop {
            self.stop.ready(file.as_raw_fd(), libc::POLLIN)?;
            match file.read(bytes) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue
                }
                // Linux PTY masters report slave closure as EIO; Darwin uses EOF.
                Err(e) if self.pty && e.raw_os_error() == Some(libc::EIO) => return Ok(0),
                result => return result,
            }
        }
    }
}

struct State {
    child: Child,
    result: Option<Result<ExitStatus, HostError>>,
}
struct Control {
    pid: u32,
    state: Mutex<State>,
    wake: Condvar,
    stop: Arc<Stop>,
}
impl Control {
    fn finish(&self, state: &mut State) -> Result<ExitStatus, HostError> {
        if let Some(result) = &state.result {
            return result.clone();
        }
        // The child is still unreaped, so its PID (and our PGID) cannot be
        // reused. Finish the owned group BEFORE reaping the leader, including
        // when that leader exited normally but left background children.
        let result = unsafe { libc::kill(-(self.pid as i32), libc::SIGKILL) };
        if result < 0 {
            let error = io::Error::last_os_error();
            // Darwin returns EPERM for a group consisting solely of zombies.
            // Still reap that waitable leader. A running child is different:
            // report loss of signalling permission instead of blocking wait.
            if error.raw_os_error() != Some(libc::ESRCH)
                && !(error.raw_os_error() == Some(libc::EPERM)
                    && exited(self.pid).map_err(failed)?)
            {
                return Err(failed(error));
            }
        }
        // Also address the recorded child if it deliberately changed groups.
        let _ = state.child.kill();
        let result = state
            .child
            .wait()
            .map(|s| ExitStatus {
                code: s.code(),
                signal: s.signal(),
            })
            .map_err(failed);
        state.result = Some(result.clone());
        self.wake.notify_all();
        result
    }
    fn cancel(&self) -> Result<ExitStatus, HostError> {
        self.stop.cancel();
        let mut state = self.state.lock().unwrap();
        // A host must not reap Ibex children itself (or use SIGCHLD=SIG_IGN).
        // Detect lost ownership before sending any numeric PID/PGID signal.
        if state.result.is_none() {
            if let Err(error) = exited(self.pid) {
                state.result = Some(Err(failed(error)));
            }
        }
        let result = self.finish(&mut state);
        self.stop.close_files();
        result
    }
    fn try_wait(&self) -> Result<Option<ExitStatus>, HostError> {
        let mut state = self.state.lock().unwrap();
        if let Some(result) = &state.result {
            return result.clone().map(Some);
        }
        match exited(self.pid) {
            Ok(false) => Ok(None),
            Ok(true) => self.finish(&mut state).map(Some),
            Err(error) => {
                let error = failed(error);
                state.result = Some(Err(error.clone()));
                Err(error)
            }
        }
    }
    fn wait(&self) -> Result<ExitStatus, HostError> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            let state = self.state.lock().unwrap();
            if let Some(result) = &state.result {
                return result.clone();
            }
            // No executor/reaper thread and no process-wide SIGCHLD handler.
            // Cancellation notifies immediately; ordinary exits poll at 10ms.
            drop(
                self.wake
                    .wait_timeout(state, Duration::from_millis(10))
                    .unwrap(),
            );
        }
    }
}

fn exited(pid: u32) -> io::Result<bool> {
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as _,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(unsafe { info.si_pid() } != 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

struct Owner {
    control: Arc<Control>,
    _registration: AbortRegistration,
}
impl Owner {
    fn new(child: Child, stop: Arc<Stop>, signal: &AbortSignal) -> Self {
        let control = Arc::new(Control {
            pid: child.id(),
            state: Mutex::new(State {
                child,
                result: None,
            }),
            wake: Condvar::new(),
            stop,
        });
        let weak = Arc::downgrade(&control);
        let registration = signal.register(move || {
            if let Some(control) = weak.upgrade() {
                let _ = control.cancel();
            }
        });
        Self {
            control,
            _registration: registration,
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.control.cancel();
    }
}

/// Owns a process group. Drop/cancel kills the group and reaps the direct
/// child, even if streams were taken. Completed status is cached. Call wait
/// or try_wait to reap a normal exit; no background executor is installed.
pub struct Process {
    owner: Owner,
    pub stdin: Option<Input>,
    pub stdout: Option<Output>,
    pub stderr: Option<Output>,
}
impl Process {
    pub fn id(&self) -> u32 {
        self.owner.control.pid
    }
    pub fn wait(&self) -> Result<ExitStatus, HostError> {
        self.owner.control.wait()
    }
    pub fn try_wait(&self) -> Result<Option<ExitStatus>, HostError> {
        self.owner.control.try_wait()
    }
    pub fn cancel(&self) -> Result<ExitStatus, HostError> {
        self.owner.control.cancel()
    }
}

/// A controlling PTY and its process group. Input/output can move to separate
/// caller workers. Close/drop invalidates retained streams and reaps the child.
pub struct Pty {
    owner: Owner,
    master: IoFile,
    pub input: Option<Input>,
    pub output: Option<Output>,
}
impl Pty {
    pub fn id(&self) -> u32 {
        self.owner.control.pid
    }
    pub fn wait(&self) -> Result<ExitStatus, HostError> {
        self.owner.control.wait()
    }
    pub fn try_wait(&self) -> Result<Option<ExitStatus>, HostError> {
        self.owner.control.try_wait()
    }
    pub fn cancel(&self) -> Result<ExitStatus, HostError> {
        self.owner.control.cancel()
    }
    pub fn resize(&self, size: PtySize) -> Result<(), HostError> {
        size.validate()?;
        self.owner.control.stop.check().map_err(failed)?;
        let master = self.master.lock().unwrap();
        let file = master
            .as_ref()
            .ok_or_else(|| HostError::Failed("PTY is closed".into()))?;
        let window = winsize(size);
        cvt(unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCSWINSZ, &window) }).map_err(failed)?;
        Ok(())
    }
    pub fn close(&mut self) -> Result<ExitStatus, HostError> {
        let result = self.cancel();
        self.input.take();
        self.output.take();
        result
    }
}

fn base(command: Command) -> std::process::Command {
    let mut child = std::process::Command::new(command.executable);
    child
        .args(command.args)
        .current_dir(command.cwd)
        .env_clear()
        .envs(command.env);
    child
}

pub(super) fn spawn(command: Command, signal: &AbortSignal) -> Result<Process, HostError> {
    let stop = Stop::new().map_err(failed)?;
    signal.check()?;
    let mut child = base(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(failed)?;
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    // Install cleanup before the first fallible descriptor setup.
    let owner = Owner::new(child, stop.clone(), signal);
    let stdin =
        stop.own(nonblocking(unsafe { File::from_raw_fd(stdin.into_raw_fd()) }).map_err(failed)?);
    let stdout =
        stop.own(nonblocking(unsafe { File::from_raw_fd(stdout.into_raw_fd()) }).map_err(failed)?);
    let stderr =
        stop.own(nonblocking(unsafe { File::from_raw_fd(stderr.into_raw_fd()) }).map_err(failed)?);
    signal.check()?;
    Ok(Process {
        owner,
        stdin: Some(Input {
            file: stdin,
            stop: stop.clone(),
        }),
        stdout: Some(Output {
            file: stdout,
            stop: stop.clone(),
            pty: false,
        }),
        stderr: Some(Output {
            file: stderr,
            stop,
            pty: false,
        }),
    })
}

pub(super) fn pty(command: Command, size: PtySize, signal: &AbortSignal) -> Result<Pty, HostError> {
    let stop = Stop::new().map_err(failed)?;
    let (master, slave) = open_pty(size).map_err(failed)?;
    let input = master.try_clone().map_err(failed)?;
    let output = master.try_clone().map_err(failed)?;
    let mut child = base(command);
    child
        .stdin(Stdio::from(slave.try_clone().map_err(failed)?))
        .stdout(Stdio::from(slave.try_clone().map_err(failed)?))
        .stderr(Stdio::from(slave));
    // Only async-signal-safe OS operations after fork. Rust's Command owns
    // argv/env, dup2, exec error reporting, and failed-spawn reaping.
    unsafe {
        child.pre_exec(|| {
            cvt(libc::setsid())?;
            cvt(libc::ioctl(0, libc::TIOCSCTTY as _, 0))?;
            Ok(())
        });
    }
    signal.check()?;
    let spawned = child.spawn().map_err(failed)?;
    drop(child); // Release the builder's retained slave copies before reading EOF.
    let master = stop.own(master);
    let input = stop.own(input);
    let output = stop.own(output);
    let owner = Owner::new(spawned, stop.clone(), signal);
    signal.check()?;
    Ok(Pty {
        owner,
        master,
        input: Some(Input {
            file: input,
            stop: stop.clone(),
        }),
        output: Some(Output {
            file: output,
            stop,
            pty: true,
        }),
    })
}

fn winsize(size: PtySize) -> libc::winsize {
    libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}
fn open_pty(size: PtySize) -> io::Result<(File, File)> {
    // openpty followed by F_SETFD has an inheritance race with concurrent
    // spawns. Allocate each descriptor atomically close-on-exec instead, using
    // the OS's POSIX PTY functions and its reentrant slave-name lookup.
    let master =
        cvt(unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) })?;
    let master = unsafe { File::from_raw_fd(master) };
    cvt(unsafe { libc::grantpt(master.as_raw_fd()) })?;
    cvt(unsafe { libc::unlockpt(master.as_raw_fd()) })?;
    let mut name = [0u8; 128];
    #[cfg(target_os = "macos")]
    cvt(unsafe {
        libc::ioctl(
            master.as_raw_fd(),
            libc::TIOCPTYGNAME as _,
            name.as_mut_ptr(),
        )
    })?;
    #[cfg(target_os = "linux")]
    {
        let result =
            unsafe { libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr().cast(), name.len()) };
        if result != 0 {
            return Err(if result < 0 {
                io::Error::last_os_error()
            } else {
                io::Error::from_raw_os_error(result)
            });
        }
    }
    let name = std::ffi::CStr::from_bytes_until_nul(&name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "unterminated PTY name"))?;
    let slave = cvt(unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    })?;
    let slave = unsafe { File::from_raw_fd(slave) };
    let window = winsize(size);
    cvt(unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, &window) })?;
    let mut attributes = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut attributes) })?;
    unsafe {
        libc::cfmakeraw(&mut attributes);
    }
    cvt(unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &attributes) })?;
    Ok((nonblocking(master)?, slave))
}
fn nonblocking(file: File) -> io::Result<File> {
    let flags = cvt(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) })?;
    cvt(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
    Ok(file)
}
fn cvt(value: i32) -> io::Result<i32> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

// A library must not depend on Rust main() having ignored SIGPIPE, or install
// a process-wide handler. Block it on this thread for the nonblocking write,
// consume only a newly generated pending signal, then restore the caller mask.
fn write_without_sigpipe(fd: RawFd, bytes: &[u8]) -> io::Result<usize> {
    unsafe {
        let mut mask = std::mem::zeroed();
        let mut old = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGPIPE);
        let result = libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut old);
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        let mut pending = std::mem::zeroed();
        libc::sigpending(&mut pending);
        let already_pending = libc::sigismember(&pending, libc::SIGPIPE) == 1;
        let written = libc::write(
            fd,
            bytes.as_ptr().cast(),
            bytes.len().min(isize::MAX as usize),
        );
        let result = if written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(written as usize)
        };
        if result
            .as_ref()
            .is_err_and(|e| e.raw_os_error() == Some(libc::EPIPE))
            && !already_pending
        {
            libc::sigpending(&mut pending);
            if libc::sigismember(&pending, libc::SIGPIPE) == 1 {
                let mut signal = 0;
                libc::sigwait(&mask, &mut signal);
            }
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pty_allocation_is_close_on_exec() {
        let (master, slave) = open_pty(PtySize { rows: 24, cols: 80 }).unwrap();
        for file in [master, slave] {
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0);
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
    }

    #[test]
    fn pty_close_releases_fds_while_taken_stream_handles_remain() {
        let mut terminal = pty(
            Command {
                executable: "/bin/cat".into(),
                args: vec![],
                cwd: "/".into(),
                env: Default::default(),
            },
            PtySize { rows: 24, cols: 80 },
            &AbortSignal::default(),
        )
        .unwrap();
        let input = terminal.input.take().unwrap();
        let output = terminal.output.take().unwrap();
        assert!(input.file.lock().unwrap().is_some());
        assert!(output.file.lock().unwrap().is_some());
        terminal.close().unwrap();
        assert!(input.file.lock().unwrap().is_none());
        assert!(output.file.lock().unwrap().is_none());
        assert!(terminal.master.lock().unwrap().is_none());
        assert!(input.stop.reader.read().unwrap().is_none());
        assert!(output.stop.writer.lock().unwrap().is_none());
    }

    #[test]
    fn pipe_cancel_releases_wake_pair_after_blocked_io_with_retained_streams() {
        let mut child = spawn(
            Command {
                executable: "/bin/sleep".into(),
                args: vec!["30".into()],
                cwd: "/".into(),
                env: Default::default(),
            },
            &AbortSignal::default(),
        )
        .unwrap();
        let input = child.stdin.take().unwrap();
        let mut output = child.stdout.take().unwrap();
        let stop = output.stop.clone();
        let reader = std::thread::spawn(move || {
            assert!(output.read(&mut [0; 1]).is_err());
            output
        });
        child.cancel().unwrap();
        let output = reader.join().unwrap();
        assert!(stop.reader.read().unwrap().is_none());
        assert!(stop.writer.lock().unwrap().is_none());
        assert!(input.file.lock().unwrap().is_none());
        assert!(output.file.lock().unwrap().is_none());
    }
}
