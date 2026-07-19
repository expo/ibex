//! Engine-independent SIGINT ownership for in-process, editorless execution.
//!
//! The signal handler does no engine, broker, allocator, or lock work. It
//! claims the interrupt cause atomically and wakes a dedicated ordinary
//! thread. That thread may request id-exact Hermes cancellation as a courtesy,
//! but termination never depends on the engine returning: the adapter-owned
//! cleanup callback restores descriptors, closes the broker under its bound,
//! and the process exits 130.
//!
//! @ref LLP 0025#1-modes-descriptors-and-topology — one interrupt terminates
//! editorless direct execution without waiting on the engine.
//! @ref LLP 0025#5-terminal-presentation-and-restoration — the handler-only
//! fallback performs only async-signal-safe descriptor restoration and exit.

use crate::engine::{AuthenticatedCancellationStatus, Engine};
use std::io;
use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;

const STATE_INACTIVE: u8 = 0;
const STATE_ACTIVE: u8 = 1;
const STATE_INTERRUPTED: u8 = 2;
const STATE_FINALIZING: u8 = 3;

const WAKE_INTERRUPT: u8 = 1 << 0;
const WAKE_SHUTDOWN: u8 = 1 << 1;

static INSTALL_LOCK: Mutex<()> = Mutex::new(());
static STATE: AtomicU8 = AtomicU8::new(STATE_INACTIVE);
static PENDING: AtomicU8 = AtomicU8::new(0);
static WRITE_FD: AtomicI32 = AtomicI32::new(-1);
static RESTORE_STDOUT_FD: AtomicI32 = AtomicI32::new(-1);
static RESTORE_STDERR_FD: AtomicI32 = AtomicI32::new(-1);

#[cfg(test)]
static TEST_PAUSE_HANDLER_BEFORE_CLAIM: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static TEST_HANDLER_ENTERED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[derive(Clone, Default)]
pub(crate) struct DirectExecutionCancellationRegistration {
    engine: Arc<OnceLock<Arc<dyn Engine>>>,
}

impl DirectExecutionCancellationRegistration {
    pub(crate) fn register(&self, engine: Arc<dyn Engine>) -> Result<(), Arc<dyn Engine>> {
        self.engine.set(engine)
    }

    fn request_exact_if_executing(&self) -> Option<AuthenticatedCancellationStatus> {
        let engine = self.engine.get()?;
        if !engine.authenticated_cancellation_available() {
            return Some(AuthenticatedCancellationStatus::Unavailable);
        }
        let target = engine.active_authenticated_target()?;
        Some(engine.cancel_authenticated_target(target))
    }
}

struct NativeFd(i32);

impl NativeFd {
    fn pipe() -> io::Result<(Self, Self)> {
        let mut descriptors = [-1; 2];
        // SAFETY: pipe initializes both elements on success.
        if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let reader = Self(descriptors[0]);
        let writer = Self(descriptors[1]);
        set_descriptor_flag(reader.0, libc::F_SETFD, libc::FD_CLOEXEC)?;
        set_descriptor_flag(writer.0, libc::F_SETFD, libc::FD_CLOEXEC)?;
        let flags = descriptor_flag(writer.0, libc::F_GETFL)?;
        set_descriptor_flag(writer.0, libc::F_SETFL, flags | libc::O_NONBLOCK)?;
        Ok((reader, writer))
    }

    fn duplicate(descriptor: i32) -> io::Result<Self> {
        loop {
            // SAFETY: fcntl receives a live descriptor and returns a fresh
            // CLOEXEC descriptor owned by this value on success.
            let duplicated = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicated >= 0 {
                return Ok(Self(duplicated));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    const fn raw(&self) -> i32 {
        self.0
    }

    fn close(&mut self) {
        if self.0 < 0 {
            return;
        }
        // SAFETY: this value uniquely owns the descriptor. Mark it closed so
        // Drop cannot close a subsequently reused descriptor number.
        unsafe {
            libc::close(self.0);
        }
        self.0 = -1;
    }
}

impl Drop for NativeFd {
    fn drop(&mut self) {
        self.close();
    }
}

fn descriptor_flag(descriptor: i32, operation: i32) -> io::Result<i32> {
    loop {
        // SAFETY: fcntl performs a descriptor query.
        let result = unsafe { libc::fcntl(descriptor, operation) };
        if result >= 0 {
            return Ok(result);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn set_descriptor_flag(descriptor: i32, operation: i32, value: i32) -> io::Result<()> {
    loop {
        // SAFETY: fcntl updates flags on one live descriptor.
        let result = unsafe { libc::fcntl(descriptor, operation, value) };
        if result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

unsafe fn handler_only_restore_and_exit() -> ! {
    let stdout = RESTORE_STDOUT_FD.load(Ordering::Acquire);
    let stderr = RESTORE_STDERR_FD.load(Ordering::Acquire);
    if stdout >= 0 {
        // SAFETY: install publishes a retained duplicate before the handler.
        unsafe {
            libc::dup2(stdout, libc::STDOUT_FILENO);
        }
    }
    if stderr >= 0 {
        // SAFETY: install publishes a retained duplicate before the handler.
        unsafe {
            libc::dup2(stderr, libc::STDERR_FILENO);
        }
    }
    // SAFETY: _exit is async-signal-safe and runs no destructors.
    unsafe { libc::_exit(128 + libc::SIGINT) }
}

unsafe extern "C" fn direct_execution_sigint_handler(_: libc::c_int) {
    #[cfg(test)]
    if TEST_PAUSE_HANDLER_BEFORE_CLAIM.load(Ordering::Acquire) {
        TEST_HANDLER_ENTERED.store(true, Ordering::Release);
        while TEST_PAUSE_HANDLER_BEFORE_CLAIM.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
    }

    match STATE.compare_exchange(
        STATE_ACTIVE,
        STATE_INTERRUPTED,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {}
        // The ordinary cleanup thread already owns the cause, or the program
        // settlement was fixed before this signal. Neither case may retarget
        // the process or replace that cause.
        Err(STATE_INTERRUPTED) | Err(STATE_FINALIZING) => return,
        Err(_) => {
            // An installed handler without an active owner is the fault-only
            // fallback case. Restore what was published and leave immediately.
            unsafe { handler_only_restore_and_exit() }
        }
    }

    PENDING.fetch_or(WAKE_INTERRUPT, Ordering::AcqRel);
    let writer = WRITE_FD.load(Ordering::Acquire);
    if writer >= 0 {
        let byte = [WAKE_INTERRUPT];
        // SAFETY: writer is a process-owned nonblocking pipe descriptor and
        // byte names initialized static-size storage.
        if unsafe { libc::write(writer, byte.as_ptr().cast(), byte.len()) } == 1 {
            return;
        }
    }
    // The ordinary lane cannot be woken. A broker flush is intentionally
    // forfeited here because it is not async-signal-safe.
    unsafe { handler_only_restore_and_exit() }
}

fn restore_sigint_action(previous: &libc::sigaction) {
    // SAFETY: previous came from a successful sigaction call.
    unsafe {
        libc::sigaction(libc::SIGINT, previous, std::ptr::null_mut());
    }
}

fn wake(writer: i32, bits: u8) {
    PENDING.fetch_or(bits, Ordering::AcqRel);
    let byte = [bits];
    // SAFETY: ordinary-thread best-effort wake of a retained pipe writer. The
    // pending bits are authoritative if the pipe is already readable/full.
    unsafe {
        libc::write(writer, byte.as_ptr().cast(), byte.len());
    }
}

/// Scoped direct-execution signal owner. `begin_settlement` linearizes the
/// no-interrupt program/lifecycle result against SIGINT before ordinary
/// adapter cleanup starts. Once a handler has been installed, the global claim
/// and CLOEXEC bridge descriptors remain process-lifetime: restoring sigaction
/// cannot join a handler already entered on another runtime thread, so the
/// process refuses a later direct-execution scope rather than risk stale reuse.
pub(crate) struct DirectExecutionInterruptCoordinator {
    _install_lock: MutexGuard<'static, ()>,
    writer: Option<NativeFd>,
    reader_keepalive: Option<NativeFd>,
    previous: Option<libc::sigaction>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DirectExecutionInterruptCoordinator {
    pub(crate) fn install(
        restore_stdout_fd: i32,
        restore_stderr_fd: i32,
        cancellation: DirectExecutionCancellationRegistration,
        cleanup: impl FnOnce() + Send + 'static,
    ) -> io::Result<Self> {
        let install_lock = INSTALL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if STATE.load(Ordering::Acquire) != STATE_INACTIVE {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the process-lifetime direct-execution SIGINT bridge was already installed",
            ));
        }
        let (reader, mut writer) = NativeFd::pipe()?;
        let reader_keepalive = NativeFd::duplicate(reader.raw())?;

        // SAFETY: sigaction is plain old data and its mask is initialized
        // before installation.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = direct_execution_sigint_handler as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let signal_thread = thread::Builder::new()
            .name("ibex-direct-execution-sigint".to_owned())
            .spawn(move || {
                let mut cleanup = Some(cleanup);
                loop {
                    let mut poll_descriptor = libc::pollfd {
                        // Calling a method forces the closure to own the
                        // NativeFd itself. Capturing the public tuple field
                        // would copy only its i32 under precise capture and
                        // close the reader on the installing thread.
                        fd: reader.raw(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: poll receives one initialized descriptor record.
                    let ready = unsafe { libc::poll(&mut poll_descriptor, 1, -1) };
                    if ready < 0 {
                        if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        // A broken ordinary lane has the same bounded escape
                        // disposition as a handler wake failure.
                        unsafe { handler_only_restore_and_exit() }
                    }
                    let mut bytes = [0_u8; 32];
                    // SAFETY: the buffer is writable and reader stays owned by
                    // this thread for the complete loop.
                    unsafe {
                        libc::read(reader.raw(), bytes.as_mut_ptr().cast(), bytes.len());
                    }
                    let pending = PENDING.swap(0, Ordering::AcqRel);
                    if pending & WAKE_INTERRUPT != 0 {
                        let cleaned =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                let _ = cancellation.request_exact_if_executing();
                                if let Some(cleanup) = cleanup.take() {
                                    cleanup();
                                }
                            }));
                        if cleaned.is_err() {
                            // A panic in an engine courtesy request or the
                            // ordinary broker lane cannot unwind this owner
                            // and strand the installed disposition.
                            unsafe { handler_only_restore_and_exit() }
                        }
                        // A cleanup implementation must not be able to turn an
                        // interrupt into a return to a wedged evaluator.
                        unsafe { libc::_exit(128 + libc::SIGINT) }
                    }
                    if pending & WAKE_SHUTDOWN != 0 {
                        return;
                    }
                }
            })?;

        // The ordinary cleanup lane exists before the handler can claim an
        // interrupt. This closes the thread-spawn failure race: once SIGINT is
        // mediated, a successful self-pipe wake always has a consumer.
        PENDING.store(0, Ordering::Release);
        RESTORE_STDOUT_FD.store(restore_stdout_fd, Ordering::Release);
        RESTORE_STDERR_FD.store(restore_stderr_fd, Ordering::Release);
        WRITE_FD.store(writer.0, Ordering::Release);
        STATE.store(STATE_ACTIVE, Ordering::Release);

        // SAFETY: both action pointers name initialized sigaction values.
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(libc::SIGINT, &action, &mut previous) } != 0 {
            let error = io::Error::last_os_error();
            STATE.store(STATE_FINALIZING, Ordering::Release);
            wake(writer.0, WAKE_SHUTDOWN);
            // EOF is the authoritative wake if the best-effort byte could
            // not be written.
            writer.close();
            let _ = signal_thread.join();
            Self::reset_uninstalled_globals();
            return Err(error);
        }

        Ok(Self {
            _install_lock: install_lock,
            writer: Some(writer),
            reader_keepalive: Some(reader_keepalive),
            previous: Some(previous),
            thread: Some(signal_thread),
        })
    }

    /// Returns false only when SIGINT linearized first. In that case the
    /// ordinary signal thread owns cleanup and will terminate the process.
    pub(crate) fn begin_settlement(&self) -> bool {
        match STATE.compare_exchange(
            STATE_ACTIVE,
            STATE_FINALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(STATE_FINALIZING) => true,
            Err(STATE_INTERRUPTED) => false,
            Err(_) => false,
        }
    }

    pub(crate) fn wait_for_interrupt_termination() -> ! {
        loop {
            thread::park();
        }
    }

    pub(crate) fn finish(mut self) -> io::Result<()> {
        if !self.begin_settlement() {
            Self::wait_for_interrupt_termination();
        }
        if let Some(previous) = self.previous.take() {
            restore_sigint_action(&previous);
        }
        let writer = self
            .writer
            .as_ref()
            .expect("installed direct-execution bridge retains its writer")
            .raw();
        wake(writer, WAKE_SHUTDOWN);
        let joined = self
            .thread
            .take()
            .expect("direct execution signal thread is present")
            .join()
            .map_err(|_| io::Error::other("direct execution signal thread panicked"));
        PENDING.store(0, Ordering::Release);
        self.retain_bridge_descriptors();
        joined
    }

    fn retain_bridge_descriptors(&mut self) {
        if let Some(writer) = self.writer.take() {
            std::mem::forget(writer);
        }
        if let Some(reader) = self.reader_keepalive.take() {
            std::mem::forget(reader);
        }
    }

    /// Reset is permitted only when sigaction never installed our handler.
    fn reset_uninstalled_globals() {
        WRITE_FD.store(-1, Ordering::Release);
        RESTORE_STDOUT_FD.store(-1, Ordering::Release);
        RESTORE_STDERR_FD.store(-1, Ordering::Release);
        PENDING.store(0, Ordering::Release);
        STATE.store(STATE_INACTIVE, Ordering::Release);
    }
}

impl Drop for DirectExecutionInterruptCoordinator {
    fn drop(&mut self) {
        if self.thread.is_none() {
            return;
        }
        let interrupt_owns_cleanup = matches!(
            STATE.compare_exchange(
                STATE_ACTIVE,
                STATE_FINALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Err(STATE_INTERRUPTED)
        );
        if interrupt_owns_cleanup {
            // The signal thread owns process termination. Waiting here avoids
            // racing its descriptor/broker cleanup from an unwind path.
            let thread = self.thread.take().expect("signal thread");
            let _ = thread.join();
            self.retain_bridge_descriptors();
            return;
        }
        if let Some(previous) = self.previous.take() {
            restore_sigint_action(&previous);
        }
        let writer = self
            .writer
            .as_ref()
            .expect("installed direct-execution bridge retains its writer")
            .raw();
        wake(writer, WAKE_SHUTDOWN);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        PENDING.store(0, Ordering::Release);
        self.retain_bridge_descriptors();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    unsafe extern "C" fn prior_sigint_sentinel(_: libc::c_int) {}

    fn query_sigint_action() -> libc::sigaction {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: a null replacement queries SIGINT into initialized storage.
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGINT, std::ptr::null(), &mut action) },
            0
        );
        action
    }

    fn install_prior_sigint_sentinel() -> libc::sigaction {
        let mut sentinel: libc::sigaction = unsafe { std::mem::zeroed() };
        sentinel.sa_sigaction = prior_sigint_sentinel as *const () as usize;
        sentinel.sa_flags = libc::SA_RESTART;
        assert_eq!(unsafe { libc::sigemptyset(&mut sentinel.sa_mask) }, 0);
        assert_eq!(
            unsafe { libc::sigaddset(&mut sentinel.sa_mask, libc::SIGTERM) },
            0
        );
        let mut original: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGINT, &sentinel, &mut original) },
            0
        );
        original
    }

    fn run_isolated(test_name: &str, child_environment: &str) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(child_environment, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "direct-interrupt child failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // @ref LLP 0025#1-modes-descriptors-and-topology
    #[test]
    fn finish_restores_prior_sigint_and_rejects_direct_reinstallation() {
        const CHILD: &str = "IBEX_TEST_DIRECT_INTERRUPT_ONE_SHOT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            run_isolated(
                "direct_execution_interrupt::tests::finish_restores_prior_sigint_and_rejects_direct_reinstallation",
                CHILD,
            );
            return;
        }

        let _original = install_prior_sigint_sentinel();
        let expected = query_sigint_action();
        let coordinator = DirectExecutionInterruptCoordinator::install(
            libc::STDOUT_FILENO,
            libc::STDERR_FILENO,
            DirectExecutionCancellationRegistration::default(),
            || panic!("uninterrupted settlement invoked direct cleanup"),
        )
        .unwrap();
        assert_ne!(query_sigint_action().sa_sigaction, expected.sa_sigaction);
        coordinator.finish().unwrap();

        let restored = query_sigint_action();
        assert_eq!(restored.sa_sigaction, expected.sa_sigaction);
        assert_eq!(restored.sa_flags, expected.sa_flags);
        assert_eq!(
            unsafe { libc::sigismember(&restored.sa_mask, libc::SIGTERM) },
            unsafe { libc::sigismember(&expected.sa_mask, libc::SIGTERM) }
        );
        assert_eq!(STATE.load(Ordering::Acquire), STATE_FINALIZING);
        let retained_writer = WRITE_FD.load(Ordering::Acquire);
        assert!(retained_writer >= 0);
        assert!(descriptor_flag(retained_writer, libc::F_GETFD).is_ok());

        let reinstall = DirectExecutionInterruptCoordinator::install(
            libc::STDOUT_FILENO,
            libc::STDERR_FILENO,
            DirectExecutionCancellationRegistration::default(),
            || {},
        );
        assert!(matches!(
            reinstall,
            Err(ref error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        std::process::exit(0);
    }

    // @ref LLP 0025#1-modes-descriptors-and-topology
    #[test]
    fn delayed_direct_handler_cannot_cross_finalization_or_reuse_fds() {
        const CHILD: &str = "IBEX_TEST_DELAYED_DIRECT_INTERRUPT_HANDLER_CHILD";
        if std::env::var_os(CHILD).is_none() {
            run_isolated(
                "direct_execution_interrupt::tests::delayed_direct_handler_cannot_cross_finalization_or_reuse_fds",
                CHILD,
            );
            return;
        }

        let _original = install_prior_sigint_sentinel();
        let expected = query_sigint_action();
        let cleanup_called = Arc::new(AtomicBool::new(false));
        let cleanup_marker = Arc::clone(&cleanup_called);
        let coordinator = DirectExecutionInterruptCoordinator::install(
            libc::STDOUT_FILENO,
            libc::STDERR_FILENO,
            DirectExecutionCancellationRegistration::default(),
            move || cleanup_marker.store(true, Ordering::Release),
        )
        .unwrap();

        TEST_HANDLER_ENTERED.store(false, Ordering::Release);
        TEST_PAUSE_HANDLER_BEFORE_CLAIM.store(true, Ordering::Release);
        let target_release = Arc::new(AtomicBool::new(false));
        let thread_release = Arc::clone(&target_release);
        let (thread_tx, thread_rx) = std::sync::mpsc::sync_channel(1);
        let target = thread::spawn(move || {
            // pthread_t is an integer on some Unix targets and a pointer on
            // others; usize is only a same-process transport for pthread_kill.
            thread_tx
                .send(unsafe { libc::pthread_self() } as usize)
                .unwrap();
            while !thread_release.load(Ordering::Acquire) {
                thread::yield_now();
            }
        });
        let target_thread = thread_rx.recv().unwrap() as libc::pthread_t;
        assert_eq!(
            unsafe { libc::pthread_kill(target_thread, libc::SIGINT) },
            0
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while !TEST_HANDLER_ENTERED.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "SIGINT handler did not reach the delayed-entry seam"
            );
            thread::sleep(Duration::from_millis(1));
        }

        let retained_writer = WRITE_FD.load(Ordering::Acquire);
        coordinator.finish().unwrap();
        assert_eq!(STATE.load(Ordering::Acquire), STATE_FINALIZING);
        assert_eq!(WRITE_FD.load(Ordering::Acquire), retained_writer);
        assert!(descriptor_flag(retained_writer, libc::F_GETFD).is_ok());
        assert_eq!(query_sigint_action().sa_sigaction, expected.sa_sigaction);

        TEST_PAUSE_HANDLER_BEFORE_CLAIM.store(false, Ordering::Release);
        target_release.store(true, Ordering::Release);
        target.join().unwrap();
        assert!(!cleanup_called.load(Ordering::Acquire));

        let reinstall = DirectExecutionInterruptCoordinator::install(
            libc::STDOUT_FILENO,
            libc::STDERR_FILENO,
            DirectExecutionCancellationRegistration::default(),
            || {},
        );
        assert!(matches!(
            reinstall,
            Err(ref error) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        std::process::exit(0);
    }
}
