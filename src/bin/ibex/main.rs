//! Ibex CLI - A JavaScript/TypeScript runtime with web APIs
//!
//! The `ibex` CLI provides a fast, modern runtime for JavaScript and TypeScript,
//! featuring web-standard APIs, a high-quality REPL, and Chrome DevTools debugging.

mod agent_logs;
mod cdp;
mod cli;
mod compat;
#[cfg(unix)]
mod direct_execution_interrupt;
mod engine;
mod history;
mod host;
mod repl;
mod repl_surface;
mod runtime;
mod runtime_tests;
#[cfg(all(test, feature = "capsec-conformance-observer"))]
mod session_semantics_conformance;
mod session_worker;
#[cfg(unix)]
mod session_worker_runtime;
mod sfe;
mod subprocess;
mod terminal_session;

// Re-export module_loader from the shared runtime crate
pub use ibex_runtime::module_loader;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands, DebugCommands};

/// Project commands owned by the Exact project CLI, not the Ibex runtime.
/// @ref LLP 0010#runtime-command-surface — `ibex` is runtime-only here.
const EXACT_PROJECT_COMMANDS: &[&str] = &[
    "new", "create", "init", "verify", "facet", "agent", "mcp", "doctor", "lint", "export", "start",
];

/// Runtime-namespace names reserved for future features:
/// absent from the clap tree, intercepted pre-clap with a pointer error so
/// they neither advertise vapor nor fall through to package-script dispatch.
/// @ref LLP 0010#runtime-command-surface — truthful runtime surface.
const RESERVED_RUNTIME_COMMANDS: &[(&str, &str)] = &[
    ("test", "a user-facing test runner is planned"),
    (
        "install",
        "package management is not implemented; use bun or npm",
    ),
    (
        "bench",
        "a benchmark harness is planned; run `ibex <file>` directly",
    ),
    ("exec", "package-binary execution (`npx`-style) is planned"),
];

const DEFAULT_WATCH_SHUTDOWN_TIMEOUT_MS: u64 = 2_000;

/// Runtime-internal env contracts use the `IBEX_*` namespace; the legacy
/// `EX_*`/`EXACT_*` spellings are honored with a one-time deprecation
/// warning while extracted consumers catch up.
/// Cross-product agent contracts (`EXACT_AGENT_*`) are unaffected.
pub(crate) fn runtime_env(ibex_name: &str, legacy_name: &str) -> Option<String> {
    if let Ok(value) = std::env::var(ibex_name) {
        return Some(value);
    }
    if let Ok(value) = std::env::var(legacy_name) {
        use std::sync::Mutex;
        static WARNED: Mutex<Vec<String>> = Mutex::new(Vec::new());
        if let Ok(mut warned) = WARNED.lock() {
            if !warned.iter().any(|name| name == legacy_name) {
                eprintln!("warning: {legacy_name} is deprecated; use {ibex_name}");
                warned.push(legacy_name.to_string());
            }
        }
        return Some(value);
    }
    None
}

/// Shared truthiness parse for boolean `IBEX_*` env flags, mirroring the C++
/// `env_flag_enabled` in hermes_runtime.cc so the Rust bundler driver and bundle
/// cache key agree with the engine on whether a flag is set. A bare presence
/// check (`var_os(..).is_some()`) disagreed with the engine's value check:
/// `IBEX_COMPARTMENTS=true` made the bundler emit `__compartments` references the
/// engine never installed, throwing ReferenceError (and caching the broken
/// artifact). Accepts a leading 1/y/Y/t/T (so `1`, `yes`, `true` all enable) and
/// rejects `0`/`false`/`no`/`off`/empty. (ENG-22634)
pub(crate) fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|v| v.chars().next())
        .map(|c| matches!(c, '1' | 'y' | 'Y' | 't' | 'T'))
        .unwrap_or(false)
}

/// @ref LLP 0034#decision — the compiler, cache identities, and embedded
/// runtimes resolve one semantic mode. The legacy flag is deliberately an
/// opt-out so ordinary Ibex execution gets correct per-iteration bindings.
pub(crate) fn hermes_es6_block_scoping_enabled() -> bool {
    !env_flag_enabled("IBEX_LEGACY_HERMES_BLOCK_SCOPING")
}

pub(crate) fn trace_startup() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        runtime_env("IBEX_STARTUP_TRACE", "EX_STARTUP_TRACE")
            .map(|v| v.starts_with('1') || v.starts_with('y') || v.starts_with('Y'))
            .unwrap_or(false)
    })
}

fn watch_shutdown_timeout_from_env(value: Option<&str>) -> std::time::Duration {
    subprocess::parse_timeout_ms(value, DEFAULT_WATCH_SHUTDOWN_TIMEOUT_MS)
}

fn watch_shutdown_timeout() -> std::time::Duration {
    let raw = runtime_env(
        "IBEX_WATCH_SHUTDOWN_TIMEOUT_MS",
        "EXACT_WATCH_SHUTDOWN_TIMEOUT_MS",
    );
    watch_shutdown_timeout_from_env(raw.as_deref())
}

/// Message prefixes that classify an error as a host-lifecycle failure
/// (exit code 3 instead of the generic 1).
///
/// These errors cross FFI/JSI boundaries as strings, so only ordinary
/// `io::Error` causes can be classified structurally here. The prefixes below
/// are produced by the local host ABI and HTTP bridge.
const HOST_LIFECYCLE_ERROR_PREFIXES: &[&str] = &[
    "Host not initialized",
    "Permission denied for ",
    "Failed to start HTTP server",
];

/// Error carrying a package script's own exit status. `run_package_script`
/// returns this on failure so `ibex` propagates the child's exit code — matching
/// npm/bun — instead of collapsing every script failure to the generic 1.
/// `exit_code_for_error` downcasts to it. (ENG-22958)
#[derive(Debug)]
struct PackageScriptExit {
    script: String,
    code: i32,
}

impl std::fmt::Display for PackageScriptExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "package script `{}` exited with code {}",
            self.script, self.code
        )
    }
}

impl std::error::Error for PackageScriptExit {}

/// A lifecycle request produced by evaluated code after the runtime has
/// unwound back into Rust. Carrying the code through `Result` lets execution
/// adapters restore descriptors and finish broker barriers before `main`
/// performs the process-level exit.
// @ref LLP 0024#6-evaluation-outcomes-and-the-abi — lifecycle is a structured
// evaluation outcome, not an in-engine hard process exit.
#[derive(Debug)]
struct ProgramRequestedExit {
    code: i32,
}

impl std::fmt::Display for ProgramRequestedExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "program requested exit code {}", self.code)
    }
}

impl std::error::Error for ProgramRequestedExit {}

/// A completed authenticated program whose primary cause requires a fixed
/// non-success status and a user-facing diagnostic. Keeping the status typed
/// lets the file execution adapter restore descriptors and finish its broker
/// barrier before `main` reports the failure and exits.
#[derive(Debug)]
struct ProgramExecutionFailure {
    code: i32,
    diagnostic: String,
}

impl std::fmt::Display for ProgramExecutionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl std::error::Error for ProgramExecutionFailure {}

fn is_program_requested_exit(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<ProgramRequestedExit>().is_some())
}

/// Preserve an already-latched program cause across inspector disposal.
/// Inspector cleanup is diagnostic-only even after orderly zero: it is not
/// output loss and therefore cannot modify the completed program disposition.
/// @ref LLP 0025#8-exit-and-lifecycle
fn preserve_file_settlement_after_inspector_cleanup(
    settlement: Result<()>,
    cleanup: Result<()>,
) -> Result<()> {
    if let Err(error) = cleanup {
        emit_pre_session_diagnostic(
            "error: file-program inspector cleanup failed after settlement: ",
            &format!("{error:#}"),
        );
    }
    settlement
}

/// Apply LLP 0025's sole cleanup-loss modifier after the caller has attempted
/// to report the loss on a structurally unaffected destination. Numeric status
/// is deliberately irrelevant: `ProgramRequestedExit` represents an orderly
/// or cooperative successful cause, while every other error is a fixed cause.
/// @ref LLP 0025#8-exit-and-lifecycle
fn apply_file_broker_loss_disposition(
    execution: Result<()>,
    loss_detail: Option<String>,
    reported: bool,
) -> Result<()> {
    let Some(loss_detail) = loss_detail else {
        return execution;
    };
    if reported {
        return execution;
    }
    let successful = execution.is_ok()
        || execution
            .as_ref()
            .err()
            .is_some_and(is_program_requested_exit);
    if successful {
        return Err(anyhow::Error::new(ProgramExecutionFailure {
            code: ibex_runtime::session_constants::EXIT_STATUS_BROKEN_PIPE,
            diagnostic: loss_detail,
        }));
    }
    execution.map_err(|error| error.context(loss_detail))
}

fn apply_file_broker_loss(
    execution: Result<()>,
    loss_detail: Option<String>,
    report_destinations: [Option<terminal_session::NativeOutputDestination>; 2],
) -> Result<()> {
    let reported = loss_detail.as_ref().is_some_and(|detail| {
        report_destinations
            .into_iter()
            .flatten()
            .any(|destination| emit_bounded_diagnostic(destination, "error: ", detail))
    });
    apply_file_broker_loss_disposition(execution, loss_detail, reported)
}

fn file_program_loss_detail(
    report: &terminal_session::FileProgramExecutionReport,
) -> Option<String> {
    if !report.has_loss() {
        return None;
    }
    let relay_count = report
        .loss()
        .relays
        .iter()
        .filter(|relay| {
            relay.program_bytes != 0
                || relay.session_bytes != 0
                || relay.program_frames != 0
                || relay.session_frames != 0
                || relay.control_frames != 0
        })
        .count();
    let finish_error = report
        .finish_error()
        .map(|error| format!(", final flush failed: {error}"))
        .unwrap_or_default();
    let open_inputs = match report.input_streams_open() {
        (true, true) => ", stdout and stderr inputs still open",
        (true, false) => ", stdout input still open",
        (false, true) => ", stderr input still open",
        (false, false) => "",
    };
    let diagnostic_failure_count = report.broker_owned_diagnostic_failures();
    let diagnostic_failures = if diagnostic_failure_count == 0 {
        String::new()
    } else {
        format!(", {diagnostic_failure_count} broker-owned diagnostic(s) refused")
    };
    Some(format!(
        "secure output broker closed with loss (forced-close sequence {}, {} affected relay(s), {} unaccepted stdout byte(s), {} unaccepted stderr byte(s){open_inputs}{diagnostic_failures}{finish_error})",
        report.loss().forced_close_sequence,
        relay_count,
        report.unaccepted_stdout_bytes(),
        report.unaccepted_stderr_bytes(),
    ))
}

/// Preserve the completed program cause when adapter cleanup itself cannot
/// produce a report. Relay failures imply unaccounted output and therefore use
/// the successful-cause 141 upgrade; descriptor-restoration failures are later
/// diagnostics and do not replace either a successful or fixed primary cause.
/// @ref LLP 0025#8-exit-and-lifecycle
fn apply_file_adapter_finish_error(
    execution: Result<()>,
    error: terminal_session::FileProgramAdapterError,
) -> Result<()> {
    let detail = format!("secure file execution adapter cleanup failed: {error}");
    match error {
        terminal_session::FileProgramAdapterError::Broker(_)
        | terminal_session::FileProgramAdapterError::RelayThreadPanicked => apply_file_broker_loss(
            execution,
            Some(detail),
            [
                Some(terminal_session::NativeOutputDestination::Stderr),
                Some(terminal_session::NativeOutputDestination::Stdout),
            ],
        ),
        terminal_session::FileProgramAdapterError::NativeWithReport { report, .. } => {
            match file_program_loss_detail(&report) {
                Some(loss) => apply_file_broker_loss(
                    execution,
                    Some(format!("{detail}; {loss}")),
                    report.loss_report_destinations(),
                ),
                None => {
                    emit_pre_session_diagnostic("error: ", &detail);
                    execution
                }
            }
        }
        terminal_session::FileProgramAdapterError::Gate(_)
        | terminal_session::FileProgramAdapterError::Native(_) => {
            emit_pre_session_diagnostic("error: ", &detail);
            execution
        }
    }
}

/// Resolve a finished child's exit code the way a shell would: the explicit
/// code when present, else `128 + signal` on Unix. Never returns 0 for a
/// non-success status (so a propagated code always signals failure).
fn package_script_exit_code(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        if code != 0 {
            return code;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

/// Install the launcher SIGINT disposition before a child is spawned. A
/// terminal-generated SIGINT still reaches the child through the foreground
/// process group, while the Ibex launcher remains alive long enough to reap it
/// and turn the signal into the shell-style `128 + signal` status. The bridge is
/// deliberately one-shot per CLI process: teardown restores the inherited
/// disposition but retains its pipe descriptors so an already-entered handler
/// can never write to a reused descriptor or a later launcher scope.
/// @ref LLP 0025#1-modes-descriptors-and-topology
#[cfg(unix)]
const LAUNCHER_SIGNAL_INTERRUPT: u8 = 1 << 0;
#[cfg(unix)]
const LAUNCHER_SIGNAL_SHUTDOWN: u8 = 1 << 1;
#[cfg(unix)]
static LAUNCHER_SIGNAL_PENDING: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
#[cfg(unix)]
static LAUNCHER_SIGNAL_WRITE_FD: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(-1);

#[cfg(unix)]
struct LauncherSignalFd(libc::c_int);

#[cfg(unix)]
impl LauncherSignalFd {
    const fn raw(&self) -> libc::c_int {
        self.0
    }

    fn close(&mut self) {
        if self.0 < 0 {
            return;
        }
        // SAFETY: this value uniquely owns the descriptor and marks it closed
        // before the number can be reused.
        unsafe {
            libc::close(self.0);
        }
        self.0 = -1;
    }
}

#[cfg(unix)]
impl Drop for LauncherSignalFd {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(unix)]
fn launcher_descriptor_flag(
    descriptor: libc::c_int,
    operation: libc::c_int,
) -> std::io::Result<i32> {
    loop {
        // SAFETY: fcntl performs a descriptor query with no third argument.
        let result = unsafe { libc::fcntl(descriptor, operation) };
        if result >= 0 {
            return Ok(result);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn set_launcher_descriptor_flag(
    descriptor: libc::c_int,
    operation: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    loop {
        // SAFETY: fcntl updates flags on one live descriptor.
        let result = unsafe { libc::fcntl(descriptor, operation, value) };
        if result >= 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn launcher_signal_pipe() -> std::io::Result<(LauncherSignalFd, LauncherSignalFd, LauncherSignalFd)>
{
    let mut descriptors = [-1; 2];
    // SAFETY: pipe initializes both descriptor slots on success.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let reader = LauncherSignalFd(descriptors[0]);
    let writer = LauncherSignalFd(descriptors[1]);
    for descriptor in [reader.raw(), writer.raw()] {
        let flags = launcher_descriptor_flag(descriptor, libc::F_GETFD)?;
        set_launcher_descriptor_flag(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC)?;
    }
    let writer_flags = launcher_descriptor_flag(writer.raw(), libc::F_GETFL)?;
    set_launcher_descriptor_flag(writer.raw(), libc::F_SETFL, writer_flags | libc::O_NONBLOCK)?;

    // Retain a second read descriptor through teardown. It prevents an
    // already-entered handler from receiving SIGPIPE after the coordinator
    // thread has observed shutdown but before the writer is closed.
    let keepalive_raw = unsafe { libc::dup(reader.raw()) };
    if keepalive_raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let keepalive = LauncherSignalFd(keepalive_raw);
    let keepalive_flags = launcher_descriptor_flag(keepalive.raw(), libc::F_GETFD)?;
    set_launcher_descriptor_flag(
        keepalive.raw(),
        libc::F_SETFD,
        keepalive_flags | libc::FD_CLOEXEC,
    )?;
    Ok((reader, writer, keepalive))
}

#[cfg(unix)]
fn write_launcher_signal_byte(descriptor: libc::c_int, byte: u8) {
    let bytes = [byte];
    loop {
        // SAFETY: descriptor is the retained nonblocking pipe writer and bytes
        // names initialized fixed-size storage.
        if unsafe { libc::write(descriptor, bytes.as_ptr().cast(), bytes.len()) } >= 0 {
            return;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return;
        }
    }
}

#[cfg(unix)]
unsafe extern "C" fn launcher_signal_handler(_: libc::c_int) {
    use std::sync::atomic::Ordering;

    LAUNCHER_SIGNAL_PENDING.fetch_or(LAUNCHER_SIGNAL_INTERRUPT, Ordering::AcqRel);
    let descriptor = LAUNCHER_SIGNAL_WRITE_FD.load(Ordering::Acquire);
    if descriptor >= 0 {
        let byte = [LAUNCHER_SIGNAL_INTERRUPT];
        // SAFETY: the active guard publishes a retained nonblocking descriptor;
        // pipe fullness is harmless because the pending bit is authoritative.
        unsafe {
            libc::write(descriptor, byte.as_ptr().cast(), byte.len());
        }
    }
}

#[cfg(unix)]
fn launcher_signal_loop(reader: LauncherSignalFd, sender: tokio::sync::mpsc::Sender<()>) {
    use std::sync::atomic::Ordering;

    loop {
        let mut poll_descriptor = libc::pollfd {
            fd: reader.raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one initialized descriptor record.
        let ready = unsafe { libc::poll(&mut poll_descriptor, 1, -1) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }

        let mut bytes = [0_u8; 64];
        // SAFETY: reader remains owned by this thread and bytes is writable.
        let amount = unsafe { libc::read(reader.raw(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if amount == 0 {
            return;
        }
        if amount < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }

        let pending = LAUNCHER_SIGNAL_PENDING.swap(0, Ordering::AcqRel);
        let observed = &bytes[..amount as usize];
        if pending & LAUNCHER_SIGNAL_INTERRUPT != 0 || observed.contains(&LAUNCHER_SIGNAL_INTERRUPT)
        {
            // Capacity one deliberately coalesces a signal burst while the
            // launcher is already inside its bounded child-cleanup grace.
            let _ = sender.try_send(());
        }
        if pending & LAUNCHER_SIGNAL_SHUTDOWN != 0 || observed.contains(&LAUNCHER_SIGNAL_SHUTDOWN) {
            return;
        }
    }
}

struct LauncherInterrupt {
    #[cfg(unix)]
    receiver: tokio::sync::mpsc::Receiver<()>,
    #[cfg(unix)]
    writer: Option<LauncherSignalFd>,
    #[cfg(unix)]
    reader_keepalive: Option<LauncherSignalFd>,
    #[cfg(unix)]
    signal_number: libc::c_int,
    #[cfg(unix)]
    previous: Option<libc::sigaction>,
    #[cfg(unix)]
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LauncherInterrupt {
    fn install() -> Result<Self> {
        #[cfg(unix)]
        {
            Self::install_for_signal(libc::SIGINT)
                .context("failed to install launcher SIGINT mediation")
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    #[cfg(unix)]
    fn install_for_signal(signal_number: libc::c_int) -> std::io::Result<Self> {
        use std::sync::atomic::Ordering;

        let (reader, writer, reader_keepalive) = launcher_signal_pipe()?;
        LAUNCHER_SIGNAL_WRITE_FD
            .compare_exchange(-1, writer.raw(), Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "another launcher signal bridge is already active",
                )
            })?;
        LAUNCHER_SIGNAL_PENDING.store(0, Ordering::Release);

        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let thread = match std::thread::Builder::new()
            .name("ibex-launcher-signal".to_owned())
            .spawn(move || launcher_signal_loop(reader, sender))
        {
            Ok(thread) => thread,
            Err(error) => {
                LAUNCHER_SIGNAL_WRITE_FD.store(-1, Ordering::Release);
                return Err(error);
            }
        };

        // The consumer exists before the handler is installed, so every
        // successfully mediated signal has an ordinary async notification lane.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = launcher_signal_handler as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            let error = std::io::Error::last_os_error();
            LAUNCHER_SIGNAL_PENDING.fetch_or(LAUNCHER_SIGNAL_SHUTDOWN, Ordering::AcqRel);
            write_launcher_signal_byte(writer.raw(), LAUNCHER_SIGNAL_SHUTDOWN);
            let _ = thread.join();
            LAUNCHER_SIGNAL_PENDING.store(0, Ordering::Release);
            LAUNCHER_SIGNAL_WRITE_FD.store(-1, Ordering::Release);
            return Err(error);
        }
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(signal_number, &action, &mut previous) } != 0 {
            let error = std::io::Error::last_os_error();
            LAUNCHER_SIGNAL_PENDING.fetch_or(LAUNCHER_SIGNAL_SHUTDOWN, Ordering::AcqRel);
            write_launcher_signal_byte(writer.raw(), LAUNCHER_SIGNAL_SHUTDOWN);
            let _ = thread.join();
            LAUNCHER_SIGNAL_PENDING.store(0, Ordering::Release);
            LAUNCHER_SIGNAL_WRITE_FD.store(-1, Ordering::Release);
            return Err(error);
        }

        Ok(Self {
            receiver,
            writer: Some(writer),
            reader_keepalive: Some(reader_keepalive),
            signal_number,
            previous: Some(previous),
            thread: Some(thread),
        })
    }

    async fn recv(&mut self) -> bool {
        #[cfg(unix)]
        {
            self.receiver.recv().await.is_some()
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<bool>().await
        }
    }
}

impl Drop for LauncherInterrupt {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::sync::atomic::Ordering;

            if let Some(previous) = self.previous.take() {
                // SAFETY: previous was returned by the successful installation
                // for this exact signal number.
                unsafe {
                    libc::sigaction(self.signal_number, &previous, std::ptr::null_mut());
                }
            }

            let writer = self
                .writer
                .as_ref()
                .expect("installed launcher bridge retains its writer");
            // Stop the ordinary consumer, but retain the pipe and its extra
            // reader for process lifetime. Restoring sigaction does not join a
            // handler already entered on another runtime thread; that handler
            // may have loaded this fd and resume arbitrarily later. Keeping the
            // global slot claimed also rejects a sequential scope, so the stale
            // handler cannot notify a new launcher.
            LAUNCHER_SIGNAL_PENDING.fetch_or(LAUNCHER_SIGNAL_SHUTDOWN, Ordering::AcqRel);
            write_launcher_signal_byte(writer.raw(), LAUNCHER_SIGNAL_SHUTDOWN);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            LAUNCHER_SIGNAL_PENDING.store(0, Ordering::Release);
            std::mem::forget(
                self.writer
                    .take()
                    .expect("installed launcher bridge retains its writer"),
            );
            std::mem::forget(
                self.reader_keepalive
                    .take()
                    .expect("installed launcher bridge retains its read keepalive"),
            );
        }
    }
}

#[derive(Debug)]
enum LauncherChildOutcome {
    Exited(std::process::ExitStatus),
    Interrupted,
}

async fn wait_for_launcher_child(
    child: &mut tokio::process::Child,
    interrupt: &mut LauncherInterrupt,
) -> Result<LauncherChildOutcome> {
    let outcome = tokio::select! {
        status = child.wait() => status
            .map(LauncherChildOutcome::Exited)
            .map_err(anyhow::Error::from),
        listener_open = interrupt.recv() => {
            if !listener_open {
                anyhow::bail!("launcher SIGINT mediation disconnected while a child was live");
            }

            // The terminal has already delivered this SIGINT to every
            // process in the foreground group. Sending it to the child a
            // second time is observably wrong for programs that distinguish
            // a first graceful interrupt from a second forced one. Give the
            // child a bounded grace period to publish its real status. If
            // the signal landed in the install-before-spawn window (or the
            // child deliberately stayed alive), reap it without fabricating
            // another SIGINT and report the controller's interrupt cause.
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                child.wait(),
            )
            .await
            {
                Ok(status) => status
                    .map(LauncherChildOutcome::Exited)
                    .map_err(anyhow::Error::from),
                Err(_) => {
                    stop_launcher_child_after_interrupt(
                        child,
                        std::time::Duration::from_secs(2),
                    )
                    .await?;
                    Ok(LauncherChildOutcome::Interrupted)
                }
            }
        }
    };
    if outcome.is_err() {
        // A wait-driver error or a disconnected signal bridge must not turn a
        // still-live package script into an unowned process. Cleanup is
        // best-effort here so the original controller failure remains the
        // reported cause; `kill_on_drop` is the final backstop.
        // @ref LLP 0025#8-exit-and-lifecycle — the launcher owns its child until reap.
        let _ = stop_launcher_child_after_interrupt(child, std::time::Duration::from_secs(2)).await;
    }
    outcome
}

fn exit_code_for_error(error: &anyhow::Error) -> i32 {
    if let Some(program_exit) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ProgramRequestedExit>())
    {
        return program_exit.code;
    }
    if let Some(program_failure) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ProgramExecutionFailure>())
    {
        return program_failure.code;
    }
    // A failing package script propagates its own exit code (e.g. eslint's 2),
    // matching npm/bun, rather than collapsing to the generic 1. (ENG-22958)
    if let Some(script_exit) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<PackageScriptExit>())
    {
        return script_exit.code;
    }
    if error.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::AddrInUse
                    | std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::TimedOut
            );
        }

        let message = cause.to_string();
        HOST_LIFECYCLE_ERROR_PREFIXES
            .iter()
            .any(|prefix| message.starts_with(prefix))
    }) {
        3
    } else {
        1
    }
}

#[cfg(unix)]
fn request_watch_child_shutdown(child: &tokio::process::Child) -> Result<bool> {
    let Some(pid) = child.id() else {
        return Ok(false);
    };

    let rc = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if rc == 0 {
        return Ok(true);
    }

    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }

    Err(error.into())
}

#[cfg(not(unix))]
fn request_watch_child_shutdown(_child: &tokio::process::Child) -> Result<bool> {
    Ok(false)
}

async fn stop_launcher_child_after_interrupt(
    child: &mut tokio::process::Child,
    timeout: std::time::Duration,
) -> Result<()> {
    if child.try_wait().ok().flatten().is_some() {
        return Ok(());
    }

    if request_watch_child_shutdown(child).unwrap_or(false) {
        if let Ok(status) = tokio::time::timeout(timeout, child.wait()).await {
            let _ = status?;
            return Ok(());
        }
    }

    let _ = child.kill().await;
    let _ = child.wait().await;
    Ok(())
}

/// A foreground-group SIGINT has already reached the watch child. Give its
/// direct-execution adapter the same two-second grace as a package child so it
/// can restore descriptors and finish its bounded broker close. Only then may
/// the controller fall back to TERM/kill; it never sends a duplicate SIGINT.
#[derive(Debug)]
enum WatchInterruptCleanup {
    Reaped(std::process::ExitStatus),
    Fallback,
}

async fn stop_watch_child_after_interrupt(
    child: &mut tokio::process::Child,
    fallback_timeout: std::time::Duration,
) -> Result<WatchInterruptCleanup> {
    if let Some(status) = child.try_wait()? {
        return Ok(WatchInterruptCleanup::Reaped(status));
    }

    if let Ok(status) = tokio::time::timeout(std::time::Duration::from_secs(2), child.wait()).await
    {
        return status
            .map(WatchInterruptCleanup::Reaped)
            .map_err(anyhow::Error::from);
    }

    eprintln!(
        "\x1b[33m[watch]\x1b[0m child did not finish SIGINT cleanup within 2000ms; terminating..."
    );
    stop_launcher_child_after_interrupt(child, fallback_timeout).await?;
    Ok(WatchInterruptCleanup::Fallback)
}

async fn stop_watch_child(
    child: &mut tokio::process::Child,
    timeout: std::time::Duration,
) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }

    if request_watch_child_shutdown(child)? {
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(status) => {
                let _ = status?;
                return Ok(());
            }
            Err(_) => {
                eprintln!(
                    "\x1b[33m[watch]\x1b[0m process did not exit within {}ms, force killing...",
                    timeout.as_millis()
                );
            }
        }
    }

    let _ = child.kill().await;
    let _ = child.wait().await;
    Ok(())
}

/// Keep non-runtime names out of clap without coupling this binary back to the
/// Exact project CLI. An existing file always wins: `ibex test` runs a file
/// named `test` when one exists; only non-paths hit these tables.
fn pre_clap_namespace_dispatch() -> bool {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let Some(first) = argv.get(1).and_then(|arg| arg.to_str()) else {
        return false;
    };
    if std::path::Path::new(first).exists() {
        return false;
    }
    if let Some((name, reason)) = RESERVED_RUNTIME_COMMANDS
        .iter()
        .find(|(name, _)| *name == first)
    {
        eprintln!("ibex {name} is reserved and not yet implemented: {reason}");
        std::process::exit(2);
    }
    if !EXACT_PROJECT_COMMANDS.contains(&first) {
        return false;
    }

    eprintln!("ibex {first} is an Exact project command; use exact {first}");
    std::process::exit(2);
}

fn legacy_project_dispatch() -> bool {
    pre_clap_namespace_dispatch()
}

/// Expand Node-style combined eval shorthands (`-pe CODE`, `-ep CODE`) into
/// `-p CODE` before clap parsing. The old implementation special-cased `-p`
/// with the literal value "e" and re-read the positional as code, which
/// misread a legitimate `ibex -p e`.
fn expand_combined_eval_shorthand(argv: &mut [std::ffi::OsString]) {
    // Only the leading flags region is rewritten: stop at `--` or the first
    // positional so script argv is never corrupted (review R5 —
    // `ibex tool.js -- -pe x` must deliver `-pe` untouched).
    for arg in argv.iter_mut().skip(1) {
        if *arg == "--" {
            break;
        }
        let is_flag = arg.to_str().is_some_and(|s| s.starts_with('-'));
        if !is_flag {
            break;
        }
        if arg == "-pe" || arg == "-ep" {
            *arg = "-p".into();
        }
    }
}

/// Render an untrusted diagnostic payload as one terminal-safe logical line.
/// Startup has no broker yet, so it applies the broker's payload escaping
/// locally before the bounded native-destination writer adds the sole literal
/// line boundary.
// @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker
#[cfg(test)]
fn escape_pre_session_diagnostic(text: &str) -> String {
    let mut escaped = String::new();
    for ch in text.chars() {
        let code = ch as u32;
        if ch == '\x1b'
            || ch.is_control()
            || (0x80..=0x9f).contains(&code)
            || matches!(code, 0x2028 | 0x2029 | 0x202a..=0x202e | 0x2066..=0x2069)
        {
            use std::fmt::Write as _;
            let _ = write!(escaped, "\\u{{{code:04x}}}");
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

/// Best-effort diagnostic delivery for paths on which the program cause is
/// already latched. The caller waits only for the broker cleanup budget; a
/// blocked standard stream cannot panic, hang, or replace that cause.
/// @ref LLP 0025#5-terminal-presentation-and-restoration
/// @ref LLP 0025#8-exit-and-lifecycle
fn emit_bounded_diagnostic(
    destination: terminal_session::NativeOutputDestination,
    prefix: &str,
    detail: &str,
) -> bool {
    terminal_session::emit_bounded_native_diagnostic(destination, prefix, detail)
}

fn emit_pre_session_diagnostic(prefix: &str, detail: &str) {
    let _ = emit_bounded_diagnostic(
        terminal_session::NativeOutputDestination::Stderr,
        prefix,
        detail,
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let t0 = std::time::Instant::now();
    // Insecure builds project the inherited host environment through
    // `process.env`. Install the snapshot first, before the worker bootstrap
    // branch, so the parent and the re-exec'd session worker capture the same
    // projection and REPL/eval/run/package-script routes all agree. Secure
    // builds have no installer and keep the digest-bound empty base.
    // @ref LLP 0038#fully-open-mode-insecure
    #[cfg(feature = "insecure")]
    ibex_runtime::host::process::install_insecure_ambient_environment();
    // Freeze launcher tracing before any worker, Host, or engine construction;
    // later diagnostics consult only the process-lifetime capture.
    // @ref LLP 0025#2-startup-configuration-is-captured-before-arming
    let _ = trace_startup();
    runtime::capture_bundler_runner_selection();
    let mut argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    match session_worker::pre_clap_worker_bootstrap(&argv) {
        Ok(Some(bootstrap)) => {
            let status = match run_session_worker(bootstrap).await {
                Ok(status) => status,
                Err(error) => {
                    emit_pre_session_diagnostic(
                        "session worker startup refused: ",
                        &format!("{error:#}"),
                    );
                    ibex_runtime::session_constants::EXIT_STATUS_STARTUP_FAILURE
                }
            };
            std::process::exit(status);
        }
        Ok(None) => {}
        Err(error) => {
            emit_pre_session_diagnostic("session worker bootstrap refused: ", &error.to_string());
            std::process::exit(ibex_runtime::session_constants::EXIT_STATUS_STARTUP_FAILURE);
        }
    }
    if legacy_project_dispatch() {
        return;
    }
    expand_combined_eval_shorthand(&mut argv);
    let history_was_explicit = cli::history_option_was_explicit(&argv);
    let mut cli = Cli::parse_from(argv);
    cli.history_was_explicit = history_was_explicit;
    // Print the one-time warning when the opt-in `unadvertised-dev-arming`
    // feature is compiled in (no-op in a default build).
    crate::runtime::emit_unadvertised_dev_arming_banner_if_active();
    if trace_startup() {
        eprintln!(
            "[startup] {:<30} {:>6} us ({:>5.1} ms)",
            "cli_parse",
            t0.elapsed().as_micros(),
            t0.elapsed().as_micros() as f64 / 1000.0
        );
    }
    if let Err(e) = run(cli).await {
        let is_program_exit = is_program_requested_exit(&e);
        if !is_program_exit {
            emit_pre_session_diagnostic("error: ", &format!("{e:#}"));
        }
        std::process::exit(exit_code_for_error(&e));
    }
}

#[cfg(unix)]
async fn run_session_worker(bootstrap: session_worker::WorkerBootstrapContext) -> Result<i32> {
    // The protected descriptor class is installed before Host or Hermes is
    // constructed and is retained by the verified endpoint for the entire
    // worker lifetime.
    // @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker
    let protected = bootstrap
        .protect_session_io()
        .context("failed to install the session-worker descriptor policy")?;
    session_worker_runtime::run_authenticated_runtime_worker(protected)
}

#[cfg(not(unix))]
async fn run_session_worker(_bootstrap: session_worker::WorkerBootstrapContext) -> Result<i32> {
    anyhow::bail!("session workers are unavailable on this platform")
}

/// The product adapter selected for an already-captured authenticated route.
/// Keeping this as one decision table lets the CLI dispatcher, each concrete
/// ingress, and executable conformance evidence agree on the same owner.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthenticatedProductIngress {
    FileProgram,
    InlineOneShot,
    WorkerProgram,
    WorkerRepl,
}

impl AuthenticatedProductIngress {
    #[allow(dead_code)]
    pub(crate) fn label(self) -> String {
        match self {
            Self::FileProgram => "file-program".to_owned(),
            Self::InlineOneShot => "inline-one-shot".to_owned(),
            Self::WorkerProgram => "worker-program".to_owned(),
            Self::WorkerRepl => "worker-repl".to_owned(),
        }
    }
}

pub(crate) const fn authenticated_product_ingress(
    route: terminal_session::SelectedExecutionRoute,
) -> Option<AuthenticatedProductIngress> {
    use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};
    match (route.entry_kind, route.mode) {
        (ArmedEntryKind::File, ArmedExecutionMode::Program) => {
            Some(AuthenticatedProductIngress::FileProgram)
        }
        (ArmedEntryKind::Eval, ArmedExecutionMode::OneShot) => {
            Some(AuthenticatedProductIngress::InlineOneShot)
        }
        (ArmedEntryKind::Stdin, ArmedExecutionMode::Program) => {
            Some(AuthenticatedProductIngress::WorkerProgram)
        }
        (
            ArmedEntryKind::Repl,
            ArmedExecutionMode::Interactive | ArmedExecutionMode::Transcript,
        ) => Some(AuthenticatedProductIngress::WorkerRepl),
        _ => None,
    }
}

async fn run(cli: Cli) -> Result<()> {
    if cli.version {
        println!("v{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if cli.completion_bash {
        print_completions(clap_complete::Shell::Bash);
        return Ok(());
    }

    runtime::configure_runtime_cache_dir(cli.runtime_cache_dir.as_deref())?;

    // Capture route, descriptor topology, and presentation facts exactly once
    // before production validation can inspect a project path or arming input.
    // Every execution branch passes this same value through snapshot arming and
    // terminal supervision.
    // @ref LLP 0025#1-modes-descriptors-and-topology
    let session_io = terminal_session::SessionIoPlan::capture_for_cli(&cli);

    // Validate production controls before dispatch can inspect a prospective
    // project path, read arming artifacts, allocate Hermes, or evaluate input.
    // Runtime construction checks again, while diagnostic/tooling subcommands
    // retain their explicitly separate workflows.
    // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
    if cli.eval_code.is_some()
        || cli.print_eval.is_some()
        || matches!(
            cli.command.as_ref(),
            None | Some(Commands::Run { .. })
                | Some(Commands::Eval { .. })
                | Some(Commands::Repl)
                | Some(Commands::Build { .. })
                | Some(Commands::Debug { .. })
        )
    {
        runtime::validate_production_inputs(&cli)?;
    }
    if let Some(code) = &cli.eval_code {
        return eval_code(
            &cli,
            code,
            false,
            session_io.context("eval route has no terminal session plan")?,
        )
        .await;
    }
    if let Some(code) = &cli.print_eval {
        return eval_code(
            &cli,
            code,
            true,
            session_io.context("print-eval route has no terminal session plan")?,
        )
        .await;
    }

    match &cli.command {
        Some(Commands::Run {
            file,
            args,
            watch,
            inspect,
            inspect_wait,
            inspect_open,
            inspect_pause,
            keep_alive,
            inspect_port,
            inspect_host,
        }) => {
            if should_run_package_script(file) {
                run_package_script(file, args).await
            } else if *watch || cli.watch {
                run_watch(&cli, file, args).await
            } else {
                run_file_with_execution_adapter(
                    &cli,
                    file,
                    args,
                    RunFileOptions {
                        inspect: *inspect,
                        inspect_wait: *inspect_wait,
                        inspect_open: *inspect_open,
                        inspect_pause: *inspect_pause,
                        keep_alive: *keep_alive,
                        inspect_port: *inspect_port,
                        inspect_host: inspect_host.as_deref(),
                    },
                    session_io.context("file route has no terminal session plan")?,
                )
                .await
            }
        }
        Some(Commands::Eval { code }) => {
            eval_code(
                &cli,
                code,
                false,
                session_io.context("eval route has no terminal session plan")?,
            )
            .await
        }
        Some(Commands::Repl) => {
            start_repl(
                &cli,
                session_io.context("REPL route has no terminal session plan")?,
            )
            .await
        }
        Some(Commands::Build { file, outdir }) => {
            build_bytecode(&cli, file, outdir.as_deref()).await
        }
        Some(Commands::Compile {
            entry,
            output,
            carrier,
            compile_policy,
            deny_unsupported,
        }) => sfe::compile(
            entry,
            output,
            *carrier,
            cli.policy.as_deref(),
            compile_policy.as_deref(),
            *deny_unsupported,
        ),
        Some(Commands::CompileApp {
            entry,
            binding,
            output,
            compile_policy,
            deny_unsupported,
        }) => sfe::compile_app_bound(
            entry,
            binding,
            output,
            cli.policy.as_deref(),
            compile_policy.as_deref(),
            *deny_unsupported,
        ),
        Some(Commands::InspectExecutable { file }) => sfe::inspect(file),
        Some(Commands::Version) => {
            print_version(&cli);
            Ok(())
        }
        Some(Commands::Completions { shell }) => {
            print_completions(*shell);
            Ok(())
        }
        Some(Commands::Debug { command }) => match command {
            DebugCommands::Modules => run_debug_modules(),
        },
        Some(Commands::Policy { command }) => runtime::run_policy_command(command).await,
        Some(Commands::Capsec { command }) => match command {
            cli::CapsecCommands::Audit { file, args } => run_capsec_audit(&cli, file, args).await,
        },
        Some(Commands::SelfTest) => runtime_tests::run_all(&cli).await,
        Some(Commands::Compat {
            probe,
            section,
            module,
            test,
            quick,
            failed,
            update_expectations,
            report,
            json,
            log,
            log_color,
            log_no_skip,
            jobs,
            strict,
            all,
            no_retry,
            timeout,
        }) => {
            compat::run_compat(compat::CompatOptions {
                probe: probe.clone(),
                section: section.clone(),
                module: module.clone(),
                test_filter: test.clone(),
                quick: *quick,
                failed: *failed,
                update_expectations: *update_expectations,
                report: *report,
                json: *json,
                log: *log,
                log_color: *log_color,
                log_no_skip: *log_no_skip,
                jobs: *jobs,
                strict: *strict,
                all: *all,
                no_retry: *no_retry,
                timeout: *timeout,
            })
            .await
        }
        None => {
            // If no command but a file is provided via positional argument
            if let Some(file) = &cli.file {
                if should_run_package_script(file) {
                    run_package_script(file, &cli.args).await
                } else if cli.watch {
                    run_watch(&cli, file, &cli.args).await
                } else {
                    run_file_with_execution_adapter(
                        &cli,
                        file,
                        &cli.args,
                        RunFileOptions {
                            inspect: cli.inspect,
                            inspect_wait: cli.inspect_wait,
                            inspect_open: cli.inspect_open,
                            inspect_pause: cli.inspect_pause,
                            keep_alive: cli.keep_alive,
                            inspect_port: cli.inspect_port,
                            inspect_host: cli.inspect_host.as_deref(),
                        },
                        session_io.context("file route has no terminal session plan")?,
                    )
                    .await
                }
            } else {
                // With no command or file, the pre-arming TTY observation is
                // semantic: a TTY selects the interactive REPL while a pipe
                // is one ESM-shaped program-stdin submission. Never re-probe
                // fd 0 after snapshot construction.
                // @ref LLP 0022#3-input-modes
                let plan =
                    session_io.context("implicit session route has no terminal session plan")?;
                match authenticated_product_ingress(plan.route) {
                    Some(AuthenticatedProductIngress::WorkerProgram) => {
                        run_stdin_program(&cli, plan).await
                    }
                    Some(AuthenticatedProductIngress::WorkerRepl) => start_repl(&cli, plan).await,
                    _ => anyhow::bail!(
                        "implicit session route did not select an authenticated product ingress"
                    ),
                }
            }
        }
    }
}

async fn run_capsec_audit(cli: &Cli, file: &str, args: &[String]) -> Result<()> {
    let runtime = runtime::Runtime::from_audit_cli(cli)?;
    suppress_runtime_banner(&runtime).await?;
    runtime.load_runtime().await?;
    runtime.run_file_with_args(file, args).await?;
    let exit_code = read_diagnostic_process_exit_code(&runtime).await;
    if let Some(report) = crate::host::abi::current_audit_report() {
        if !report.is_empty() {
            eprintln!("{report}");
        }
    }
    if let Some(code) = exit_code {
        return Err(ProgramRequestedExit { code }.into());
    }
    Ok(())
}

fn should_run_package_script(file: &str) -> bool {
    let path = std::path::Path::new(file);
    if path.exists() {
        return false;
    }

    if file.contains('/') || file.contains('\\') || file.starts_with('.') || file.ends_with('/') {
        return false;
    }

    if let Some(ext) = path.extension().and_then(|ext| ext.to_str()) {
        let ext = ext.to_ascii_lowercase();
        if matches!(
            ext.as_str(),
            "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx" | "mts" | "cts"
        ) {
            return false;
        }
    }

    true
}

fn run_debug_modules() -> Result<()> {
    println!("specifier\tsource_key\tkind\tpath\tavailability\tmodule_builtin\tbundle_external");
    for entry in module_loader::builtin_module_debug_entries() {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            entry.specifier,
            entry.source_key,
            entry.source_kind,
            entry.source_path.unwrap_or("<inline>"),
            entry.platform_availability,
            entry.module_builtin,
            entry.bundle_external,
        );
    }
    Ok(())
}

async fn run_package_script(script: &str, args: &[String]) -> Result<()> {
    let package_root = find_package_root(std::env::current_dir()?)?;
    let package_json = package_root.join("package.json");

    let manifest = std::fs::read_to_string(&package_json)
        .with_context(|| format!("Failed to read {}", package_json.display()))?;
    let package: serde_json::Value = serde_json::from_str(&manifest)
        .with_context(|| format!("Invalid package manifest {}", package_json.display()))?;
    let scripts = package
        .get("scripts")
        .and_then(|s| s.as_object())
        .and_then(|scripts| scripts.get(script))
        .and_then(|entry| entry.as_str())
        .map(|entry| entry.to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Package script '{}' not found in {}",
                script,
                package_json.display()
            )
        })?;

    // Spawn the script line via the shell with `node_modules/.bin` prepended to
    // PATH, matching the npm/bun execution model. The script body's own tool
    // requirements are the script's business.
    let bin_dir = package_root.join("node_modules").join(".bin");
    let mut path_entries: Vec<std::path::PathBuf> = vec![bin_dir];
    if let Some(existing) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&existing));
    }
    let child_path =
        std::env::join_paths(path_entries).context("Failed to compose PATH for package script")?;

    let mut command_line = scripts.clone();
    for arg in args {
        command_line.push(' ');
        command_line.push_str(&escape_script_arg(arg)?);
    }

    #[cfg(not(windows))]
    let mut cmd = {
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(&command_line);
        cmd
    };
    #[cfg(windows)]
    let mut cmd = {
        let mut cmd = tokio::process::Command::new("cmd");
        cmd.arg("/C").arg(&command_line);
        cmd
    };

    cmd.env("PATH", &child_path);
    cmd.current_dir(&package_root);
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());
    // Error returns from the async wait path still unwind through this owner;
    // ensure Tokio terminates the child even if explicit bounded cleanup also
    // encounters an OS error.
    // @ref LLP 0025#8-exit-and-lifecycle — no launcher child outlives ownership.
    cmd.kill_on_drop(true);

    eprintln!("running package script `{}` ({})", script, scripts);

    // Register before spawning: installing the handler only after `spawn`
    // leaves a race in which a terminal Ctrl+C can still kill this launcher.
    let mut interrupt = LauncherInterrupt::install()?;
    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to run package script `{script}`"))?;
    let outcome = wait_for_launcher_child(&mut child, &mut interrupt)
        .await
        .with_context(|| format!("Failed to wait for package script `{script}`"))?;
    let status = match outcome {
        LauncherChildOutcome::Exited(status) => status,
        LauncherChildOutcome::Interrupted => {
            return Err(PackageScriptExit {
                script: script.to_string(),
                code: 128 + libc::SIGINT,
            }
            .into());
        }
    };
    if !status.success() {
        // Propagate the child's own exit code so `ibex check` mirrors npm/bun
        // (e.g. an eslint script exiting 2 makes `ibex` exit 2, not 1). (ENG-22958)
        return Err(PackageScriptExit {
            script: script.to_string(),
            code: package_script_exit_code(&status),
        }
        .into());
    }

    Ok(())
}

/// Escape an argument appended to a package-script line for the platform
/// shell. Plain identifier-ish arguments pass through unquoted so command
/// lines stay readable.
#[cfg(not(windows))]
fn escape_script_arg(arg: &str) -> Result<String> {
    let is_plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '='));
    Ok(if is_plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    })
}

/// cmd.exe ignores single quotes and treats `&|<>^%` as live metacharacters
/// even inside some quoting forms (review R8). Spaced arguments are
/// double-quoted with embedded quotes doubled; metacharacter arguments are
/// rejected with an instructive error rather than mis-executed.
#[cfg(windows)]
fn escape_script_arg(arg: &str) -> Result<String> {
    if arg
        .chars()
        .any(|c| matches!(c, '&' | '|' | '<' | '>' | '^' | '%'))
    {
        anyhow::bail!(
            "package-script argument {arg:?} contains cmd.exe metacharacters;              quote the call inside the script itself or run the tool directly"
        );
    }
    let needs_quotes = arg.is_empty() || arg.chars().any(|c| c.is_whitespace() || c == '"');
    Ok(if needs_quotes {
        format!("\"{}\"", arg.replace('"', "\"\""))
    } else {
        arg.to_string()
    })
}

fn find_package_root(start: std::path::PathBuf) -> Result<std::path::PathBuf> {
    let mut current = if start.is_file() {
        start
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Cannot resolve package root"))?
            .to_path_buf()
    } else {
        start
    };

    loop {
        if current.join("package.json").exists() {
            return Ok(current);
        }
        if !current.pop() {
            break;
        }
    }

    anyhow::bail!("Could not find package.json in current directory or any parent directories");
}

async fn suppress_runtime_banner(runtime: &runtime::Runtime) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = runtime;
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        runtime
            .engine()
            .eval_immediate("globalThis.__exactSuppressRuntimeBanner = true;")
            .await?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct RunFileOptions<'a> {
    inspect: bool,
    inspect_wait: bool,
    inspect_open: bool,
    inspect_pause: bool,
    keep_alive: bool,
    inspect_port: Option<u16>,
    inspect_host: Option<&'a str>,
}

/// Runtime ownership crosses the file adapter's restore/broker barrier so no
/// inspector shutdown or runtime destructor can run while fd 1/fd 2 are still
/// captured. The program cause is already settled and travels independently.
/// @ref LLP 0025#5-terminal-presentation-and-restoration
struct CapturedFileProgramExecution {
    runtime: runtime::Runtime,
    settlement: Result<()>,
    deferred_diagnostics: Vec<String>,
}

fn emit_file_program_diagnostic(
    port: &terminal_session::FileProgramDiagnosticPort,
    deferred: &mut Vec<String>,
    prefix: &str,
    detail: &str,
) {
    if matches!(
        port.diagnostic(prefix, detail),
        terminal_session::FileProgramDiagnosticDisposition::Deferred
    ) {
        deferred.push(format!("{prefix}{detail}"));
    }
}

fn effective_run_cli(cli: &Cli, options: RunFileOptions<'_>) -> Cli {
    let mut effective = cli.clone();
    effective.inspect |= options.inspect;
    effective.inspect_wait |= options.inspect_wait;
    effective.inspect_open |= options.inspect_open;
    effective.inspect_pause |= options.inspect_pause;
    effective.inspect_port = options.inspect_port.or(effective.inspect_port);
    effective.inspect_host = options
        .inspect_host
        .map(str::to_owned)
        .or(effective.inspect_host);
    effective
}

/// Run a JavaScript/TypeScript file
async fn run_file(
    cli: &Cli,
    file: &str,
    args: &[String],
    options: RunFileOptions<'_>,
    session_io: terminal_session::SessionIoPlan,
    diagnostics: terminal_session::FileProgramDiagnosticPort,
    interrupt_cancellation: terminal_session::DirectExecutionCancellationRegistration,
) -> Result<CapturedFileProgramExecution> {
    let t0 = std::time::Instant::now();
    // `run` owns a second set of inspector flags for Node-compatible argument
    // placement. Fold those into the configuration authenticated by armed
    // startup so subcommand spelling cannot bypass the closed inspector route.
    // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
    let effective_cli = effective_run_cli(cli, options);
    let runtime = runtime::Runtime::from_cli_with_session(&effective_cli, session_io)?;
    interrupt_cancellation
        .register(runtime.engine())
        .map_err(|_| anyhow::anyhow!("file execution interrupt engine was already registered"))?;
    let mut deferred_diagnostics = Vec::new();
    let settlement = async {
        if trace_startup() {
            emit_file_program_diagnostic(
                &diagnostics,
                &mut deferred_diagnostics,
                "",
                &format!(
                    "[startup] {:<30} {:>6} us ({:>5.1} ms)",
                    "runtime_from_cli",
                    t0.elapsed().as_micros(),
                    t0.elapsed().as_micros() as f64 / 1000.0
                ),
            );
        }

        suppress_runtime_banner(&runtime).await?;

        // Load the runtime bundle first
        let t1 = std::time::Instant::now();
        runtime.load_runtime().await?;
        if trace_startup() {
            emit_file_program_diagnostic(
                &diagnostics,
                &mut deferred_diagnostics,
                "",
                &format!(
                    "[startup] {:<30} {:>6} us ({:>5.1} ms)",
                    "load_runtime",
                    t1.elapsed().as_micros(),
                    t1.elapsed().as_micros() as f64 / 1000.0
                ),
            );
        }

        // Set up inspector if requested.
        let inspect_enabled = options.inspect
            || options.inspect_wait
            || options.inspect_open
            || options.inspect_pause
            || cli.inspect
            || cli.inspect_wait
            || cli.inspect_open
            || cli.inspect_pause;
        let open_devtools = options.inspect_open || cli.inspect_open;
        // Wait for debugger if explicitly requested, or if we opened DevTools
        // (since opening DevTools implies wanting to debug before code runs).
        let wait_for_debugger = options.inspect_wait
            || cli.inspect_wait
            || options.inspect_pause
            || cli.inspect_pause
            || open_devtools;
        if inspect_enabled {
            let host = options
                .inspect_host
                .or(cli.inspect_host.as_deref())
                .unwrap_or("127.0.0.1");
            let port = options.inspect_port.or(cli.inspect_port).unwrap_or(9229);
            runtime.start_inspector(host, port).await?;
            emit_file_program_diagnostic(
                &diagnostics,
                &mut deferred_diagnostics,
                "",
                &format!("Debugger listening on ws://{host}:{port}"),
            );
            emit_file_program_diagnostic(
                &diagnostics,
                &mut deferred_diagnostics,
                "",
                "For help, see: https://nodejs.org/en/guides/debugging-getting-started",
            );
            emit_file_program_diagnostic(
                &diagnostics,
                &mut deferred_diagnostics,
                "",
                &format!("DevTools URL: {}", devtools_url(host, port)),
            );
            if open_devtools {
                open_devtools_for_port(port);
            }
            if wait_for_debugger {
                emit_file_program_diagnostic(
                    &diagnostics,
                    &mut deferred_diagnostics,
                    "",
                    "Waiting for debugger to attach...",
                );
                runtime.wait_for_inspector().await?;
                emit_file_program_diagnostic(
                    &diagnostics,
                    &mut deferred_diagnostics,
                    "",
                    "Debugger attached.",
                );
                // Also wait for the Debugger domain to be enabled.
                runtime.wait_for_debugger().await?;
            }
        }

        if options.inspect_pause || cli.inspect_pause {
            runtime.pause_inspector().await?;
        }

        // Run the user's file through the authenticated settlement path. Its
        // lifecycle and failure statuses remain distinct from orderly exitCode.
        let _authenticated_at_construction = file;
        let mut file_outcome = runtime.run_authenticated_file_program(args).await;

        // @ref LLP 0013#phase-1 — surface would-deny decisions collected in
        // audit mode so operators see exactly what to declare before enforcing.
        if let Some(report) = crate::host::abi::current_audit_report() {
            emit_file_program_diagnostic(
                &diagnostics,
                &mut deferred_diagnostics,
                "capsec audit: ",
                &report,
            );
        }

        if matches!(
            &file_outcome,
            Ok(runtime::AuthenticatedFileProgramOutcome::Completed)
        ) && (options.keep_alive || cli.keep_alive)
        {
            emit_file_program_diagnostic(
                &diagnostics,
                &mut deferred_diagnostics,
                "",
                "Press Ctrl+C to exit.",
            );
            if let Some(outcome) = run_debug_loop(&runtime).await {
                file_outcome = Ok(outcome);
            }
        }

        match file_outcome {
            Err(error) => Err(error),
            Ok(runtime::AuthenticatedFileProgramOutcome::Completed) => process_exit_code(&runtime)
                .map_or(Ok(()), |code| {
                    Err(anyhow::Error::new(ProgramRequestedExit { code }))
                }),
            Ok(runtime::AuthenticatedFileProgramOutcome::Lifecycle {
                status,
                secondary_diagnostics,
            }) => {
                for diagnostic in secondary_diagnostics {
                    emit_file_program_diagnostic(
                        &diagnostics,
                        &mut deferred_diagnostics,
                        "",
                        &diagnostic,
                    );
                }
                Err(anyhow::Error::new(ProgramRequestedExit { code: status }))
            }
            Ok(runtime::AuthenticatedFileProgramOutcome::Failed { status, diagnostic }) => {
                Err(anyhow::Error::new(ProgramExecutionFailure {
                    code: status,
                    diagnostic,
                }))
            }
        }
    }
    .await;

    Ok(CapturedFileProgramExecution {
        runtime,
        settlement,
        deferred_diagnostics,
    })
}

/// Keep the non-forgeable file-adapter readiness lease alive across runtime
/// construction, user-code execution, descriptor restoration, and bounded
/// broker completion. A file run is successful only if both the runtime and
/// the broker complete without unaccounted output loss.
// @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker — file
// execution owns fd 1/fd 2 through one adapter lifetime and reports forced loss.
async fn run_file_with_execution_adapter(
    cli: &Cli,
    file: &str,
    args: &[String],
    options: RunFileOptions<'_>,
    session_io: terminal_session::SessionIoPlan,
) -> Result<()> {
    if authenticated_product_ingress(session_io.route)
        != Some(AuthenticatedProductIngress::FileProgram)
    {
        anyhow::bail!("file route did not select the authenticated file ingress");
    }
    let adapter = terminal_session::FileProgramExecutionAdapter::new(session_io)
        .context("failed to activate the secure file execution adapter")?;
    let (execution, finish) = adapter
        .run_with_diagnostics_and_interrupt(|diagnostics, interrupt_cancellation| {
            run_file(
                cli,
                file,
                args,
                options,
                session_io,
                diagnostics,
                interrupt_cancellation,
            )
        })
        .await
        .context("secure file execution adapter failed")?;
    let (runtime, mut execution, deferred_diagnostics) = match execution {
        Ok(execution) => (
            Some(execution.runtime),
            execution.settlement,
            execution.deferred_diagnostics,
        ),
        Err(error) => (None, Err(error), Vec::new()),
    };
    execution = match finish {
        Ok(report) => apply_file_broker_loss(
            execution,
            file_program_loss_detail(&report),
            report.loss_report_destinations(),
        ),
        Err(error) => apply_file_adapter_finish_error(execution, error),
    };
    execution = deferred_diagnostics
        .into_iter()
        .fold(execution, |execution, diagnostic| {
            apply_file_broker_loss(
                execution,
                Some(format!(
                    "active file output broker refused a session diagnostic: {diagnostic}"
                )),
                [
                    Some(terminal_session::NativeOutputDestination::Stderr),
                    Some(terminal_session::NativeOutputDestination::Stdout),
                ],
            )
        });

    let Some(runtime) = runtime else {
        return execution;
    };
    // The adapter has restored fd 1/fd 2 and finished its bounded broker
    // barrier. Inspector shutdown may now block safely; it still cannot
    // replace the program settlement or its output-loss disposition.
    // The CDP thread holds a raw runtime pointer, so stop it before drop.
    // @ref LLP 0025#5-terminal-presentation-and-restoration
    let inspector_cleanup = runtime.stop_inspector().await;
    preserve_file_settlement_after_inspector_cleanup(execution, inspector_cleanup)
}

/// A script that sets `process.exitCode` and returns must exit with that code.
/// The setter mirrors into the supervisor-owned lifecycle port synchronously,
/// so the process never re-enters JavaScript to discover its final status.
fn process_exit_code(runtime: &runtime::Runtime) -> Option<i32> {
    let code = runtime.lifecycle_exit_code();
    (code != 0).then_some(code)
}

/// The separately named `capsec audit` workflow is intentionally unarmed and
/// retains the historical Node-shaped JavaScript exitCode accessor. It has no
/// authenticated lifecycle setter to populate the Host mirror, so only this
/// diagnostic compatibility route may read the local value after execution.
/// Production callers use `process_exit_code` above and never re-enter JS.
async fn read_diagnostic_process_exit_code(runtime: &runtime::Runtime) -> Option<i32> {
    let result = runtime
        .engine()
        .eval_immediate(
            "(typeof globalThis.process === 'object' && globalThis.process !== null && \
             typeof globalThis.process.exitCode === 'number') \
             ? String(globalThis.process.exitCode) : ''",
        )
        .await
        .ok()??;
    result.trim().parse::<i32>().ok().filter(|code| *code != 0)
}

/// Run a file in watch mode — re-run on file changes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchTrigger {
    Restart,
    WatcherClosed,
    Interrupt,
}

async fn run_watch(cli: &Cli, file: &str, args: &[String]) -> Result<()> {
    use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
    use std::time::Duration;
    use tokio::sync::mpsc;

    let file_path = std::path::Path::new(file)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(file));
    let watch_dir = file_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    // Install before publishing readiness: a test or operator that observes
    // the banner can then rely on mediation already being active.
    let mut interrupt = LauncherInterrupt::install()?;

    eprintln!(
        "\x1b[2m[watch]\x1b[0m watching for changes in {}",
        watch_dir.display()
    );

    let shutdown_timeout = watch_shutdown_timeout();
    let debounce = Duration::from_millis(300);

    // Create the watcher ONCE and keep it alive across restarts. The old code
    // rebuilt the watcher + channel every iteration, so any change that landed
    // between stopping the old child and re-arming the watcher was lost. (ENG-22958)
    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        Config::default().with_poll_interval(Duration::from_millis(200)),
    )
    .context("Failed to create file watcher")?;
    watcher
        .watch(watch_dir, RecursiveMode::Recursive)
        .context("Failed to watch directory")?;

    loop {
        // Run the file in a child process so we can kill it on change
        let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("ibex"));
        let mut cmd = tokio::process::Command::new(&exe);
        for flag in watch_child_args(cli) {
            cmd.arg(flag);
        }
        cmd.arg("run").arg(file);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.stdin(std::process::Stdio::inherit());
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());

        let mut child = cmd.spawn().context("Failed to spawn child process")?;

        let trigger = await_restart_trigger(&mut child, &mut rx, debounce, &mut interrupt).await;
        // A group SIGINT already reached the direct-execution child. Preserve
        // its own restoration/broker guarantee before the controller falls
        // back to TERM/kill. Non-interrupt triggers retain normal watch-stop
        // behavior.
        if trigger == WatchTrigger::Interrupt {
            match stop_watch_child_after_interrupt(&mut child, shutdown_timeout).await {
                Ok(WatchInterruptCleanup::Reaped(status)) => {
                    if status.code() != Some(128 + libc::SIGINT) {
                        emit_pre_session_diagnostic(
                            "watch child exited with an unexpected status during SIGINT grace: ",
                            &status.to_string(),
                        );
                    }
                }
                Ok(WatchInterruptCleanup::Fallback) => {}
                Err(error) => {
                    emit_pre_session_diagnostic(
                        "watch child cleanup after SIGINT failed: ",
                        &format!("{error:#}"),
                    );
                }
            }
            return Err(anyhow::Error::new(ProgramRequestedExit {
                code: 128 + libc::SIGINT,
            }));
        }

        stop_watch_child(&mut child, shutdown_timeout).await?;
        match trigger {
            WatchTrigger::Restart => {}
            WatchTrigger::WatcherClosed => break,
            WatchTrigger::Interrupt => unreachable!("interrupt returned above"),
        }
    }

    Ok(())
}

/// Block until watch mode should restart the child.
///
/// Trailing-edge debounce (ENG-22958): after the first relevant change,
/// coalesce further relevant changes and only restart once the filesystem has
/// been quiet for `debounce`. The old leading-edge check *discarded* any change
/// arriving within the window (`if last_change.elapsed() < debounce { continue }`),
/// so a format-on-save write landing shortly after a restart left the new child
/// running stale code until the next manual save. Here that trailing write is
/// deferred, never dropped — each relevant change extends the quiet window, so
/// the restarted child always sees the final file contents.
///
/// If the child exits on its own first, wait for the next relevant change before
/// restarting. Returns `false` only if the watch channel closed (watcher gone),
/// signalling the caller to stop watching.
async fn await_restart_trigger(
    child: &mut tokio::process::Child,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<notify::Event>,
    debounce: std::time::Duration,
    interrupt: &mut LauncherInterrupt,
) -> WatchTrigger {
    use std::time::Instant;

    // Phase 1: wait for the first trigger — a relevant change or the child
    // exiting on its own. `child_running` disables the exit arm after the child
    // is reaped so we keep waiting for a change instead of re-polling `wait()`.
    let mut child_running = true;
    loop {
        tokio::select! {
            status = child.wait(), if child_running => {
                child_running = false;
                match status {
                    Ok(status) => {
                        let code = status.code().unwrap_or(0);
                        if code != 0 {
                            eprintln!(
                                "\x1b[31m[watch]\x1b[0m process exited with code {}",
                                code
                            );
                        }
                        eprintln!("\x1b[2m[watch]\x1b[0m waiting for changes...");
                        // Keep looping — the change arm below drives the restart.
                    }
                    Err(e) => {
                        eprintln!("\x1b[31m[watch]\x1b[0m error: {}", e);
                        return WatchTrigger::Restart;
                    }
                }
            }
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else { return WatchTrigger::WatcherClosed; };
                if is_relevant_change(&event) {
                    break;
                }
            }
            listener_open = interrupt.recv() => {
                return if listener_open {
                    WatchTrigger::Interrupt
                } else {
                    WatchTrigger::WatcherClosed
                };
            }
        }
    }

    // Phase 2: a relevant change arrived. Coalesce a burst (format-on-save,
    // multi-file writes) by extending a quiet window on each further relevant
    // change; restart only once it elapses. Irrelevant events don't extend it.
    let mut deadline = Instant::now() + debounce;
    loop {
        let now = Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            break;
        };
        tokio::select! {
            _ = tokio::time::sleep(remaining) => break,
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else {
                    return WatchTrigger::WatcherClosed;
                };
                if is_relevant_change(&event) {
                    deadline = Instant::now() + debounce;
                }
            }
            listener_open = interrupt.recv() => {
                return if listener_open {
                    WatchTrigger::Interrupt
                } else {
                    WatchTrigger::WatcherClosed
                };
            }
        }
    }

    eprintln!("\x1b[33m[watch]\x1b[0m change detected, restarting...");
    WatchTrigger::Restart
}

/// Reconstruct the global flag set for the watch child. The child previously
/// received only `--engine`, silently dropping `--capsec`/`--allow`/`--deny`
/// and the rest. `--watch` itself and `--keep-alive` are intentionally
/// excluded: the watch loop owns the child's lifecycle.
fn watch_child_args(cli: &Cli) -> Vec<String> {
    let mut flags = vec!["--engine".to_string(), cli.engine.clone()];

    match cli.capsec {
        // Auto is the default — forward nothing so the child also defers to policy.
        cli::CapSecMode::Auto => {}
        cli::CapSecMode::Permissive => flags.extend(["--capsec".into(), "permissive".into()]),
        cli::CapSecMode::Audit => flags.extend(["--capsec".into(), "audit".into()]),
        cli::CapSecMode::Enforce => flags.extend(["--capsec".into(), "enforce".into()]),
    }
    if cli.lockdown {
        flags.push("--lockdown".into());
    }
    if let Some(policy) = &cli.policy {
        flags.extend(["--policy".into(), policy.to_string_lossy().into_owned()]);
    }
    if let Some(snapshot) = &cli.capsec_armed_snapshot {
        flags.extend([
            "--capsec-armed-snapshot".into(),
            snapshot.to_string_lossy().into_owned(),
        ]);
    }
    if let Some(identity) = &cli.capsec_arming_identity {
        flags.extend([
            "--capsec-arming-identity".into(),
            identity.to_string_lossy().into_owned(),
        ]);
    }
    for allow in &cli.allow {
        flags.extend(["--allow".into(), allow.clone()]);
    }
    for deny in &cli.deny {
        flags.extend(["--deny".into(), deny.clone()]);
    }
    if cli.allow_all {
        flags.push("--allow-all".into());
    }
    // @ref LLP 0013#mechanism-2 — (ENG-22684) — the env-endowment escape hatch must
    // reach the watch child, else an enforce-mode restart would drop IBEX_ENDOW
    // the parent honored, silently changing behavior across a reload.
    if cli.allow_env_endowments {
        flags.push("--allow-env-endowments".into());
    }
    if cli.capsec_allow_advisory {
        flags.push("--capsec-allow-advisory".into());
    }
    if cli.bundle_format != cli::BundleFormat::Esm {
        flags.extend(["--bundle-format".into(), cli.bundle_format.as_str().into()]);
    }
    if cli.inspect {
        flags.push("--inspect".into());
    }
    if cli.inspect_wait {
        flags.push("--inspect-wait".into());
    }
    if cli.inspect_open {
        flags.push("--inspect-open".into());
    }
    if cli.inspect_pause {
        flags.push("--inspect-pause".into());
    }
    if let Some(port) = cli.inspect_port {
        flags.extend(["--inspect-port".into(), port.to_string()]);
    }
    if let Some(host) = &cli.inspect_host {
        flags.extend(["--inspect-host".into(), host.clone()]);
    }
    // Opt-in compat surfaces and the hidden compat-fidelity flags ride along
    // too (review R1 — `ibex --watch --compat=bun` lost the Bun surface).
    if let Some(compat) = &cli.compat {
        flags.extend(["--compat".into(), compat.clone()]);
    }
    if cli.expose_internals {
        flags.push("--expose-internals".into());
    }
    if let Some(stack_size) = &cli.stack_size {
        flags.extend(["--stack-size".into(), stack_size.clone()]);
    }
    if let Some(size) = cli.max_http_header_size {
        flags.extend(["--max-http-header-size".into(), size.to_string()]);
    }

    flags
}

fn is_relevant_change(event: &notify::Event) -> bool {
    use notify::EventKind;
    match &event.kind {
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
            // Only restart for relevant file types
            event.paths.iter().any(|p| {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                matches!(
                    ext,
                    "js" | "ts" | "tsx" | "jsx" | "mjs" | "cjs" | "json" | "css" | "html"
                )
            })
        }
        _ => false,
    }
}

/// Run an event loop that allows debugger interactions while keeping the process
/// alive. It drives the runtime's event loop each tick so DevTools
/// `Runtime.evaluate` and timers scheduled from DevTools actually run — the old
/// loop only ticked a counter and never polled, so those hung. (ENG-22958)
async fn run_debug_loop(
    runtime: &runtime::Runtime,
) -> Option<runtime::AuthenticatedFileProgramOutcome> {
    use tokio::sync::mpsc;
    use tokio::time::{interval, Duration, Instant};

    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<()>();

    let tx = shutdown_tx.clone();
    let ctrl_handle = tokio::spawn(async move {
        loop {
            if tokio::signal::ctrl_c().await.is_err() {
                break;
            }
            let _ = tx.send(());
        }
    });

    #[cfg(unix)]
    let terminate_handle = if let Ok(mut signal) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        let tx = shutdown_tx.clone();
        Some(tokio::spawn(async move {
            while signal.recv().await.is_some() {
                let _ = tx.send(());
            }
        }))
    } else {
        None
    };

    let mut shutdown_requests = 0u8;
    let mut force_deadline: Option<Instant> = None;
    let mut ticker = interval(Duration::from_millis(50));

    const SHUTDOWN_FORCE_DELAY_MS: u64 = 5_000;

    let stop_signal_watchers = || {
        ctrl_handle.abort();
        #[cfg(unix)]
        if let Some(handle) = terminate_handle.as_ref() {
            handle.abort();
        }
    };

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Drive the runtime's event loop so DevTools evaluations and
                // timers scheduled from DevTools run while we stay alive.
                if let Some(outcome) = runtime
                    .settle_authenticated_file_keep_alive_tick()
                    .await
                {
                    stop_signal_watchers();
                    return Some(outcome);
                }
                if shutdown_requests == 0 {
                    continue;
                }
                let active = crate::host::http_server::ex_host_http_has_referenced() != 0
                    || crate::host::http_server::ex_host_http_has_pending_requests() != 0;
                if !active {
                    stop_signal_watchers();
                    break;
                }
                if let Some(deadline) = force_deadline {
                    if Instant::now() >= deadline {
                        let _ = crate::host::http_server::close_all_http_servers(1);
                        stop_signal_watchers();
                        break;
                    }
                }
            }
            signal = shutdown_rx.recv() => {
                match signal {
                    Some(()) => {
                        shutdown_requests = shutdown_requests.saturating_add(1);
                        if shutdown_requests == 1 {
                            let active = crate::host::http_server::close_all_http_servers(0);
                            if active == 0 {
                                stop_signal_watchers();
                                break;
                            }
                            force_deadline = Some(
                                Instant::now() + Duration::from_millis(SHUTDOWN_FORCE_DELAY_MS),
                            );
                        } else {
                            let _ = crate::host::http_server::close_all_http_servers(1);
                            stop_signal_watchers();
                            break;
                        }
                    }
                    None => {
                        stop_signal_watchers();
                        break;
                    }
                }
            }
        }
    }
    None
}

/// Evaluate a one-liner JavaScript expression
async fn eval_code(
    cli: &Cli,
    code: &str,
    print_result: bool,
    session_io: terminal_session::SessionIoPlan,
) -> Result<()> {
    if authenticated_product_ingress(session_io.route)
        != Some(AuthenticatedProductIngress::InlineOneShot)
    {
        anyhow::bail!("eval route did not select the authenticated inline ingress");
    }
    let runtime_t0 = std::time::Instant::now();
    let runtime = runtime::Runtime::from_cli_with_session(cli, session_io)?;
    if trace_startup() {
        eprintln!(
            "[startup] {:<30} {:>6} us ({:>5.1} ms)",
            "eval_runtime_from_cli",
            runtime_t0.elapsed().as_micros(),
            runtime_t0.elapsed().as_micros() as f64 / 1000.0
        );
    }
    let suppress_t0 = std::time::Instant::now();
    suppress_runtime_banner(&runtime).await?;
    if trace_startup() {
        eprintln!(
            "[startup] {:<30} {:>6} us ({:>5.1} ms)",
            "eval_engine_initialize",
            suppress_t0.elapsed().as_micros(),
            suppress_t0.elapsed().as_micros() as f64 / 1000.0
        );
    }
    let load_t0 = std::time::Instant::now();
    runtime.load_runtime().await?;
    if trace_startup() {
        eprintln!(
            "[startup] {:<30} {:>6} us ({:>5.1} ms)",
            "eval_load_runtime",
            load_t0.elapsed().as_micros(),
            load_t0.elapsed().as_micros() as f64 / 1000.0
        );
        eprintln!(
            "[startup] {:<30} {:>6} us ({:>5.1} ms)",
            "eval_ready_from_cli",
            runtime_t0.elapsed().as_micros(),
            runtime_t0.elapsed().as_micros() as f64 / 1000.0
        );
    }
    configure_session_inspector(cli, &runtime).await?;

    // The adapter owns descriptors 1/2 for the complete source/result
    // transaction and obtains its request from AuthenticatedInlineIngress.
    // Source bytes are the only caller-controlled request field; no wrapper,
    // raw evaluator, mutable require alias, or caller-selected referrer crosses
    // this boundary.
    // @ref LLP 0024#1-the-in-memory-source-api
    let user_code_t0 = std::time::Instant::now();
    let presentation = if print_result {
        terminal_session::InlineResultPresentation::Print
    } else {
        terminal_session::InlineResultPresentation::Suppress
    };
    let status = terminal_session::run_authenticated_inline_execution_adapter(
        &runtime,
        code.as_bytes().to_vec(),
        presentation,
    )
    .await?;
    if trace_startup() {
        eprintln!(
            "[startup] {:<30} {:>6} us ({:>5.1} ms)",
            "eval_user_code",
            user_code_t0.elapsed().as_micros(),
            user_code_t0.elapsed().as_micros() as f64 / 1000.0
        );
    }
    status_result(status)
}

/// Consume at most one byte past the generated input bound. Passing that
/// sentinel byte into the authenticated ingress produces the same typed
/// `InputTooLarge` refusal as every other in-memory source without allocating
/// an attacker-selected amount of memory or pre-decoding UTF-8.
fn read_program_stdin_bounded() -> Result<Vec<u8>> {
    read_program_source_bounded(std::io::stdin().lock())
}

fn read_program_source_bounded(mut reader: impl std::io::Read) -> Result<Vec<u8>> {
    use std::io::Read;

    let max = ibex_runtime::session_constants::MAX_INPUT_BYTES;
    let limit = max
        .checked_add(1)
        .context("session input bound cannot represent its refusal sentinel")?;
    let mut source = Vec::with_capacity(limit.min(64 * 1024));
    reader
        .by_ref()
        .take(limit as u64)
        .read_to_end(&mut source)
        .context("failed to read program source from stdin")?;
    Ok(source)
}

/// Execute implicit non-TTY stdin as one authenticated ESM program. The
/// session plan was captured before arming, so this function neither re-probes
/// TTY state nor lets JavaScript reopen the source descriptor.
/// @ref LLP 0022#3-input-modes
/// @ref LLP 0024#1-the-in-memory-source-api
async fn run_stdin_program(cli: &Cli, session_io: terminal_session::SessionIoPlan) -> Result<()> {
    if authenticated_product_ingress(session_io.route)
        != Some(AuthenticatedProductIngress::WorkerProgram)
    {
        anyhow::bail!("program-stdin route did not select the authenticated worker ingress");
    }
    let source = read_program_stdin_bounded()?;
    #[cfg(unix)]
    {
        let spawned = session_worker_runtime::spawn_session_worker(cli, session_io)?;
        let (program, relays) = spawned.into_remote_program();
        let status = terminal_session::run_worker_program_execution_adapter(
            session_io, program, relays, source,
        )
        .await?;
        status_result(status)
    }
    #[cfg(not(unix))]
    {
        let _ = (cli, session_io, source);
        anyhow::bail!(
            "secure program-stdin workers are not yet available on this target; refusing an in-process fallback"
        )
    }
}

fn status_result(status: i32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(ProgramRequestedExit { code: status }.into())
    }
}

async fn configure_session_inspector(cli: &Cli, runtime: &runtime::Runtime) -> Result<()> {
    if !(cli.inspect || cli.inspect_wait || cli.inspect_open || cli.inspect_pause) {
        return Ok(());
    }
    let host = cli.inspect_host.as_deref().unwrap_or("127.0.0.1");
    let port = cli.inspect_port.unwrap_or(9229);
    runtime.start_inspector(host, port).await?;
    eprintln!("Debugger listening on ws://{}:{}", host, port);
    eprintln!("For help, see: https://nodejs.org/en/guides/debugging-getting-started");
    eprintln!("DevTools URL: {}", devtools_url(host, port));
    if cli.inspect_open {
        open_devtools_for_port(port);
    }
    if cli.inspect_wait || cli.inspect_pause || cli.inspect_open {
        eprintln!("Waiting for debugger to attach...");
        runtime.wait_for_inspector().await?;
        eprintln!("Debugger attached.");
        runtime.wait_for_debugger().await?;
    }
    if cli.inspect_pause {
        runtime.pause_inspector().await?;
    }
    Ok(())
}

/// Start the interactive REPL
async fn start_repl(cli: &Cli, session_io: terminal_session::SessionIoPlan) -> Result<()> {
    if authenticated_product_ingress(session_io.route)
        != Some(AuthenticatedProductIngress::WorkerRepl)
    {
        anyhow::bail!("REPL route did not select the authenticated worker ingress");
    }
    // The supervisor owns stdin, terminal state, history, output, signals, and
    // final disposition. Hermes exists only in the authenticated worker, so a
    // stuck/native-exiting engine cannot bypass restoration or consume the
    // operator's next command.
    // @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker
    #[cfg(unix)]
    {
        let status = repl::start_worker(cli, session_io).await?;
        status_result(status)
    }
    #[cfg(not(unix))]
    {
        let _ = (cli, session_io);
        anyhow::bail!(
            "secure REPL workers are not yet available on this target; refusing an in-process fallback"
        )
    }
}

/// Compile a file to Hermes bytecode
async fn build_bytecode(cli: &Cli, file: &str, outdir: Option<&std::path::Path>) -> Result<()> {
    if cli.engine != "hermes" {
        anyhow::bail!("build command is only supported for the Hermes engine");
    }

    // Apply the same enforce/audit isolation prerequisite the run path applies,
    // so a build under an enforce policy produces a per-package-chunked artifact
    // (each dependency in its own Domain/principal) instead of a flat,
    // single-principal bundle that attributes every dependency to trusted root.
    // Sets IBEX_PER_PACKAGE_CHUNKS before bundling so the bundler chunks and the
    // cache key agrees. @ref LLP 0013#mechanism-3 — (ENG-22760)
    runtime::apply_build_isolation(cli)?;

    let output_path = runtime::compute_build_output(file, outdir)?;
    let map_path = output_path.with_extension("hbc.map");
    // hermesc doesn't support ESM — always use CJS for bytecode compilation
    let format = if cli.bundle_format == crate::cli::BundleFormat::Esm {
        crate::cli::BundleFormat::Cjs
    } else {
        cli.bundle_format
    };
    let runtime_cache = runtime::authenticate_build_runtime_cache(cli, file)?;
    let bundled =
        runtime::prepare_entry_for_bytecode_build_in_cache(file, format, &runtime_cache).await?;
    let _bundle_lease = runtime::acquire_bundle_execution_lease(&bundled).await?;
    let bundled_str = bundled.to_string_lossy().to_string();

    engine::hermes::compile_to_bytecode(&bundled_str, &output_path, Some(&map_path)).await?;

    // Under per-package chunking the entry bundle requires sibling chunk files
    // (`__ibexpkg__*`, `rolldown-runtime.js`) that live in the bundle cache dir,
    // not next to the built `.hbc`. The run path resolves them against the
    // artifact's own directory (`__exactChunkDir`), so ship them alongside the
    // `.hbc` — otherwise the built artifact silently loses per-package
    // attribution (a flat single-Domain run). @ref LLP 0013#mechanism-3 — (ENG-22760)
    if let Some(dest_dir) = output_path.parent() {
        let copied = runtime::ship_chunk_siblings(&bundled, dest_dir)?;
        if copied > 0 {
            println!(
                "Shipped {} per-package chunk file(s) alongside {}",
                copied,
                output_path.display()
            );
        }
    }

    println!("Compiled {} -> {}", file, output_path.display());
    Ok(())
}

/// Print version information
fn print_version(cli: &Cli) {
    println!("ibex {} ({})", env!("CARGO_PKG_VERSION"), cli.engine);
    println!("Ibex - JavaScript Runtime");

    // Print engine-specific version
    if cli.engine == "hermes" {
        if let Ok(version) = engine::hermes::get_version() {
            println!("Hermes: {}", version);
        }
    }
}

fn print_completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "ibex", &mut std::io::stdout());
}

fn devtools_url(host: &str, port: u16) -> String {
    format!(
        "devtools://devtools/bundled/inspector.html?ws={}:{}/",
        host, port
    )
}

fn open_devtools_for_port(port: u16) {
    let devtools_url = devtools_url("127.0.0.1", port);
    let inspect_url = "chrome://inspect/#devices";
    let json_url = format!("http://127.0.0.1:{}/json", port);

    #[cfg(target_os = "macos")]
    {
        let mut opened = false;
        for app in ["Google Chrome", "Chromium"] {
            if let Ok(status) = std::process::Command::new("open")
                .args(["-a", app, &devtools_url])
                .status()
            {
                if status.success() {
                    opened = true;
                    break;
                }
            }
        }

        if !opened {
            let _ = std::process::Command::new("open").arg(inspect_url).status();
        }

        if !opened {
            eprintln!("Open DevTools manually: {}", devtools_url);
            eprintln!("Or open: {}", inspect_url);
            eprintln!("Or open: {}", json_url);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut opened = false;
        if let Ok(status) = std::process::Command::new("xdg-open")
            .arg(&devtools_url)
            .status()
        {
            opened = status.success();
        }
        if !opened {
            let _ = std::process::Command::new("xdg-open")
                .arg(inspect_url)
                .status();
        }
        if !opened {
            eprintln!("Open DevTools manually: {}", devtools_url);
            eprintln!("Or open: {}", inspect_url);
            eprintln!("Or open: {}", json_url);
        }
    }
    #[cfg(target_os = "windows")]
    {
        let mut opened = false;
        if let Ok(status) = std::process::Command::new("cmd")
            .args(["/C", "start", &devtools_url])
            .status()
        {
            opened = status.success();
        }
        if !opened {
            let _ = std::process::Command::new("cmd")
                .args(["/C", "start", inspect_url])
                .status();
        }
        if !opened {
            eprintln!("Open DevTools manually: {}", devtools_url);
            eprintln!("Or open: {}", inspect_url);
            eprintln!("Or open: {}", json_url);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{
        apply_file_adapter_finish_error, apply_file_broker_loss_disposition,
        authenticated_product_ingress, cli, effective_run_cli, escape_pre_session_diagnostic,
        exit_code_for_error, is_program_requested_exit,
        preserve_file_settlement_after_inspector_cleanup, read_program_source_bounded,
        stop_watch_child_after_interrupt, watch_child_args, watch_shutdown_timeout_from_env,
        AuthenticatedProductIngress, LauncherInterrupt, ProgramExecutionFailure,
        ProgramRequestedExit, RunFileOptions, DEFAULT_WATCH_SHUTDOWN_TIMEOUT_MS,
        EXACT_PROJECT_COMMANDS, RESERVED_RUNTIME_COMMANDS,
    };
    use clap::Parser;

    #[cfg(unix)]
    unsafe extern "C" fn launcher_signal_restore_sentinel(_: libc::c_int) {}

    #[cfg(unix)]
    fn query_signal_action(signal: libc::c_int) -> libc::sigaction {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: a null replacement queries the current action into action.
        assert_eq!(
            unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) },
            0
        );
        action
    }

    #[cfg(unix)]
    struct SignalActionReset {
        signal: libc::c_int,
        action: libc::sigaction,
    }

    #[cfg(unix)]
    impl Drop for SignalActionReset {
        fn drop(&mut self) {
            // SAFETY: action was returned by sigaction for this signal.
            unsafe {
                libc::sigaction(self.signal, &self.action, std::ptr::null_mut());
            }
        }
    }

    // @ref LLP 0025#1-modes-descriptors-and-topology
    #[cfg(unix)]
    #[test]
    fn launcher_interrupt_drop_restores_prior_and_rejects_reinstallation() {
        const CHILD: &str = "IBEX_TEST_LAUNCHER_ONE_SHOT_SIGNAL_CHILD";
        if std::env::var_os(CHILD).is_some() {
            // Use SIGUSR2 so this disposition test cannot interfere with the
            // test harness's own SIGINT behavior. Production calls the same
            // installer with SIGINT.
            let signal = libc::SIGUSR2;
            let mut sentinel: libc::sigaction = unsafe { std::mem::zeroed() };
            sentinel.sa_sigaction = launcher_signal_restore_sentinel as *const () as usize;
            sentinel.sa_flags = libc::SA_RESTART;
            assert_eq!(unsafe { libc::sigemptyset(&mut sentinel.sa_mask) }, 0);
            assert_eq!(
                unsafe { libc::sigaddset(&mut sentinel.sa_mask, libc::SIGTERM) },
                0
            );
            let mut original: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sigaction(signal, &sentinel, &mut original) },
                0
            );
            let _reset = SignalActionReset {
                signal,
                action: original,
            };
            let expected = query_signal_action(signal);

            let guard = LauncherInterrupt::install_for_signal(signal).unwrap();
            assert_ne!(
                query_signal_action(signal).sa_sigaction,
                expected.sa_sigaction,
                "launcher mediation did not replace the prior action"
            );
            drop(guard);

            let restored = query_signal_action(signal);
            assert_eq!(restored.sa_sigaction, expected.sa_sigaction);
            assert_eq!(restored.sa_flags, expected.sa_flags);
            assert_eq!(
                unsafe { libc::sigismember(&restored.sa_mask, libc::SIGTERM) },
                unsafe { libc::sigismember(&expected.sa_mask, libc::SIGTERM) }
            );
            let reinstall = LauncherInterrupt::install_for_signal(signal);
            assert!(matches!(
                reinstall,
                Err(ref error) if error.kind() == std::io::ErrorKind::AlreadyExists
            ));
            std::process::exit(0);
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::launcher_interrupt_drop_restores_prior_and_rejects_reinstallation",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "one-shot launcher signal child failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn pre_session_diagnostic_payload_is_one_terminal_safe_line() {
        let escaped = escape_pre_session_diagnostic(
            "ordinary \x1b[31mred\nnext\r\t\u{0085}\u{2028}\u{202e}spoof\u{2066} text",
        );
        assert_eq!(
            escaped,
            "ordinary \\u{001b}[31mred\\u{000a}next\\u{000d}\\u{0009}\\u{0085}\\u{2028}\\u{202e}spoof\\u{2066} text"
        );
        assert!(!escaped.chars().any(char::is_control));
    }

    #[test]
    fn run_subcommand_inspector_configuration_reaches_armed_validation() {
        let cli = cli::Cli::parse_from([
            "ibex",
            "--capsec-armed-snapshot",
            "missing-snapshot.json",
            "--capsec-arming-identity",
            "missing-identity.json",
            "run",
            "app.ts",
        ]);
        let effective = effective_run_cli(
            &cli,
            RunFileOptions {
                inspect: true,
                inspect_wait: false,
                inspect_open: false,
                inspect_pause: false,
                keep_alive: false,
                inspect_port: Some(9230),
                inspect_host: Some("127.0.0.1"),
            },
        );
        assert!(effective.inspect);
        assert_eq!(effective.inspect_port, Some(9230));
        assert_eq!(effective.inspect_host.as_deref(), Some("127.0.0.1"));
        let error = super::runtime::Runtime::from_cli(&effective)
            .err()
            .expect("run-subcommand inspector must be rejected before artifact I/O")
            .to_string();
        assert!(
            error.contains("closes compatibility, inspector")
                && error.contains("runtime-fidelity overrides"),
            "{error}"
        );
        assert!(!error.contains("failed to read"), "{error}");
    }

    /// The pre-clap dispatcher tables must agree with the runtime surface
    /// manifest (`runtime-surface.json`, LLP 0010#runtime-command-surface):
    /// cli.rs::surface_manifest_matches_clap_tree proves the names are absent
    /// from clap; this proves the dispatcher actually owns exactly those names.
    #[test]
    fn dispatcher_tables_match_surface_manifest() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../../runtime-surface.json"))
                .expect("runtime-surface.json parses");
        let names = |key: &str| -> Vec<String> {
            manifest[key]
                .as_array()
                .unwrap_or_else(|| panic!("{key} is an array"))
                .iter()
                .map(|v| v.as_str().expect("string entry").to_string())
                .collect()
        };

        let mut reserved: Vec<String> = RESERVED_RUNTIME_COMMANDS
            .iter()
            .map(|(name, _)| name.to_string())
            .collect();
        reserved.sort();
        let mut manifest_reserved = names("reservedCommands");
        manifest_reserved.sort();
        assert_eq!(reserved, manifest_reserved, "reserved runtime commands");

        let mut legacy: Vec<String> = EXACT_PROJECT_COMMANDS
            .iter()
            .map(|name| name.to_string())
            .collect();
        legacy.sort();
        let mut manifest_legacy = names("legacyProjectCommands");
        manifest_legacy.sort();
        assert_eq!(legacy, manifest_legacy, "legacy Exact project commands");
    }

    #[test]
    fn product_ingress_table_owns_every_authenticated_cli_route() {
        let route = |args: &[&str], stdin_is_tty| {
            super::terminal_session::selected_execution_route(
                &cli::Cli::parse_from(args),
                stdin_is_tty,
            )
            .expect("CLI fixture selects an execution route")
        };
        assert_eq!(
            authenticated_product_ingress(route(&["ibex", "-e", "void 0"], false)),
            Some(AuthenticatedProductIngress::InlineOneShot)
        );
        assert_eq!(
            authenticated_product_ingress(route(&["ibex"], false)),
            Some(AuthenticatedProductIngress::WorkerProgram)
        );
        for args in [&["ibex"][..], &["ibex", "repl"][..]] {
            assert_eq!(
                authenticated_product_ingress(route(args, true)),
                Some(AuthenticatedProductIngress::WorkerRepl)
            );
        }
        assert_eq!(
            authenticated_product_ingress(route(&["ibex", "app.ts"], false)),
            Some(AuthenticatedProductIngress::FileProgram)
        );
    }

    #[test]
    fn watch_child_preserves_security_flags() {
        // @ref LLP 0013#phase-0 — `strict` is a back-compat alias that parses to
        // Enforce; the child receives the canonical `--capsec enforce`.
        let cli = cli::Cli::parse_from([
            "ibex",
            "--watch",
            "--capsec",
            "strict",
            "--allow",
            "fs:read:/tmp",
            "--deny",
            "net",
            "app.ts",
        ]);
        let flags = watch_child_args(&cli);
        let joined = flags.join(" ");
        assert!(joined.contains("--capsec enforce"), "flags: {joined}");
        assert!(joined.contains("--allow fs:read:/tmp"), "flags: {joined}");
        assert!(joined.contains("--deny net"), "flags: {joined}");
        assert!(
            !joined.contains("--watch"),
            "watch must not recurse: {joined}"
        );

        // Audit mode round-trips.
        let cli = cli::Cli::parse_from(["ibex", "--watch", "--capsec", "audit", "app.ts"]);
        let joined = watch_child_args(&cli).join(" ");
        assert!(joined.contains("--capsec audit"), "flags: {joined}");

        // ENG-22684 — the env-endowment escape hatch must survive a watch restart,
        // else an enforce reload would silently drop IBEX_ENDOW the parent honored.
        let cli = cli::Cli::parse_from([
            "ibex",
            "--watch",
            "--capsec",
            "enforce",
            "--allow-env-endowments",
            "--capsec-allow-advisory",
            "app.ts",
        ]);
        let joined = watch_child_args(&cli).join(" ");
        assert!(joined.contains("--allow-env-endowments"), "flags: {joined}");
        assert!(
            joined.contains("--capsec-allow-advisory"),
            "flags: {joined}"
        );
        // Not passed → not forwarded.
        let cli = cli::Cli::parse_from(["ibex", "--watch", "--capsec", "enforce", "app.ts"]);
        assert!(
            !watch_child_args(&cli)
                .join(" ")
                .contains("--allow-env-endowments"),
            "should not forward the hatch when it wasn't set"
        );
        assert!(
            !watch_child_args(&cli)
                .join(" ")
                .contains("--capsec-allow-advisory"),
            "should not forward the advisory hatch when it wasn't set"
        );

        // review R1: opt-in compat surfaces ride along too.
        let cli = cli::Cli::parse_from(["ibex", "--watch", "--compat", "bun", "app.ts"]);
        let joined = watch_child_args(&cli).join(" ");
        assert!(joined.contains("--compat bun"), "flags: {joined}");
    }

    #[test]
    fn watch_child_preserves_armed_snapshot_pair() {
        let cli = cli::Cli::parse_from([
            "ibex",
            "--watch",
            "--capsec-armed-snapshot",
            "armed.json",
            "--capsec-arming-identity",
            "identity.json",
            "app.ts",
        ]);
        let flags = watch_child_args(&cli);
        assert!(flags
            .windows(2)
            .any(|pair| pair == ["--capsec-armed-snapshot", "armed.json"]));
        assert!(flags
            .windows(2)
            .any(|pair| pair == ["--capsec-arming-identity", "identity.json"]));
    }

    #[test]
    fn watch_child_excludes_lifecycle_flags() {
        let cli = cli::Cli::parse_from(["ibex", "--watch", "--keep-alive", "app.ts"]);
        let flags = watch_child_args(&cli);
        assert!(!flags.contains(&"--keep-alive".to_string()));
        assert_eq!(flags, vec!["--engine".to_string(), "hermes".to_string()]);
    }

    #[test]
    fn watch_shutdown_timeout_uses_override() {
        assert_eq!(
            watch_shutdown_timeout_from_env(Some("3500")).as_millis(),
            3500
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn watch_group_interrupt_grace_does_not_preempt_child_cleanup_with_sigterm() {
        let directory = tempfile::tempdir().expect("watch grace directory");
        let ready = directory.path().join("ready");
        let interrupted = directory.path().join("interrupted");
        let cleaned = directory.path().join("cleaned");
        let terminated = directory.path().join("terminated");
        let script = r#"
trap 'printf x > "$TERM_MARKER"; exit 143' TERM
trap 'printf x > "$INT_MARKER"; sleep 0.2; printf x > "$CLEAN_MARKER"; exit 130' INT
printf x > "$READY_MARKER"
while :; do :; done
"#;
        let mut child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .env("READY_MARKER", &ready)
            .env("INT_MARKER", &interrupted)
            .env("CLEAN_MARKER", &cleaned)
            .env("TERM_MARKER", &terminated)
            .spawn()
            .expect("spawn watch grace child");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "watch grace child did not become ready"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let pid = child.id().expect("watch grace child pid") as i32;
        assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);
        let cleanup =
            stop_watch_child_after_interrupt(&mut child, std::time::Duration::from_millis(100))
                .await
                .expect("wait for watch child interrupt cleanup");

        let status = child
            .try_wait()
            .expect("poll cleaned watch child")
            .expect("watch grace child was not reaped");
        assert_eq!(status.code(), Some(130));
        assert!(matches!(cleanup, super::WatchInterruptCleanup::Reaped(_)));
        assert!(interrupted.exists(), "child did not observe its SIGINT");
        assert!(cleaned.exists(), "child cleanup was not allowed to finish");
        assert!(
            !terminated.exists(),
            "controller preempted SIGINT cleanup with SIGTERM"
        );
    }

    #[test]
    fn watch_shutdown_timeout_falls_back_to_default() {
        assert_eq!(
            watch_shutdown_timeout_from_env(None).as_millis(),
            DEFAULT_WATCH_SHUTDOWN_TIMEOUT_MS as u128
        );
    }

    #[test]
    fn exit_code_for_error_marks_host_io_failures() {
        let error = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "nope",
        ));

        assert_eq!(exit_code_for_error(&error), 3);
    }

    #[test]
    fn exit_code_for_error_leaves_runtime_failures_as_generic() {
        let error = anyhow::anyhow!("syntax error");

        assert_eq!(exit_code_for_error(&error), 1);
    }

    #[test]
    fn exit_code_for_error_propagates_package_script_code() {
        // A failing package script must surface its own exit code (eslint's 2),
        // matching npm/bun, not the generic 1. (ENG-22958)
        let error = anyhow::Error::new(super::PackageScriptExit {
            script: "lint".to_string(),
            code: 2,
        });
        assert_eq!(exit_code_for_error(&error), 2);

        // The code survives extra context layered on top of the error.
        let wrapped = error.context("running package script `lint`");
        assert_eq!(exit_code_for_error(&wrapped), 2);
    }

    #[test]
    fn exit_code_for_error_propagates_structured_program_status() {
        let error = anyhow::Error::new(ProgramRequestedExit { code: 70 })
            .context("descriptor restoration completed");
        assert_eq!(exit_code_for_error(&error), 70);

        let error = anyhow::Error::new(ProgramExecutionFailure {
            code: 1,
            diagnostic: "unhandled asynchronous file-program failure".to_owned(),
        })
        .context("descriptor restoration completed");
        assert_eq!(exit_code_for_error(&error), 1);
    }

    #[test]
    fn file_broker_loss_upgrades_only_successful_program_causes() {
        let orderly =
            apply_file_broker_loss_disposition(Ok(()), Some("orderly loss".to_owned()), false)
                .expect_err("unreportable orderly output loss must become a typed failure");
        assert_eq!(
            exit_code_for_error(&orderly),
            ibex_runtime::session_constants::EXIT_STATUS_BROKEN_PIPE
        );
        assert!(format!("{orderly:#}").contains("orderly loss"));

        let lifecycle = apply_file_broker_loss_disposition(
            Err(anyhow::Error::new(ProgramRequestedExit { code: 7 })),
            Some("cooperative loss".to_owned()),
            false,
        )
        .expect_err("unreportable cooperative output loss must become a typed failure");
        assert_eq!(
            exit_code_for_error(&lifecycle),
            ibex_runtime::session_constants::EXIT_STATUS_BROKEN_PIPE
        );
        assert!(
            !is_program_requested_exit(&lifecycle),
            "the replacement failure must remain visible to main's diagnostic path"
        );
        assert!(format!("{lifecycle:#}").contains("cooperative loss"));

        let reported_lifecycle = apply_file_broker_loss_disposition(
            Err(anyhow::Error::new(ProgramRequestedExit { code: 9 })),
            Some("reported cooperative loss".to_owned()),
            true,
        )
        .expect_err("the original cooperative exit remains non-returning");
        assert!(is_program_requested_exit(&reported_lifecycle));
        assert_eq!(exit_code_for_error(&reported_lifecycle), 9);
        assert!(!format!("{reported_lifecycle:#}").contains("reported cooperative loss"));

        let reported_orderly = apply_file_broker_loss_disposition(
            Ok(()),
            Some("reported orderly loss".to_owned()),
            true,
        );
        assert!(reported_orderly.is_ok());

        let fixed = apply_file_broker_loss_disposition(
            Err(anyhow::Error::new(ProgramExecutionFailure {
                code: ibex_runtime::session_constants::EXIT_STATUS_ENGINE_FAULT,
                diagnostic: "primary engine fault".to_owned(),
            })),
            Some("later broker loss".to_owned()),
            false,
        )
        .expect_err("a fixed primary cause remains an error");
        assert_eq!(
            exit_code_for_error(&fixed),
            ibex_runtime::session_constants::EXIT_STATUS_ENGINE_FAULT
        );
        let diagnostic = format!("{fixed:#}");
        assert!(diagnostic.contains("primary engine fault"));
        assert!(diagnostic.contains("later broker loss"));
    }

    #[test]
    fn inspector_cleanup_cannot_replace_a_latched_file_settlement() {
        let lifecycle = preserve_file_settlement_after_inspector_cleanup(
            Err(anyhow::Error::new(ProgramRequestedExit { code: 7 })),
            Err(anyhow::anyhow!("inspector stop failed")),
        )
        .expect_err("the lifecycle settlement remains non-returning");
        assert!(is_program_requested_exit(&lifecycle));
        assert_eq!(exit_code_for_error(&lifecycle), 7);

        let orderly = preserve_file_settlement_after_inspector_cleanup(
            Ok(()),
            Err(anyhow::anyhow!("inspector stop failed")),
        );
        assert!(orderly.is_ok(), "cleanup cannot replace orderly completion");
    }

    #[test]
    fn adapter_finish_errors_retain_the_program_cause_class() {
        let relay_loss = apply_file_adapter_finish_error(
            Err(anyhow::Error::new(ProgramRequestedExit { code: 7 })),
            crate::terminal_session::FileProgramAdapterError::Broker(
                "relay disconnected".to_owned(),
            ),
        )
        .expect_err("a directly reportable relay failure preserves the cooperative cause");
        assert_eq!(exit_code_for_error(&relay_loss), 7);
        assert!(is_program_requested_exit(&relay_loss));

        let fixed = apply_file_adapter_finish_error(
            Err(anyhow::Error::new(ProgramExecutionFailure {
                code: ibex_runtime::session_constants::EXIT_STATUS_ENGINE_FAULT,
                diagnostic: "primary engine fault".to_owned(),
            })),
            crate::terminal_session::FileProgramAdapterError::RelayThreadPanicked,
        )
        .expect_err("relay loss cannot replace a fixed cause");
        assert_eq!(
            exit_code_for_error(&fixed),
            ibex_runtime::session_constants::EXIT_STATUS_ENGINE_FAULT
        );
        assert!(format!("{fixed:#}").contains("primary engine fault"));

        let restoration = apply_file_adapter_finish_error(
            Err(anyhow::Error::new(ProgramRequestedExit { code: 9 })),
            crate::terminal_session::FileProgramAdapterError::Native(std::io::Error::other(
                "descriptor restore failed",
            )),
        )
        .expect_err("restoration diagnostics cannot replace a lifecycle cause");
        assert!(is_program_requested_exit(&restoration));
        assert_eq!(exit_code_for_error(&restoration), 9);

        let restoration_with_loss = apply_file_adapter_finish_error(
            Err(anyhow::Error::new(ProgramRequestedExit { code: 11 })),
            crate::terminal_session::FileProgramAdapterError::NativeWithReport {
                error: std::io::Error::other("descriptor restore failed"),
                report: Box::new(
                    crate::terminal_session::FileProgramExecutionReport::with_unaccepted_stdout_byte_for_test(),
                ),
            },
        )
        .expect_err("reported output loss still upgrades a successful cause");
        assert_eq!(
            exit_code_for_error(&restoration_with_loss),
            ibex_runtime::session_constants::EXIT_STATUS_BROKEN_PIPE
        );
        assert!(!is_program_requested_exit(&restoration_with_loss));

        let reportable_restoration_with_loss = apply_file_adapter_finish_error(
            Err(anyhow::Error::new(ProgramRequestedExit { code: 12 })),
            crate::terminal_session::FileProgramAdapterError::NativeWithReport {
                error: std::io::Error::other("descriptor restore failed"),
                report: Box::new(
                    crate::terminal_session::FileProgramExecutionReport::with_reportable_unaccepted_stdout_byte_for_test(),
                ),
            },
        )
        .expect_err("a reportable cleanup loss preserves the cooperative cause");
        assert!(is_program_requested_exit(&reportable_restoration_with_loss));
        assert_eq!(exit_code_for_error(&reportable_restoration_with_loss), 12);
    }

    #[test]
    fn program_stdin_reader_preserves_bytes_and_stops_at_refusal_sentinel() {
        let max = ibex_runtime::session_constants::MAX_INPUT_BYTES;
        let invalid_utf8 = vec![0xff, 0xfe, 0x00];
        assert_eq!(
            read_program_source_bounded(invalid_utf8.as_slice()).unwrap(),
            invalid_utf8
        );

        let oversized = vec![b'x'; max + 257];
        let bounded = read_program_source_bounded(oversized.as_slice()).unwrap();
        assert_eq!(bounded.len(), max + 1);
        assert!(bounded.iter().all(|byte| *byte == b'x'));
    }

    #[test]
    fn exit_code_for_error_marks_host_lifecycle_messages() {
        for message in [
            "Host not initialized",
            "Permission denied for /tmp/blocked.txt",
            "Failed to start HTTP server",
        ] {
            assert_eq!(
                exit_code_for_error(&anyhow::anyhow!("{message}")),
                3,
                "message: {message}"
            );
        }
    }

    /// Read an error-origin source file in this repo. Test-only use of
    /// CARGO_MANIFEST_DIR is intentional: these tests pin local source strings
    /// that cross the FFI/JSI boundary.
    fn origin_source(relative: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
    }

    // `exit_code_for_error` cannot downcast these errors, so each matched
    // prefix is pinned to its origin file. If one fails, update the prefix
    // table and this test together.

    #[test]
    fn host_lifecycle_host_not_initialized_matches_origin() {
        let source = origin_source("src/host/abi.rs");
        assert!(
            source.contains(r#"anyhow!("Host not initialized")"#),
            "with_host() defaults in ibex-runtime/src/host/abi.rs no longer use \
             \"Host not initialized\""
        );
    }

    #[test]
    fn host_lifecycle_permission_denied_matches_origin() {
        let source = origin_source("src/host/mod.rs");
        assert!(
            source.contains(r#""Permission denied for {}""#),
            "Host::resolve_module in ibex-runtime/src/host/mod.rs no longer uses \
             \"Permission denied for {{}}\""
        );
    }

    #[test]
    fn host_lifecycle_http_server_matches_origin() {
        let cc_source = origin_source("src/engine/hermes_runtime_http.cc");
        assert!(
            cc_source.contains(r#""Failed to start HTTP server""#),
            "__exactHttpServe in ibex-runtime/src/engine/hermes_runtime_http.cc no longer \
             uses \"Failed to start HTTP server\""
        );

        let js_source = origin_source("src/engine/bootstrap/exact-global.js");
        assert!(
            js_source.contains("'Failed to start HTTP server'"),
            "the exact:http bootstrap in ibex-runtime/src/engine/bootstrap/exact-global.js \
             no longer uses 'Failed to start HTTP server'"
        );
    }
}
