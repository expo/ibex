//! C ABI surface for the Exact host.
//!
//! These functions are intended to be called from engine adapters (C/C++).
//! The CLI stores a singleton Host instance that backs these calls.
//!
//! # Safety
//! FFI functions receive raw pointers from foreign code. The safety contract
//! is between the caller (C/C++ code) and this module. Functions validate
//! null pointers where possible but assume pointers are valid when non-null.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use super::Host;
use base64::Engine as _;
use getrandom::getrandom;
use rusqlite::{
    hooks::{AuthAction, AuthContext, Authorization},
    params_from_iter,
    types::ValueRef,
    Connection, OpenFlags, ToSql,
};
use serde_json::json;
use std::cell::Cell;
use std::collections::HashMap;
#[cfg(target_os = "android")]
use std::ffi::c_int;
use std::ffi::{c_char, CStr, CString};
use std::io::{self, Write};
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
#[cfg(unix)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    /// Normalized POSIX-style error code for the most recent host filesystem
    /// failure on this thread. Windows `raw_os_error()` values are Win32
    /// status codes, not errno values, so the C++ bridge must not interpret
    /// them directly. The worker-pool caller consumes this immediately after
    /// a failed ABI call on the same thread.
    static LAST_FS_ERROR: Cell<i32> = const { Cell::new(0) };
}

fn normalized_io_error_code(err: &std::io::Error) -> i32 {
    use std::io::ErrorKind;
    #[cfg(windows)]
    if let Some(code) = err.raw_os_error() {
        // Preserve Win32 conditions that Node callers branch on. Mapping all
        // unrecognized Windows errors to EIO made rename fallbacks and rimraf
        // retries unreachable even though the C++ bridge understands these
        // POSIX spellings.
        match code {
            4 => return libc::EMFILE,        // ERROR_TOO_MANY_OPEN_FILES
            17 => return libc::EXDEV,        // ERROR_NOT_SAME_DEVICE
            39 | 112 => return libc::ENOSPC, // ERROR_HANDLE_DISK_FULL / ERROR_DISK_FULL
            145 => return libc::ENOTEMPTY,   // ERROR_DIR_NOT_EMPTY
            267 => return libc::ENOTDIR,     // ERROR_DIRECTORY
            _ => {}
        }
    }
    match err.kind() {
        ErrorKind::NotFound => libc::ENOENT,
        ErrorKind::PermissionDenied => libc::EACCES,
        ErrorKind::AlreadyExists => libc::EEXIST,
        ErrorKind::NotADirectory => libc::ENOTDIR,
        ErrorKind::IsADirectory => libc::EISDIR,
        ErrorKind::DirectoryNotEmpty => libc::ENOTEMPTY,
        ErrorKind::StorageFull | ErrorKind::QuotaExceeded => libc::ENOSPC,
        ErrorKind::CrossesDevices => libc::EXDEV,
        ErrorKind::InvalidInput | ErrorKind::InvalidData => libc::EINVAL,
        ErrorKind::UnexpectedEof => libc::EIO,
        ErrorKind::WriteZero => libc::ENOSPC,
        ErrorKind::WouldBlock => libc::EAGAIN,
        ErrorKind::TimedOut => libc::ETIMEDOUT,
        ErrorKind::Interrupted => libc::EINTR,
        _ => {
            #[cfg(unix)]
            {
                err.raw_os_error().unwrap_or(libc::EIO)
            }
            #[cfg(not(unix))]
            {
                libc::EIO
            }
        }
    }
}

fn record_fs_error(code: i32) {
    LAST_FS_ERROR.with(|slot| slot.set(code));
}

#[no_mangle]
pub extern "C" fn ex_host_fs_last_error() -> i32 {
    LAST_FS_ERROR.with(Cell::get)
}

#[cfg(all(
    unix,
    not(target_os = "android"),
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "tvos"),
    not(target_os = "watchos")
))]
#[inline]
fn set_errno_from_io_error(err: &std::io::Error) {
    let code = normalized_io_error_code(err);
    record_fs_error(code);
    unsafe {
        *libc::__errno_location() = code;
    }
}

#[cfg(target_os = "android")]
#[inline]
fn set_errno_from_io_error(err: &std::io::Error) {
    let code = normalized_io_error_code(err);
    record_fs_error(code);
    unsafe {
        *libc::__errno() = code;
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
#[inline]
fn set_errno_from_io_error(err: &std::io::Error) {
    let code = normalized_io_error_code(err);
    record_fs_error(code);
    unsafe {
        *libc::__error() = code;
    }
}

#[cfg(not(unix))]
#[inline]
fn set_errno_from_io_error(err: &std::io::Error) {
    record_fs_error(normalized_io_error_code(err));
}
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub const EXACT_HOST_ABI_VERSION: u32 = 1;

static HOST: OnceLock<RwLock<Host>> = OnceLock::new();
struct HostContextRecord {
    host: Arc<Host>,
    claimed: bool,
}

static HOST_CONTEXTS: OnceLock<RwLock<HashMap<u64, HostContextRecord>>> = OnceLock::new();

struct PendingHostContext(Cell<u64>);

impl Drop for PendingHostContext {
    fn drop(&mut self) {
        let context_id = self.0.replace(0);
        if context_id != 0 {
            release_unclaimed_host_context(context_id);
        }
    }
}

thread_local! {
    static ACTIVE_HOST_CONTEXT: Cell<u64> = const { Cell::new(0) };
    /// Exact install-to-create handoff. A runtime can claim only the Host that
    /// its own creating thread most recently installed; equal snapshot digests
    /// in concurrent creators are therefore not interchangeable credentials.
    static PENDING_HOST_CONTEXT: PendingHostContext = const { PendingHostContext(Cell::new(0)) };
}
static SECURITY_LOG_ENABLED: OnceLock<bool> = OnceLock::new();
static CONSOLE_MIRROR_ENABLED: OnceLock<bool> = OnceLock::new();

#[cfg(test)]
pub(crate) fn host_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// A SQLite connection is wrapped in its own `Mutex` and shared via `Arc` so
/// each connection can be locked independently. The process-global registry
/// lock is only held long enough to look up and clone this handle, not across
/// query execution — so a slow query on one connection no longer stalls every
/// other SQLite call process-wide.
type SqliteConnection = Arc<Mutex<Connection>>;

#[derive(Clone)]
struct SqliteStatementRecord {
    db_id: u64,
    sql: String,
    read_only: bool,
}

struct SqliteState {
    next_db_handle: u64,
    next_statement_handle: u64,
    dbs: HashMap<u64, SqliteConnection>,
    statements: HashMap<u64, SqliteStatementRecord>,
}

impl SqliteState {
    fn new() -> Self {
        Self {
            next_db_handle: 1,
            next_statement_handle: 1,
            dbs: HashMap::new(),
            statements: HashMap::new(),
        }
    }

    fn allocate_db_handle(&mut self) -> Option<u64> {
        let handle = self.next_db_handle;
        if handle == 0 || self.dbs.contains_key(&handle) {
            return None;
        }
        self.next_db_handle = handle.checked_add(1)?;
        Some(handle)
    }

    fn allocate_statement_handle(&mut self) -> Option<u64> {
        let handle = self.next_statement_handle;
        if handle == 0 || self.statements.contains_key(&handle) {
            return None;
        }
        self.next_statement_handle = handle.checked_add(1)?;
        Some(handle)
    }
}

static SQLITE_STATE: OnceLock<Mutex<SqliteState>> = OnceLock::new();

fn with_sqlite_state<T>(f: impl FnOnce(&mut SqliteState) -> T) -> T {
    let mutex = SQLITE_STATE.get_or_init(|| Mutex::new(SqliteState::new()));
    let mut state = match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut state)
}

/// Clone the shared handle for a connection. The registry lock is held only for
/// the lookup + `Arc` clone; callers then lock the per-connection mutex on their
/// own so independent connections execute concurrently.
fn sqlite_connection(db_id: u64) -> Option<SqliteConnection> {
    with_sqlite_state(|state| state.dbs.get(&db_id).map(Arc::clone))
}

/// Resolve a prepared-statement handle to its record plus the shared handle for
/// the connection it belongs to, in a single registry-lock critical section.
fn sqlite_statement_connection(
    statement_handle: u64,
) -> Option<(SqliteStatementRecord, SqliteConnection)> {
    with_sqlite_state(|state| {
        let statement = state.statements.get(&statement_handle)?.clone();
        let connection = state.dbs.get(&statement.db_id).map(Arc::clone)?;
        Some((statement, connection))
    })
}

/// Lock a connection for the duration of an operation, recovering the guard if a
/// previous holder panicked (a poisoned SQLite connection is still usable).
fn lock_connection(connection: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    match connection.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn insert_host_context(host: Arc<Host>, claimed: bool) -> u64 {
    // Random, non-zero context tokens are capabilities, not enumerable IDs.
    // Entropy failure or repeated collisions fail closed instead of falling
    // back to a wrapping process-global counter.
    for _ in 0..32 {
        let mut bytes = [0u8; std::mem::size_of::<u64>()];
        if getrandom(&mut bytes).is_err() {
            return 0;
        }
        let context_id = u64::from_ne_bytes(bytes);
        if context_id == 0 {
            continue;
        }
        let contexts = HOST_CONTEXTS.get_or_init(|| RwLock::new(HashMap::new()));
        let mut contexts = match contexts.write() {
            Ok(contexts) => contexts,
            Err(poisoned) => poisoned.into_inner(),
        };
        if contexts.contains_key(&context_id) {
            continue;
        }
        contexts.insert(
            context_id,
            HostContextRecord {
                host: Arc::clone(&host),
                claimed,
            },
        );
        return context_id;
    }
    0
}

fn release_unclaimed_host_context(context_id: u64) {
    let Some(contexts) = HOST_CONTEXTS.get() else {
        return;
    };
    let mut contexts = match contexts.write() {
        Ok(contexts) => contexts,
        Err(poisoned) => poisoned.into_inner(),
    };
    if contexts
        .get(&context_id)
        .is_some_and(|context| !context.claimed)
    {
        contexts.remove(&context_id);
    }
}

/// Publish a Host and retain an exact, thread-bound creation token for the
/// next Hermes constructor on this thread. Replacing an unclaimed install
/// retires it immediately; thread teardown retires any remaining token.
pub fn install_host(host: Host) -> u64 {
    let previous = PENDING_HOST_CONTEXT.with(|pending| pending.0.replace(0));
    if previous != 0 {
        release_unclaimed_host_context(previous);
    }

    let context_id = insert_host_context(Arc::new(host.clone()), false);
    if context_id != 0 {
        PENDING_HOST_CONTEXT.with(|pending| pending.0.set(context_id));
    }
    if let Some(slot) = HOST.get() {
        match slot.write() {
            Ok(mut current) => {
                *current = host;
            }
            Err(poisoned) => {
                *poisoned.into_inner() = host;
            }
        }
        return context_id;
    }

    let _ = HOST.set(RwLock::new(host));
    context_id
}

/// Install an immutable armed host from caller-owned bytes. The bytes are
/// copied and authenticated before publication; later caller mutation cannot
/// affect the installed decision context.
/// @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
pub fn install_armed_host(snapshot: &[u8], expected_json: &[u8]) -> Result<(), String> {
    use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
    super::reject_closed_startup_environment().map_err(|error| error.to_string())?;
    let expected_text = std::str::from_utf8(expected_json)
        .map_err(|error| format!("expected arming identity is not UTF-8: {error}"))?;
    let expected_value = capsec_semantics::strict_json::parse_strict(expected_text)
        .map_err(|error| error.to_string())?;
    let expected: ExpectedArmingIdentity = serde_json::from_value(expected_value)
        .map_err(|error| format!("invalid expected arming identity: {error}"))?;
    let armed = ArmedSnapshot::load(snapshot, &expected).map_err(|error| error.to_string())?;
    let host = Host::new_armed(
        super::HostConfig {
            mode: super::SecurityMode::Enforce,
            ..Default::default()
        },
        Arc::new(armed),
    )
    .map_err(|error| error.to_string())?;
    if install_host(host) == 0 {
        return Err("failed to allocate an armed Host context token".into());
    }
    Ok(())
}

fn with_host<T>(f: impl FnOnce(&Host) -> T, default: T) -> T {
    let active = ACTIVE_HOST_CONTEXT.with(Cell::get);
    if active != 0 {
        let selected = HOST_CONTEXTS.get().and_then(|contexts| {
            contexts
                .read()
                .ok()?
                .get(&active)
                .map(|row| row.host.clone())
        });
        if let Some(host) = selected {
            return f(&host);
        }
        return default;
    }
    let Some(host) = HOST.get() else {
        return default;
    };

    match host.read() {
        Ok(current) => f(&current),
        Err(poisoned) => f(&poisoned.into_inner()),
    }
}

fn claim_pending_host_context(require_armed_digest: Option<&str>) -> u64 {
    let context_id = PENDING_HOST_CONTEXT.with(|pending| pending.0.get());
    if context_id == 0 {
        // Diagnostic construction is explicit and may be used without an
        // embedder-installed Host. Its fallback is a fresh audit context;
        // armed construction never has a fallback.
        return if require_armed_digest.is_none() {
            insert_host_context(
                Arc::new(Host::new(super::HostConfig {
                    mode: super::SecurityMode::Audit,
                    ..Default::default()
                })),
                true,
            )
        } else {
            0
        };
    }
    let Some(contexts) = HOST_CONTEXTS.get() else {
        return 0;
    };
    let mut contexts = match contexts.write() {
        Ok(contexts) => contexts,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(context) = contexts.get_mut(&context_id) else {
        return 0;
    };
    if context.claimed {
        return 0;
    }
    let kind_matches = match require_armed_digest {
        Some(digest) => context
            .host
            .armed_snapshot()
            .is_some_and(|snapshot| snapshot.digest().as_str() == digest),
        None => context.host.armed_snapshot().is_none(),
    };
    if !kind_matches {
        return 0;
    }
    context.claimed = true;
    PENDING_HOST_CONTEXT.with(|pending| pending.0.set(0));
    context_id
}

#[no_mangle]
pub unsafe extern "C" fn ex_host_claim_armed_context(digest: *const c_char) -> u64 {
    if digest.is_null() {
        return 0;
    }
    let digest = unsafe { CStr::from_ptr(digest) }.to_string_lossy();
    claim_pending_host_context(Some(&digest))
}

#[no_mangle]
pub extern "C" fn ex_host_claim_diagnostic_context() -> u64 {
    claim_pending_host_context(None)
}

#[no_mangle]
pub extern "C" fn ex_host_enter_context(context_id: u64) -> u64 {
    let exists = HOST_CONTEXTS
        .get()
        .and_then(|contexts| {
            contexts
                .read()
                .ok()
                .map(|rows| rows.get(&context_id).is_some_and(|row| row.claimed))
        })
        .unwrap_or(false);
    if !exists {
        return u64::MAX;
    }
    ACTIVE_HOST_CONTEXT.with(|active| active.replace(context_id))
}

#[no_mangle]
pub extern "C" fn ex_host_restore_context(previous: u64) {
    ACTIVE_HOST_CONTEXT.with(|active| active.set(previous));
}

#[no_mangle]
pub extern "C" fn ex_host_release_context(context_id: u64) {
    if let Some(contexts) = HOST_CONTEXTS.get() {
        match contexts.write() {
            Ok(mut contexts) => {
                contexts.remove(&context_id);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(&context_id);
            }
        }
    }
}

#[doc(hidden)]
pub fn installed_typed_decision_count() -> usize {
    with_host(Host::typed_decision_count, 0)
}

#[doc(hidden)]
pub fn installed_legacy_authorization_check_count() -> usize {
    with_host(Host::legacy_authorization_check_count, 0)
}

#[cfg(feature = "capsec-conformance-observer")]
pub fn begin_installed_conformance_observation(terminal_branch_id: &str) -> bool {
    with_host(
        |host| {
            host.begin_conformance_observation(terminal_branch_id);
            true
        },
        false,
    )
}

#[cfg(feature = "capsec-conformance-observer")]
pub fn take_installed_conformance_observations() -> (
    Vec<super::capability::ObservedCapabilityDecision>,
    Vec<super::ObservedTypedDecision>,
) {
    with_host(
        |host| {
            (
                host.take_conformance_observations(),
                host.take_typed_conformance_observations(),
            )
        },
        (Vec::new(), Vec::new()),
    )
}

/// Render the would-deny audit report for the installed host, but only when it
/// is running in `Audit` mode and something was flagged.
///
/// @ref LLP 0013#phase-1 — printed at process shutdown so `ibex run --capsec
/// audit` surfaces the grants an app must declare before moving to `enforce`.
pub fn current_audit_report() -> Option<String> {
    with_host(
        |host| {
            if host.security_mode() == super::SecurityMode::Audit {
                let report = host.audit_report();
                if report.is_empty() {
                    None
                } else {
                    Some(report)
                }
            } else {
                None
            }
        },
        None,
    )
}

fn security_log_enabled() -> bool {
    *SECURITY_LOG_ENABLED.get_or_init(|| {
        std::env::var("EXACT_SECURITY_LOG")
            .map(|v| !matches!(v.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
            .unwrap_or(false)
    })
}

fn console_mirror_enabled() -> bool {
    // Memoized like `security_log_enabled` above: `ex_host_console_log` calls this
    // on every log line on the JS thread, and an env lookup per line (allocating
    // on a hit) is needless per-line work for a value fixed for the process
    // lifetime (ENG-22955).
    *CONSOLE_MIRROR_ENABLED.get_or_init(|| {
        std::env::var("IBEX_SUPPRESS_CONSOLE_MIRROR")
            .map(|v| matches!(v.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
            .unwrap_or(true)
    })
}

fn write_stdio_line(writer: &mut impl Write, msg: &str) -> io::Result<()> {
    writer.write_all(msg.as_bytes())?;
    writer.write_all(b"\n")
}

fn write_stdout_line(msg: &str) {
    let mut stdout = io::stdout().lock();
    let _ = write_stdio_line(&mut stdout, msg);
}

fn write_stderr_line(msg: &str) {
    let mut stderr = io::stderr().lock();
    let _ = write_stdio_line(&mut stderr, msg);
}

// @ref LLP 0006#degrade-diagnostics-never-the-caller — console output is mirrored to stdio from the JS
// thread, which is the app host's main thread. stdout there is a PTY or pipe
// drained by a console UI (Xcode) or a script wrapper; when the consumer
// stalls, a direct write blocks the main thread ("Application Not
// Responding"), and a vanished consumer used to abort the process through the
// `println!` panic path. Stdio mirroring is best-effort diagnostics, so it
// goes through a bounded queue to a writer thread and drops lines under
// backpressure instead of ever blocking or failing the caller.
const CONSOLE_QUEUE_CAPACITY: usize = 2048;

enum ConsoleLine {
    Out(String),
    Err(String),
}

struct ConsoleQueue {
    tx: std::sync::mpsc::SyncSender<ConsoleLine>,
    dropped: std::sync::atomic::AtomicU64,
}

// Lines accepted into the queue but not yet written by the writer thread.
// `ex_host_console_flush` waits (bounded) on this reaching zero so
// process.exit does not discard output enqueued in the same tick — the
// writer thread otherwise races process teardown, and on Windows
// (exactHostExit -> ExitProcess) it loses deterministically. (ENG-23639)
static CONSOLE_PENDING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl ConsoleQueue {
    fn enqueue(&self, line: ConsoleLine) {
        use std::sync::atomic::Ordering;

        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let notice = ConsoleLine::Err(format!(
                "[ibex-console] dropped {dropped} line(s) under stdio backpressure"
            ));
            // Count BEFORE sending so the writer's decrement can never land
            // first and transiently wrap the counter below zero.
            CONSOLE_PENDING.fetch_add(1, Ordering::Release);
            if self.tx.try_send(notice).is_err() {
                CONSOLE_PENDING.fetch_sub(1, Ordering::Release);
                self.dropped.fetch_add(dropped, Ordering::Relaxed);
            }
        }
        CONSOLE_PENDING.fetch_add(1, Ordering::Release);
        if self.tx.try_send(line).is_err() {
            CONSOLE_PENDING.fetch_sub(1, Ordering::Release);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn console_queue() -> &'static ConsoleQueue {
    static QUEUE: OnceLock<ConsoleQueue> = OnceLock::new();
    QUEUE.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<ConsoleLine>(CONSOLE_QUEUE_CAPACITY);
        // If the spawn fails the receiver is dropped and enqueue() degrades to
        // counting drops; console mirroring is lost but the app keeps running.
        let _ = std::thread::Builder::new()
            .name("ibex-console".to_string())
            .spawn(move || {
                while let Ok(line) = rx.recv() {
                    match line {
                        ConsoleLine::Out(msg) => write_stdout_line(&msg),
                        ConsoleLine::Err(msg) => write_stderr_line(&msg),
                    }
                    CONSOLE_PENDING.fetch_sub(1, std::sync::atomic::Ordering::Release);
                }
            });
        ConsoleQueue {
            tx,
            dropped: std::sync::atomic::AtomicU64::new(0),
        }
    })
}

/// Wait (bounded by `timeout_ms`) for the console writer thread to drain
/// every line already accepted into the queue. Called by `exactHostExit`
/// before terminating so `console.log(...); process.exit(0)` cannot lose
/// the log line; a stalled stdio consumer only delays exit by the timeout,
/// never wedges it. (ENG-23639)
#[no_mangle]
pub extern "C" fn ex_host_console_flush(timeout_ms: u32) {
    use std::sync::atomic::Ordering;

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(u64::from(timeout_ms));
    while CONSOLE_PENDING.load(Ordering::Acquire) > 0 {
        if std::time::Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn enqueue_stdout_line(msg: String) {
    console_queue().enqueue(ConsoleLine::Out(msg));
}

fn enqueue_stderr_line(msg: String) {
    console_queue().enqueue(ConsoleLine::Err(msg));
}

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __android_log_print(prio: c_int, tag: *const c_char, fmt: *const c_char, ...) -> c_int;
}

#[cfg(target_os = "android")]
fn write_android_logcat(level: i32, msg: &str) {
    const ANDROID_LOG_INFO: c_int = 4;
    const ANDROID_LOG_ERROR: c_int = 6;
    static TAG: &[u8] = b"Ibex\0";
    static FORMAT: &[u8] = b"%s\0";

    let sanitized;
    let c_msg = match CString::new(msg) {
        Ok(value) => value,
        Err(_) => {
            sanitized = msg.replace('\0', "\\0");
            match CString::new(sanitized.as_str()) {
                Ok(value) => value,
                Err(_) => return,
            }
        }
    };
    let priority = if level == 1 {
        ANDROID_LOG_ERROR
    } else {
        ANDROID_LOG_INFO
    };
    unsafe {
        // @ref LLP 0008#android-backend-matrix — Android console output is
        // mirrored to logcat while retaining the host/stdout queue.
        __android_log_print(
            priority,
            TAG.as_ptr() as *const c_char,
            FORMAT.as_ptr() as *const c_char,
            c_msg.as_ptr(),
        );
    }
}

const SQLITE_OPEN_READONLY: u64 = 0x00000001;
const SQLITE_OPEN_READWRITE: u64 = 0x00000002;
const SQLITE_OPEN_CREATE: u64 = 0x00000004;

#[derive(Default)]
#[allow(dead_code)]
struct SqliteOpenOptions {
    readonly: bool,
    create: bool,
    readwrite: bool,
    flags: Option<u64>,
}

fn parse_sqlite_open_options(raw: *const c_char) -> SqliteOpenOptions {
    if raw.is_null() {
        return SqliteOpenOptions {
            readonly: false,
            create: true,
            readwrite: true,
            flags: None,
        };
    }

    let raw = unsafe { CStr::from_ptr(raw) }.to_string_lossy();
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(serde_json::Value::Object(values)) => {
            let flags = values
                .get("flags")
                .and_then(serde_json::Value::as_u64)
                .or(None);
            SqliteOpenOptions {
                readonly: values
                    .get("readonly")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                create: values
                    .get("create")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
                readwrite: values
                    .get("readwrite")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
                flags,
            }
        }
        Ok(serde_json::Value::Number(flags)) => SqliteOpenOptions {
            readonly: false,
            create: true,
            readwrite: true,
            flags: flags.as_u64(),
        },
        _ => SqliteOpenOptions {
            readonly: false,
            create: true,
            readwrite: true,
            flags: None,
        },
    }
}

fn sqlite_open_flags(options: &SqliteOpenOptions) -> OpenFlags {
    if let Some(raw_flags) = options.flags {
        let mut open_flags = OpenFlags::empty();
        if raw_flags & SQLITE_OPEN_READONLY != 0 {
            open_flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        }
        if raw_flags & SQLITE_OPEN_READWRITE != 0 {
            open_flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        }
        if raw_flags & SQLITE_OPEN_CREATE != 0 {
            open_flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
        }
        return open_flags;
    }

    // A read-only connection must not also carry READ_WRITE or CREATE: SQLite
    // rejects `READ_ONLY|CREATE` with SQLITE_MISUSE, which is why `{readonly:
    // true}` opens silently failed (returning handle 0 with no error) even for a
    // file that exists and is readable. When not read-only, honor the previously
    // ignored `readwrite` field, and treat `create` as implying write access
    // (CREATE requires READ_WRITE, or SQLite likewise returns SQLITE_MISUSE).
    let mut open_flags = OpenFlags::empty();
    if options.readonly {
        open_flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
    } else {
        if options.readwrite || options.create {
            open_flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        }
        if options.create {
            open_flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
        }
        if open_flags.is_empty() {
            // `{readonly:false, readwrite:false, create:false}` requested no access
            // mode at all; fall back to read-only rather than hand SQLite empty
            // flags (also SQLITE_MISUSE).
            open_flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
        }
    }
    open_flags
}

fn sqlite_authorizer(ctx: AuthContext<'_>) -> Authorization {
    match ctx.action {
        AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,
        AuthAction::Function { function_name }
            if function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Deny
        }
        _ => Authorization::Allow,
    }
}

fn install_sqlite_authorizer(db: &Connection) {
    db.authorizer(Some(sqlite_authorizer));
}

fn stable_legacy_json_text(value: &serde_json::Value, output: &mut String) {
    match value {
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                stable_legacy_json_text(value, output);
            }
            output.push(']');
        }
        serde_json::Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            output.push('{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output
                    .push_str(&serde_json::to_string(key).expect("JSON object key must serialize"));
                output.push(':');
                stable_legacy_json_text(value, output);
            }
            output.push('}');
        }
        _ => output.push_str(&value.to_string()),
    }
}

/// Convert an ordinary user binding using the legacy SQLite semantics. This
/// function deliberately does not recognize the private transport envelope:
/// envelope decoding happens exactly once at the binding boundary, otherwise
/// a user value nested inside `{kind:"value"}` can smuggle a second envelope.
fn plain_sql_value(value: &serde_json::Value) -> rusqlite::types::Value {
    match value {
        serde_json::Value::Null => rusqlite::types::Value::Null,
        serde_json::Value::Bool(value) => {
            rusqlite::types::Value::Integer(if *value { 1 } else { 0 })
        }
        serde_json::Value::Number(value) => {
            if let Some(num) = value.as_i64() {
                rusqlite::types::Value::Integer(num)
            } else if let Some(num) = value.as_u64() {
                if num <= i64::MAX as u64 {
                    rusqlite::types::Value::Integer(num as i64)
                } else {
                    rusqlite::types::Value::Real(num as f64)
                }
            } else {
                rusqlite::types::Value::Real(value.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(value) => rusqlite::types::Value::Text(value.clone()),
        serde_json::Value::Array(values) => rusqlite::types::Value::Blob(
            values
                .iter()
                .map(|value| value.as_u64().unwrap_or_default() as u8)
                .collect(),
        ),
        serde_json::Value::Object(value) => {
            // serde_json's map representation is feature-unified across the
            // workspace. Do not let an unrelated dependency enabling
            // `preserve_order` silently change the legacy SQLite text value.
            let mut entries = value.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            rusqlite::types::Value::Text(entries.into_iter().fold(
                String::new(),
                |mut out, (key, value)| {
                    if !out.is_empty() {
                        out.push(',');
                    }
                    out.push_str(key);
                    out.push('=');
                    stable_legacy_json_text(value, &mut out);
                    out
                },
            ))
        }
    }
}

fn to_sql_value(value: &serde_json::Value) -> rusqlite::types::Value {
    if let serde_json::Value::Object(object) = value {
        if object.len() == 1 {
            if let Some(envelope) = object
                .get("$ibexSqliteBindingV1")
                .and_then(serde_json::Value::as_object)
            {
                match envelope.get("kind").and_then(serde_json::Value::as_str) {
                    Some("blob") if envelope.len() == 2 => {
                        if let Some(encoded) =
                            envelope.get("base64").and_then(serde_json::Value::as_str)
                        {
                            if let Ok(bytes) =
                                base64::engine::general_purpose::STANDARD.decode(encoded)
                            {
                                return rusqlite::types::Value::Blob(bytes);
                            }
                        }
                    }
                    Some("value") if envelope.len() == 2 => {
                        if let Some(inner) = envelope.get("value") {
                            return plain_sql_value(inner);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    plain_sql_value(value)
}

enum SqlBindings {
    Positional(Vec<rusqlite::types::Value>),
    Named(Vec<(String, rusqlite::types::Value)>),
}

fn parse_bindings(raw: *const c_char) -> SqlBindings {
    if raw.is_null() {
        return SqlBindings::Positional(vec![]);
    }

    let raw = unsafe { CStr::from_ptr(raw) }.to_string_lossy();
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(serde_json::Value::Array(values)) => {
            SqlBindings::Positional(values.iter().map(to_sql_value).collect())
        }
        Ok(serde_json::Value::Object(values)) => SqlBindings::Named(
            values
                .into_iter()
                .map(|(key, value)| (key, to_sql_value(&value)))
                .collect(),
        ),
        Ok(serde_json::Value::Null) => SqlBindings::Positional(vec![]),
        Ok(other) => SqlBindings::Positional(vec![to_sql_value(&other)]),
        Err(_) => SqlBindings::Positional(vec![]),
    }
}

fn query_with_bindings<'stmt>(
    stmt: &'stmt mut rusqlite::Statement<'_>,
    bindings: &SqlBindings,
) -> rusqlite::Result<rusqlite::Rows<'stmt>> {
    match bindings {
        SqlBindings::Positional(values) => stmt.query(params_from_iter(values.iter())),
        SqlBindings::Named(values) => {
            let named: Vec<(&str, &dyn ToSql)> = values
                .iter()
                .map(|(name, value)| (name.as_str(), value as &dyn ToSql))
                .collect();
            stmt.query(named.as_slice())
        }
    }
}

fn execute_with_bindings(
    stmt: &mut rusqlite::Statement<'_>,
    bindings: &SqlBindings,
) -> rusqlite::Result<usize> {
    match bindings {
        SqlBindings::Positional(values) => stmt.execute(params_from_iter(values.iter())),
        SqlBindings::Named(values) => {
            let named: Vec<(&str, &dyn ToSql)> = values
                .iter()
                .map(|(name, value)| (name.as_str(), value as &dyn ToSql))
                .collect();
            stmt.execute(named.as_slice())
        }
    }
}

fn sqlite_value_to_json(value: ValueRef<'_>) -> serde_json::Value {
    match value {
        ValueRef::Null => serde_json::Value::Null,
        ValueRef::Integer(value) => serde_json::json!(value),
        ValueRef::Real(value) => serde_json::json!(value),
        ValueRef::Text(value) => std::str::from_utf8(value)
            .map(std::string::ToString::to_string)
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
        ValueRef::Blob(value) => {
            serde_json::json!({
                "$ibexSqliteBlobResultBase64":
                    base64::engine::general_purpose::STANDARD.encode(value)
            })
        }
    }
}

fn sqlite_value_type_name(value: &ValueRef<'_>) -> &'static str {
    match value {
        ValueRef::Null => "NULL",
        ValueRef::Integer(_) => "INTEGER",
        ValueRef::Real(_) => "FLOAT",
        ValueRef::Text(_) => "TEXT",
        ValueRef::Blob(_) => "BLOB",
    }
}

fn as_json_cstring(value: &serde_json::Value) -> *mut c_char {
    match serde_json::to_string(value) {
        Ok(payload) => match CString::new(payload) {
            Ok(value) => value.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

fn unix_time_millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos() / 1_000_000)
        .unwrap_or(0) as u64
}

fn unix_time_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0) as u64
}

fn make_stat_payload(path: &str, follow_links: bool) -> Option<serde_json::Value> {
    let meta = if follow_links {
        std::fs::metadata(path).ok()?
    } else {
        std::fs::symlink_metadata(path).ok()?
    };

    Some(make_stat_payload_from_metadata(meta))
}

fn make_stat_payload_from_metadata(meta: std::fs::Metadata) -> serde_json::Value {
    let mode = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode()
        }
        #[cfg(not(unix))]
        {
            0u32
        }
    };

    let (dev, ino, nlink, uid, gid, rdev, blksize, blocks) = {
        #[cfg(unix)]
        {
            (
                meta.dev(),
                meta.ino(),
                meta.nlink(),
                meta.uid(),
                meta.gid(),
                meta.rdev(),
                meta.blksize(),
                meta.blocks(),
            )
        }
        #[cfg(not(unix))]
        {
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64)
        }
    };

    let atime = meta.accessed().ok().unwrap_or(UNIX_EPOCH);
    let mtime = meta.modified().ok().unwrap_or(UNIX_EPOCH);
    let (ctime, birthtime) = {
        #[cfg(unix)]
        {
            let ctime_sec = meta.ctime();
            let ctime_nsec = meta.ctime_nsec() as u32;
            let ctime = if ctime_sec >= 0 {
                UNIX_EPOCH + Duration::new(ctime_sec as u64, ctime_nsec)
            } else {
                UNIX_EPOCH
            };
            (ctime, meta.created().ok().unwrap_or(ctime))
        }
        #[cfg(not(unix))]
        {
            let ctime = meta.modified().unwrap_or(UNIX_EPOCH);
            let birthtime = meta.created().unwrap_or(ctime);
            (ctime, birthtime)
        }
    };

    let atime_ms = unix_time_millis(atime);
    let mtime_ms = unix_time_millis(mtime);
    let ctime_ms = unix_time_millis(ctime);
    let birthtime_ms = unix_time_millis(birthtime);

    let atime_ns = unix_time_nanos(atime);
    let mtime_ns = unix_time_nanos(mtime);
    let ctime_ns = unix_time_nanos(ctime);
    let birthtime_ns = unix_time_nanos(birthtime);
    let file_type = meta.file_type();
    let (is_char_device, is_block_device, is_fifo, is_socket) = {
        #[cfg(unix)]
        {
            (
                file_type.is_char_device(),
                file_type.is_block_device(),
                file_type.is_fifo(),
                file_type.is_socket(),
            )
        }
        #[cfg(not(unix))]
        {
            (false, false, false, false)
        }
    };

    json!({
        "size": meta.len(),
        "mode": mode,
        "dev": dev,
        "ino": ino,
        "nlink": nlink,
        "uid": uid,
        "gid": gid,
        "rdev": rdev,
        "blksize": blksize,
        "blocks": blocks,
        "is_dir": file_type.is_dir(),
        "is_file": file_type.is_file(),
        "is_symlink": file_type.is_symlink(),
        "is_char_device": is_char_device,
        "is_block_device": is_block_device,
        "is_fifo": is_fifo,
        "is_socket": is_socket,
        "atime_ms": atime_ms,
        "mtime_ms": mtime_ms,
        "ctime_ms": ctime_ms,
        "birthtime_ms": birthtime_ms,
        "atime_ns": atime_ns,
        "mtime_ns": mtime_ns,
        "ctime_ns": ctime_ns,
        "birthtime_ns": birthtime_ns
    })
}

#[no_mangle]
pub extern "C" fn ex_host_version() -> u32 {
    EXACT_HOST_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn ex_host_init() {}

/// Install a closed, unarmed host singleton for ABI compatibility.
/// Called from iOS/Swift before creating a runtime.
/// Production embedders must replace it through `ex_host_install_armed`
/// before calling the armed Hermes constructor.
#[no_mangle]
pub extern "C" fn ex_host_install() {
    install_host(Host::closed_unarmed());
}

/// Explicit fail-closed embedder arming entry point. Returns 0 only after the
/// immutable snapshot is authenticated and installed.
///
/// # Safety
///
/// Each pointer must reference its declared byte length for the duration of
/// this call. The buffers are copied before return.
#[no_mangle]
pub unsafe extern "C" fn ex_host_install_armed(
    snapshot: *const u8,
    snapshot_len: usize,
    expected_identity: *const u8,
    expected_identity_len: usize,
) -> i32 {
    if snapshot.is_null() || expected_identity.is_null() {
        return -1;
    }
    let snapshot = unsafe { std::slice::from_raw_parts(snapshot, snapshot_len) };
    let expected = unsafe { std::slice::from_raw_parts(expected_identity, expected_identity_len) };
    match install_armed_host(snapshot, expected) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error: refusing host arming: {error}");
            -1
        }
    }
}

/// Engine/host handshake: exact digest equality proves the runtime being
/// created is attached to the decision context the caller authenticated.
///
/// # Safety
///
/// `digest` must be null or point to a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ex_host_matches_armed_snapshot_digest(digest: *const c_char) -> i32 {
    if digest.is_null() {
        return 0;
    }
    let Ok(digest) = unsafe { CStr::from_ptr(digest) }.to_str() else {
        return 0;
    };
    with_host(
        |host| {
            i32::from(
                host.armed_snapshot()
                    .is_some_and(|snapshot| snapshot.digest().as_str() == digest),
            )
        },
        0,
    )
}

/// Evaluate a complete typed decision set against the installed immutable
/// context. Returns a heap-owned JSON decision/evidence envelope; malformed
/// input, missing arming, and semantic errors return an `error` envelope and
/// must be treated as denial by the caller.
/// @ref LLP 0021#decision-staging-and-principal-semantics
///
/// # Safety
///
/// Non-null pointers must reference their declared byte lengths for the
/// duration of this call. The returned string is owned by the caller and must
/// be released with `ex_host_free_string`.
#[no_mangle]
pub unsafe extern "C" fn ex_host_evaluate_typed_decision(
    decision_set: *const u8,
    decision_set_len: usize,
    gates: *const u8,
    gates_len: usize,
) -> *mut c_char {
    if decision_set.is_null() || gates.is_null() {
        return as_json_cstring(&json!({"error": "null typed decision input"}));
    }
    let decision_set = unsafe { std::slice::from_raw_parts(decision_set, decision_set_len) };
    let gates = unsafe { std::slice::from_raw_parts(gates, gates_len) };
    let result = with_host(
        |host| match host.evaluate_typed_decision_json_with_evidence(decision_set, gates) {
            Ok(result) => as_json_cstring(&json!({
                "decision": result.decision,
                "evidence": result.evidence,
            })),
            Err(error) => as_json_cstring(&json!({"error": error.to_string()})),
        },
        std::ptr::null_mut(),
    );
    if result.is_null() {
        as_json_cstring(&json!({"error": "host is not installed"}))
    } else {
        result
    }
}

/// Authorize one stage of the native `fs.open` branch against authenticated
/// logical roots, a retained parent directory, and the actual descriptor.
/// Returns 1 allow, 0 deny, and -1 for malformed/unsupported adapter input.
///
/// # Safety
/// `module_ids` must reference `module_ids_len` values. `path` and an optional
/// `presented_handle_id` must be valid C strings for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_fs_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    path: *const c_char,
    stage: u32,
    surface: u32,
    parent_fd: i32,
    fd: i32,
    needs_read: i32,
    needs_write: i32,
    presented_handle_id: *const c_char,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{NonEmptyString, Stage};

    if path.is_null()
        || module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || !matches!(stage, 0..=5)
    {
        return -1;
    }
    let (operation_key, coverage_edge_id) = match surface {
        0 => ("fs-open", "surface.native.op.exactfsopen.05ao6wa"),
        1 => ("fs-read-file", "surface.native.op.exactreadfile.1cmzco7"),
        2 => (
            "fs-read-file-async",
            "surface.native.op.exactfsreadfileasync.0fw3fo0",
        ),
        3 => ("fs-stat", "surface.native.op.exactstat.1432ztv"),
        4 => ("fs-readdir", "surface.native.op.exactreaddir.0tg30vk"),
        5 => ("fs-write-file", "surface.native.op.exactwritefile.1h0gy8u"),
        6 => (
            "fs-append-file",
            "surface.native.op.exactappendfile.1b1b7nn",
        ),
        7 => (
            "fs-write-file-async",
            "surface.native.op.exactfswritefileasync.0fv6zp9",
        ),
        8 => (
            "fs-stat-async",
            "surface.native.op.exactfsstatasync.0b0hr8s",
        ),
        9 => ("fs-realpath", "surface.native.op.exactrealpath.06qb6s2"),
        10 => ("fs-lstat", "surface.native.op.exactlstat.1c98s6l"),
        11 => (
            "fs-lstat-async",
            "surface.native.op.exactfsstatasync.0b0hr8s",
        ),
        12 => ("fs-mkdir", "surface.native.op.exactmkdir.021eaz0"),
        _ => return -1,
    };
    let follow_mode = if matches!(surface, 10 | 11) {
        capsec_semantics::model::FollowMode::NoFollowFinal
    } else {
        capsec_semantics::model::FollowMode::FollowFinal
    };
    let path_bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStrExt;
        std::path::PathBuf::from(std::ffi::OsStr::from_bytes(path_bytes))
    };
    #[cfg(not(unix))]
    let path = match std::str::from_utf8(path_bytes) {
        Ok(path) => std::path::PathBuf::from(path),
        Err(_) => return -1,
    };
    let presented = if presented_handle_id.is_null() {
        Vec::new()
    } else {
        let value = unsafe { CStr::from_ptr(presented_handle_id) }
            .to_string_lossy()
            .into_owned();
        match NonEmptyString::new(value) {
            Ok(value) => vec![value],
            Err(_) => return -1,
        }
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let (stage, object_state, disclosure_only, parent_object, final_object, retained_handle) =
        if stage == 0 {
            (
                Stage::Requested,
                capsec_semantics::model::ObjectState::Existing,
                true,
                None,
                None,
                None,
            )
        } else if matches!(stage, 3 | 4) {
            #[cfg(unix)]
            {
                if parent_fd < 0 {
                    return -1;
                }
                let Some(parent_object) = object_identity_for_fd(parent_fd) else {
                    return 0;
                };
                let (object_state, final_object) = match object_identity_at(
                    parent_fd,
                    &path,
                    follow_mode == capsec_semantics::model::FollowMode::FollowFinal,
                ) {
                    Ok(Some(identity)) => (
                        capsec_semantics::model::ObjectState::Existing,
                        Some(identity),
                    ),
                    Ok(None) => (capsec_semantics::model::ObjectState::AbsentCreate, None),
                    Err(()) => return 0,
                };
                (
                    Stage::Discovery,
                    object_state,
                    stage == 3,
                    Some(parent_object),
                    final_object,
                    None,
                )
            }
            #[cfg(not(unix))]
            {
                return -1;
            }
        } else {
            if parent_fd < 0 || fd < 0 {
                return -1;
            }
            #[cfg(unix)]
            {
                let Some(final_object) = object_identity_for_fd(fd) else {
                    return -1;
                };
                let Some(parent_object) = object_identity_for_fd(parent_fd) else {
                    return -1;
                };
                let retained = match NonEmptyString::new(format!("fd:{fd}")) {
                    Ok(value) => value,
                    Err(_) => return -1,
                };
                (
                    if stage == 1 {
                        Stage::Commit
                    } else {
                        Stage::Repeat
                    },
                    capsec_semantics::model::ObjectState::Existing,
                    stage == 5,
                    Some(parent_object),
                    Some(final_object),
                    Some(retained),
                )
            }
            #[cfg(not(unix))]
            {
                return -1;
            }
        };
    let resolved_parent_path = if stage == Stage::Requested {
        None
    } else {
        match resolved_path_for_fd(parent_fd) {
            Some(path) => Some(path),
            None => return 0,
        }
    };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            #[cfg(unix)]
            if matches!(stage, Stage::Discovery | Stage::Commit) {
                let Some(principal) = host.typed_principal_for_module(&module_id.to_string())
                else {
                    return -1;
                };
                let requested = match host.typed_logical_path(&principal, &path) {
                    Ok(requested) => requested,
                    Err(error) => {
                        eprintln!("error: typed filesystem path refused: {error}");
                        return -1;
                    }
                };
                // Opening a logical root necessarily retains its parent, which
                // is outside that root. The decision below binds the discovered
                // final object to the authenticated root object; descendants
                // still require the retained parent itself to descend from it.
                // @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
                if !requested.components.is_empty() {
                    match host.validate_typed_parent_fd_ancestry(&principal, &path, parent_fd) {
                        Ok(true) => {}
                        Ok(false) => return 0,
                        Err(error) => {
                            eprintln!(
                                "error: retained filesystem parent ancestry refused: {error}"
                            );
                            return -1;
                        }
                    }
                }
            }
            match host.authorize_typed_fs_open_stage(
                &module_id.to_string(),
                operation_key,
                coverage_edge_id,
                constrained_principals,
                &path,
                stage,
                object_state,
                follow_mode,
                disclosure_only,
                resolved_parent_path.as_deref(),
                needs_read != 0
                    && !(stage == Stage::Discovery
                        && object_state == capsec_semantics::model::ObjectState::AbsentCreate
                        && !disclosure_only),
                needs_write != 0,
                parent_object,
                final_object,
                retained_handle,
                presented,
            ) {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(_) => 0,
                Err(error) => {
                    eprintln!("error: typed filesystem authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one declared stage of a reviewed native system-information read.
/// Returns 1 for allow, 0 for deny, and -1 for malformed or unsupported input.
///
/// `surface` selects a closed native adapter/coverage-edge mapping.  The
/// `info_name` tag is consulted only by the generic cached-value gate; native
/// readers have an immutable resource kind in the table below.  This keeps
/// JavaScript from supplying action ids or coverage-edge ids as strings.
///
/// # Safety
/// `module_ids` must reference `module_ids_len` values for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_system_info_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    surface: u32,
    info_name: u32,
    stage: u32,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{Stage, SystemInfoName};

    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 || stage > 1 {
        return -1;
    }
    let decode_name = |tag| match tag {
        0 => Some(SystemInfoName::Architecture),
        1 => Some(SystemInfoName::CameraMetadata),
        2 => Some(SystemInfoName::Cpus),
        3 => Some(SystemInfoName::Cwd),
        4 => Some(SystemInfoName::Hostname),
        5 => Some(SystemInfoName::Language),
        6 => Some(SystemInfoName::LoadAverage),
        7 => Some(SystemInfoName::Locale),
        8 => Some(SystemInfoName::Memory),
        9 => Some(SystemInfoName::NetworkInterfaces),
        10 => Some(SystemInfoName::OsRelease),
        11 => Some(SystemInfoName::Platform),
        12 => Some(SystemInfoName::Screen),
        13 => Some(SystemInfoName::StoragePaths),
        14 => Some(SystemInfoName::Uptime),
        15 => Some(SystemInfoName::User),
        _ => None,
    };
    let (operation_key, coverage_edge_id, name) = match surface {
        0 => (
            "get-cpu-count",
            "surface.native.op.exactgetcpucount.1k05aty",
            SystemInfoName::Cpus,
        ),
        1 => (
            "get-free-memory",
            "surface.native.op.exactgetfreemem.0dytp7m",
            SystemInfoName::Memory,
        ),
        2 => (
            "get-hostname",
            "surface.native.op.exactgethostname.01gi6am",
            SystemInfoName::Hostname,
        ),
        3 => (
            "get-load-average",
            "surface.native.op.exactgetloadavg.10t3k2t",
            SystemInfoName::LoadAverage,
        ),
        4 => (
            "get-network-interfaces",
            "surface.native.op.exactgetnetworkinterfaces.15q8n2j",
            SystemInfoName::NetworkInterfaces,
        ),
        5 => (
            "get-total-memory",
            "surface.native.op.exactgettotalmem.0ziuv9c",
            SystemInfoName::Memory,
        ),
        6 => (
            "get-uptime",
            "surface.native.op.exactgetuptime.0ydqt27",
            SystemInfoName::Uptime,
        ),
        7 => (
            "get-user-info",
            "surface.native.op.exactgetuserinfo.027b1gs",
            SystemInfoName::User,
        ),
        8 => (
            "authorize-cached-system-info",
            "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
            match decode_name(info_name) {
                Some(name) => name,
                None => return -1,
            },
        ),
        9 => (
            "system-info-process-rss",
            "surface.native.op.exactgetprocessrss.0o50wgs",
            SystemInfoName::Memory,
        ),
        10 => (
            "system-info-cwd",
            "surface.native.op.exactgetcwd.1bhagb7",
            SystemInfoName::Cwd,
        ),
        _ => return -1,
    };
    let stage = if stage == 0 {
        Stage::Requested
    } else {
        Stage::Commit
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            match host.authorize_typed_system_info_stage(
                &module_id.to_string(),
                operation_key,
                coverage_edge_id,
                constrained_principals,
                name,
                stage,
            ) {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(_) => 0,
                Err(error) => {
                    eprintln!("error: typed system-information authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one requested/commit stage for an exact broker-base environment
/// read. Returns 1 allow, 0 deny, and -1 for malformed adapter input.
///
/// # Safety
/// `module_ids` and `name` must reference their declared lengths for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_environment_read_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    stage: u32,
    name: *const u8,
    name_len: usize,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{EnvironmentName, Stage};

    if module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || name.is_null()
        || name_len == 0
        || name_len > 32_768
        || stage > 1
    {
        return -1;
    }
    let stage = if stage == 0 {
        Stage::Requested
    } else {
        Stage::Commit
    };
    let name = unsafe { std::slice::from_raw_parts(name, name_len) };
    let name = match std::str::from_utf8(name)
        .ok()
        .and_then(|name| EnvironmentName::new(name).ok())
    {
        Some(name) => name,
        None => return -1,
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            match host.authorize_typed_environment_read_stage(
                &module_id.to_string(),
                constrained_principals,
                name,
                stage,
            ) {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(_) => 0,
                Err(error) => {
                    eprintln!("error: typed environment authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one stage of the direct global `print()` stdout broker write.
/// Returns 1 allow, 0 deny, and -1 for malformed adapter input.
///
/// # Safety
/// `module_ids` must reference `module_ids_len` values for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_print_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    stage: u32,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::Stage;

    if module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return -1;
    }
    let stage = match stage {
        0 => Stage::Requested,
        2 => Stage::Commit,
        4 => Stage::Repeat,
        _ => return -1,
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            match host.authorize_typed_print_stage(
                &module_id.to_string(),
                constrained_principals,
                stage,
            ) {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(_) => 0,
                Err(error) => {
                    eprintln!("error: typed print authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one staged fetch or raw-connect occurrence from an engine adapter.
/// Returns 1 allow, 0 deny, and -1 for malformed or unsupported input.
///
/// `network_kind` is 0/1 for HTTP/HTTPS fetch and 2..=7 for
/// TCP/TLS/UDP/WS/WSS connect. `stage` is requested, candidate,
/// commit, delivery, repeat, or cleanup as 0..=5. Candidates are a canonical
/// JSON array of IP address strings; optional strings use null pointers.
///
/// # Safety
/// All pointer/length pairs and C strings must remain valid for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_network_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    network_kind: u32,
    host: *const c_char,
    port: u16,
    stage: u32,
    candidates_json: *const c_char,
    selected_candidate: *const c_char,
    verified_peer: *const c_char,
    connection_id: *const c_char,
    redirect_index: u64,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{
        ConcreteHost, ConnectTransport, DnsName, FetchScheme, IpAddress, NonEmptyString, Port,
        SafeUint, Stage, VerifiedPeer,
    };

    if module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || host.is_null()
        || candidates_json.is_null()
        || port == 0
        || stage > 5
        || network_kind > 6
    {
        return -1;
    }
    let stage = match stage {
        0 => Stage::Requested,
        1 => Stage::Candidate,
        2 => Stage::Commit,
        3 => Stage::Delivery,
        4 => Stage::Repeat,
        5 => Stage::Cleanup,
        _ => return -1,
    };
    let host_text = unsafe { CStr::from_ptr(host) }.to_string_lossy();
    let concrete_host = match host_text.parse::<std::net::IpAddr>() {
        Ok(address) if IpAddress::new(address).to_string() == host_text => ConcreteHost::Ip {
            address: IpAddress::new(address),
        },
        Ok(_) => return -1,
        Err(_) => match DnsName::new(host_text.as_ref()) {
            Ok(name) => ConcreteHost::DnsName { name },
            Err(_) => return -1,
        },
    };
    let Some(port) = Port::new(port) else {
        return -1;
    };
    let candidates_text = unsafe { CStr::from_ptr(candidates_json) }.to_bytes();
    let candidates: Vec<IpAddress> = match std::str::from_utf8(candidates_text)
        .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))
        .and_then(capsec_semantics::strict_json::parse_strict)
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))
        }) {
        Ok(candidates) => candidates,
        Err(_) => return -1,
    };
    let parse_optional_ip = |value: *const c_char| -> Option<Option<IpAddress>> {
        if value.is_null() {
            return Some(None);
        }
        let text = unsafe { CStr::from_ptr(value) }.to_string_lossy();
        let address = text.parse::<std::net::IpAddr>().ok()?;
        (IpAddress::new(address).to_string() == text).then_some(Some(IpAddress::new(address)))
    };
    let Some(selected_candidate) = parse_optional_ip(selected_candidate) else {
        return -1;
    };
    let Some(verified_address) = parse_optional_ip(verified_peer) else {
        return -1;
    };
    let verified_peer = verified_address.map(|address| VerifiedPeer { address, port });
    let connection_id = if connection_id.is_null() {
        None
    } else {
        match NonEmptyString::new(
            unsafe { CStr::from_ptr(connection_id) }
                .to_string_lossy()
                .into_owned(),
        ) {
            Ok(value) => Some(value),
            Err(_) => return -1,
        }
    };
    let redirect_index = if redirect_index == u64::MAX {
        None
    } else {
        match SafeUint::new(redirect_index) {
            Ok(value) => Some(value),
            Err(_) => return -1,
        }
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(_) => return -1,
                };
            let result = match network_kind {
                0 | 1 => host.authorize_typed_fetch_stage(
                    &module_id.to_string(),
                    constrained_principals,
                    if network_kind == 0 {
                        FetchScheme::Http
                    } else {
                        FetchScheme::Https
                    },
                    concrete_host,
                    port,
                    stage,
                    candidates,
                    selected_candidate,
                    verified_peer,
                    connection_id,
                    redirect_index,
                ),
                2..=6 => host.authorize_typed_connect_stage(
                    &module_id.to_string(),
                    match network_kind {
                        2 | 3 => "tcp-connect",
                        4 => "udp-send",
                        5 | 6 => "websocket-connect",
                        _ => unreachable!(),
                    },
                    match network_kind {
                        2 | 3 => "surface.native.op.exacttcpconnect.1cs9rhu",
                        4 => "surface.native.op.exactudpsend.0k2gg86",
                        5 | 6 => "surface.native.op.exactwsconnect.026jz87",
                        _ => unreachable!(),
                    },
                    constrained_principals,
                    match network_kind {
                        2 => ConnectTransport::Tcp,
                        3 => ConnectTransport::Tls,
                        4 => ConnectTransport::Udp,
                        5 => ConnectTransport::Ws,
                        6 => ConnectTransport::Wss,
                        _ => unreachable!(),
                    },
                    concrete_host,
                    port,
                    stage,
                    candidates,
                    selected_candidate,
                    verified_peer,
                    connection_id,
                ),
                _ => return -1,
            };
            match result {
                Ok(decision)
                    if matches!(
                        decision.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    ) =>
                {
                    1
                }
                Ok(_) => 0,
                Err(error) => {
                    eprintln!("error: typed network authorization refused: {error}");
                    -1
                }
            }
        },
        -1,
    )
}

/// Authorize one literal-destination UDP datagram across requested, candidate,
/// and commit stages while parsing and attributing its inputs only once.
///
/// # Safety
/// Pointer arguments must remain valid for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_authorize_typed_udp_datagram_stack(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    host: *const c_char,
    port: u16,
    connection_id: *const c_char,
) -> i32 {
    use capsec_semantics::decision::DecisionOutcome;
    use capsec_semantics::model::{
        ConcreteHost, ConnectTransport, IpAddress, NonEmptyString, Port, Stage, VerifiedPeer,
    };

    if module_ids.is_null()
        || module_ids_len == 0
        || module_ids_len > 257
        || host.is_null()
        || connection_id.is_null()
        || port == 0
    {
        return -1;
    }
    let host_text = unsafe { CStr::from_ptr(host) }.to_string_lossy();
    let address = match host_text.parse::<std::net::IpAddr>() {
        Ok(address) if IpAddress::new(address).to_string() == host_text => IpAddress::new(address),
        _ => return -1,
    };
    let Some(port) = Port::new(port) else {
        return -1;
    };
    let connection_id = match NonEmptyString::new(
        unsafe { CStr::from_ptr(connection_id) }
            .to_string_lossy()
            .into_owned(),
    ) {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    with_host(
        |host| {
            let mut constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => return -1,
            };
            constrained_principals
                .sort_by_key(|principal| principal.canonical_sort_key().unwrap_or_default());
            constrained_principals.dedup();
            let requested = ConcreteHost::Ip { address };
            for stage in [Stage::Requested, Stage::Candidate, Stage::Commit] {
                let selected = (stage != Stage::Requested).then_some(address);
                let verified = (stage == Stage::Commit).then_some(VerifiedPeer { address, port });
                let committed_id = (stage == Stage::Commit).then_some(connection_id.clone());
                let result = host.authorize_typed_connect_stage(
                    &module_id.to_string(),
                    "udp-send",
                    "surface.native.op.exactudpsend.0k2gg86",
                    constrained_principals.clone(),
                    ConnectTransport::Udp,
                    requested.clone(),
                    port,
                    stage,
                    vec![address],
                    selected,
                    verified,
                    committed_id,
                );
                match result {
                    Ok(decision)
                        if matches!(
                            decision.outcome,
                            DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                        ) => {}
                    Ok(_) => return 0,
                    Err(error) => {
                        eprintln!("error: typed UDP authorization refused: {error}");
                        return -1;
                    }
                }
            }
            1
        },
        -1,
    )
}

#[cfg(unix)]
fn object_identity_for_fd(fd: i32) -> Option<capsec_semantics::model::ObjectIdentity> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return None;
    }
    object_identity_from_stat(unsafe { stat.assume_init() })
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn resolved_path_for_fd(fd: i32) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buffer = vec![0u8; libc::PATH_MAX as usize];
    if unsafe { libc::fcntl(fd, libc::F_GETPATH, buffer.as_mut_ptr()) } != 0 {
        return None;
    }
    let length = buffer.iter().position(|byte| *byte == 0)?;
    Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        &buffer[..length],
    )))
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
fn resolved_path_for_fd(fd: i32) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

#[cfg(unix)]
fn object_identity_at(
    parent_fd: i32,
    path: &std::path::Path,
    follow_final: bool,
) -> Result<Option<capsec_semantics::model::ObjectIdentity>, ()> {
    use std::os::unix::ffi::OsStrExt;
    let name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("."));
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| ())?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let flags = if follow_final {
        0
    } else {
        libc::AT_SYMLINK_NOFOLLOW
    };
    if unsafe { libc::fstatat(parent_fd, name.as_ptr(), stat.as_mut_ptr(), flags) } == 0 {
        return Ok(object_identity_from_stat(unsafe { stat.assume_init() }));
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOENT) => Ok(None),
        _ => Err(()),
    }
}

#[cfg(unix)]
fn object_identity_from_stat(stat: libc::stat) -> Option<capsec_semantics::model::ObjectIdentity> {
    object_identity(stat.st_dev as u64, stat.st_ino)
}

#[cfg(unix)]
fn object_identity(dev: u64, ino: u64) -> Option<capsec_semantics::model::ObjectIdentity> {
    use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
    Some(ObjectIdentity {
        platform: if cfg!(any(target_os = "macos", target_os = "ios")) {
            ObjectPlatform::Apple
        } else {
            ObjectPlatform::Unix
        },
        volume: NonEmptyString::new(format!("dev:{dev}")).ok()?,
        file: NonEmptyString::new(format!("ino:{ino}")).ok()?,
    })
}

/// Publish a ceiling-bounded typed dynamic grant. Returns 1 when applied, 0
/// for an idempotent duplicate, and -1 on malformed/forbidden input.
///
/// # Safety
///
/// `request` must reference `request_len` readable bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_typed_dynamic_grant(
    module_id: u64,
    request: *const u8,
    request_len: usize,
) -> i32 {
    if request.is_null() {
        return -1;
    }
    let request = unsafe { std::slice::from_raw_parts(request, request_len) };
    let result = with_host(
        |host| match host.typed_principal_for_module(&module_id.to_string()) {
            Some(principal) => {
                match host.grant_typed_dynamic_json_for_principal(principal, request) {
                    Ok(applied) => i32::from(applied),
                    Err(error) => {
                        eprintln!("error: typed dynamic grant refused: {error}");
                        -1
                    }
                }
            }
            None => {
                eprintln!("error: typed dynamic grant refused: unknown executing principal");
                -1
            }
        },
        -1,
    );
    if result == 1 {
        notify_runtime_authority_change();
    }
    result
}

/// Revoke a typed dynamic grant by its JSON string ID. Returns 1 when removed,
/// 0 when absent, and -1 on malformed input.
///
/// # Safety
///
/// `request` must reference `request_len` readable bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_typed_dynamic_revoke(
    module_id: u64,
    request: *const u8,
    request_len: usize,
) -> i32 {
    if request.is_null() {
        return -1;
    }
    let request = unsafe { std::slice::from_raw_parts(request, request_len) };
    let result = with_host(
        |host| match host.typed_principal_for_module(&module_id.to_string()) {
            Some(principal) => {
                match host.revoke_typed_dynamic_json_for_principal(&principal, request) {
                    Ok(removed) => i32::from(removed),
                    Err(error) => {
                        eprintln!("error: typed dynamic revocation refused: {error}");
                        -1
                    }
                }
            }
            None => {
                eprintln!("error: typed dynamic revocation refused: unknown executing principal");
                -1
            }
        },
        -1,
    );
    if result == 1 {
        notify_runtime_authority_change();
    }
    result
}

/// Mint or re-attenuate an unguessable typed bearer handle. Returns a
/// heap-owned JSON `handleId` or `error` envelope.
///
/// # Safety
///
/// `request` must reference `request_len` readable bytes for this call. Free
/// the returned string with `ex_host_free_string`.
#[no_mangle]
pub unsafe extern "C" fn ex_host_typed_handle_mint(
    module_id: u64,
    module_ids: *const u64,
    module_ids_len: usize,
    request: *const u8,
    request_len: usize,
) -> *mut c_char {
    if request.is_null() || module_ids.is_null() || module_ids_len == 0 || module_ids_len > 257 {
        return as_json_cstring(&json!({"error": "null typed handle request"}));
    }
    let request = unsafe { std::slice::from_raw_parts(request, request_len) };
    let module_ids = unsafe { std::slice::from_raw_parts(module_ids, module_ids_len) };
    let result = with_host(
        |host| {
            let Some(actor) = host.typed_principal_for_module(&module_id.to_string()) else {
                return as_json_cstring(&json!({"error": "authenticated handle actor is unknown"}));
            };
            let constrained_principals = match module_ids
                .iter()
                .map(|id| host.typed_principal_for_module(&id.to_string()))
                .collect::<Option<Vec<_>>>()
            {
                Some(principals) => principals,
                None => {
                    return as_json_cstring(
                        &json!({"error": "constrained handle principal is unknown"}),
                    )
                }
            };
            let constrained_principals =
                match capsec_semantics::model::canonicalize_principal_set(constrained_principals) {
                    Ok(principals) => principals,
                    Err(error) => {
                        return as_json_cstring(&json!({"error": error.to_string()}));
                    }
                };
            match host.mint_typed_handle_json_for_actor(actor, constrained_principals, request) {
                Ok(handle_id) => {
                    notify_runtime_authority_change();
                    as_json_cstring(&json!({"handleId": handle_id.as_str()}))
                }
                Err(error) => as_json_cstring(&json!({"error": error.to_string()})),
            }
        },
        std::ptr::null_mut(),
    );
    if result.is_null() {
        as_json_cstring(&json!({"error": "host is not installed"}))
    } else {
        result
    }
}

/// Revoke a typed bearer handle and all descendants by JSON string ID.
/// Returns 1 when removed, 0 when absent, and -1 on malformed input.
///
/// # Safety
///
/// `request` must reference `request_len` readable bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn ex_host_typed_handle_revoke(
    module_id: u64,
    request: *const u8,
    request_len: usize,
) -> i32 {
    if request.is_null() {
        return -1;
    }
    let request = unsafe { std::slice::from_raw_parts(request, request_len) };
    let result = with_host(
        |host| {
            let Some(actor) = host.typed_principal_for_module(&module_id.to_string()) else {
                return -1;
            };
            match host.revoke_typed_handle_json_for_actor(&actor, request) {
                Ok(removed) => i32::from(removed),
                Err(error) => {
                    eprintln!("error: typed handle revocation refused: {error}");
                    -1
                }
            }
        },
        -1,
    );
    if result == 1 {
        notify_runtime_authority_change();
    }
    result
}

/// Copy the current authenticated authority generations into caller-owned
/// outputs. Returns 1 for an armed host and 0 otherwise.
///
/// # Safety
/// All output pointers must be non-null and writable.
#[no_mangle]
pub unsafe extern "C" fn ex_host_typed_generations(
    negative: *mut u64,
    dynamic: *mut u64,
    handle: *mut u64,
) -> i32 {
    if negative.is_null() || dynamic.is_null() || handle.is_null() {
        return 0;
    }
    let Some(generations) = with_host(|host| host.typed_generations(), None) else {
        return 0;
    };
    unsafe {
        *negative = generations.negative.get();
        *dynamic = generations.dynamic.get();
        *handle = generations.handle.get();
    }
    1
}

fn notify_runtime_authority_change() {
    unsafe extern "C" {
        fn ex_hermes_notify_callback();
    }
    unsafe { ex_hermes_notify_callback() };
}

/// Returns 1 if the host is in Legacy (allow-all) mode, 0 otherwise.
/// Used by the C++ bridge to skip expensive capability checks.
#[no_mangle]
pub extern "C" fn ex_host_is_allow_all() -> i32 {
    with_host(|host| if host.is_allow_all() { 1 } else { 0 }, 0)
}

#[no_mangle]
pub extern "C" fn ex_host_is_armed() -> i32 {
    with_host(|host| i32::from(host.armed_snapshot().is_some()), 0)
}

/// Return the authenticated snapshot endowments for the active Host context.
/// Bootstrap consumes and frees this copy; no process-global environment
/// channel participates in production authority.
#[no_mangle]
pub extern "C" fn ex_host_armed_endowments() -> *mut c_char {
    let groups = with_host(
        |host| {
            host.armed_snapshot()
                .map_or(Ok(None), |snapshot| snapshot.endowment_groups().map(Some))
        },
        Ok(None),
    );
    let Ok(Some(groups)) = groups else {
        return ptr::null_mut();
    };
    CString::new(groups.join(";"))
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}

/// Return the current legacy capability-decision generation. Zero means no
/// host is installed and therefore cannot validate a retained-resource lease.
#[no_mangle]
pub extern "C" fn ex_host_legacy_authorization_generation() -> u64 {
    with_host(Host::legacy_authorization_generation, 0)
}

/// Only enforce-mode allows may be memoized. Audit would-denies deliberately
/// proceed but must still append evidence on every occurrence.
#[no_mangle]
pub extern "C" fn ex_host_legacy_authorization_cacheable() -> i32 {
    with_host(|host| i32::from(host.legacy_authorization_cacheable()), 0)
}

/// Read an entire file into a heap-allocated buffer in a single call.
/// Returns null on error. Caller must free with `ex_host_free_buffer`.
#[no_mangle]
pub extern "C" fn ex_host_fs_read_file(
    path: *const c_char,
    out_len: *mut u64,
    out_errno: *mut i32,
) -> *mut u8 {
    if path.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            let errno_code = normalized_io_error_code(&err);
            record_fs_error(errno_code);
            unsafe {
                *out_len = 0;
                if !out_errno.is_null() {
                    *out_errno = errno_code;
                }
            }
            return ptr::null_mut();
        }
    };

    let mut data = Vec::new();
    match std::io::Read::read_to_end(&mut file, &mut data) {
        Ok(_) => {
            let boxed = data.into_boxed_slice();
            // Report the true allocation length. `usize as u64` is lossless on all
            // supported targets; the C++ caller passes this exact value back to
            // `ex_host_free_buffer`, so the reconstructed slice layout matches the
            // allocation. Truncating to u32 here corrupted the free layout and
            // silently short-read files >= 4 GiB.
            let len = boxed.len();
            unsafe { *out_len = len as u64 };
            Box::into_raw(boxed) as *mut u8
        }
        Err(err) => {
            let errno_code = normalized_io_error_code(&err);
            record_fs_error(errno_code);
            unsafe {
                *out_len = 0;
                if !out_errno.is_null() {
                    *out_errno = errno_code;
                }
            }
            ptr::null_mut()
        }
    }
}

/// Free a buffer returned by `ex_host_fs_read_file`.
#[no_mangle]
pub extern "C" fn ex_host_free_buffer(buf: *mut u8, len: u64) {
    if !buf.is_null() && len > 0 {
        unsafe {
            let raw = ptr::slice_from_raw_parts_mut(buf, len as usize);
            drop(Box::from_raw(raw));
        }
    }
}

/// A u64 principal id rendered to its decimal-string form in a fixed inline
/// buffer. The capability manager keys principals by decimal string; the check
/// FFI entry points run on the enforce/audit hot path (every gated syscall), so
/// they must not heap-allocate a `String` per call just to perform a lookup —
/// the string form is only materialized on the heap where audit rendering
/// actually records it (a would-deny). (ENG-22644)
#[derive(Clone, Copy)]
struct PrincipalIdBuf {
    buf: [u8; 20],
    start: usize,
}

impl PrincipalIdBuf {
    const EMPTY: PrincipalIdBuf = PrincipalIdBuf {
        buf: [b'0'; 20],
        start: 20,
    };

    fn new(mut value: u64) -> Self {
        let mut buf = [b'0'; 20];
        let mut start = 20;
        loop {
            start -= 1;
            buf[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        PrincipalIdBuf { buf, start }
    }

    fn as_str(&self) -> &str {
        // The buffer holds only ASCII digits.
        std::str::from_utf8(&self.buf[self.start..]).unwrap_or("0")
    }
}

/// Render a principal-id stack to the decimal-string forms the capability
/// manager keys on, without per-call heap allocation for the common case.
/// Stacks carry DISTINCT principals (one per package on the call chain), so
/// almost every real stack fits the inline capacity; deeper stacks fall back
/// to a heap rendering. (ENG-22644)
fn with_rendered_principal_stack<R>(ids: &[u64], f: impl FnOnce(&[&str]) -> R) -> R {
    const INLINE_STACK_PRINCIPALS: usize = 16;
    if ids.len() <= INLINE_STACK_PRINCIPALS {
        let mut bufs = [PrincipalIdBuf::EMPTY; INLINE_STACK_PRINCIPALS];
        for (slot, id) in bufs.iter_mut().zip(ids.iter()) {
            *slot = PrincipalIdBuf::new(*id);
        }
        let mut refs: [&str; INLINE_STACK_PRINCIPALS] = [""; INLINE_STACK_PRINCIPALS];
        for (slot, buf) in refs.iter_mut().zip(bufs.iter()).take(ids.len()) {
            *slot = buf.as_str();
        }
        f(&refs[..ids.len()])
    } else {
        let strings: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        f(&refs)
    }
}

#[no_mangle]
pub extern "C" fn ex_host_check_capability(module_id: u64, capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }

    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();

    let module = PrincipalIdBuf::new(module_id);
    let allowed = with_host(|host| host.check_capability(module.as_str(), &cap), false);
    if allowed {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn ex_host_check_capability_no_follow_final(
    module_id: u64,
    capability: *const c_char,
) -> i32 {
    if capability.is_null() {
        return 0;
    }

    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();

    let module = PrincipalIdBuf::new(module_id);
    let allowed = with_host(
        |host| host.check_capability_no_follow_final(module.as_str(), &cap),
        false,
    );
    if allowed {
        1
    } else {
        0
    }
}

/// Handle minting is stricter than ordinary root operations: the caller must
/// have an explicit grant for the exact capability carried by the handle, so an
/// ambient trusted root operation cannot mint a passable subtree token.
#[no_mangle]
pub extern "C" fn ex_host_check_handle_mint(module_id: u64, capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }

    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();

    let module = PrincipalIdBuf::new(module_id);
    let allowed = with_host(|host| host.check_handle_mint(module.as_str(), &cap), false);
    if allowed {
        1
    } else {
        0
    }
}

/// Stack-intersection capability check for deputy-sensitive classes (Phase 5).
/// `module_ids` is the distinct principal stack, innermost-first, from
/// frame-derived attribution; the effective grant is the AND over the stack for
/// configured deputy classes, and the normal top-principal check otherwise.
/// @ref LLP 0013#phase-5
#[no_mangle]
pub extern "C" fn ex_host_check_capability_stack(
    module_ids: *const u64,
    len: usize,
    capability: *const c_char,
) -> i32 {
    if capability.is_null() || module_ids.is_null() || len == 0 {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();
    let ids = unsafe { std::slice::from_raw_parts(module_ids, len) };
    // Render each numeric principal to the decimal-string form the manager keys
    // on (matching ex_host_check_capability's single-principal conversion),
    // using inline stack buffers instead of a per-call Vec<String>. (ENG-22644)
    let allowed = with_rendered_principal_stack(ids, |stack_refs| {
        with_host(|host| host.check_capability_stack(stack_refs, &cap), false)
    });
    if allowed {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn ex_host_check_capability_stack_no_follow_final(
    module_ids: *const u64,
    len: usize,
    capability: *const c_char,
) -> i32 {
    if capability.is_null() || module_ids.is_null() || len == 0 {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }.to_string_lossy();
    let ids = unsafe { std::slice::from_raw_parts(module_ids, len) };
    let allowed = with_rendered_principal_stack(ids, |stack_refs| {
        with_host(
            |host| host.check_capability_stack_no_follow_final(stack_refs, &cap),
            false,
        )
    });
    if allowed {
        1
    } else {
        0
    }
}

/// Whether any deputy capability classes are configured. The engine only
/// collects the full principal stack when this returns non-zero. @ref LLP 0013#phase-5
#[no_mangle]
pub extern "C" fn ex_host_has_deputy_classes() -> i32 {
    if with_host(|host| host.has_deputy_classes(), false) {
        1
    } else {
        0
    }
}

// --- Authority-bearing capability handles (attenuators). @ref LLP 0013#delegation-and-authority-flow

/// Mint a handle carrying `capability` and return its (unforgeable, random) id.
/// The engine only calls this after verifying the *calling frame* holds
/// `capability` — so a package cannot mint a handle for authority it lacks.
#[no_mangle]
pub extern "C" fn ex_host_handle_create(capability: *const c_char) -> u64 {
    if capability.is_null() {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    with_host(|host| host.handles().create(&cap), 0)
}

/// Re-attenuate handle `parent` to a narrower grant (a full capability that must
/// be within the parent, or a bare sub-path appended to the parent's resource).
/// Returns 0 if the parent is missing/dead or the request would widen it.
#[no_mangle]
pub extern "C" fn ex_host_handle_scoped(parent: u64, narrower: *const c_char) -> u64 {
    if narrower.is_null() {
        return 0;
    }
    let n = unsafe { CStr::from_ptr(narrower) }
        .to_string_lossy()
        .to_string();
    with_host(|host| host.handles().scoped(parent, &n), 0)
}

/// Possession check: is the handle live (no revoked ancestor) and does its grant
/// cover `capability`? This does NOT consult the calling frame — a handle is
/// authority-bearing.
#[no_mangle]
pub extern "C" fn ex_host_handle_check(id: u64, capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    if with_host(|host| host.handles().check(id, &cap), false) {
        1
    } else {
        0
    }
}

/// Revoke a handle; every handle derived from it fail-closes on its next check.
#[no_mangle]
pub extern "C" fn ex_host_handle_revoke(id: u64) {
    with_host(|host| host.handles().revoke(id), ());
}

// --- Dynamic root-principal permissions. @ref LLP 0013 — §dynamic permissions

/// Runtime-grant `capability` to the root principal, bounded by the policy
/// ceiling. Returns 1 if applied, 0 if outside the ceiling (denied).
#[no_mangle]
pub extern "C" fn ex_host_permission_request(capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    if with_host(|host| host.runtime_grant_root(&cap), false) {
        1
    } else {
        0
    }
}

/// Runtime-revoke a previously runtime-granted root capability.
#[no_mangle]
pub extern "C" fn ex_host_permission_revoke(capability: *const c_char) {
    if capability.is_null() {
        return;
    }
    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    with_host(|host| host.runtime_revoke_root(&cap), ());
}

/// Tri-state grant status: 1 = granted, 2 = prompt (acquirable), 0 = denied.
#[no_mangle]
pub extern "C" fn ex_host_permission_status(capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }
    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    with_host(|host| host.grant_status(&cap) as i32, 0)
}

#[no_mangle]
pub extern "C" fn ex_host_grant_capability(module_id: u64, capability: *const c_char) {
    if capability.is_null() {
        return;
    }

    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();

    let module = module_id.to_string();
    // @ref LLP 0013 — §self-grant — this ABI is the JS-reachable package self-grant
    // (Exact.setModuleCapabilities / require({needs})); route it through
    // runtime_self_grant so it is refused under enforce and audited without
    // changing behavior under audit. Policy-driven grants use grant() directly
    // and are unaffected. (ENG-22695/ENG-22770)
    with_host(
        |host| host.capabilities().runtime_self_grant(&module, &cap),
        (),
    );
}

/// Register the resolved package principal for a numeric module id, so
/// per-package policy resolves at the host boundary.
///
/// @ref LLP 0013#mechanism-3 — Phase 1 attribution is loader-provided and thus
/// forgeable; Phase 2 replaces it with frame-derived provenance.
#[no_mangle]
pub extern "C" fn ex_host_register_module_package(
    module_id: u64,
    package: *const c_char,
    locator: *const c_char,
    integrity: *const c_char,
) {
    if package.is_null() {
        return;
    }
    let package = unsafe { CStr::from_ptr(package) }
        .to_string_lossy()
        .to_string();
    let locator = if locator.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(locator) }
                .to_string_lossy()
                .to_string(),
        )
    };
    let integrity = if integrity.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(integrity) }
                .to_string_lossy()
                .to_string(),
        )
    };
    let module = module_id.to_string();
    with_host(
        |host| {
            host.register_module_package(
                &module,
                &package,
                locator.as_deref(),
                integrity.as_deref(),
            )
        },
        (),
    );
}

/// Import-graph gate: may `module_id` load `specifier`? Returns 1 if the load
/// may proceed under the active mode (audit logs but permits), else 0.
///
/// @ref LLP 0013#policy — builtins are reachable by `require`, so import policy
/// is the primary containment gate for them.
#[no_mangle]
pub extern "C" fn ex_host_check_import(module_id: u64, specifier: *const c_char) -> i32 {
    if specifier.is_null() {
        return 1;
    }
    let specifier = unsafe { CStr::from_ptr(specifier) }.to_string_lossy();
    let module = PrincipalIdBuf::new(module_id);
    let allowed = with_host(|host| host.check_import(module.as_str(), &specifier), true);
    if allowed {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn ex_host_log_event(
    event_type: *const c_char,
    module_id: u64,
    capability: *const c_char,
    result: i32,
) {
    if event_type.is_null() || capability.is_null() {
        return;
    }
    if !security_log_enabled() {
        return;
    }
    let event_type = unsafe { CStr::from_ptr(event_type) }
        .to_string_lossy()
        .to_string();
    let capability = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();
    let module = module_id.to_string();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let payload = json!({
        "ts": ts,
        "event": event_type,
        "module": module,
        "capability": capability,
        "result": result,
        "allowed": result != 0
    });
    enqueue_stderr_line(payload.to_string());
}

/// Decode the `(specifier, referrer)` C-string pair the module-resolve bridges
/// receive. Returns `None` when the specifier is null (caller returns null).
fn module_resolve_args(
    specifier: *const c_char,
    referrer: *const c_char,
) -> Option<(String, Option<String>)> {
    if specifier.is_null() {
        return None;
    }
    let spec = unsafe { CStr::from_ptr(specifier) }
        .to_string_lossy()
        .to_string();
    let referrer = if referrer.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(referrer) }
                .to_string_lossy()
                .to_string(),
        )
    };
    Some((spec, referrer))
}

/// The resolution-metadata fields shared by the full-resolve and metadata-only
/// bridges: everything except the module `source`. `require.resolve` needs only
/// these; the full `require`/`import` load path additionally attaches `source`.
fn module_meta_json(module: &crate::module_loader::ResolvedModule) -> serde_json::Value {
    json!({
        "id": module.id,
        "kind": match module.kind {
            crate::module_loader::ModuleKind::Builtin => "builtin",
            crate::module_loader::ModuleKind::CommonJs => "cjs",
            crate::module_loader::ModuleKind::Json => "json",
            crate::module_loader::ModuleKind::Esm => "esm",
        },
        "path": module.path.as_ref().map(|p| p.to_string_lossy().to_string()),
        // Resolver-owned package metadata. The JS loader must not decide
        // root-vs-package trust solely from the path shape because symlinked
        // and realpathed dependencies can live outside `node_modules`.
        "pkgName": module.package_name,
        "pkgRoot": module.package_root.as_ref().map(|p| p.to_string_lossy().to_string()),
        // The resolved package's own version (node_modules packages only),
        // so the loader can form the `name@version` runtime identity for
        // version-distinguished principals/compartments. (ENG-22621)
        "pkgVersion": module.package_version,
        "pkgIntegrity": module.package_integrity,
    })
}

fn module_resolve_cstring(payload: &serde_json::Value) -> *mut c_char {
    match std::ffi::CString::new(payload.to_string()) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn ex_host_module_resolve(
    requester_module_id: u64,
    specifier: *const c_char,
    referrer: *const c_char,
) -> *mut c_char {
    let Some((spec, referrer)) = module_resolve_args(specifier, referrer) else {
        return ptr::null_mut();
    };

    let resolved = with_host(
        |host| {
            let path = referrer.as_ref().map(std::path::PathBuf::from);
            host.resolve_module_for_principal(
                &spec,
                path.as_deref(),
                Some(&requester_module_id.to_string()),
            )
        },
        Err(anyhow::anyhow!("Host not initialized")),
    );

    let payload = match resolved {
        Ok(module) => {
            let mut record = module_meta_json(&module);
            record["source"] = json!(module.source.unwrap_or_default());
            record
        }
        Err(err) => json!({
            "error": format!("{err:#}")
        }),
    };

    module_resolve_cstring(&payload)
}

/// Loader-private resolver for trusted builtin implementation fan-out. The
/// host method accepts only exact generated-manifest specifiers and can never
/// enter package/path resolution. The corresponding JSI global is captured and
/// deleted by the bootstrap loader before package code can execute.
/// @ref LLP 0013#policy
#[no_mangle]
pub extern "C" fn ex_host_resolve_manifest_builtin_internal(
    specifier: *const c_char,
) -> *mut c_char {
    if specifier.is_null() {
        return ptr::null_mut();
    }
    let spec = unsafe { CStr::from_ptr(specifier) }
        .to_string_lossy()
        .to_string();
    let resolved = with_host(
        |host| host.resolve_manifest_builtin_internal(&spec),
        Err(anyhow::anyhow!("Host not initialized")),
    );
    let payload = match resolved {
        Ok(module) => {
            let mut record = module_meta_json(&module);
            record["source"] = json!(module.source.unwrap_or_default());
            record
        }
        Err(err) => json!({
            "error": format!("{err:#}")
        }),
    };
    module_resolve_cstring(&payload)
}

/// Metadata-only resolve: returns just the resolution record (id/kind/path/pkg
/// fields, no `source`) so `require.resolve` can get the resolved path without
/// the full-resolve bridge reading + transpiling + JSON-escaping the entire
/// module body only for the loader to discard it. (ENG-23007)
///
/// Caller must free the returned string with `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_module_resolve_meta(
    requester_module_id: u64,
    specifier: *const c_char,
    referrer: *const c_char,
) -> *mut c_char {
    let Some((spec, referrer)) = module_resolve_args(specifier, referrer) else {
        return ptr::null_mut();
    };

    let resolved = with_host(
        |host| {
            let path = referrer.as_ref().map(std::path::PathBuf::from);
            host.resolve_module_meta_for_principal(
                &spec,
                path.as_deref(),
                Some(&requester_module_id.to_string()),
            )
        },
        Err(anyhow::anyhow!("Host not initialized")),
    );

    let payload = match resolved {
        Ok(module) => module_meta_json(&module),
        Err(err) => json!({
            "error": err.to_string()
        }),
    };

    module_resolve_cstring(&payload)
}

#[no_mangle]
pub extern "C" fn ex_host_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = std::ffi::CString::from_raw(ptr);
    }
}

#[repr(C)]
pub struct ExactFileHandle {
    file: std::fs::File,
}

const FS_READ: u32 = 1;
const FS_WRITE: u32 = 2;
const FS_CREATE: u32 = 4;
const FS_TRUNCATE: u32 = 8;
const FS_APPEND: u32 = 16;

#[no_mangle]
pub extern "C" fn ex_host_fs_open(path: *const c_char, flags: u32) -> *mut ExactFileHandle {
    if path.is_null() {
        return ptr::null_mut();
    }

    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let mut opts = std::fs::OpenOptions::new();
    opts.read(flags & FS_READ != 0);
    opts.write(flags & FS_WRITE != 0);
    opts.create(flags & FS_CREATE != 0);
    opts.truncate(flags & FS_TRUNCATE != 0);
    opts.append(flags & FS_APPEND != 0);

    match opts.open(path) {
        Ok(file) => Box::into_raw(Box::new(ExactFileHandle { file })),
        Err(err) => {
            set_errno_from_io_error(&err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn ex_host_fs_read(file: *mut ExactFileHandle, buf: *mut u8, len: u32) -> i32 {
    if file.is_null() || buf.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *file };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    match std::io::Read::read(&mut handle.file, slice) {
        Ok(bytes) => bytes as i32,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn ex_host_fs_write(file: *mut ExactFileHandle, buf: *const u8, len: u32) -> i32 {
    if file.is_null() || buf.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *file };
    let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    match std::io::Write::write(&mut handle.file, slice) {
        Ok(bytes) => bytes as i32,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn ex_host_fs_seek(file: *mut ExactFileHandle, position: u64) -> i32 {
    if file.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *file };
    match std::io::Seek::seek(&mut handle.file, std::io::SeekFrom::Start(position)) {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Positional read: read up to `len` bytes at absolute `offset` WITHOUT leaving
/// the handle's file cursor moved. Node's `readSync` leaves the fd offset
/// unchanged when `position` is a number, so the Windows JSI bridge needs a
/// `pread`-equivalent; the previous `ex_host_fs_seek` + `ex_host_fs_read`
/// permanently moved the cursor and corrupted a "header at a fixed offset then
/// stream sequentially" read pattern (ENG-22993, mirroring the POSIX `pread`
/// fix in ENG-22982). Implemented as save-cursor / seek / read / restore-cursor
/// rather than a platform positional API because Windows overlapped reads still
/// advance the pointer; this keeps behavior identical on every platform.
/// Returns the number of bytes read, or -1 on error.
#[no_mangle]
pub extern "C" fn ex_host_fs_pread(
    file: *mut ExactFileHandle,
    buf: *mut u8,
    len: u32,
    offset: u64,
) -> i32 {
    if file.is_null() || buf.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *file };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    let saved = match std::io::Seek::stream_position(&mut handle.file) {
        Ok(pos) => pos,
        Err(err) => {
            set_errno_from_io_error(&err);
            return -1;
        }
    };
    if let Err(err) = std::io::Seek::seek(&mut handle.file, std::io::SeekFrom::Start(offset)) {
        set_errno_from_io_error(&err);
        return -1;
    }
    let read_result = std::io::Read::read(&mut handle.file, slice);
    // Restore the cursor regardless of the read outcome so a positional read
    // never disturbs a subsequent sequential read.
    let restore_result = std::io::Seek::seek(&mut handle.file, std::io::SeekFrom::Start(saved));
    match (read_result, restore_result) {
        (Ok(bytes), Ok(_)) => bytes as i32,
        (Err(err), _) | (Ok(_), Err(err)) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Positional write: write up to `len` bytes at absolute `offset` WITHOUT
/// leaving the handle's file cursor moved (see `ex_host_fs_pread`; ENG-22993,
/// mirroring the POSIX `pwrite` fix in ENG-22982). Returns the number of bytes
/// written, which — like a single `std::io::Write::write` — may be fewer than
/// `len`; the JS caller is responsible for looping on a short write. Returns -1
/// on error.
#[no_mangle]
pub extern "C" fn ex_host_fs_pwrite(
    file: *mut ExactFileHandle,
    buf: *const u8,
    len: u32,
    offset: u64,
) -> i32 {
    if file.is_null() || buf.is_null() {
        return -1;
    }
    let handle = unsafe { &mut *file };
    let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    let saved = match std::io::Seek::stream_position(&mut handle.file) {
        Ok(pos) => pos,
        Err(err) => {
            set_errno_from_io_error(&err);
            return -1;
        }
    };
    if let Err(err) = std::io::Seek::seek(&mut handle.file, std::io::SeekFrom::Start(offset)) {
        set_errno_from_io_error(&err);
        return -1;
    }
    let write_result = std::io::Write::write(&mut handle.file, slice);
    // Restore the cursor regardless of the write outcome so a positional write
    // never disturbs a subsequent sequential write.
    let restore_result = std::io::Seek::seek(&mut handle.file, std::io::SeekFrom::Start(saved));
    match (write_result, restore_result) {
        (Ok(bytes), Ok(_)) => bytes as i32,
        // The write is irreversible. Reporting failure here invites callers
        // to retry and duplicate the write; retain the restore diagnostic for
        // observability but report the committed byte count.
        (Ok(bytes), Err(err)) => {
            set_errno_from_io_error(&err);
            bytes as i32
        }
        (Err(err), _) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn ex_host_fs_close(file: *mut ExactFileHandle) {
    if file.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(file));
    }
}

/// Flush file contents and metadata (`data_only == 0`) or file contents only
/// (`data_only != 0`) to stable storage.
#[no_mangle]
pub extern "C" fn ex_host_fs_sync(file: *mut ExactFileHandle, data_only: i32) -> i32 {
    if file.is_null() {
        record_fs_error(libc::EBADF);
        return -1;
    }
    let handle = unsafe { &mut *file };
    let result = if data_only != 0 {
        handle.file.sync_data()
    } else {
        handle.file.sync_all()
    };
    match result {
        Ok(()) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Return metadata for the open file identity, independent of later path
/// rename/unlink operations. Caller frees the JSON string with
/// `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_fs_fstat(file: *mut ExactFileHandle) -> *mut c_char {
    if file.is_null() {
        record_fs_error(libc::EBADF);
        return ptr::null_mut();
    }
    let handle = unsafe { &mut *file };
    match handle.file.metadata() {
        Ok(metadata) => as_json_cstring(&make_stat_payload_from_metadata(metadata)),
        Err(err) => {
            set_errno_from_io_error(&err);
            ptr::null_mut()
        }
    }
}

/// Return a JSON string with file metadata matching Node-style Stats payload fields.
/// Caller must free the returned string with `ex_host_free_string`.
/// Returns null on error.
#[no_mangle]
pub extern "C" fn ex_host_fs_stat(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match make_stat_payload(&path, true) {
        Some(payload) => as_json_cstring(&payload),
        None => match std::fs::metadata(&path) {
            Ok(_) => {
                set_errno_from_io_error(&std::io::Error::other("stat payload failed"));
                ptr::null_mut()
            }
            Err(err) => {
                set_errno_from_io_error(&err);
                ptr::null_mut()
            }
        },
    }
}

/// Like stat but does not follow symlinks.
#[no_mangle]
pub extern "C" fn ex_host_fs_lstat(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match make_stat_payload(&path, false) {
        Some(payload) => as_json_cstring(&payload),
        None => match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                set_errno_from_io_error(&std::io::Error::other("lstat payload failed"));
                ptr::null_mut()
            }
            Err(err) => {
                set_errno_from_io_error(&err);
                ptr::null_mut()
            }
        },
    }
}

/// Return a JSON array of entry names in the directory.
/// Caller must free the returned string with `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_fs_readdir(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match std::fs::read_dir(&path) {
        Ok(entries) => {
            let names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            let payload = serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_string());
            match CString::new(payload) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => {
                    set_errno_from_io_error(&std::io::Error::other("invalid JSON payload"));
                    ptr::null_mut()
                }
            }
        }
        Err(err) => {
            set_errno_from_io_error(&err);
            ptr::null_mut()
        }
    }
}

/// Create a directory. If `recursive` is non-zero, creates parent directories too.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn ex_host_fs_mkdir(path: *const c_char, recursive: i32) -> i32 {
    if path.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let result = if recursive != 0 {
        std::fs::create_dir_all(&path)
    } else {
        std::fs::create_dir(&path)
    };
    match result {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Recursively create a directory and return the highest missing path that
/// this call created (Node's recursive-mkdir result), or an empty string when
/// the full path already existed. Caller frees the result with
/// `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_fs_mkdir_recursive_result(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = std::path::PathBuf::from(
        unsafe { CStr::from_ptr(path) }
            .to_string_lossy()
            .into_owned(),
    );
    let mut cursor = path.clone();
    let mut first_created = None;
    while !cursor.exists() {
        first_created = Some(cursor.clone());
        if !cursor.pop() {
            break;
        }
    }
    if let Err(err) = std::fs::create_dir_all(&path) {
        set_errno_from_io_error(&err);
        return ptr::null_mut();
    }
    let value = first_created
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    CString::new(value)
        .map(CString::into_raw)
        .unwrap_or(ptr::null_mut())
}

/// Remove an empty directory.
#[no_mangle]
pub extern "C" fn ex_host_fs_rmdir(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match std::fs::remove_dir(&path) {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Remove a file.
#[no_mangle]
pub extern "C" fn ex_host_fs_unlink(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match std::fs::remove_file(&path) {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Rename / move a file or directory.
#[no_mangle]
pub extern "C" fn ex_host_fs_rename(from: *const c_char, to: *const c_char) -> i32 {
    if from.is_null() || to.is_null() {
        return -1;
    }
    let from = unsafe { CStr::from_ptr(from) }
        .to_string_lossy()
        .to_string();
    let to = unsafe { CStr::from_ptr(to) }.to_string_lossy().to_string();
    match std::fs::rename(&from, &to) {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Copy a file.
#[no_mangle]
pub extern "C" fn ex_host_fs_copy(from: *const c_char, to: *const c_char) -> i32 {
    if from.is_null() || to.is_null() {
        return -1;
    }
    let from = unsafe { CStr::from_ptr(from) }
        .to_string_lossy()
        .to_string();
    let to = unsafe { CStr::from_ptr(to) }.to_string_lossy().to_string();
    match std::fs::copy(&from, &to) {
        Ok(_) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Copy a file while atomically refusing an existing destination.
#[no_mangle]
pub extern "C" fn ex_host_fs_copy_exclusive(from: *const c_char, to: *const c_char) -> i32 {
    if from.is_null() || to.is_null() {
        return -1;
    }
    let from = unsafe { CStr::from_ptr(from) }
        .to_string_lossy()
        .into_owned();
    let to = unsafe { CStr::from_ptr(to) }.to_string_lossy().into_owned();
    let result = (|| -> std::io::Result<()> {
        let mut source = std::fs::File::open(&from)?;
        let mut destination = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&to)?;
        std::io::copy(&mut source, &mut destination)?;
        if let Ok(metadata) = source.metadata() {
            destination.set_permissions(metadata.permissions())?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Resize a file by path.
#[no_mangle]
pub extern "C" fn ex_host_fs_truncate(path: *const c_char, len: u64) -> i32 {
    if path.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    match std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_len(len))
    {
        Ok(()) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

fn system_time_from_unix_seconds(value: f64) -> Option<SystemTime> {
    if !value.is_finite() {
        return None;
    }
    let duration = std::time::Duration::try_from_secs_f64(value.abs()).ok()?;
    if value.is_sign_negative() {
        UNIX_EPOCH.checked_sub(duration)
    } else {
        UNIX_EPOCH.checked_add(duration)
    }
}

/// Set path access and modification timestamps from Unix seconds.
#[no_mangle]
pub extern "C" fn ex_host_fs_utimes(path: *const c_char, atime: f64, mtime: f64) -> i32 {
    if path.is_null() {
        return -1;
    }
    let Some(atime) = system_time_from_unix_seconds(atime) else {
        record_fs_error(libc::EINVAL);
        return -1;
    };
    let Some(mtime) = system_time_from_unix_seconds(mtime) else {
        record_fs_error(libc::EINVAL);
        return -1;
    };
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    let times = std::fs::FileTimes::new()
        .set_accessed(atime)
        .set_modified(mtime);
    match std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_times(times))
    {
        Ok(()) => 0,
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

/// Return Node-shaped filesystem capacity metadata as JSON.
#[no_mangle]
pub extern "C" fn ex_host_fs_statfs(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let payload = {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "Kernel32")]
        extern "system" {
            fn GetDiskFreeSpaceW(
                root: *const u16,
                sectors_per_cluster: *mut u32,
                bytes_per_sector: *mut u32,
                free_clusters: *mut u32,
                total_clusters: *mut u32,
            ) -> i32;
        }
        let canonical = match std::fs::canonicalize(&path) {
            Ok(path) => path,
            Err(err) => {
                set_errno_from_io_error(&err);
                return ptr::null_mut();
            }
        };
        let mut root = std::path::PathBuf::new();
        for component in canonical.components() {
            root.push(component.as_os_str());
            if matches!(component, std::path::Component::RootDir) {
                break;
            }
        }
        let mut wide = root.as_os_str().encode_wide().collect::<Vec<_>>();
        wide.push(0);
        let mut sectors = 0u32;
        let mut bytes_per_sector = 0u32;
        let mut free_clusters = 0u32;
        let mut total_clusters = 0u32;
        if unsafe {
            GetDiskFreeSpaceW(
                wide.as_ptr(),
                &mut sectors,
                &mut bytes_per_sector,
                &mut free_clusters,
                &mut total_clusters,
            )
        } == 0
        {
            let err = std::io::Error::last_os_error();
            set_errno_from_io_error(&err);
            return ptr::null_mut();
        }
        let block_size = u64::from(sectors) * u64::from(bytes_per_sector);
        json!({
            "type": 0,
            "bsize": block_size,
            "blocks": total_clusters,
            "bfree": free_clusters,
            "bavail": free_clusters,
            "files": 0,
            "ffree": 0,
        })
    };
    #[cfg(unix)]
    let payload = {
        use std::os::unix::ffi::OsStrExt;
        let Ok(path) = CString::new(std::ffi::OsStr::new(&path).as_bytes()) else {
            record_fs_error(libc::EINVAL);
            return ptr::null_mut();
        };
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
            record_fs_error(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            );
            return ptr::null_mut();
        }
        json!({
            "type": 0,
            "bsize": stat.f_bsize,
            "blocks": stat.f_blocks,
            "bfree": stat.f_bfree,
            "bavail": stat.f_bavail,
            "files": stat.f_files,
            "ffree": stat.f_ffree,
        })
    };
    #[cfg(not(any(unix, windows)))]
    let payload = {
        record_fs_error(libc::ENOSYS);
        return ptr::null_mut();
    };
    as_json_cstring(&payload)
}

/// Return the canonical absolute path. Caller must free with `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_fs_realpath(path: *const c_char) -> *mut c_char {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    match std::fs::canonicalize(&path) {
        Ok(canonical) => match CString::new(canonical.to_string_lossy().to_string()) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => {
                set_errno_from_io_error(&std::io::Error::other("invalid canonical path"));
                ptr::null_mut()
            }
        },
        Err(err) => {
            set_errno_from_io_error(&err);
            ptr::null_mut()
        }
    }
}

/// Check access to a path. `mode` is a bitmask that matches Node.js `fs.access`
/// constants: 0=existence, 1=execute, 2=write, 4=read.
/// Returns 0 if accessible, -1 if not.
#[no_mangle]
pub extern "C" fn ex_host_fs_access(path: *const c_char, mode: i32) -> i32 {
    if path.is_null() {
        return -1;
    }
    #[cfg(unix)]
    {
        let c_path = unsafe { CStr::from_ptr(path) };
        let flags = if mode == 0 {
            libc::F_OK
        } else {
            let mut requested = 0;
            if mode & 1 != 0 {
                requested |= libc::X_OK;
            }
            if mode & 2 != 0 {
                requested |= libc::W_OK;
            }
            if mode & 4 != 0 {
                requested |= libc::R_OK;
            }
            requested
        };

        let result = unsafe { libc::access(c_path.as_ptr(), flags) };
        if result == 0 {
            0
        } else {
            set_errno_from_io_error(&std::io::Error::last_os_error());
            -1
        }
    }
    #[cfg(not(unix))]
    {
        let path = unsafe { CStr::from_ptr(path) }
            .to_string_lossy()
            .to_string();
        if mode == 0 {
            return match std::fs::metadata(&path) {
                Ok(_) => 0,
                Err(err) => {
                    set_errno_from_io_error(&err);
                    -1
                }
            };
        }

        if mode & 4 != 0 {
            if let Err(err) = std::fs::File::open(&path) {
                set_errno_from_io_error(&err);
                return -1;
            }
        }
        if mode & 2 != 0 {
            if let Err(err) = std::fs::OpenOptions::new().write(true).open(&path) {
                set_errno_from_io_error(&err);
                return -1;
            }
        }
        if mode & 1 != 0 {
            if let Err(err) = std::fs::metadata(&path) {
                set_errno_from_io_error(&err);
                return -1;
            }
        }
        0
    }
}

/// Change file permissions (unix mode).
#[no_mangle]
pub extern "C" fn ex_host_fs_chmod(path: *const c_char, mode: u32) -> i32 {
    if path.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        match std::fs::set_permissions(&path, perms) {
            Ok(_) => 0,
            Err(err) => {
                set_errno_from_io_error(&err);
                -1
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        let _ = mode;
        -1
    }
}

/// Create a temporary directory with the given prefix.
/// Caller must free the returned path with `ex_host_free_string`.
#[no_mangle]
pub extern "C" fn ex_host_fs_mkdtemp(prefix: *const c_char, module_id: u64) -> *mut c_char {
    let prefix_str = if prefix.is_null() {
        "tmp".to_string()
    } else {
        unsafe { CStr::from_ptr(prefix) }
            .to_string_lossy()
            .to_string()
    };

    // Generate random suffix
    let mut rng_bytes = [0u8; 6];
    if getrandom(&mut rng_bytes).is_err() {
        return ptr::null_mut();
    }
    let suffix: String = rng_bytes
        .iter()
        .map(|b| {
            let idx = (*b as usize) % 36;
            if idx < 10 {
                (b'0' + idx as u8) as char
            } else {
                (b'a' + (idx - 10) as u8) as char
            }
        })
        .collect();

    let dir_path = std::env::temp_dir().join(format!("{}{}", prefix_str, suffix));
    let cap = format!("fs:write:{}", dir_path.to_string_lossy());
    let module = module_id.to_string();
    let allowed = with_host(|host| host.check_capability(&module, &cap), false);
    if !allowed {
        set_errno_from_io_error(&std::io::Error::from_raw_os_error(libc::EACCES));
        return ptr::null_mut();
    }
    match std::fs::create_dir(&dir_path) {
        Ok(_) => match CString::new(dir_path.to_string_lossy().to_string()) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => {
                set_errno_from_io_error(&std::io::Error::other("invalid temp path"));
                ptr::null_mut()
            }
        },
        Err(err) => {
            set_errno_from_io_error(&err);
            ptr::null_mut()
        }
    }
}

fn write_all_return_count(writer: &mut impl Write, data: &[u8]) -> io::Result<i32> {
    writer.write_all(data)?;
    i32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "write length exceeds i32"))
}

/// Append data to a file. Returns bytes written or -1 on error.
#[no_mangle]
pub extern "C" fn ex_host_fs_append(path: *const c_char, data: *const u8, len: u32) -> i32 {
    if path.is_null() || data.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let slice = unsafe { std::slice::from_raw_parts(data, len as usize) };

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).append(true);
    match opts.open(&path) {
        Ok(mut file) => match write_all_return_count(&mut file, slice) {
            Ok(n) => n,
            Err(err) => {
                set_errno_from_io_error(&err);
                -1
            }
        },
        Err(err) => {
            set_errno_from_io_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_open(path: *const c_char, options: *const c_char) -> u64 {
    if path.is_null() {
        return 0;
    }

    let path = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let options = parse_sqlite_open_options(options);
    let flags = sqlite_open_flags(&options);

    let db = match Connection::open_with_flags(path.as_str(), flags) {
        Ok(db) => db,
        Err(_) => return 0,
    };
    install_sqlite_authorizer(&db);

    with_sqlite_state(|state| {
        let Some(handle) = state.allocate_db_handle() else {
            return 0;
        };
        state.dbs.insert(handle, Arc::new(Mutex::new(db)));
        handle
    })
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_close(handle: u64) -> i32 {
    with_sqlite_state(|state| {
        if state.dbs.remove(&handle).is_some() {
            state
                .statements
                .retain(|_, statement| statement.db_id != handle);
            0
        } else {
            -1
        }
    })
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_prepare(db_handle: u64, sql: *const c_char) -> *mut c_char {
    if db_handle == 0 || sql.is_null() {
        return ptr::null_mut();
    }

    let sql = unsafe { CStr::from_ptr(sql) }.to_string_lossy().to_string();

    let connection = match sqlite_connection(db_handle) {
        Some(connection) => connection,
        None => return ptr::null_mut(),
    };

    // Compile via `prepare_cached` and read the statement's metadata under the
    // per-connection lock only. Caching the compiled plan here means the later
    // exec/query calls for the same SQL reuse it instead of re-tokenizing,
    // re-parsing and re-planning on every invocation.
    let (column_names, declared_types, read_only, params_count) = {
        let guard = lock_connection(&connection);
        let statement = match guard.prepare_cached(&sql) {
            Ok(statement) => statement,
            Err(err) => {
                return as_json_cstring(&json!({ "error": err.to_string() }));
            }
        };

        let column_count = statement.column_count();
        let column_names: Vec<String> = (0..column_count)
            .filter_map(|index| {
                statement
                    .column_name(index)
                    .ok()
                    .map(|name| name.to_string())
            })
            .collect();

        let declared_types: Vec<Option<String>> = statement
            .columns()
            .into_iter()
            .map(|column| column.decl_type().map(std::string::ToString::to_string))
            .collect();
        let read_only = statement.readonly();
        let params_count = statement.parameter_count() as usize;

        (column_names, declared_types, read_only, params_count)
    };

    let statement_handle = with_sqlite_state(|state| {
        let statement_handle = state.allocate_statement_handle()?;
        state.statements.insert(
            statement_handle,
            SqliteStatementRecord {
                db_id: db_handle,
                sql,
                read_only,
            },
        );
        Some(statement_handle)
    });
    let Some(statement_handle) = statement_handle else {
        return as_json_cstring(&json!({"error": "sqlite statement handle space exhausted"}));
    };

    as_json_cstring(&json!({
        "handle": statement_handle,
        "columnNames": column_names,
        "declaredTypes": declared_types,
        "paramsCount": params_count,
        "readOnly": read_only,
    }))
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_finalize(statement_handle: u64) -> i32 {
    with_sqlite_state(|state| {
        if state.statements.remove(&statement_handle).is_some() {
            0
        } else {
            -1
        }
    })
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_expanded_sql(statement_handle: u64) -> *mut c_char {
    if statement_handle == 0 {
        return ptr::null_mut();
    }

    with_sqlite_state(|state| {
        let statement = match state.statements.get(&statement_handle) {
            Some(statement) => statement,
            None => return ptr::null_mut(),
        };
        match CString::new(statement.sql.clone()) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_in_transaction(handle: u64) -> i32 {
    let connection = match sqlite_connection(handle) {
        Some(connection) => connection,
        None => return 0,
    };
    let guard = lock_connection(&connection);
    if guard.is_autocommit() {
        0
    } else {
        1
    }
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_all(
    statement_handle: u64,
    bindings_json: *const c_char,
) -> *mut c_char {
    if statement_handle == 0 {
        return ptr::null_mut();
    }

    let bindings = parse_bindings(bindings_json);

    let (statement, connection) = match sqlite_statement_connection(statement_handle) {
        Some(pair) => pair,
        None => return ptr::null_mut(),
    };
    let read_only = statement.read_only;
    let guard = lock_connection(&connection);

    let mut stmt = match guard.prepare_cached(&statement.sql) {
        Ok(statement) => statement,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .filter_map(|index| stmt.column_name(index).ok().map(|name| name.to_string()))
        .collect();
    let mut rows = match query_with_bindings(&mut stmt, &bindings) {
        Ok(result) => result,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let mut payload_rows = Vec::new();
    let mut column_types: Option<Vec<String>> = None;
    loop {
        // A step error after N rows (SQLITE_BUSY, an I/O error, a RAISE in a
        // trigger, arithmetic overflow) must surface as an error — not exit the
        // loop and return the partial rows as a silently truncated success. The
        // old `while let Ok(Some(row))` form dropped the error on the floor.
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };
        let mut object = serde_json::Map::new();
        let mut row_column_types = if read_only {
            Some(Vec::with_capacity(column_count))
        } else {
            None
        };
        for index in 0..column_count {
            let name = match column_names.get(index) {
                Some(name) => name.clone(),
                None => continue,
            };

            if let Ok(value) = row.get_ref(index) {
                if let Some(ref mut types) = row_column_types {
                    types.push(sqlite_value_type_name(&value).to_string());
                }
                object.insert(name, sqlite_value_to_json(value));
            } else if let Some(ref mut types) = row_column_types {
                types.push(String::new());
            }
        }
        if column_types.is_none() {
            column_types = row_column_types;
        }
        payload_rows.push(serde_json::Value::Object(object));
    }

    as_json_cstring(&json!({
        "rows": payload_rows,
        "columnNames": column_names,
        "columnTypes": column_types.unwrap_or_default(),
    }))
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_get(
    statement_handle: u64,
    bindings_json: *const c_char,
) -> *mut c_char {
    if statement_handle == 0 {
        return ptr::null_mut();
    }

    let bindings = parse_bindings(bindings_json);

    let (statement, connection) = match sqlite_statement_connection(statement_handle) {
        Some(pair) => pair,
        None => return ptr::null_mut(),
    };
    let read_only = statement.read_only;
    let guard = lock_connection(&connection);

    let mut stmt = match guard.prepare_cached(&statement.sql) {
        Ok(statement) => statement,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .filter_map(|index| stmt.column_name(index).ok().map(|name| name.to_string()))
        .collect();
    let mut rows = match query_with_bindings(&mut stmt, &bindings) {
        Ok(result) => result,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let mut column_types = Vec::new();
    let row = match rows.next() {
        Ok(Some(row)) => {
            let mut object = serde_json::Map::new();
            for index in 0..column_count {
                let name = match column_names.get(index) {
                    Some(name) => name.clone(),
                    None => continue,
                };
                if let Ok(value) = row.get_ref(index) {
                    if read_only {
                        column_types.push(sqlite_value_type_name(&value).to_string());
                    }
                    object.insert(name, sqlite_value_to_json(value));
                } else if read_only {
                    column_types.push(String::new());
                }
            }
            serde_json::Value::Object(object)
        }
        Ok(None) => serde_json::Value::Null,
        Err(err) => serde_json::json!({"error": err.to_string()}),
    };

    as_json_cstring(&json!({
        "row": row,
        "columnNames": column_names,
        "columnTypes": column_types,
    }))
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_values(
    statement_handle: u64,
    bindings_json: *const c_char,
) -> *mut c_char {
    if statement_handle == 0 {
        return ptr::null_mut();
    }

    let bindings = parse_bindings(bindings_json);

    let (statement, connection) = match sqlite_statement_connection(statement_handle) {
        Some(pair) => pair,
        None => return ptr::null_mut(),
    };
    let read_only = statement.read_only;
    let guard = lock_connection(&connection);

    let mut stmt = match guard.prepare_cached(&statement.sql) {
        Ok(statement) => statement,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let column_count = stmt.column_count();
    let mut rows = match query_with_bindings(&mut stmt, &bindings) {
        Ok(result) => result,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    let mut payload_rows = Vec::new();
    let mut column_types: Option<Vec<String>> = None;
    loop {
        // As in `ex_host_sqlite_all`: surface a mid-iteration step error instead
        // of returning the rows gathered so far as a silently truncated success.
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };
        let mut values = Vec::new();
        let mut row_column_types = if read_only {
            Some(Vec::with_capacity(column_count))
        } else {
            None
        };
        for index in 0..column_count {
            if let Ok(value) = row.get_ref(index) {
                if let Some(ref mut types) = row_column_types {
                    types.push(sqlite_value_type_name(&value).to_string());
                }
                values.push(sqlite_value_to_json(value));
            } else if let Some(ref mut types) = row_column_types {
                types.push(String::new());
            }
        }
        if column_types.is_none() {
            column_types = row_column_types;
        }
        payload_rows.push(serde_json::Value::Array(values));
    }

    as_json_cstring(&json!({
        "rows": payload_rows,
        "columnTypes": column_types.unwrap_or_default(),
    }))
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_run(
    statement_handle: u64,
    bindings_json: *const c_char,
) -> *mut c_char {
    if statement_handle == 0 {
        return ptr::null_mut();
    }

    let bindings = parse_bindings(bindings_json);

    let (statement, connection) = match sqlite_statement_connection(statement_handle) {
        Some(pair) => pair,
        None => return ptr::null_mut(),
    };
    let guard = lock_connection(&connection);

    let mut stmt = match guard.prepare_cached(&statement.sql) {
        Ok(statement) => statement,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    if let Err(err) = execute_with_bindings(&mut stmt, &bindings) {
        return as_json_cstring(&json!({"error": err.to_string()}));
    }
    // Return the cached statement to the connection's cache before reading the
    // connection-level counters.
    drop(stmt);

    as_json_cstring(&json!({
        "changes": guard.changes(),
        "lastInsertRowid": guard.last_insert_rowid(),
    }))
}

#[no_mangle]
pub extern "C" fn ex_host_sqlite_exec(
    db_handle: u64,
    sql: *const c_char,
    bindings_json: *const c_char,
) -> *mut c_char {
    if db_handle == 0 || sql.is_null() {
        return ptr::null_mut();
    }

    let sql = unsafe { CStr::from_ptr(sql) }.to_string_lossy().to_string();
    let bindings = parse_bindings(bindings_json);

    let connection = match sqlite_connection(db_handle) {
        Some(connection) => connection,
        None => return ptr::null_mut(),
    };
    let guard = lock_connection(&connection);

    let mut stmt = match guard.prepare_cached(&sql) {
        Ok(statement) => statement,
        Err(err) => {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }
    };

    if let Err(err) = execute_with_bindings(&mut stmt, &bindings) {
        return as_json_cstring(&json!({"error": err.to_string()}));
    }
    drop(stmt);

    as_json_cstring(&json!({
        "changes": guard.changes(),
        "lastInsertRowid": guard.last_insert_rowid(),
    }))
}

/// Read an environment variable into `out_buf`.
///
/// Returns the value's *full* byte length (which may exceed `len`), or `-1` when
/// the variable is unset. This lets a caller (a) distinguish "unset" from
/// "present but empty" — the previous `unwrap_or_default()` folded both to an
/// empty string — and (b) detect truncation: if the return value is `>= len`,
/// the buffer held only a `len - 1` byte prefix and the caller should re-query
/// with a buffer of at least `return + 1` bytes. `out_buf`/`len` may be
/// null/`0` to query the length without copying. Previously values longer than
/// the buffer (notably the C++ side's fixed 4096-byte buffer) were clipped with
/// no signal (ENG-22955).
#[no_mangle]
pub extern "C" fn ex_host_env_get(key: *const c_char, out_buf: *mut c_char, len: u32) -> i64 {
    if key.is_null() {
        return -1;
    }
    let key = unsafe { CStr::from_ptr(key) }.to_string_lossy().to_string();
    // `var_os` returns None only when the variable is absent, so unset stays
    // distinguishable from empty; a non-UTF-8 value is rendered lossily (like the
    // key) rather than reported as absent.
    let value = match std::env::var_os(&key) {
        Some(v) => v,
        None => return -1,
    };
    let value = value.to_string_lossy();
    let bytes = value.as_bytes();
    let full_len = bytes.len();

    if !out_buf.is_null() && len > 0 {
        let write_len = full_len.min((len as usize).saturating_sub(1));
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf as *mut u8, write_len);
            *out_buf.add(write_len) = 0;
        }
    }

    full_len as i64
}

#[no_mangle]
pub extern "C" fn ex_host_time_now_ms() -> u64 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn ex_host_random_fill(buf: *mut u8, len: u32) -> i32 {
    if buf.is_null() || len == 0 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    match getrandom(slice) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn ex_host_console_log(level: i32, message: *const c_char) {
    if message.is_null() {
        return;
    }
    let msg = unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .to_string();
    #[cfg(target_os = "android")]
    write_android_logcat(level, &msg);
    if !console_mirror_enabled() {
        return;
    }
    match level {
        1 => enqueue_stderr_line(msg),
        _ => enqueue_stdout_line(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Host, HostConfig, SecurityMode};
    use std::io::{self, Write};

    // The inline decimal rendering must agree byte-for-byte with the
    // `u64::to_string` keying the capability manager has always used, across
    // the special principals (root 0, kNoUserPrincipal, kRuntimePackageId) and
    // the extremes. (ENG-22644)
    #[test]
    fn principal_id_buf_matches_to_string() {
        for id in [
            0u64,
            1,
            9,
            10,
            42,
            0xFFFF_FFFE, // kNoUserPrincipal (4294967294)
            0xFFFF_FFFF, // runtime principal
            u64::MAX,
        ] {
            assert_eq!(PrincipalIdBuf::new(id).as_str(), id.to_string());
        }
    }

    #[test]
    fn rendered_principal_stack_matches_to_string_inline_and_heap() {
        // Inline path (<= 16 principals) and the heap fallback (> 16) must
        // produce identical renderings.
        let short: Vec<u64> = vec![0, 7, 4294967294, u64::MAX];
        let long: Vec<u64> = (0..40).map(|i| i * 1_000_003 + 7).collect();
        for ids in [&short, &long] {
            let expected: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
            with_rendered_principal_stack(ids, |refs| {
                assert_eq!(refs.len(), expected.len());
                for (r, e) in refs.iter().zip(expected.iter()) {
                    assert_eq!(*r, e.as_str());
                }
            });
        }
    }

    #[test]
    fn typed_network_abi_rejects_noncanonical_inputs_before_host_lookup() {
        let ids = [0u64];
        let candidates = CString::new("[]").unwrap();
        let uppercase_host = CString::new("API.example.com").unwrap();
        let mapped_host = CString::new("::ffff:169.254.169.254").unwrap();
        let canonical_host = CString::new("api.example.com").unwrap();
        let malformed_candidates = CString::new(r#"{"a":1,"a":2}"#).unwrap();

        let uppercase = unsafe {
            ex_host_authorize_typed_network_stack(
                0,
                ids.as_ptr(),
                ids.len(),
                1,
                uppercase_host.as_ptr(),
                443,
                0,
                candidates.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                u64::MAX,
            )
        };
        assert_eq!(uppercase, -1);

        let mapped = unsafe {
            ex_host_authorize_typed_network_stack(
                0,
                ids.as_ptr(),
                ids.len(),
                4,
                mapped_host.as_ptr(),
                80,
                0,
                candidates.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                u64::MAX,
            )
        };
        assert_eq!(mapped, -1);

        let duplicate_key = unsafe {
            ex_host_authorize_typed_network_stack(
                0,
                ids.as_ptr(),
                ids.len(),
                1,
                canonical_host.as_ptr(),
                443,
                0,
                malformed_candidates.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                u64::MAX,
            )
        };
        assert_eq!(duplicate_key, -1);

        let unsafe_redirect = unsafe {
            ex_host_authorize_typed_network_stack(
                0,
                ids.as_ptr(),
                ids.len(),
                1,
                canonical_host.as_ptr(),
                443,
                0,
                candidates.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                9_007_199_254_740_992,
            )
        };
        assert_eq!(unsafe_redirect, -1);
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FragmentedInterruptingWriter {
        bytes: Vec<u8>,
        max_chunk: usize,
        interrupt_once: bool,
    }

    impl Write for FragmentedInterruptingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.interrupt_once {
                self.interrupt_once = false;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "signal"));
            }
            let n = self.max_chunk.min(buf.len());
            self.bytes.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stdio_line_writer_appends_newline() {
        let mut output = Vec::new();

        write_stdio_line(&mut output, "hello").unwrap();

        assert_eq!(output, b"hello\n");
    }

    #[test]
    fn stdio_line_writer_returns_broken_pipe_without_panicking() {
        let mut writer = FailingWriter;

        let result = write_stdio_line(&mut writer, "hello");

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn append_write_helper_retries_interrupted_and_short_writes() {
        let mut writer = FragmentedInterruptingWriter {
            bytes: Vec::new(),
            max_chunk: 3,
            interrupt_once: true,
        };
        let payload = b"abcdefghij";

        let written = write_all_return_count(&mut writer, payload).unwrap();

        assert_eq!(written, payload.len() as i32);
        assert_eq!(writer.bytes, payload);
    }

    #[test]
    fn console_queue_drops_under_backpressure_then_reports() {
        use std::sync::atomic::Ordering;

        let (tx, rx) = std::sync::mpsc::sync_channel::<ConsoleLine>(2);
        let queue = ConsoleQueue {
            tx,
            dropped: std::sync::atomic::AtomicU64::new(0),
        };

        queue.enqueue(ConsoleLine::Out("first".to_string()));
        queue.enqueue(ConsoleLine::Out("second".to_string()));
        queue.enqueue(ConsoleLine::Out("third".to_string()));
        assert_eq!(queue.dropped.load(Ordering::Relaxed), 1);

        assert!(matches!(rx.recv().unwrap(), ConsoleLine::Out(ref m) if m == "first"));
        assert!(matches!(rx.recv().unwrap(), ConsoleLine::Out(ref m) if m == "second"));

        queue.enqueue(ConsoleLine::Out("fourth".to_string()));
        assert_eq!(queue.dropped.load(Ordering::Relaxed), 0);
        match rx.recv().unwrap() {
            ConsoleLine::Err(m) => assert!(m.contains("dropped 1 line(s)")),
            ConsoleLine::Out(m) => panic!("expected drop notice before line, got {m}"),
        }
        assert!(matches!(rx.recv().unwrap(), ConsoleLine::Out(ref m) if m == "fourth"));
    }

    #[test]
    fn console_queue_survives_missing_receiver() {
        use std::sync::atomic::Ordering;

        let (tx, rx) = std::sync::mpsc::sync_channel::<ConsoleLine>(4);
        drop(rx);
        let queue = ConsoleQueue {
            tx,
            dropped: std::sync::atomic::AtomicU64::new(0),
        };

        queue.enqueue(ConsoleLine::Out("lost".to_string()));

        assert_eq!(queue.dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn named_sqlite_bindings_are_bound_by_name() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)", [])
            .unwrap();

        let insert_json = CString::new("{\":name\":\"alice\",\":id\":7}").unwrap();
        let insert_bindings = parse_bindings(insert_json.as_ptr());
        let mut insert = conn
            .prepare("INSERT INTO items (id, name) VALUES (:id, :name)")
            .unwrap();
        execute_with_bindings(&mut insert, &insert_bindings).unwrap();

        let query_json = CString::new("{\":id\":7}").unwrap();
        let query_bindings = parse_bindings(query_json.as_ptr());
        let mut query = conn
            .prepare("SELECT name FROM items WHERE id = :id")
            .unwrap();
        let mut rows = query_with_bindings(&mut query, &query_bindings).unwrap();
        let row = rows.next().unwrap().unwrap();
        let name: String = row.get(0).unwrap();

        assert_eq!(name, "alice");
    }

    #[test]
    fn sqlite_handle_allocators_refuse_before_wrap_or_reuse() {
        let mut state = SqliteState::new();
        state.next_db_handle = u64::MAX - 1;
        state.next_statement_handle = u64::MAX - 1;

        assert_eq!(state.allocate_db_handle(), Some(u64::MAX - 1));
        assert_eq!(state.allocate_db_handle(), None);
        assert_eq!(state.next_db_handle, u64::MAX);

        assert_eq!(state.allocate_statement_handle(), Some(u64::MAX - 1));
        assert_eq!(state.allocate_statement_handle(), None);
        assert_eq!(state.next_statement_handle, u64::MAX);
    }

    #[test]
    fn install_host_replaces_existing_host() {
        let _guard = host_test_lock();

        install_host(Host::default_legacy());
        assert!(with_host(|host| host.is_allow_all(), false));

        install_host(Host::new(HostConfig {
            mode: SecurityMode::Enforce,
            ..Default::default()
        }));
        assert!(!with_host(|host| host.is_allow_all(), true));
    }

    #[test]
    fn typed_decision_abi_returns_fail_closed_error_envelope() {
        let result =
            unsafe { ex_host_evaluate_typed_decision(std::ptr::null(), 0, std::ptr::null(), 0) };
        assert!(!result.is_null());
        let payload = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        let value: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(value["error"], "null typed decision input");
        ex_host_free_string(result);
    }

    #[test]
    fn read_file_round_trips_full_length_and_frees_true_layout() {
        // The `ex_host_fs_read_file` / `ex_host_free_buffer` length must survive the
        // FFI round trip without truncation: the caller frees with the exact length
        // read_file reported, so the reconstructed Box layout must match the
        // allocation. A payload larger than a page ensures a non-trivial layout.
        // (A real >= 4 GiB reproduction of the former `as u32` truncation is
        // impractical in a unit test; the regression this guards is that the ABI
        // carries the full length through.)
        let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();

        let mut file = tempfile::NamedTempFile::new().unwrap();
        Write::write_all(&mut file, &payload).unwrap();
        Write::flush(&mut file).unwrap();
        let path = CString::new(file.path().to_str().unwrap()).unwrap();

        let mut out_len: u64 = 0;
        let mut out_errno: i32 = 0;
        let buf = ex_host_fs_read_file(path.as_ptr(), &mut out_len, &mut out_errno);
        assert!(!buf.is_null());
        assert_eq!(out_len, payload.len() as u64);

        let read_back = unsafe { std::slice::from_raw_parts(buf, out_len as usize) };
        assert_eq!(read_back, payload.as_slice());

        // Free with the exact reported length so the Box layout matches the
        // allocation (this is the path the C++ caller takes).
        ex_host_free_buffer(buf, out_len);
    }

    #[test]
    fn pread_pwrite_are_positional_and_leave_the_cursor_unchanged() {
        // ENG-22993 / ENG-22982: a numeric `position` in Node's readSync/writeSync
        // is a *positional* op that must not move the fd cursor. ex_host_fs_pread /
        // ex_host_fs_pwrite must read/write at the given offset and restore the
        // cursor so a subsequent sequential read/write continues where it left
        // off (the pre-fix seek+read/seek+write path moved the cursor and
        // corrupted header-then-stream access).
        let mut file = tempfile::NamedTempFile::new().unwrap();
        Write::write_all(&mut file, b"ABCDEFGHIJ").unwrap();
        Write::flush(&mut file).unwrap();
        let path = CString::new(file.path().to_str().unwrap()).unwrap();

        // Open read+write (no truncate): cursor starts at 0, contents preserved.
        let handle = ex_host_fs_open(path.as_ptr(), FS_READ | FS_WRITE);
        assert!(!handle.is_null());

        // Sequential read of the first 3 bytes advances the cursor to 3.
        let mut head = [0u8; 3];
        assert_eq!(ex_host_fs_read(handle, head.as_mut_ptr(), 3), 3);
        assert_eq!(&head, b"ABC");

        // Positional read at offset 7 must NOT disturb the cursor.
        let mut mid = [0u8; 2];
        assert_eq!(ex_host_fs_pread(handle, mid.as_mut_ptr(), 2, 7), 2);
        assert_eq!(&mid, b"HI");

        // The next sequential read continues from 3 (not from 9). With the
        // pre-fix seek+read bug this would have returned bytes at offset 9.
        let mut next = [0u8; 3];
        assert_eq!(ex_host_fs_read(handle, next.as_mut_ptr(), 3), 3);
        assert_eq!(&next, b"DEF");

        // Positional write at offset 0 must also leave the cursor at 6.
        assert_eq!(ex_host_fs_pwrite(handle, b"xy".as_ptr(), 2, 0), 2);

        // Sequential read continues from 6 -> "GHI".
        let mut after = [0u8; 3];
        assert_eq!(ex_host_fs_read(handle, after.as_mut_ptr(), 3), 3);
        assert_eq!(&after, b"GHI");

        ex_host_fs_close(handle);

        // The positional write landed at offset 0, leaving the rest intact.
        let contents = std::fs::read(file.path()).unwrap();
        assert_eq!(&contents, b"xyCDEFGHIJ");
    }

    #[test]
    fn portable_path_abi_preserves_node_creation_and_metadata_semantics() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("first/second");
        let nested_c = CString::new(nested.to_string_lossy().as_bytes()).unwrap();
        let created = ex_host_fs_mkdir_recursive_result(nested_c.as_ptr());
        assert!(!created.is_null());
        let created_path = unsafe { CStr::from_ptr(created) }
            .to_string_lossy()
            .into_owned();
        ex_host_free_string(created);
        assert_eq!(created_path, root.path().join("first").to_string_lossy());
        let created_again = ex_host_fs_mkdir_recursive_result(nested_c.as_ptr());
        assert_eq!(unsafe { CStr::from_ptr(created_again) }.to_bytes(), b"");
        ex_host_free_string(created_again);

        let source = root.path().join("source");
        let destination = root.path().join("destination");
        std::fs::write(&source, b"abcdef").unwrap();
        let source_c = CString::new(source.to_string_lossy().as_bytes()).unwrap();
        let destination_c = CString::new(destination.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(
            ex_host_fs_copy_exclusive(source_c.as_ptr(), destination_c.as_ptr()),
            0
        );
        std::fs::write(&source, b"replacement").unwrap();
        assert_eq!(
            ex_host_fs_copy_exclusive(source_c.as_ptr(), destination_c.as_ptr()),
            -1
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"abcdef");

        assert_eq!(ex_host_fs_truncate(destination_c.as_ptr(), 3), 0);
        assert_eq!(std::fs::read(&destination).unwrap(), b"abc");
        let timestamp = 1_700_000_000.0;
        assert_eq!(
            ex_host_fs_utimes(destination_c.as_ptr(), timestamp, timestamp),
            0
        );
        let modified = std::fs::metadata(&destination)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(modified, timestamp as u64);

        let root_c = CString::new(root.path().to_string_lossy().as_bytes()).unwrap();
        let statfs = ex_host_fs_statfs(root_c.as_ptr());
        assert!(!statfs.is_null());
        let payload: serde_json::Value =
            serde_json::from_slice(unsafe { CStr::from_ptr(statfs) }.to_bytes()).unwrap();
        ex_host_free_string(statfs);
        assert!(payload["bsize"].as_u64().is_some_and(|size| size > 0));
        assert!(payload["blocks"].as_u64().is_some_and(|blocks| blocks > 0));
    }

    /// Run `sql` through the exec ABI, asserting it did not fault, and free the
    /// returned status string.
    #[cfg(test)]
    fn exec_ok(db: u64, sql: &str, bindings: Option<&str>) {
        let c_sql = CString::new(sql).unwrap();
        let c_bindings = bindings.map(|b| CString::new(b).unwrap());
        let bindings_ptr = c_bindings.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        let result = ex_host_sqlite_exec(db, c_sql.as_ptr(), bindings_ptr);
        assert!(!result.is_null(), "exec returned null for {sql}");
        let text = unsafe { CStr::from_ptr(result) }
            .to_string_lossy()
            .into_owned();
        ex_host_free_string(result);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(
            value.get("error").is_none(),
            "exec of {sql} unexpectedly errored: {text}"
        );
    }

    /// Read a `*mut c_char` JSON result out of the SQLite ABI and free it.
    #[cfg(test)]
    fn take_json(ptr: *mut c_char) -> serde_json::Value {
        assert!(!ptr.is_null(), "SQLite ABI returned null");
        let text = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        ex_host_free_string(ptr);
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn sqlite_tagged_blob_binding_is_stored_as_blob() {
        let _guard = host_test_lock();

        let mem = CString::new(":memory:").unwrap();
        let db = ex_host_sqlite_open(mem.as_ptr(), ptr::null());
        assert_ne!(db, 0);
        exec_ok(db, "CREATE TABLE bytes (value BLOB)", None);
        exec_ok(
            db,
            "INSERT INTO bytes (value) VALUES (?)",
            Some(r#"[{"$ibexSqliteBindingV1":{"kind":"blob","base64":"AAEC/v8="}}]"#),
        );

        let prep = CString::new(
            "SELECT typeof(value) AS kind, length(value) AS size, hex(value) AS hex FROM bytes",
        )
        .unwrap();
        let prepared = take_json(ex_host_sqlite_prepare(db, prep.as_ptr()));
        let handle = prepared["handle"].as_u64().unwrap();
        let result = take_json(ex_host_sqlite_get(handle, ptr::null()));
        assert_eq!(result["row"]["kind"], "blob");
        assert_eq!(result["row"]["size"], 5);
        assert_eq!(result["row"]["hex"], "000102FEFF");

        assert_eq!(ex_host_sqlite_close(db), 0);
    }

    #[test]
    fn sqlite_blob_tag_lookalike_plain_object_keeps_legacy_text_semantics() {
        let value = serde_json::json!({"$ibexSqliteBlobBase64": "AAEC/v8="});
        assert!(matches!(
            to_sql_value(&value),
            rusqlite::types::Value::Text(text)
                if text == "$ibexSqliteBlobBase64=\"AAEC/v8=\""
        ));
    }

    #[test]
    fn sqlite_value_envelope_does_not_recursively_decode_user_transport_lookalike() {
        let value = serde_json::json!({
            "$ibexSqliteBindingV1": {
                "kind": "value",
                "value": {
                    "$ibexSqliteBindingV1": {
                        "kind": "blob",
                        "base64": "AAEC/v8="
                    }
                }
            }
        });
        assert_eq!(
            to_sql_value(&value),
            rusqlite::types::Value::Text(
                "$ibexSqliteBindingV1={\"base64\":\"AAEC/v8=\",\"kind\":\"blob\"}".into(),
            ),
        );
    }

    #[test]
    fn sqlite_readonly_open_of_existing_file_succeeds() {
        let _guard = host_test_lock();

        // Create an on-disk database and write a row through a read-write open.
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let c_path = CString::new(path).unwrap();

        let rw = ex_host_sqlite_open(c_path.as_ptr(), ptr::null());
        assert_ne!(rw, 0, "default (read-write) open should succeed");
        exec_ok(rw, "CREATE TABLE t (v INTEGER)", None);
        exec_ok(rw, "INSERT INTO t (v) VALUES (42)", None);
        assert_eq!(ex_host_sqlite_close(rw), 0);

        // Reopen read-only. Before the fix this produced `READ_ONLY|CREATE`,
        // which rusqlite rejects with SQLITE_MISUSE, so open returned 0.
        let ro_opts = CString::new("{\"readonly\":true}").unwrap();
        let ro = ex_host_sqlite_open(c_path.as_ptr(), ro_opts.as_ptr());
        assert_ne!(
            ro, 0,
            "{{readonly:true}} open of an existing file must succeed"
        );

        // Reads work.
        let prep = CString::new("SELECT v FROM t").unwrap();
        let prepared = take_json(ex_host_sqlite_prepare(ro, prep.as_ptr()));
        let handle = prepared["handle"].as_u64().unwrap();
        let rows = take_json(ex_host_sqlite_all(handle, ptr::null()));
        assert_eq!(rows["rows"][0]["v"].as_i64(), Some(42));

        // Writes are rejected on a read-only connection.
        let write = CString::new("INSERT INTO t (v) VALUES (7)").unwrap();
        let write_result = take_json(ex_host_sqlite_exec(ro, write.as_ptr(), ptr::null()));
        assert!(
            write_result.get("error").is_some(),
            "write on a read-only connection must error, got {write_result}"
        );

        assert_eq!(ex_host_sqlite_close(ro), 0);
    }

    #[test]
    fn sqlite_authorizer_denies_attach_detach_and_load_extension() {
        let _guard = host_test_lock();

        let mem = CString::new(":memory:").unwrap();
        let db = ex_host_sqlite_open(mem.as_ptr(), ptr::null());
        assert_ne!(db, 0);

        let attach = CString::new("ATTACH DATABASE ':memory:' AS other").unwrap();
        let attach_result = take_json(ex_host_sqlite_exec(db, attach.as_ptr(), ptr::null()));
        assert!(
            attach_result
                .get("error")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|err| err.to_ascii_lowercase().contains("not authorized")),
            "ATTACH must be denied by the SQLite authorizer, got {attach_result}"
        );

        let detach = CString::new("DETACH DATABASE main").unwrap();
        let detach_result = take_json(ex_host_sqlite_exec(db, detach.as_ptr(), ptr::null()));
        assert!(
            detach_result
                .get("error")
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "DETACH must be denied by the SQLite authorizer, got {detach_result}"
        );

        let load_extension = CString::new("SELECT load_extension('x')").unwrap();
        let load_extension_result = take_json(ex_host_sqlite_prepare(db, load_extension.as_ptr()));
        assert!(
            load_extension_result.get("error").is_some(),
            "load_extension() must be denied or unavailable, got {load_extension_result}"
        );

        assert_eq!(ex_host_sqlite_close(db), 0);
    }

    #[test]
    fn sqlite_all_surfaces_mid_iteration_step_error() {
        let _guard = host_test_lock();

        let mem = CString::new(":memory:").unwrap();
        let db = ex_host_sqlite_open(mem.as_ptr(), ptr::null());
        assert_ne!(db, 0);

        // One well-behaved row, then i64::MIN (bound as an integer so it is stored
        // as INTEGER, not coerced to REAL). `abs(i64::MIN)` raises "integer
        // overflow" during step — a genuine mid-iteration error after a good row.
        exec_ok(db, "CREATE TABLE t (v INTEGER)", None);
        exec_ok(db, "INSERT INTO t (v) VALUES (1)", None);
        exec_ok(
            db,
            "INSERT INTO t (v) VALUES (?)",
            Some("[-9223372036854775808]"),
        );

        let prep = CString::new("SELECT abs(v) AS a FROM t").unwrap();
        let prepared = take_json(ex_host_sqlite_prepare(db, prep.as_ptr()));
        let handle = prepared["handle"].as_u64().unwrap();

        let result = take_json(ex_host_sqlite_all(handle, ptr::null()));
        assert!(
            result.get("error").is_some(),
            "a mid-iteration step error must surface as an error, got {result}"
        );
        assert!(
            result.get("rows").is_none(),
            "must not return partial rows as a successful result, got {result}"
        );

        // `values` takes the same code path and must behave the same way.
        let values = take_json(ex_host_sqlite_values(handle, ptr::null()));
        assert!(
            values.get("error").is_some(),
            "values must also surface the step error, got {values}"
        );

        assert_eq!(ex_host_sqlite_close(db), 0);
    }

    #[test]
    fn env_get_distinguishes_unset_empty_and_reports_full_length() {
        // ENG-22955: the ABI must (a) distinguish unset (-1) from present-but-empty
        // (0), which the old `unwrap_or_default()` folded together, and (b) report
        // the value's full byte length so a caller can detect truncation and
        // re-query instead of silently clipping long values (the C++ side's 4096
        // buffer used to lose the tail with no signal).
        use std::os::raw::c_char;

        const KEY: &str = "IBEX_ENG22955_ENV_TEST";
        let key = CString::new(KEY).unwrap();
        let call = |buf: &mut [c_char]| -> i64 {
            ex_host_env_get(key.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };

        std::env::remove_var(KEY);
        // Unset -> -1 (distinct from empty).
        let mut buf = [0x7f as c_char; 32];
        assert_eq!(call(&mut buf), -1);

        // Present but empty -> length 0, null-terminated at index 0.
        std::env::set_var(KEY, "");
        buf = [0x7f as c_char; 32];
        assert_eq!(call(&mut buf), 0);
        assert_eq!(buf[0], 0);

        // Normal value -> full length, exact bytes + null terminator.
        std::env::set_var(KEY, "hello");
        buf = [0x7f as c_char; 32];
        assert_eq!(call(&mut buf), 5);
        assert_eq!(
            &buf[..5].iter().map(|&b| b as u8).collect::<Vec<_>>(),
            b"hello"
        );
        assert_eq!(buf[5], 0);

        // Value longer than the buffer -> return is the FULL length (> buffer),
        // the buffer holds a len-1 byte prefix and stays null-terminated: the
        // caller can see it was truncated and re-query with a bigger buffer.
        let long = "x".repeat(10_000);
        std::env::set_var(KEY, &long);
        let mut small = [0x7f as c_char; 8];
        assert_eq!(call(&mut small), 10_000);
        assert_eq!(small[7], 0);
        assert!(small[..7].iter().all(|&b| b as u8 == b'x'));

        // A null/zero buffer is a pure length query: no write, just the length.
        assert_eq!(ex_host_env_get(key.as_ptr(), ptr::null_mut(), 0), 10_000);

        std::env::remove_var(KEY);
    }
}
