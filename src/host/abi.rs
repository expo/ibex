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
    match err.kind() {
        ErrorKind::NotFound => libc::ENOENT,
        ErrorKind::PermissionDenied => libc::EACCES,
        ErrorKind::AlreadyExists => libc::EEXIST,
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

pub fn install_host(host: Host) {
    if let Some(slot) = HOST.get() {
        match slot.write() {
            Ok(mut current) => {
                *current = host;
            }
            Err(poisoned) => {
                *poisoned.into_inner() = host;
            }
        }
        return;
    }

    let _ = HOST.set(RwLock::new(host));
}

/// Install an immutable armed host from caller-owned bytes. The bytes are
/// copied and authenticated before publication; later caller mutation cannot
/// affect the installed decision context.
/// @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
pub fn install_armed_host(snapshot: &[u8], expected_json: &[u8]) -> Result<(), String> {
    use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
    let expected_text = std::str::from_utf8(expected_json)
        .map_err(|error| format!("expected arming identity is not UTF-8: {error}"))?;
    let expected_value = capsec_semantics::strict_json::parse_strict(expected_text)
        .map_err(|error| error.to_string())?;
    let expected: ExpectedArmingIdentity = serde_json::from_value(expected_value)
        .map_err(|error| format!("invalid expected arming identity: {error}"))?;
    let armed = ArmedSnapshot::load(snapshot, &expected).map_err(|error| error.to_string())?;
    install_host(Host::new_armed(
        super::HostConfig {
            mode: super::SecurityMode::Enforce,
            ..Default::default()
        },
        Arc::new(armed),
    ));
    Ok(())
}

fn with_host<T>(f: impl FnOnce(&Host) -> T, default: T) -> T {
    let Some(host) = HOST.get() else {
        return default;
    };

    match host.read() {
        Ok(current) => f(&current),
        Err(poisoned) => f(&poisoned.into_inner()),
    }
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

fn to_sql_value(value: &serde_json::Value) -> rusqlite::types::Value {
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
        serde_json::Value::Object(value) => rusqlite::types::Value::Text(value.iter().fold(
            String::new(),
            |mut out, (key, value)| {
                if !out.is_empty() {
                    out.push(',');
                }
                out.push_str(key);
                out.push('=');
                out.push_str(&value.to_string());
                out
            },
        )),
    }
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
            serde_json::Value::Array(value.iter().copied().map(serde_json::Value::from).collect())
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

/// Install the host singleton with default (permissive) configuration.
/// Called from iOS/Swift before creating a runtime.
/// On the CLI, `install_host()` is called with a configured Host instead.
#[no_mangle]
pub extern "C" fn ex_host_install() {
    install_host(Host::default_legacy());
}

/// Explicit fail-closed embedder arming entry point. Returns 0 only after the
/// immutable snapshot is authenticated and installed.
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

/// Returns 1 if the host is in Legacy (allow-all) mode, 0 otherwise.
/// Used by the C++ bridge to skip expensive capability checks.
#[no_mangle]
pub extern "C" fn ex_host_is_allow_all() -> i32 {
    with_host(|host| if host.is_allow_all() { 1 } else { 0 }, 0)
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
    let module = module_id.to_string();
    with_host(
        |host| host.register_module_package(&module, &package, locator.as_deref()),
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
    specifier: *const c_char,
    referrer: *const c_char,
) -> *mut c_char {
    let Some((spec, referrer)) = module_resolve_args(specifier, referrer) else {
        return ptr::null_mut();
    };

    let resolved = with_host(
        |host| {
            let path = referrer.as_ref().map(std::path::PathBuf::from);
            host.resolve_module(&spec, path.as_deref())
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
            "error": err.to_string()
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
    specifier: *const c_char,
    referrer: *const c_char,
) -> *mut c_char {
    let Some((spec, referrer)) = module_resolve_args(specifier, referrer) else {
        return ptr::null_mut();
    };

    let resolved = with_host(
        |host| {
            let path = referrer.as_ref().map(std::path::PathBuf::from);
            host.resolve_module_meta(&spec, path.as_deref())
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
        (Err(err), _) | (Ok(_), Err(err)) => {
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
        let handle = state.next_db_handle;
        state.next_db_handle = state.next_db_handle.saturating_add(1);
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
        let statement_handle = state.next_statement_handle;
        state.next_statement_handle = state.next_statement_handle.saturating_add(1);
        state.statements.insert(
            statement_handle,
            SqliteStatementRecord {
                db_id: db_handle,
                sql,
                read_only,
            },
        );
        statement_handle
    });

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
