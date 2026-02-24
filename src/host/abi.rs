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
use rusqlite::{params_from_iter, types::ValueRef, Connection, OpenFlags};
use serde_json::json;
use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::ptr;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const EXACT_HOST_ABI_VERSION: u32 = 1;

static HOST: OnceLock<Host> = OnceLock::new();
static SECURITY_LOG_ENABLED: OnceLock<bool> = OnceLock::new();

struct SqliteConnectionRecord {
    db: Connection,
}

#[derive(Clone)]
struct SqliteStatementRecord {
    db_id: u64,
    sql: String,
}

struct SqliteState {
    next_db_handle: u64,
    next_statement_handle: u64,
    dbs: HashMap<u64, SqliteConnectionRecord>,
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

pub fn install_host(host: Host) {
    let _ = HOST.set(host);
}

fn with_host<T>(f: impl FnOnce(&Host) -> T, default: T) -> T {
    HOST.get().map(f).unwrap_or(default)
}

fn security_log_enabled() -> bool {
    *SECURITY_LOG_ENABLED.get_or_init(|| {
        std::env::var("EXACT_SECURITY_LOG")
            .map(|v| !matches!(v.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
            .unwrap_or(true)
    })
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

    let mut open_flags = OpenFlags::empty();
    if options.readonly {
        open_flags.insert(OpenFlags::SQLITE_OPEN_READ_ONLY);
    } else {
        open_flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
    }
    if options.create {
        open_flags.insert(OpenFlags::SQLITE_OPEN_CREATE);
    }
    open_flags
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

fn parse_bindings(raw: *const c_char) -> Vec<rusqlite::types::Value> {
    if raw.is_null() {
        return vec![];
    }

    let raw = unsafe { CStr::from_ptr(raw) }.to_string_lossy();
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(serde_json::Value::Array(values)) => values.iter().map(to_sql_value).collect(),
        Ok(serde_json::Value::Object(values)) => values.values().map(to_sql_value).collect(),
        Ok(serde_json::Value::Null) => vec![],
        Ok(other) => vec![to_sql_value(&other)],
        Err(_) => vec![],
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

fn as_json_cstring(value: &serde_json::Value) -> *mut c_char {
    match serde_json::to_string(value) {
        Ok(payload) => match CString::new(payload) {
            Ok(value) => value.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
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

/// Returns 1 if the host is in Legacy (allow-all) mode, 0 otherwise.
/// Used by the C++ bridge to skip expensive capability checks.
#[no_mangle]
pub extern "C" fn ex_host_is_allow_all() -> i32 {
    with_host(|host| if host.is_allow_all() { 1 } else { 0 }, 0)
}

/// Read an entire file into a heap-allocated buffer in a single call.
/// Returns null on error. Caller must free with `ex_host_free_buffer`.
#[no_mangle]
pub extern "C" fn ex_host_fs_read_file(path: *const c_char, out_len: *mut u32) -> *mut u8 {
    if path.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(path) }.to_string_lossy();
    match std::fs::read(path.as_ref()) {
        Ok(data) => {
            let boxed = data.into_boxed_slice();
            let len = boxed.len();
            unsafe { *out_len = len as u32 };
            Box::into_raw(boxed) as *mut u8
        }
        Err(_) => {
            unsafe { *out_len = 0 };
            ptr::null_mut()
        }
    }
}

/// Free a buffer returned by `ex_host_fs_read_file`.
#[no_mangle]
pub extern "C" fn ex_host_free_buffer(buf: *mut u8, len: u32) {
    if !buf.is_null() && len > 0 {
        unsafe {
            let raw = ptr::slice_from_raw_parts_mut(buf, len as usize);
            drop(Box::from_raw(raw));
        }
    }
}

#[no_mangle]
pub extern "C" fn ex_host_check_capability(module_id: u64, capability: *const c_char) -> i32 {
    if capability.is_null() {
        return 0;
    }

    let cap = unsafe { CStr::from_ptr(capability) }
        .to_string_lossy()
        .to_string();

    let module = module_id.to_string();
    let allowed = with_host(|host| host.check_capability(&module, &cap), false);
    if allowed {
        1
    } else {
        0
    }
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
    with_host(|host| host.capabilities().grant(&module, &cap, None), ());
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
    eprintln!("{}", payload);
}

#[no_mangle]
pub extern "C" fn ex_host_module_resolve(
    specifier: *const c_char,
    referrer: *const c_char,
) -> *mut c_char {
    if specifier.is_null() {
        return ptr::null_mut();
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

    let resolved = with_host(
        |host| {
            let path = referrer.as_ref().map(std::path::PathBuf::from);
            host.resolve_module(&spec, path.as_deref())
        },
        Err(anyhow::anyhow!("Host not initialized")),
    );

    let payload = match resolved {
        Ok(module) => json!({
            "id": module.id,
            "kind": match module.kind {
                crate::module_loader::ModuleKind::Builtin => "builtin",
                crate::module_loader::ModuleKind::CommonJs => "cjs",
                crate::module_loader::ModuleKind::Json => "json",
                crate::module_loader::ModuleKind::Esm => "esm",
            },
            "path": module.path.as_ref().map(|p| p.to_string_lossy().to_string()),
            "source": module.source.unwrap_or_default()
        }),
        Err(err) => json!({
            "error": err.to_string()
        }),
    };

    match std::ffi::CString::new(payload.to_string()) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => ptr::null_mut(),
    }
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

    match opts.open(path) {
        Ok(file) => Box::into_raw(Box::new(ExactFileHandle { file })),
        Err(_) => ptr::null_mut(),
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
        Err(_) => -1,
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
        Err(_) => -1,
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

/// Return a JSON string with file metadata: {size, mtime_ms, is_dir, is_file, mode}
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
    match std::fs::metadata(&path) {
        Ok(meta) => {
            let mtime_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
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
            let payload = json!({
                "size": meta.len(),
                "mtime_ms": mtime_ms,
                "is_dir": meta.is_dir(),
                "is_file": meta.is_file(),
                "mode": mode
            });
            match CString::new(payload.to_string()) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
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
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            let mtime_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let is_symlink = meta.file_type().is_symlink();
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
            let payload = json!({
                "size": meta.len(),
                "mtime_ms": mtime_ms,
                "is_dir": meta.is_dir(),
                "is_file": meta.is_file(),
                "is_symlink": is_symlink,
                "mode": mode
            });
            match CString::new(payload.to_string()) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
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
                Err(_) => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
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
        Err(_) => -1,
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
        Err(_) => -1,
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
        Err(_) => -1,
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
        Err(_) => -1,
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
        Err(_) => -1,
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
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Check access to a path. `mode` is a bitmask: 0=existence, 1=read, 2=write, 4=execute.
/// Returns 0 if accessible, -1 if not.
#[no_mangle]
pub extern "C" fn ex_host_fs_access(path: *const c_char, mode: i32) -> i32 {
    if path.is_null() {
        return -1;
    }
    let path_str = unsafe { CStr::from_ptr(path) }
        .to_string_lossy()
        .to_string();
    let p = std::path::Path::new(&path_str);

    // mode 0 = F_OK (existence check)
    if !p.exists() {
        return -1;
    }
    if mode == 0 {
        return 0;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(&path_str) {
            Ok(meta) => {
                let perms = meta.permissions().mode();
                // Simple check: mode 1=read(R_OK), 2=write(W_OK), 4=execute(X_OK)
                if mode & 1 != 0 && perms & 0o444 == 0 {
                    return -1;
                }
                if mode & 2 != 0 && perms & 0o222 == 0 {
                    return -1;
                }
                if mode & 4 != 0 && perms & 0o111 == 0 {
                    return -1;
                }
                0
            }
            Err(_) => -1,
        }
    }
    #[cfg(not(unix))]
    {
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
            Err(_) => -1,
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
pub extern "C" fn ex_host_fs_mkdtemp(prefix: *const c_char) -> *mut c_char {
    let prefix_str = if prefix.is_null() {
        "tmp".to_string()
    } else {
        unsafe { CStr::from_ptr(prefix) }
            .to_string_lossy()
            .to_string()
    };

    let mut template = std::env::temp_dir();
    template.push(format!("{}{}", prefix_str, "XXXXXX"));

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
    match std::fs::create_dir(&dir_path) {
        Ok(_) => match CString::new(dir_path.to_string_lossy().to_string()) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
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

    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).append(true);
    match opts.open(&path) {
        Ok(mut file) => match file.write(slice) {
            Ok(n) => n as i32,
            Err(_) => -1,
        },
        Err(_) => -1,
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

    with_sqlite_state(|state| {
        let handle = state.next_db_handle;
        state.next_db_handle = state.next_db_handle.saturating_add(1);
        state.dbs.insert(handle, SqliteConnectionRecord { db });
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

    with_sqlite_state(|state| {
        let connection = match state.dbs.get_mut(&db_handle) {
            Some(db) => db,
            None => return ptr::null_mut(),
        };

        let statement = match connection.db.prepare(&sql) {
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

        let declared_types: Vec<String> = statement
            .columns()
            .into_iter()
            .map(|column| column.decl_type().unwrap_or("").to_string())
            .collect();

        let params_count = statement.parameter_count() as usize;
        let statement_handle = state.next_statement_handle;
        state.next_statement_handle = state.next_statement_handle.saturating_add(1);
        state.statements.insert(
            statement_handle,
            SqliteStatementRecord {
                db_id: db_handle,
                sql,
            },
        );

        as_json_cstring(&json!({
            "handle": statement_handle,
            "columnNames": column_names,
            "declaredTypes": declared_types,
            "paramsCount": params_count,
        }))
    })
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
    with_sqlite_state(|state| {
        let connection = match state.dbs.get(&handle) {
            Some(connection) => connection,
            None => return 0,
        };
        if connection.db.is_autocommit() {
            0
        } else {
            1
        }
    })
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

    with_sqlite_state(|state| {
        let statement = match state.statements.get(&statement_handle) {
            Some(statement) => statement,
            None => return ptr::null_mut(),
        };
        let connection = match state.dbs.get_mut(&statement.db_id) {
            Some(connection) => connection,
            None => return ptr::null_mut(),
        };

        let mut stmt = match connection.db.prepare(&statement.sql) {
            Ok(statement) => statement,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };

        let column_count = stmt.column_count();
        let column_names: Vec<String> = (0..column_count)
            .filter_map(|index| stmt.column_name(index).ok().map(|name| name.to_string()))
            .collect();
        let column_types: Vec<String> = stmt
            .columns()
            .into_iter()
            .map(|column| column.decl_type().unwrap_or("").to_string())
            .collect();

        let mut rows = match stmt.query(params_from_iter(bindings.iter())) {
            Ok(result) => result,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };

        let mut payload_rows = Vec::new();
        while let Ok(Some(row)) = rows.next() {
            let mut object = serde_json::Map::new();
            for index in 0..column_count {
                let name = match column_names.get(index) {
                    Some(name) => name.clone(),
                    None => continue,
                };

                if let Ok(value) = row.get_ref(index) {
                    object.insert(name, sqlite_value_to_json(value));
                }
            }
            payload_rows.push(serde_json::Value::Object(object));
        }

        as_json_cstring(&json!({
            "rows": payload_rows,
            "columnTypes": column_types,
        }))
    })
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

    with_sqlite_state(|state| {
        let statement = match state.statements.get(&statement_handle) {
            Some(statement) => statement,
            None => return ptr::null_mut(),
        };
        let connection = match state.dbs.get_mut(&statement.db_id) {
            Some(connection) => connection,
            None => return ptr::null_mut(),
        };

        let mut stmt = match connection.db.prepare(&statement.sql) {
            Ok(statement) => statement,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };

        let column_count = stmt.column_count();
        let column_names: Vec<String> = (0..column_count)
            .filter_map(|index| stmt.column_name(index).ok().map(|name| name.to_string()))
            .collect();
        let column_types: Vec<String> = stmt
            .columns()
            .into_iter()
            .map(|column| column.decl_type().unwrap_or("").to_string())
            .collect();

        let mut rows = match stmt.query(params_from_iter(bindings.iter())) {
            Ok(result) => result,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };

        let row = match rows.next() {
            Ok(Some(row)) => {
                let mut object = serde_json::Map::new();
                for index in 0..column_count {
                    let name = match column_names.get(index) {
                        Some(name) => name.clone(),
                        None => continue,
                    };
                    if let Ok(value) = row.get_ref(index) {
                        object.insert(name, sqlite_value_to_json(value));
                    }
                }
                serde_json::Value::Object(object)
            }
            Ok(None) => serde_json::Value::Null,
            Err(err) => serde_json::json!({"error": err.to_string()}),
        };

        as_json_cstring(&json!({
            "row": row,
            "columnTypes": column_types,
        }))
    })
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

    with_sqlite_state(|state| {
        let statement = match state.statements.get(&statement_handle) {
            Some(statement) => statement,
            None => return ptr::null_mut(),
        };
        let connection = match state.dbs.get_mut(&statement.db_id) {
            Some(connection) => connection,
            None => return ptr::null_mut(),
        };

        let mut stmt = match connection.db.prepare(&statement.sql) {
            Ok(statement) => statement,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };

        let column_count = stmt.column_count();
        let column_types: Vec<String> = stmt
            .columns()
            .into_iter()
            .map(|column| column.decl_type().unwrap_or("").to_string())
            .collect();

        let mut rows = match stmt.query(params_from_iter(bindings.iter())) {
            Ok(result) => result,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };

        let mut payload_rows = Vec::new();
        while let Ok(Some(row)) = rows.next() {
            let mut values = Vec::new();
            for index in 0..column_count {
                if let Ok(value) = row.get_ref(index) {
                    values.push(sqlite_value_to_json(value));
                }
            }
            payload_rows.push(serde_json::Value::Array(values));
        }

        as_json_cstring(&json!({
            "rows": payload_rows,
            "columnTypes": column_types,
        }))
    })
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

    with_sqlite_state(|state| {
        let statement = match state.statements.get(&statement_handle) {
            Some(statement) => statement,
            None => return ptr::null_mut(),
        };
        let connection = match state.dbs.get_mut(&statement.db_id) {
            Some(connection) => connection,
            None => return ptr::null_mut(),
        };

        let mut stmt = match connection.db.prepare(&statement.sql) {
            Ok(statement) => statement,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };

        if let Err(err) = stmt.execute(params_from_iter(bindings.iter())) {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }

        as_json_cstring(&json!({
            "changes": connection.db.changes(),
            "lastInsertRowid": connection.db.last_insert_rowid(),
        }))
    })
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

    with_sqlite_state(|state| {
        let connection = match state.dbs.get_mut(&db_handle) {
            Some(connection) => connection,
            None => return ptr::null_mut(),
        };

        let mut stmt = match connection.db.prepare(&sql) {
            Ok(statement) => statement,
            Err(err) => {
                return as_json_cstring(&json!({"error": err.to_string()}));
            }
        };

        if let Err(err) = stmt.execute(params_from_iter(bindings.iter())) {
            return as_json_cstring(&json!({"error": err.to_string()}));
        }

        as_json_cstring(&json!({
            "changes": connection.db.changes(),
            "lastInsertRowid": connection.db.last_insert_rowid(),
        }))
    })
}

#[no_mangle]
pub extern "C" fn ex_host_env_get(key: *const c_char, out_buf: *mut c_char, len: u32) -> u32 {
    if key.is_null() || out_buf.is_null() || len == 0 {
        return 0;
    }
    let key = unsafe { CStr::from_ptr(key) }.to_string_lossy().to_string();
    let value = std::env::var(key).unwrap_or_default();
    let bytes = value.as_bytes();
    let max_len = len as usize;

    let write_len = bytes.len().min(max_len.saturating_sub(1));
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf as *mut u8, write_len);
        *out_buf.add(write_len) = 0;
    }

    write_len as u32
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
    match level {
        0 => println!("{}", msg),
        1 => eprintln!("{}", msg),
        _ => println!("{}", msg),
    }
}
