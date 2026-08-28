//! The C ABI carrying `hostCall(op, args)` across the engine seam.
//!
//! LLP 0059.000 §1 asks for **one** surface, so this is one entry point taking
//! an opcode and an argument vector — not N specific entry points, which would
//! be a different design wearing the same words.
//!
//! §1.1: primitives and handles only. A value is a tag plus either a double or
//! a pointer/length pair; strings and byte buffers cross as borrowed spans in
//! and Rust-owned allocations out. Nothing is serialized.
//!
//! @ref LLP 0059.000#1-the-host-call-boundary — one surface, no JSON

use std::ffi::{c_char, c_int, c_uchar};

use crate::boundary::{HostArg, HostError, HostValue};
use crate::grant::GrantSet;
use crate::stdlib::{base64, console, text, url};

pub const TAG_UNDEFINED: i32 = 0;
pub const TAG_NULL: i32 = 1;
pub const TAG_BOOL: i32 = 2;
pub const TAG_NUMBER: i32 = 3;
pub const TAG_STRING: i32 = 4;
pub const TAG_BYTES: i32 = 5;

/// One value on the boundary. Repr-C so the shim and Rust agree byte for byte.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AbiValue {
    pub tag: i32,
    pub number: f64,
    pub data: *const c_uchar,
    pub len: usize,
}

impl AbiValue {
    fn undefined() -> Self {
        Self {
            tag: TAG_UNDEFINED,
            number: 0.0,
            data: std::ptr::null(),
            len: 0,
        }
    }

    /// Borrow this value as an argument. **No bytes are copied** — see
    /// LLP 0059.000 §1.2. `HostArg` has no owned byte variant, so this cannot
    /// silently regress into a copy.
    ///
    /// # Safety
    /// `data`/`len` must describe a span valid for the duration of the call,
    /// and the returned borrow must not outlive it.
    unsafe fn borrow<'a>(self) -> Result<HostArg<'a>, HostError> {
        Ok(match self.tag {
            TAG_UNDEFINED => HostArg::Undefined,
            TAG_NULL => HostArg::Null,
            TAG_BOOL => HostArg::Bool(self.number != 0.0),
            TAG_NUMBER => HostArg::Number(self.number),
            TAG_STRING => {
                // The engine already produced UTF-8; borrow it rather than
                // re-validating into a new String. Invalid UTF-8 here would be
                // an engine bug, so it is an error rather than a lossy repair.
                let text = std::str::from_utf8(self.span()).map_err(|_| {
                    HostError::InvalidArgument("string argument was not valid UTF-8".into())
                })?;
                HostArg::Str(text)
            }
            TAG_BYTES => HostArg::Bytes(self.span()),
            other => {
                return Err(HostError::InvalidArgument(format!(
                    "unknown value tag {other}"
                )))
            }
        })
    }

    /// Borrow a byte argument mutably, so Rust writes through to the engine's
    /// own buffer.
    ///
    /// This is the inbound half of §1.2 and the reason `ArrayBuffer` is in the
    /// boundary contract at all: `encodeInto` must be visible in the buffer the
    /// caller already holds, and an `encodeInto` that copies has implemented
    /// `encode` with extra steps.
    ///
    /// # Safety
    /// The span must be valid, writable, and unaliased for the call.
    unsafe fn borrow_mut<'a>(self) -> Option<&'a mut [u8]> {
        if self.tag != TAG_BYTES || self.data.is_null() || self.len == 0 {
            return None;
        }
        Some(std::slice::from_raw_parts_mut(
            self.data as *mut u8,
            self.len,
        ))
    }

    unsafe fn span<'a>(self) -> &'a [u8] {
        if self.data.is_null() || self.len == 0 {
            return &[];
        }
        std::slice::from_raw_parts(self.data, self.len)
    }
}

/// Ops the pure tier answers. Delegating and ambient ops arrive with the
/// job-queue adapter; they are not squeezed into this synchronous path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Op {
    ConsoleLog = 1,
    ConsoleInfo = 2,
    ConsoleDebug = 3,
    ConsoleWarn = 4,
    ConsoleError = 5,
    Btoa = 10,
    Atob = 11,
    TextEncode = 20,
    TextDecode = 21,
    TextEncodeInto = 22,
    UrlParse = 30,
    UrlSearchParamsGet = 31,
    HeadersNew = 40,
    HeadersAppend = 41,
    HeadersSet = 42,
    HeadersGet = 43,
    HeadersHas = 44,
    HeadersDelete = 45,
    HeadersCount = 46,
    HeadersNameAt = 47,
    HeadersValueAt = 48,
    HeadersValidName = 49,
    HeadersValidValue = 50,
    HeadersFree = 51,
    TimerSet = 60,
    TimerSetRepeating = 61,
    TimerClear = 62,
    PerformanceNow = 63,
}

impl Op {
    fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            1 => Op::ConsoleLog,
            2 => Op::ConsoleInfo,
            3 => Op::ConsoleDebug,
            4 => Op::ConsoleWarn,
            5 => Op::ConsoleError,
            10 => Op::Btoa,
            11 => Op::Atob,
            20 => Op::TextEncode,
            21 => Op::TextDecode,
            22 => Op::TextEncodeInto,
            30 => Op::UrlParse,
            31 => Op::UrlSearchParamsGet,
            40 => Op::HeadersNew,
            41 => Op::HeadersAppend,
            42 => Op::HeadersSet,
            43 => Op::HeadersGet,
            44 => Op::HeadersHas,
            45 => Op::HeadersDelete,
            46 => Op::HeadersCount,
            47 => Op::HeadersNameAt,
            48 => Op::HeadersValueAt,
            49 => Op::HeadersValidName,
            50 => Op::HeadersValidValue,
            51 => Op::HeadersFree,
            60 => Op::TimerSet,
            61 => Op::TimerSetRepeating,
            62 => Op::TimerClear,
            63 => Op::PerformanceNow,
            _ => return None,
        })
    }

    fn console_level(self) -> Option<console::Level> {
        Some(match self {
            Op::ConsoleLog => console::Level::Log,
            Op::ConsoleInfo => console::Level::Info,
            Op::ConsoleDebug => console::Level::Debug,
            Op::ConsoleWarn => console::Level::Warn,
            Op::ConsoleError => console::Level::Error,
            _ => return None,
        })
    }
}

thread_local! {
    /// The console queue for this runtime's thread.
    ///
    /// Thread-local rather than global: a runtime belongs to one thread, and a
    /// process-wide queue would interleave two runtimes' output. Note this is
    /// buffering, NOT authority — LLP 0060 D1 forbids ambient authority, and
    /// nothing capability-bearing may ever live here.
    static CONSOLE: std::cell::RefCell<console::Console> =
        std::cell::RefCell::new(console::Console::with_capacity(4096));
}

/// Drain this thread's console queue.
pub fn drain_console() -> Vec<console::Record> {
    CONSOLE.with(|c| c.borrow_mut().drain())
}

fn dispatch(
    op: Op,
    args: &[HostArg],
    state: Option<&crate::task::RuntimeState>,
) -> Result<HostValue, HostError> {
    if let Some(result) = crate::stdlib::headers_ops::dispatch(op as u32, args, state) {
        return result;
    }
    if let Some(level) = op.console_level() {
        CONSOLE.with(|c| c.borrow_mut().write(level, args));
        return Ok(HostValue::Undefined);
    }

    let first_str = |label: &str| -> Result<&str, HostError> {
        args.first()
            .and_then(HostArg::as_str)
            .ok_or_else(|| HostError::InvalidArgument(format!("{label} expects a string")))
    };

    if matches!(
        op,
        Op::TimerSet | Op::TimerSetRepeating | Op::TimerClear | Op::PerformanceNow
    ) {
        let state = state.ok_or_else(|| HostError::Failed("no runtime state".into()))?;
        let number = |index: usize| -> f64 {
            match args.get(index) {
                Some(HostArg::Number(n)) => *n,
                _ => 0.0,
            }
        };
        return Ok(match op {
            Op::PerformanceNow => HostValue::Number(state.now()),
            Op::TimerClear => {
                state.clear_timer(number(0) as u64);
                HostValue::Undefined
            }
            _ => HostValue::Number(state.set_timer(number(0), op == Op::TimerSetRepeating) as f64),
        });
    }

    match op {
        Op::Btoa => base64::btoa(first_str("btoa")?).map(HostValue::Str),
        Op::Atob => base64::atob(first_str("atob")?).map(HostValue::Str),
        Op::TextEncode => Ok(HostValue::Bytes(text::encode(first_str("encode")?))),
        Op::TextDecode => {
            let bytes = args
                .first()
                .and_then(HostArg::as_bytes)
                .ok_or_else(|| HostError::InvalidArgument("decode expects bytes".into()))?;
            let fatal = matches!(args.get(1), Some(HostArg::Bool(true)));
            let ignore_bom = matches!(args.get(2), Some(HostArg::Bool(true)));
            let on_invalid = if fatal {
                text::OnInvalid::Throw
            } else {
                text::OnInvalid::Replace
            };
            text::decode(bytes, on_invalid, ignore_bom).map(HostValue::Str)
        }
        Op::UrlParse => {
            let base = args.get(1).and_then(HostArg::as_str);
            // Returned as href for the spike; the object shape is the binding
            // layer's job, not the boundary's.
            url::parse(first_str("URL")?, base).map(|parsed| HostValue::Str(parsed.href))
        }
        Op::UrlSearchParamsGet => {
            let query = first_str("URLSearchParams")?;
            let name = args
                .get(1)
                .and_then(HostArg::as_str)
                .ok_or_else(|| HostError::InvalidArgument("get expects a name".into()))?;
            Ok(match url::SearchParams::parse(query).get(name) {
                Some(value) => HostValue::Str(value.to_string()),
                None => HostValue::Null,
            })
        }
        Op::TextEncodeInto => {
            unreachable!("handled in ibex2_host_call, which owns the mutable span")
        }
        _ => unreachable!("console ops returned above"),
    }
}

/// The single host-call entry point.
///
/// Returns 0 on success and 1 when the operation failed or was refused; `out`
/// receives the result or the error message either way. Any string or byte
/// buffer in `out` is Rust-owned and must be released with
/// `ibex2_host_release`.
///
/// # Safety
/// `argv` must point to `argc` initialized `AbiValue`s whose spans are valid
/// for this call, and `out` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn ibex2_host_call(
    state: *const crate::task::RuntimeState,
    op: u32,
    argv: *const AbiValue,
    argc: usize,
    out: *mut AbiValue,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    *out = AbiValue::undefined();

    let raw = if argv.is_null() || argc == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(argv, argc)
    };

    let mut args = Vec::with_capacity(raw.len());
    for value in raw {
        match value.borrow() {
            Ok(value) => args.push(value),
            Err(err) => return fail(out, &err.to_string()),
        }
    }

    let Some(op) = Op::from_u32(op) else {
        return fail(out, &format!("unknown host op {op}"));
    };

    // encodeInto is the one op that writes through to the caller's buffer, so
    // it takes the mutable span here rather than through the shared immutable
    // argument vector. Arg 0 is the source string, arg 1 the destination.
    if op == Op::TextEncodeInto {
        let Some(source) = args.first().and_then(HostArg::as_str) else {
            return fail(out, "encodeInto expects a string source");
        };
        let Some(destination) = raw.get(1).copied().and_then(|value| value.borrow_mut()) else {
            return fail(out, "encodeInto expects a writable destination buffer");
        };
        let (read, written) = crate::stdlib::text::encode_into(source, destination);
        // (read, written) packed as the spec's two fields; the binding layer
        // turns this into { read, written }.
        *out = leak_value(HostValue::Str(format!("{read},{written}")));
        return 0;
    }

    let state = crate::task::clone_queue(state);
    match dispatch(op, &args, state.as_deref()) {
        Ok(value) => {
            *out = leak_value(value);
            0
        }
        Err(err) => fail(out, &err.to_string()),
    }
}

fn fail(out: *mut AbiValue, message: &str) -> c_int {
    // SAFETY: callers check `out` for null before reaching here.
    unsafe { *out = leak_value(HostValue::Str(message.to_string())) };
    1
}

/// Move a value into a Rust allocation the shim borrows until it releases it.
fn leak_value(value: HostValue) -> AbiValue {
    match value {
        HostValue::Undefined => AbiValue::undefined(),
        HostValue::Null => AbiValue {
            tag: TAG_NULL,
            ..AbiValue::undefined()
        },
        HostValue::Bool(b) => AbiValue {
            tag: TAG_BOOL,
            number: if b { 1.0 } else { 0.0 },
            ..AbiValue::undefined()
        },
        HostValue::Number(n) => AbiValue {
            tag: TAG_NUMBER,
            number: n,
            ..AbiValue::undefined()
        },
        HostValue::Str(text) => {
            let boxed = text.into_bytes().into_boxed_slice();
            let len = boxed.len();
            AbiValue {
                tag: TAG_STRING,
                number: 0.0,
                data: Box::into_raw(boxed) as *const c_uchar,
                len,
            }
        }
        HostValue::Bytes(bytes) => {
            let boxed = bytes.into_boxed_slice();
            let len = boxed.len();
            AbiValue {
                tag: TAG_BYTES,
                number: 0.0,
                data: Box::into_raw(boxed) as *const c_uchar,
                len,
            }
        }
    }
}

/// Build a grant set from a spec and hand ownership to the caller.
///
/// This is how authority becomes *carried* (LLP 0060 D1): the caller binds the
/// result to a binding at install time, and the binding passes it back on every
/// call. There is no way to ask for "the current grants" — no ambient lookup
/// exists, by construction.
///
/// # Safety
/// `spec` must be a NUL-terminated UTF-8 string. Release with
/// `ibex2_grants_destroy`.
#[no_mangle]
pub unsafe extern "C" fn ibex2_grants_create(spec: *const c_char) -> *const GrantSet {
    let spec = if spec.is_null() {
        ""
    } else {
        match std::ffi::CStr::from_ptr(spec).to_str() {
            Ok(text) => text,
            Err(_) => return std::ptr::null(),
        }
    };
    match GrantSet::parse(spec) {
        Ok(set) => std::sync::Arc::into_raw(std::sync::Arc::new(set)),
        Err(_) => std::ptr::null(),
    }
}

/// # Safety
/// `grants` must come from `ibex2_grants_create`.
#[no_mangle]
pub unsafe extern "C" fn ibex2_grants_destroy(grants: *const GrantSet) {
    if !grants.is_null() {
        drop(std::sync::Arc::from_raw(grants));
    }
}

unsafe fn clone_grants(grants: *const GrantSet) -> Option<std::sync::Arc<GrantSet>> {
    if grants.is_null() {
        return None;
    }
    std::sync::Arc::increment_strong_count(grants);
    Some(std::sync::Arc::from_raw(grants))
}

/// Read a field from a stored response.
///
/// A `Response` crosses as a **handle**, not a value: §1.1 forbids serializing
/// at the boundary, and a response is a status plus headers plus a body. These
/// are the accessors the binding layer turns back into a `Response` object.
///
/// # Safety
/// `state` must be live; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn ibex2_response_field(
    state: *const crate::task::RuntimeState,
    handle: f64,
    field: u32,
    name: *const AbiValue,
    out: *mut AbiValue,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    *out = AbiValue::undefined();
    let Some(state) = crate::task::clone_queue(state) else {
        return fail(out, "no runtime state");
    };
    let handle = handle as u64;

    // Field 4 consumes the response, moving the body out rather than copying.
    if field == 4 {
        return match state.take_response(handle) {
            Some(response) => {
                *out = leak_value(HostValue::Bytes(response.body));
                0
            }
            None => fail(out, "TypeError: body already consumed or unknown response"),
        };
    }

    let result = state.with_response(handle, |response| match field {
        0 => Ok(HostValue::Number(f64::from(response.status))),
        1 => Ok(HostValue::Bool(response.ok())),
        2 => Ok(HostValue::Str(response.url.clone())),
        3 => {
            let wanted = match name.as_ref().and_then(|v| v.borrow().ok()) {
                Some(HostArg::Str(text)) => text.to_string(),
                _ => return Err(HostError::InvalidArgument("header name expected".into())),
            };
            Ok(match response.headers.get(&wanted) {
                Some(value) => HostValue::Str(value.to_string()),
                None => HostValue::Null,
            })
        }
        5 => Ok(HostValue::Bool(response.redirected)),
        other => Err(HostError::InvalidArgument(format!(
            "unknown response field {other}"
        ))),
    });

    match result {
        Some(Ok(value)) => {
            *out = leak_value(value);
            0
        }
        Some(Err(err)) => fail(out, &err.to_string()),
        None => fail(out, "TypeError: unknown response handle"),
    }
}

/// Start a delegating op on another thread.
///
/// Returns immediately. The op is **not** run on the JavaScript thread — that
/// is the entire point of the delegating shape (LLP 0059.000 §1.1) — and it
/// touches no engine state, because nothing in `crate::task` may hold a `jsi`
/// value.
///
/// # Safety
/// `argv` must point to `argc` initialized `AbiValue`s valid for this call.
/// Arguments are copied here, deliberately: they must outlive the call that
/// started the work, so the borrowed-span rule that governs synchronous ops
/// cannot apply.
#[no_mangle]
pub unsafe extern "C" fn ibex2_async_begin(
    state: *const crate::task::RuntimeState,
    grants: *const GrantSet,
    op: u32,
    argv: *const AbiValue,
    argc: usize,
    task_id: u64,
) -> c_int {
    let Some(state) = crate::task::clone_queue(state) else {
        return 1;
    };
    let raw = if argv.is_null() || argc == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(argv, argc)
    };

    // Owned snapshot: the worker outlives this call, so it cannot borrow.
    let mut owned = Vec::with_capacity(raw.len());
    for value in raw {
        match value.borrow() {
            Ok(HostArg::Str(text)) => owned.push(HostValue::Str(text.to_string())),
            Ok(HostArg::Bytes(bytes)) => owned.push(HostValue::Bytes(bytes.to_vec())),
            Ok(HostArg::Number(n)) => owned.push(HostValue::Number(n)),
            Ok(HostArg::Bool(b)) => owned.push(HostValue::Bool(b)),
            Ok(HostArg::Null) => owned.push(HostValue::Null),
            Ok(HostArg::Undefined) => owned.push(HostValue::Undefined),
            Err(_) => return 1,
        }
    }

    let Some(op) = AsyncOp::from_u32(op) else {
        return 1;
    };

    // The binding's own grants, captured at install time and handed back on
    // every call. Nothing here consults ambient state.
    let grants = clone_grants(grants).unwrap_or_else(|| std::sync::Arc::new(GrantSet::none()));

    // Counted before the thread starts, so the loop cannot see an idle moment
    // between "started" and "running".
    state.task_started();
    std::thread::spawn(move || {
        let result = run_async(op, &owned, &state, &grants);
        state.queue.complete(task_id, result);
        state.task_finished();
    });
    0
}

/// The delegating ops. `fetch` joins this list once the adapter is proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum AsyncOp {
    /// Echo the first argument back after leaving the thread. Exists so the
    /// ordering contract can be tested without a network in the way.
    Echo = 100,
    /// `fetch`. Resolves with a response handle, never with a serialized body.
    Fetch = 101,
    /// `fs`, one op per method. Delegating and capability-bearing, so it leaves
    /// the JavaScript thread like fetch does — LLP 0059.000 §3.11 has no
    /// synchronous variants on purpose.
    FsReadFile = 110,
    FsWriteFile = 111,
    FsAppendFile = 112,
    FsReadDir = 113,
    FsMkdir = 114,
    FsRemove = 115,
    FsStat = 116,
    FsRename = 117,
    FsCopyFile = 118,
    FsRealpath = 119,
}

impl AsyncOp {
    fn from_u32(value: u32) -> Option<Self> {
        match value {
            100 => Some(AsyncOp::Echo),
            101 => Some(AsyncOp::Fetch),
            110 => Some(AsyncOp::FsReadFile),
            111 => Some(AsyncOp::FsWriteFile),
            112 => Some(AsyncOp::FsAppendFile),
            113 => Some(AsyncOp::FsReadDir),
            114 => Some(AsyncOp::FsMkdir),
            115 => Some(AsyncOp::FsRemove),
            116 => Some(AsyncOp::FsStat),
            117 => Some(AsyncOp::FsRename),
            118 => Some(AsyncOp::FsCopyFile),
            119 => Some(AsyncOp::FsRealpath),
            _ => None,
        }
    }
}

fn run_async(
    op: AsyncOp,
    args: &[HostValue],
    state: &crate::task::RuntimeState,
    grants: &GrantSet,
) -> Result<HostValue, HostError> {
    if let Some(fs_op) = fs_op_for(op) {
        return run_fs(fs_op, args, grants);
    }
    match op {
        AsyncOp::Fetch => {
            use crate::stdlib::fetch::{RedirectMode, Request};
            let url = match args.first() {
                Some(HostValue::Str(url)) => url.clone(),
                _ => return Err(HostError::InvalidArgument("fetch expects a URL".into())),
            };
            let mut request = Request::get(&url);
            if let Some(HostValue::Str(method)) = args.get(1) {
                if !method.is_empty() {
                    request.method = method.to_ascii_uppercase();
                }
            }
            if let Some(HostValue::Bytes(body)) = args.get(2) {
                request.body = Some(body.clone());
            }
            if let Some(HostValue::Str(mode)) = args.get(3) {
                request.redirect = match mode.as_str() {
                    "manual" => RedirectMode::Manual,
                    "error" => RedirectMode::Error,
                    _ => RedirectMode::Follow,
                };
            }
            let response = crate::stdlib::fetch::fetch(state.transport(), grants, request)?;
            // The handle, not the response. §1.1.
            Ok(HostValue::Number(state.store_response(response) as f64))
        }
        AsyncOp::Echo => {
            let text = match args.first() {
                Some(HostValue::Str(text)) => text.clone(),
                _ => return Err(HostError::InvalidArgument("echo expects a string".into())),
            };
            // A deliberate marker: an argument of "fail" rejects, so the
            // rejection path is exercised by the same op.
            if text == "fail" {
                return Err(HostError::Failed("echo was asked to fail".into()));
            }
            Ok(HostValue::Str(text))
        }
        _ => unreachable!("fs ops returned above, via fs_op_for"),
    }
}

/// Resolve a module and produce its executable form.
///
/// Returns 0 on success, writing the resolved specifier into `out_resolved` and
/// the module's bytes into `out_source` — Hermes bytecode when a compiler is
/// configured, wrapped source otherwise. 1 on failure with the message in
/// `out_resolved`. Both are Rust-owned and released with `ibex2_host_release`.
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn ibex2_loader_load(
    state: *const crate::task::RuntimeState,
    from: *const c_char,
    specifier: *const c_char,
    out_resolved: *mut AbiValue,
    out_source: *mut AbiValue,
) -> c_int {
    if out_resolved.is_null() || out_source.is_null() {
        return 1;
    }
    *out_resolved = AbiValue::undefined();
    *out_source = AbiValue::undefined();

    let Some(state) = crate::task::clone_queue(state) else {
        return fail(out_resolved, "no runtime state");
    };
    let read = |raw: *const c_char| -> String {
        if raw.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned()
        }
    };

    match state.load_module(&read(from), &read(specifier)) {
        Ok((resolved, bytes)) => {
            *out_resolved = leak_value(HostValue::Str(resolved));
            *out_source = leak_value(HostValue::Bytes(bytes));
            0
        }
        Err(message) => fail(out_resolved, &message),
    }
}

/// The grant set for one module, as an owned pointer.
///
/// # Safety
/// The result must be released with `ibex2_grants_destroy`.
#[no_mangle]
pub unsafe extern "C" fn ibex2_loader_grants_for(
    state: *const crate::task::RuntimeState,
    specifier: *const c_char,
) -> *const GrantSet {
    let Some(state) = crate::task::clone_queue(state) else {
        return std::ptr::null();
    };
    let specifier = if specifier.is_null() {
        String::new()
    } else {
        std::ffi::CStr::from_ptr(specifier)
            .to_string_lossy()
            .into_owned()
    };
    std::sync::Arc::into_raw(state.grants_for(&specifier))
}

/// Milliseconds until the next timer, or -1 when none is scheduled.
///
/// # Safety
/// `state` must be a live runtime state.
#[no_mangle]
pub unsafe extern "C" fn ibex2_millis_until_next_timer(
    state: *const crate::task::RuntimeState,
) -> f64 {
    let Some(state) = crate::task::clone_queue(state) else {
        return -1.0;
    };
    state.millis_until_next_timer().unwrap_or(-1.0)
}

/// Block until a completion is ready or `timeout_ms` elapses.
///
/// # Safety
/// `state` must be a live runtime state.
#[no_mangle]
pub unsafe extern "C" fn ibex2_wait_for_completion(
    state: *const crate::task::RuntimeState,
    timeout_ms: u64,
) -> c_int {
    let Some(state) = crate::task::clone_queue(state) else {
        return 0;
    };
    i32::from(
        state
            .queue
            .wait(std::time::Duration::from_millis(timeout_ms)),
    )
}

fn fs_op_for(op: AsyncOp) -> Option<crate::stdlib::fs::FsOp> {
    use crate::stdlib::fs::FsOp;
    Some(match op {
        AsyncOp::FsReadFile => FsOp::ReadFile,
        AsyncOp::FsWriteFile => FsOp::WriteFile,
        AsyncOp::FsAppendFile => FsOp::AppendFile,
        AsyncOp::FsReadDir => FsOp::ReadDir,
        AsyncOp::FsMkdir => FsOp::Mkdir,
        AsyncOp::FsRemove => FsOp::Remove,
        AsyncOp::FsStat => FsOp::Stat,
        AsyncOp::FsRename => FsOp::Rename,
        AsyncOp::FsCopyFile => FsOp::CopyFile,
        AsyncOp::FsRealpath => FsOp::Realpath,
        _ => return None,
    })
}

/// Normalize, admit, then act — in that order, always.
///
/// Normalizing after the check would let `/data/../etc/passwd` pass a `/data`
/// grant, which is the whole reason the order is stated rather than implied.
fn run_fs(
    op: crate::stdlib::fs::FsOp,
    args: &[HostValue],
    grants: &GrantSet,
) -> Result<HostValue, HostError> {
    use crate::stdlib::fs::{admit, normalize, perform, FsResult};

    let path_arg = |index: usize| -> Result<&str, HostError> {
        match args.get(index) {
            Some(HostValue::Str(text)) => Ok(text),
            _ => Err(HostError::InvalidArgument("fs expects a path".into())),
        }
    };

    let path = normalize(path_arg(0)?)?;
    let destination = if op.takes_second_path() {
        Some(normalize(path_arg(1)?)?)
    } else {
        None
    };
    admit(grants, op, &path, destination.as_deref())?;

    // Data is the second argument for single-path writes.
    let data = match args.get(1) {
        Some(HostValue::Bytes(bytes)) => Some(bytes.as_slice()),
        _ => None,
    };

    Ok(match perform(op, &path, destination.as_deref(), data)? {
        FsResult::Done => HostValue::Undefined,
        FsResult::Bytes(bytes) => HostValue::Bytes(bytes),
        FsResult::Text(text) => HostValue::Str(text),
        // A directory listing and a stat are small records. They cross as text
        // the binding splits, rather than as a serialized object: §1.1 forbids
        // JSON at the boundary, and a newline-joined list is not a document
        // format that could grow into one.
        FsResult::Names(names) => HostValue::Str(names.join("\n")),
        FsResult::Stat(stat) => HostValue::Str(format!(
            "{}\t{}\t{}\t{}",
            stat.size,
            u8::from(stat.is_file),
            u8::from(stat.is_directory),
            stat.modified_ms
        )),
    })
}

/// Take at most ONE admitted host task for the engine to run.
///
/// LLP 0058.000.000 §8: one task per drive cycle, from one FIFO carrying both
/// timer deliveries and settlements. `kind` is 0 for none, 1 for a settlement,
/// 2 for a timer; a timer's handle arrives in `task_id`.
///
/// # Safety
/// All out pointers must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn ibex2_take_task(
    state: *const crate::task::RuntimeState,
    kind: *mut c_int,
    task_id: *mut u64,
    out: *mut AbiValue,
    is_error: *mut c_int,
) -> c_int {
    if kind.is_null() || task_id.is_null() || out.is_null() || is_error.is_null() {
        return 0;
    }
    *kind = 0;
    let Some(state) = crate::task::clone_queue(state) else {
        return 0;
    };
    let Some(task) = state.queue.take() else {
        return 0;
    };
    match task {
        crate::task::HostTask::Timer { handle } => {
            *kind = 2;
            *task_id = handle;
            1
        }
        crate::task::HostTask::Settlement(completion) => {
            *kind = 1;
            *task_id = completion.task_id;
            match completion.result {
                Ok(value) => {
                    *is_error = 0;
                    *out = leak_value(value);
                }
                Err(err) => {
                    *is_error = 1;
                    *out = leak_value(HostValue::Str(err.to_string()));
                }
            }
            1
        }
    }
}

/// Move every timer due now into the host-task FIFO, and report how many.
///
/// # Safety
/// `state` must be a live runtime state.
#[no_mangle]
pub unsafe extern "C" fn ibex2_admit_due_timers(state: *const crate::task::RuntimeState) -> c_int {
    let Some(state) = crate::task::clone_queue(state) else {
        return 0;
    };
    state.admit_due_timers() as c_int
}

/// Claim the driver, so a nested drive records a wakeup instead of starting a
/// second host task inside project JavaScript.
///
/// # Safety
/// `state` must be a live runtime state.
#[no_mangle]
pub unsafe extern "C" fn ibex2_begin_drive(state: *const crate::task::RuntimeState) -> c_int {
    match crate::task::clone_queue(state) {
        Some(state) => c_int::from(state.begin_drive()),
        None => 0,
    }
}

/// # Safety
/// `state` must be a live runtime state.
#[no_mangle]
pub unsafe extern "C" fn ibex2_end_drive(state: *const crate::task::RuntimeState) {
    if let Some(state) = crate::task::clone_queue(state) {
        state.end_drive();
    }
}

/// Release a value produced by `ibex2_host_call`.
///
/// # Safety
/// `value` must be a value this module produced and not yet released.
#[no_mangle]
pub unsafe extern "C" fn ibex2_host_release(value: *mut AbiValue) {
    if value.is_null() {
        return;
    }
    let owned = &mut *value;
    if !owned.data.is_null() && owned.len > 0 {
        // slice_from_raw_parts_mut builds the fat pointer directly; going
        // through slice::from_raw_parts_mut would create a reference to memory
        // we are about to free.
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            owned.data as *mut u8,
            owned.len,
        )));
    }
    *owned = AbiValue::undefined();
}

/// Drain the console into a newline-joined `level:message` block.
///
/// A convenience for the spike's tests; the embedder drains structurally.
///
/// # Safety
/// The returned pointer must be freed with `ibex2_host_free_string`.
#[no_mangle]
pub unsafe extern "C" fn ibex2_console_drain() -> *mut c_char {
    let text = drain_console()
        .into_iter()
        .map(|record| format!("{}:{}", record.level.as_str(), record.message))
        .collect::<Vec<_>>()
        .join("\n");
    match std::ffi::CString::new(text) {
        Ok(text) => text.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `value` must come from `ibex2_console_drain`.
#[no_mangle]
pub unsafe extern "C" fn ibex2_host_free_string(value: *mut c_char) {
    if !value.is_null() {
        drop(std::ffi::CString::from_raw(value));
    }
}
