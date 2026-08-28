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

use crate::boundary::{HostError, HostValue};
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

    /// # Safety
    /// `data`/`len` must describe a span valid for the duration of the call.
    unsafe fn to_host_value(self) -> Result<HostValue, HostError> {
        Ok(match self.tag {
            TAG_UNDEFINED => HostValue::Undefined,
            TAG_NULL => HostValue::Null,
            TAG_BOOL => HostValue::Bool(self.number != 0.0),
            TAG_NUMBER => HostValue::Number(self.number),
            TAG_STRING => {
                let bytes = self.span();
                HostValue::Str(String::from_utf8_lossy(bytes).into_owned())
            }
            TAG_BYTES => HostValue::Bytes(self.span().to_vec()),
            other => {
                return Err(HostError::InvalidArgument(format!(
                    "unknown value tag {other}"
                )))
            }
        })
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
    UrlParse = 30,
    UrlSearchParamsGet = 31,
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
            30 => Op::UrlParse,
            31 => Op::UrlSearchParamsGet,
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

fn dispatch(op: Op, args: &[HostValue]) -> Result<HostValue, HostError> {
    if let Some(level) = op.console_level() {
        CONSOLE.with(|c| c.borrow_mut().write(level, args));
        return Ok(HostValue::Undefined);
    }

    let first_str = |label: &str| -> Result<&str, HostError> {
        args.first()
            .and_then(HostValue::as_str)
            .ok_or_else(|| HostError::InvalidArgument(format!("{label} expects a string")))
    };

    match op {
        Op::Btoa => base64::btoa(first_str("btoa")?).map(HostValue::Str),
        Op::Atob => base64::atob(first_str("atob")?).map(HostValue::Str),
        Op::TextEncode => Ok(HostValue::Bytes(text::encode(first_str("encode")?))),
        Op::TextDecode => {
            let bytes = args
                .first()
                .and_then(HostValue::as_bytes)
                .ok_or_else(|| HostError::InvalidArgument("decode expects bytes".into()))?;
            let fatal = matches!(args.get(1), Some(HostValue::Bool(true)));
            let ignore_bom = matches!(args.get(2), Some(HostValue::Bool(true)));
            let on_invalid = if fatal {
                text::OnInvalid::Throw
            } else {
                text::OnInvalid::Replace
            };
            text::decode(bytes, on_invalid, ignore_bom).map(HostValue::Str)
        }
        Op::UrlParse => {
            let base = args.get(1).and_then(HostValue::as_str);
            // Returned as href for the spike; the object shape is the binding
            // layer's job, not the boundary's.
            url::parse(first_str("URL")?, base).map(|parsed| HostValue::Str(parsed.href))
        }
        Op::UrlSearchParamsGet => {
            let query = first_str("URLSearchParams")?;
            let name = args
                .get(1)
                .and_then(HostValue::as_str)
                .ok_or_else(|| HostError::InvalidArgument("get expects a name".into()))?;
            Ok(match url::SearchParams::parse(query).get(name) {
                Some(value) => HostValue::Str(value.to_string()),
                None => HostValue::Null,
            })
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
        match value.to_host_value() {
            Ok(value) => args.push(value),
            Err(err) => return fail(out, &err.to_string()),
        }
    }

    let Some(op) = Op::from_u32(op) else {
        return fail(out, &format!("unknown host op {op}"));
    };

    match dispatch(op, &args) {
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
