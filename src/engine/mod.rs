//! Engine support utilities
//!
//! The C++ Hermes adapter (`hermes_runtime.cc`) is compiled by build.rs and
//! linked into this crate. It exposes C functions (`ex_hermes_create`,
//! `ex_hermes_eval`, `ex_hermes_poll`, etc.) that can be called from both
//! Rust (via the CLI's hermes.rs wrapper) and Swift (via the bridging header).
//!
//! This module provides supporting utilities like source map handling.

pub mod sourcemap;

use std::sync::atomic::{AtomicBool, Ordering};

/// Flag set when a background callback is pushed.
/// iOS polls this to know when to wake up the event loop.
static CALLBACK_PENDING: AtomicBool = AtomicBool::new(false);

/// Default implementation of ex_hermes_notify_callback for iOS/standalone use.
/// This is called from C++ (hermes_runtime.cc) when async callbacks are pushed
/// from background threads.
///
/// The CLI provides its own implementation in hermes.rs that uses
/// tokio::sync::Notify for more efficient wakeup. When building the CLI,
/// set EXACT_CLI_NOTIFY=1 to skip this default implementation.
#[cfg(not(feature = "cli-notify"))]
#[no_mangle]
pub extern "C" fn ex_hermes_notify_callback() {
    CALLBACK_PENDING.store(true, Ordering::Release);
}

/// Check and clear the callback pending flag.
/// Called from the event loop polling code.
pub fn take_callback_pending() -> bool {
    CALLBACK_PENDING.swap(false, Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use std::os::raw::c_char;

    #[repr(C)]
    struct HermesRuntimeOpaque {
        _private: [u8; 0],
    }

    extern "C" {
        fn ex_hermes_create() -> *mut HermesRuntimeOpaque;
        fn ex_hermes_destroy(runtime: *mut HermesRuntimeOpaque);
        fn ex_hermes_eval(
            runtime: *mut HermesRuntimeOpaque,
            data: *const u8,
            len: usize,
            source_url: *const c_char,
            is_bytecode: i32,
            out_value: *mut *mut c_char,
        ) -> i32;
        fn ex_hermes_free_string(value: *mut c_char);
        fn ex_hermes_poll(runtime: *mut HermesRuntimeOpaque, now_ms: u64) -> i32;
    }

    fn eval(runtime: *mut HermesRuntimeOpaque, source: &str) -> (i32, Option<String>) {
        let url = std::ffi::CString::new("r1-test.js").expect("source url");
        let mut out: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_eval(
                runtime,
                source.as_ptr(),
                source.len(),
                url.as_ptr(),
                0,
                &mut out,
            )
        };
        let value = if out.is_null() {
            None
        } else {
            let text = unsafe { std::ffi::CStr::from_ptr(out) }
                .to_string_lossy()
                .into_owned();
            unsafe { ex_hermes_free_string(out) };
            Some(text)
        };
        (status, value)
    }

    /// A one-shot timer whose callback throws must be retired before the
    /// error propagates out of `ex_hermes_poll`; before the fix it stayed
    /// due and refired on every subsequent poll. @ref LLP 0159 R1
    #[test]
    fn throwing_one_shot_timer_does_not_refire() {
        unsafe {
            let runtime = ex_hermes_create();
            assert!(!runtime.is_null());

            let (status, value) = eval(
                runtime,
                "globalThis.__r1Count = 0;\n\
                 setTimeout(function () { globalThis.__r1Count++; throw new Error('boom'); }, 0);\n\
                 'armed';",
            );
            assert_eq!(status, 0, "arming eval failed: {value:?}");

            // Timer due_ms is monotonic-ms since process start; a huge `now`
            // guarantees the timer is due on the first poll.
            let now = u64::MAX / 2;
            let first = ex_hermes_poll(runtime, now);
            assert_eq!(first, -1, "throwing timer should surface a poll error");

            let second = ex_hermes_poll(runtime, now + 1_000);
            assert_eq!(second, 0, "retired one-shot timer must not refire");
            let third = ex_hermes_poll(runtime, now + 2_000);
            assert_eq!(third, 0, "retired one-shot timer must not refire");

            let (status, value) = eval(runtime, "String(globalThis.__r1Count)");
            assert_eq!(status, 0);
            assert_eq!(value.as_deref(), Some("1"));

            ex_hermes_destroy(runtime);
        }
    }
}
