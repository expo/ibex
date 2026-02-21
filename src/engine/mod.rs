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
