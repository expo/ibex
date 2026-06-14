//! Ibex shared runtime
//!
//! This crate contains the shared runtime components used by both the `ibex`
//! binary and embedding apps. It provides:
//!
//! - **Module Loader**: Node.js-compatible `require()` with 30+ builtin modules
//! - **Host ABI**: C-level functions for filesystem, SQLite, crypto, etc.
//! - **Hermes C++ adapter**: The `hermes_runtime.cc` compiled into this library
//!   provides `ex_hermes_create()`, `ex_hermes_eval()`, `ex_hermes_poll()`, etc.
//!
//! The `ibex` binary wraps these in async Rust (via tokio). The iOS app calls the C API
//! directly from Swift via the bridging header.

#[cfg(feature = "host-http-server")]
pub mod cdp;
pub mod engine;
pub mod host;
pub mod identity_generated;
pub mod module_loader;
#[cfg(feature = "host-http-server")]
mod sync;

use anyhow::Result;
use std::path::PathBuf;

/// Determine runtime cache directory.
/// - macOS: ~/Library/Caches/Exact
/// - iOS: app's Caches directory
/// - Linux/Android: platform cache directory, falling back to ~/.cache/exact
pub fn runtime_cache_dir() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join("Library").join("Caches").join("Exact"));
        }
    }

    #[cfg(target_os = "ios")]
    {
        // On iOS, use the app's Caches directory
        if let Some(dir) = dirs::cache_dir() {
            return Ok(dir.join("Exact"));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        #[cfg(target_os = "android")]
        if let Ok(dir) = std::env::var("EXACT_ANDROID_CACHE_DIR") {
            if !dir.is_empty() {
                return Ok(PathBuf::from(dir).join("exact"));
            }
        }
        if let Some(dir) = dirs::cache_dir() {
            return Ok(dir.join("exact"));
        }
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join(".cache").join("exact"));
        }
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    )))]
    {
        if let Some(dir) = dirs::cache_dir() {
            return Ok(dir.join("exact"));
        }
    }

    anyhow::bail!("Failed to determine cache directory")
}
