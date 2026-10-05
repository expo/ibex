//! Link metadata for the repository's pinned, unmodified Hermes engine.
//!
//! Resolution prefers a caller-supplied install, then this repository's local
//! development layout, then a SHA-256-pinned release bundle in the per-user
//! Cargo cache.

/// Full VM archive selected for this target. The owning Ibex runtime needs
/// its source entrance; the `link` feature controls only link-line emission.
pub const ARCHIVE: &str = env!("HERMES_LEAN_ARCHIVE");

/// Digest of [`ARCHIVE`], independent of the `link` feature.
pub const ENGINE_DIGEST: &str = env!("HERMES_LEAN_ENGINE_DIGEST");

/// HBC version reported by the matching `hermesc`.
pub const BYTECODE_VERSION: &str = env!("HERMES_LEAN_BYTECODE_VERSION");

/// Keep this native-link dependency in binaries that call into Hermes through
/// a sibling C++ shim rather than through Rust FFI declared in this crate.
#[inline(never)]
pub fn ensure_linked() {}
