//! Link metadata for the repository's pinned, unmodified Hermes engine.
//!
//! Resolution prefers a caller-supplied install, then this repository's local
//! development layout, then a SHA-256-pinned release bundle in the per-user
//! Cargo cache.

// @ref LLP 0057.000#l1--the-bindings-door — R-e requires one linked archive
// identity per process; Cargo feature unification must not select both VMs.
#[cfg(all(feature = "link", feature = "link-lean"))]
compile_error!(
    "hermes-lean-sys features `link` and `link-lean` are mutually exclusive; select exactly one VM archive"
);

/// Full VM archive selected for this target. The owning Ibex runtime needs
/// its source entrance; the `link` feature controls only link-line emission.
pub const ARCHIVE: &str = env!("HERMES_LEAN_ARCHIVE");

/// Digest of [`ARCHIVE`], independent of the `link` feature.
pub const ENGINE_DIGEST: &str = env!("HERMES_LEAN_ENGINE_DIGEST");

/// Expected lean VM archive path for this target. Older local layouts may not
/// contain it; [`LEAN_ENGINE_DIGEST`] is `None` in that case unless
/// `link-lean` is requested, which fails resolution clearly.
pub const LEAN_ARCHIVE: &str = env!("HERMES_LEAN_LEAN_ARCHIVE");

/// Digest of [`LEAN_ARCHIVE`] when that archive is available and authenticated.
pub const LEAN_ENGINE_DIGEST: Option<&str> = option_env!("HERMES_LEAN_LEAN_ENGINE_DIGEST");

/// HBC version reported by the matching `hermesc`.
pub const BYTECODE_VERSION: &str = env!("HERMES_LEAN_BYTECODE_VERSION");

/// HBC version consumed by the lean VM from the same source commit.
pub const LEAN_BYTECODE_VERSION: &str = env!("HERMES_LEAN_LEAN_BYTECODE_VERSION");

/// Archive actually selected by `link` or `link-lean`, if either is enabled.
pub const LINKED_ARCHIVE: Option<&str> = option_env!("HERMES_LEAN_LINKED_ARCHIVE");

/// Digest of [`LINKED_ARCHIVE`], naming the archive this feature context links.
pub const LINKED_ENGINE_DIGEST: Option<&str> = option_env!("HERMES_LEAN_LINKED_ENGINE_DIGEST");

/// Keep this native-link dependency in binaries that call into Hermes through
/// a sibling C++ shim rather than through Rust FFI declared in this crate.
#[inline(never)]
pub fn ensure_linked() {}
