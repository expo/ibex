//! The owning Ibex 2 runtime: vanilla Hermes, loading, and the application loop.
//!
//! The engine-independent standard library and installable JSI projection live
//! in `ibex2`; this crate is one caller of that bindings door.

extern crate self as ibex2_runtime;

pub mod bytecode;
pub mod engine;
#[cfg(feature = "loader")]
pub mod esm;
pub mod loader;
pub mod receipt;
#[cfg(feature = "loader")]
pub mod typescript;

mod loader_state;

pub use ibex2::{bindings, boundary, boundary_abi, grant, host, pool, stdlib, task, transport};

/// Identity of the VM linked through `hermes-lean-sys`.
pub const LINKED_ENGINE_DIGEST: &str = env!("IBEX2_LINKED_ENGINE_DIGEST");

/// Archive whose link lines `hermes-lean-sys` emitted for this runtime.
pub const LINKED_ENGINE_ARCHIVE: &str = env!("IBEX2_LINKED_ENGINE_ARCHIVE");

/// Linux ICU data archive linked beside [`LINKED_ENGINE_ARCHIVE`]. This is
/// base by default, English under `intl`, and full under `intl-all-locales`.
pub const LINKED_ICU_DATA_ARCHIVE: Option<&str> = option_env!("IBEX2_LINKED_ICU_DATA_ARCHIVE");

/// Digest of [`LINKED_ICU_DATA_ARCHIVE`], the data-variant half of the linked
/// engine identity on Linux.
pub const LINKED_ICU_DATA_DIGEST: Option<&str> = option_env!("IBEX2_LINKED_ICU_DATA_DIGEST");

/// HBC format shared by the selected target engine and supplying compiler.
pub const LINKED_BYTECODE_VERSION: &str = env!("IBEX2_LINKED_BYTECODE_VERSION");

/// Compiler selected by the same `hermes-lean-sys` resolution as the VM.
pub const HERMESC_PATH: &str = env!("IBEX2_HERMESC_PATH");

/// Engine install selected by `hermes-lean-sys` for this runtime.
pub const ENGINE_DIR: &str = env!("IBEX2_ENGINE_DIR");

/// Cargo target whose engine receipt must match this runtime.
pub const TARGET_TRIPLE: &str = env!("IBEX2_TARGET_TRIPLE");

/// Retain this crate's native shim for embedders whose Rust code calls only
/// C entry points from the linked test/host adapter.
#[doc(hidden)]
#[inline(never)]
pub fn ensure_linked() {
    hermes_lean_sys::ensure_linked();
}
