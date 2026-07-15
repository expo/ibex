//! Generated REPL command, `.load`, and keybinding authority.
//!
//! The canonical rows live in `runtime-surface.json`; this module deliberately
//! contains no handwritten command, alias, load-extension, or control-byte
//! table.
//!
//! @ref LLP 0010#surface-manifest — the CLI manifest owns the REPL surface.
//! @ref LLP 0022#8-commands — dispatch, help, and completion share one table.

#[path = "../vendored-generated/repl_surface.generated.rs"]
mod generated;

pub use generated::*;
