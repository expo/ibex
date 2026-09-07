//! The Ibex 2 standard library: Rust implementations with JavaScript bindings.
//!
//! Algorithms and host operations shared by Rust callers and the bindings.
//! Platform transport and entropy stay below the Rust semantics; capabilities
//! are admitted at the boundary (LLP 0059.000).

pub mod base64;
pub mod console;
pub mod crypto;
pub mod fetch;
pub mod fs;
pub mod headers_ops;
pub mod text;
pub mod timers;
pub mod url;

pub mod abort;
mod fetch_body;
