//! The Ibex 2 standard library: Rust implementations with JavaScript bindings.
//!
//! Only the **pure** shape lives here so far — computed entirely in Rust, no
//! platform call, no capability (LLP 0059.000 Summary). The delegating and
//! ambient shapes wait on the job-queue adapter (LLP 0058 OQ1).

pub mod base64;
pub mod console;
pub mod fetch;
pub mod headers_ops;
pub mod text;
pub mod timers;
pub mod url;
