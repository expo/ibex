//! End-to-end proof that the Ibex bindings door runs on Hermes's lean VM.

/// Keep this crate's C++ bridge in the integration-test link graph.
#[inline(never)]
pub fn ensure_linked() {}
