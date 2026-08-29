//! Ibex 2 — a Rust standard library with JavaScript bindings.
//!
//! This crate is the staging ground for the inversion described in LLP 0057:
//! capabilities implemented in Rust, reached through one host-call boundary,
//! with the JavaScript engine demoted from foundation to component.
//!
//! It is a strangler, not a fork. The end state is that this crate replaces
//! the root `ibex-runtime` crate — not that the two coexist indefinitely.
//!
//! What is here today is the part that needs no engine: the authority model.
//! Everything that touches Hermes arrives with the spike.
//!
//! @ref LLP 0057#2-the-inversion — the three-category split this crate implements
//! @ref LLP 0067#1-five-properties — authority is carried, not inferred

pub mod boundary;
pub mod boundary_abi;
pub mod bytecode;
pub mod engine;
pub mod esm;
pub mod grant;
pub mod loader;
pub mod receipt;
pub mod stdlib;
pub mod task;
pub mod transport;
pub mod typescript;
