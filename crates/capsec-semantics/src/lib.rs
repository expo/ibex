//! Product-neutral CapSec policy and effect semantics.
//!
//! The crate accepts only typed, normalized actions and resources. Product
//! vocabularies, registry rows, and runtime adapters stay outside this crate.
//! @ref LLP 0021#ownership-and-profile-identity — neutral semantics boundary

pub mod arming;
pub mod cache;
pub mod canonical;
pub mod compiled_mount;
pub mod containment;
pub mod decision;
pub mod digest;
pub mod error;
pub mod graph_snapshot;
pub mod model;
pub mod policy;
pub mod registry;
pub mod retained;
pub mod strict_json;

pub use error::{Error, Result};
