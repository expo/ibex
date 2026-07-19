//! Generated engine-independent session limits.
//!
//! The canonical values live in `session/session-constants.v1.json`; runtime
//! code imports this projection instead of restating security-relevant bounds.
//! @ref LLP 0025#12-constants

#[path = "../vendored-generated/session_constants.generated.rs"]
mod generated;

pub use generated::*;
