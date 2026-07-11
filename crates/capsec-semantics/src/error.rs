//! Errors produced while validating or evaluating CapSec semantics.

use thiserror::Error;

/// Errors are refusal conditions: callers must never reinterpret one as an
/// audit-mode allow.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("duplicate JSON object key at {path}: {key:?}")]
    DuplicateKey { path: String, key: String },
    #[error("I-JSON violation at {path}: {message}")]
    InvalidIJson { path: String, message: String },
    #[error("invalid canonical data at {path}: {message}")]
    InvalidCanonicalData { path: String, message: String },
    #[error("invalid semantic model: {0}")]
    InvalidModel(String),
    #[error("invalid registry: {0}")]
    InvalidRegistry(String),
    #[error("unknown action: {0}")]
    UnknownAction(String),
    #[error("authorization context refused arming: {0}")]
    ArmRefused(String),
}

pub type Result<T> = std::result::Result<T, Error>;
