//! Policy file parsing for CLI capability configuration.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
pub struct PolicyFile {
    /// Optional policy mode (strict/legacy)
    pub mode: Option<String>,
    /// Global allow list
    #[serde(default)]
    pub allow: Vec<String>,
    /// Global deny list
    #[serde(default)]
    pub deny: Vec<String>,
    /// Per-module policies
    #[serde(default)]
    pub modules: HashMap<String, ModulePolicy>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ModulePolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl PolicyFile {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read policy file {}", path.display()))?;
        let policy = serde_json::from_str::<PolicyFile>(&contents)
            .with_context(|| format!("Failed to parse policy file {}", path.display()))?;
        Ok(policy)
    }
}
