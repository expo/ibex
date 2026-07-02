//! Policy file parsing for CLI capability configuration.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
pub struct PolicyFile {
    /// Optional policy mode (permissive/legacy, audit, enforce/strict).
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
    /// Per-package policies, keyed by the package **selector** (name, or
    /// `name@version` to narrow a specific coexisting version).
    ///
    /// @ref LLP 0013#policy — packages govern three surfaces: host
    /// capabilities, endowed globals, and the import graph.
    #[serde(default)]
    pub packages: HashMap<String, PackagePolicy>,

    /// Capability classes (`fs:write`, `process:spawn`, …) subject to optional
    /// stack-intersection enforcement: the effective permission is the AND of
    /// every principal on the call stack. Off (empty) by default.
    ///
    /// @ref LLP 0013#phase-5
    #[serde(default, rename = "deputyClasses")]
    pub deputy_classes: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ModulePolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Policy for a single package selector.
///
/// ```json
/// { "node-fetch": { "capabilities": ["network:fetch"],
///                   "builtins": ["node:http", "node:https"] } }
/// ```
///
/// `builtins`/`packages` are `Option`: absent means "unrestricted on that
/// axis", an explicit (possibly empty) list means "only these are allowed".
#[derive(Debug, Deserialize, Default)]
pub struct PackagePolicy {
    /// Host capabilities granted to this package's frames.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Explicit capability denials (take precedence over grants).
    #[serde(default)]
    pub deny: Vec<String>,
    /// Allowed builtin modules (`node:fs`, ...). Absent = unrestricted.
    #[serde(default)]
    pub builtins: Option<Vec<String>>,
    /// Allowed dependency packages. Absent = unrestricted.
    #[serde(default)]
    pub packages: Option<Vec<String>>,
    /// Endowed globals to expose on this package's compartment global. Consumed
    /// by the loader/transform layer (Phase 1); recorded here for policy round
    /// trips. Absent = policy default surface only.
    #[serde(default)]
    pub endow: Option<Vec<String>>,
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
