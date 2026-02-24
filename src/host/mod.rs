//! Host ABI implementation
//!
//! This module provides the stable Host ABI that bridges JavaScript
//! to native capabilities.
//!
//! The Host ABI includes:
//! - Capability checks and logging
//! - File system operations (synchronous, via std::fs)
//! - Process and environment access
//! - Crypto operations (via C++ CommonCrypto/OpenSSL)
//! - SQLite operations (via rusqlite)
//! - Module resolution

pub mod abi;
pub mod capability;
pub mod policy;
pub mod process;

use crate::module_loader::{ModuleLoader, ResolvedModule};
use std::sync::Arc;

/// Capability security enforcement mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityMode {
    /// Allow all capabilities (development/legacy mode)
    #[default]
    Permissive,
    /// Enforce capability declarations, wildcards allowed
    Capability,
    /// Enforce capability declarations, no wildcards
    Strict,
}

/// The host configuration
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// Security mode
    pub mode: SecurityMode,
    /// Optional policy file path
    pub policy_path: Option<std::path::PathBuf>,
    /// Explicit allow list (CLI overrides)
    pub allow: Vec<String>,
    /// Explicit deny list (CLI overrides)
    pub deny: Vec<String>,
    /// Root directory for file access (if restricted)
    pub root_dir: Option<std::path::PathBuf>,
    /// Allowed network hosts (if restricted)
    pub allowed_hosts: Option<Vec<String>>,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            mode: SecurityMode::Strict,
            policy_path: None,
            allow: Vec::new(),
            deny: Vec::new(),
            root_dir: None,
            allowed_hosts: None,
        }
    }
}

/// The main host implementation
#[derive(Clone)]
pub struct Host {
    config: HostConfig,
    capability_manager: Arc<capability::CapabilityManager>,
    module_loader: Arc<ModuleLoader>,
}

impl Host {
    /// Create a new host with the given configuration
    pub fn new(config: HostConfig) -> Self {
        let mut config = config;
        let mut policy_file = None;

        // Load policy file if present
        if let Some(policy_path) = config.policy_path.as_ref() {
            if policy_path.exists() {
                match policy::PolicyFile::load(policy_path) {
                    Ok(policy) => {
                        if config.mode != SecurityMode::Permissive {
                            if let Some(mode) = policy.mode.as_deref() {
                                if mode.eq_ignore_ascii_case("legacy") {
                                    config.mode = SecurityMode::Permissive;
                                } else if mode.eq_ignore_ascii_case("strict") {
                                    config.mode = SecurityMode::Strict;
                                }
                            }
                        }
                        policy_file = Some(policy);
                    }
                    Err(err) => {
                        eprintln!("Failed to load policy {}: {}", policy_path.display(), err)
                    }
                }
            }
        }

        let manager = Arc::new(capability::CapabilityManager::new(config.mode));
        let loader = Arc::new(ModuleLoader::new());

        if let Some(policy) = policy_file {
            manager.apply_policy(&policy);
        }

        // Apply overrides (allow/deny)
        for cap in &config.allow {
            manager.grant("*", cap, None);
        }
        for cap in &config.deny {
            manager.deny("*", cap, None);
        }

        Self {
            capability_manager: manager,
            config,
            module_loader: loader,
        }
    }

    /// Create a host with default (legacy) configuration
    pub fn default_legacy() -> Self {
        Self::new(HostConfig {
            mode: SecurityMode::Permissive,
            ..Default::default()
        })
    }

    /// Create a host with strict security mode
    pub fn strict() -> Self {
        Self::new(HostConfig {
            mode: SecurityMode::Strict,
            ..Default::default()
        })
    }

    /// Get the capability manager
    pub fn capabilities(&self) -> &Arc<capability::CapabilityManager> {
        &self.capability_manager
    }

    /// Check if this host is in allow-all (Legacy) mode
    pub fn is_allow_all(&self) -> bool {
        self.config.mode == SecurityMode::Permissive
    }

    /// Check if a capability is granted
    pub fn check_capability(&self, module_id: &str, capability: &str) -> bool {
        self.capability_manager.check(module_id, capability)
    }

    /// Resolve and load a module (basic loader).
    pub fn resolve_module(
        &self,
        specifier: &str,
        referrer: Option<&std::path::Path>,
    ) -> anyhow::Result<ResolvedModule> {
        let meta = self.module_loader.resolve_meta(specifier, referrer)?;
        if let Some(path) = meta.path.as_ref() {
            let cap = format!("fs:read:{}", path.to_string_lossy());
            if !self.check_capability("module-loader", &cap) {
                anyhow::bail!("Permission denied for {}", path.display());
            }
        }
        self.module_loader.load_source(meta)
    }
}
