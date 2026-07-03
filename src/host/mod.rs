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
pub mod capability_bits;
// @ref LLP 0005#c-compilation — the hyper-based `ex_host_http_*` server is
// feature-gated; without it the C++ adapter links no-op stubs.
#[cfg(feature = "host-http-server")]
pub mod http_server;
pub mod policy;
pub mod process;

use crate::module_loader::{ModuleLoader, ResolvedModule};
use std::sync::Arc;

/// Capability security enforcement mode.
///
/// @ref LLP 0013#phase-0 — the historical `Capability` and `Strict` modes were
/// behaviourally identical (`capability.rs` only ever branched on `Permissive`),
/// so they collapse into a single `Enforce` mode. `Audit` is the Phase 1
/// supply-chain rollout mode: the real policy decision is computed and logged,
/// but denied operations are allowed to proceed so a compat corpus can be built
/// before enforcement is turned on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityMode {
    /// Allow all capabilities (development/legacy mode).
    #[default]
    Permissive,
    /// Compute and log the real decision (would-deny included), but let the
    /// operation proceed. Attribution is best-effort/forgeable in Phase 1.
    Audit,
    /// Enforce capability declarations; deny on a miss (default-deny).
    Enforce,
}

impl SecurityMode {
    /// Whether denied operations are blocked (only `Enforce`).
    pub fn enforces(self) -> bool {
        matches!(self, SecurityMode::Enforce)
    }

    /// Whether checks are evaluated and logged (`Audit` or `Enforce`). In these
    /// modes the C++ boundary must NOT short-circuit via `is_allow_all`, or the
    /// would-deny record is never produced.
    pub fn evaluates(self) -> bool {
        !matches!(self, SecurityMode::Permissive)
    }

    /// Parse a policy-file `mode` string. Unknown values return `None`.
    pub fn from_policy_str(s: &str) -> Option<SecurityMode> {
        match s.to_ascii_lowercase().as_str() {
            "legacy" | "permissive" => Some(SecurityMode::Permissive),
            "audit" => Some(SecurityMode::Audit),
            // `strict`/`capability` are retained as back-compat aliases for the
            // single enforced mode.
            "enforce" | "strict" | "capability" => Some(SecurityMode::Enforce),
            _ => None,
        }
    }
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
            mode: SecurityMode::Enforce,
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
                            if let Some(parsed) = policy
                                .mode
                                .as_deref()
                                .and_then(SecurityMode::from_policy_str)
                            {
                                config.mode = parsed;
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
            mode: SecurityMode::Enforce,
            ..Default::default()
        })
    }

    /// Get the capability manager
    pub fn capabilities(&self) -> &Arc<capability::CapabilityManager> {
        &self.capability_manager
    }

    /// Check if this host is in allow-all (Legacy) mode.
    ///
    /// @ref LLP 0013#phase-1 — this MUST remain true only for `Permissive`. In
    /// `Audit` mode the C++ boundary relies on this returning false so the real
    /// check runs and the would-deny decision gets logged even though the
    /// operation ultimately proceeds.
    pub fn is_allow_all(&self) -> bool {
        self.config.mode == SecurityMode::Permissive
    }

    /// The active security mode.
    pub fn security_mode(&self) -> SecurityMode {
        self.config.mode
    }

    /// Check if a capability is granted
    pub fn check_capability(&self, module_id: &str, capability: &str) -> bool {
        self.capability_manager.check(module_id, capability)
    }

    /// Stack-intersection check for deputy-sensitive capability classes: the
    /// effective grant is the AND of every principal on the call stack
    /// (innermost-first). @ref LLP 0013#phase-5
    pub fn check_capability_stack(&self, stack: &[&str], capability: &str) -> bool {
        self.capability_manager.check_stack(stack, capability)
    }

    /// Whether any deputy capability classes are configured. When none are, the
    /// engine skips the (slightly more expensive) stack collection and uses the
    /// single-frame check. @ref LLP 0013#phase-5
    pub fn has_deputy_classes(&self) -> bool {
        self.capability_manager.has_deputy_classes()
    }

    /// Bridge the numeric module principal to a package selector so per-package
    /// policy can be resolved at the host boundary.
    ///
    /// @ref LLP 0013#mechanism-3 — the loader registers this mapping; with the
    /// carried Hermes patch stack the principal it keys on is the executing
    /// frame's Domain packageId (engine truth, not a forgeable thread-local).
    pub fn register_module_package(&self, module_id: &str, package: &str, locator: Option<&str>) {
        self.capability_manager
            .register_module_package(module_id, package, locator);
    }

    /// Import-graph gate: may the module identified by `module_id` load
    /// `specifier` (a builtin like `node:fs` or a dependency package name)?
    ///
    /// @ref LLP 0013#policy — builtins are reachable by `require`, so import
    /// policy is the primary gate for them. Returns whether the load may
    /// proceed under the active mode (audit logs but allows).
    pub fn check_import(&self, module_id: &str, specifier: &str) -> bool {
        self.capability_manager.check_import(module_id, specifier)
    }

    /// Render a human-readable audit report of would-deny decisions. Empty
    /// string when nothing was flagged.
    pub fn audit_report(&self) -> String {
        self.capability_manager.audit_report()
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
