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
pub mod handles;
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
    /// Parse a policy-file `mode` string. Surrounding whitespace is trimmed
    /// (`"enforce "` must not silently become an unrecognized value that degrades
    /// to permissive); unknown values return `None`.
    pub fn from_policy_str(s: &str) -> Option<SecurityMode> {
        match s.trim().to_ascii_lowercase().as_str() {
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
    /// @ref LLP 0013#delegation-and-authority-flow — authority-bearing capability handles.
    handles: Arc<handles::HandleRegistry>,
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
                        // Do NOT re-apply the policy's declared `mode` here: the
                        // caller's mode wins. On the CLI path build_host_config
                        // already resolves the Auto default from the policy mode
                        // upstream, and an explicit `--capsec` (enforce, audit, or
                        // permissive) must win — the previous re-application let a
                        // committed `{"mode":"permissive"}` silently downgrade an
                        // explicit `--capsec enforce` (fail-open), and conversely
                        // would have upgraded an explicit `--capsec permissive` a
                        // policy's enforce. (ENG-22632)
                        policy_file = Some(policy);
                    }
                    Err(err) => {
                        // A configured policy that exists but cannot be parsed must
                        // FAIL CLOSED: continuing unpoliced would run permissively
                        // (silently unprotected). Escalate to enforce so a missing
                        // grant denies rather than allows. On the CLI path
                        // build_host_config already rejects this before we get here;
                        // this covers the embedder/ABI path. (ENG-22620)
                        eprintln!(
                            "error: failed to load capability policy {}: {}; failing closed (enforce)",
                            policy_path.display(),
                            err
                        );
                        config.mode = SecurityMode::Enforce;
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
            handles: Arc::new(handles::HandleRegistry::new()),
        }
    }

    /// The authority-bearing handle registry. @ref LLP 0013#delegation-and-authority-flow
    pub fn handles(&self) -> &handles::HandleRegistry {
        &self.handles
    }

    /// Runtime-grant a capability to the root principal, bounded by the static
    /// ceiling. Returns whether it was applied. @ref LLP 0013 §dynamic permissions
    pub fn runtime_grant_root(&self, capability: &str) -> bool {
        self.capability_manager.runtime_grant_root(capability)
    }

    /// Runtime-revoke a runtime-granted root capability.
    pub fn runtime_revoke_root(&self, capability: &str) {
        self.capability_manager.runtime_revoke_root(capability)
    }

    /// Tri-state grant status (1 granted / 2 prompt / 0 denied) for root.
    pub fn grant_status(&self, capability: &str) -> u8 {
        self.capability_manager.grant_status(capability)
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

    /// Check whether a principal may mint a passable authority-bearing handle.
    pub fn check_handle_mint(&self, module_id: &str, capability: &str) -> bool {
        self.capability_manager
            .check_handle_mint(module_id, capability)
    }

    /// Check a capability for a symlink-owning filesystem operation. This uses
    /// no-follow-final normalization while preserving normal audit/enforce
    /// semantics.
    pub fn check_capability_no_follow_final(&self, module_id: &str, capability: &str) -> bool {
        self.capability_manager
            .check_no_follow_final(module_id, capability)
    }

    /// Stack-intersection check for deputy-sensitive capability classes: the
    /// effective grant is the AND of every principal on the call stack
    /// (innermost-first). @ref LLP 0013#phase-5
    pub fn check_capability_stack(&self, stack: &[&str], capability: &str) -> bool {
        self.capability_manager.check_stack(stack, capability)
    }

    pub fn check_capability_stack_no_follow_final(&self, stack: &[&str], capability: &str) -> bool {
        self.capability_manager
            .check_stack_no_follow_final(stack, capability)
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
