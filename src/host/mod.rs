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
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

const MAX_TYPED_EVIDENCE_ENTRIES: usize = 1024;

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
    /// The parsed policy artifact, when the caller already loaded it. The CLI
    /// path parses the policy file exactly once per startup and threads it
    /// through here; when absent, `Host::new` falls back to loading from
    /// `policy_path` (the embedder/ABI path). (ENG-22644)
    pub policy: Option<Arc<policy::PolicyFile>>,
    /// Explicit allow list (CLI overrides)
    pub allow: Vec<String>,
    /// Explicit deny list (CLI overrides)
    pub deny: Vec<String>,
    /// Host-boundary fence for filesystem access: when set, EVERY `fs:*`
    /// capability value (module loading included) must name a path inside this
    /// root or it is denied. The fence is enforced in every `SecurityMode` —
    /// Permissive and Audit do not bypass it — and applies to every principal
    /// including root; policy grants compose *within* it and cannot widen past
    /// it. (ENG-23876) @ref LLP 0002#host-boundary-constraints
    pub root_dir: Option<std::path::PathBuf>,
    /// Host-boundary fence for network access: when set, EVERY `network:*`
    /// capability value must name one of these hosts (`host` or `host:port`
    /// entries; a port-less entry covers the host across ports) or it is
    /// denied. Same hard-fence semantics as `root_dir`: all modes, all
    /// principals, not widenable by policy grants. An empty list denies all
    /// network access. (ENG-23876) @ref LLP 0002#host-boundary-constraints
    pub allowed_hosts: Option<Vec<String>>,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            mode: SecurityMode::Enforce,
            policy_path: None,
            policy: None,
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
    /// Authenticated immutable decision input. Authored files and environment
    /// values are intentionally absent after this point.
    /// @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
    armed_snapshot: Option<Arc<capsec_semantics::arming::ArmedSnapshot>>,
    /// Typed, validated authority state decoded from the immutable snapshot.
    /// Legacy `PolicyFile` data never enters this context.
    /// @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence
    decision_context: Option<Arc<capsec_semantics::decision::VerifiedDecisionContext>>,
    typed_evidence: Arc<RwLock<VecDeque<capsec_semantics::decision::StructuredDecisionEvidence>>>,
}

impl Host {
    /// Create a new host with the given configuration
    pub fn new(config: HostConfig) -> Self {
        let mut config = config;
        // Prefer the policy the caller already parsed (the CLI path loads the
        // artifact exactly once per startup and threads it through HostConfig —
        // ENG-22644); fall back to loading from `policy_path` for embedders
        // that only provide a path.
        let mut policy_file = config.policy.clone();

        if policy_file.is_none() {
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
                            policy_file = Some(Arc::new(policy));
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
        }

        let mut manager = capability::CapabilityManager::new(config.mode);
        // Translate the embedder's host-boundary fields into the enforced
        // fence before the manager is shared; they were previously stored but
        // never consulted (fail-open for embedders that relied on them).
        // (ENG-23876) @ref LLP 0002#host-boundary-constraints
        manager.set_host_boundary(config.root_dir.as_deref(), config.allowed_hosts.as_deref());
        let manager = Arc::new(manager);
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
            armed_snapshot: None,
            decision_context: None,
            typed_evidence: Arc::new(RwLock::new(VecDeque::with_capacity(
                MAX_TYPED_EVIDENCE_ENTRIES,
            ))),
        }
    }

    /// Construct an explicitly armed host. Embedders must authenticate the
    /// snapshot before creating the engine; there is no permissive fallback.
    pub fn new_armed(
        config: HostConfig,
        armed_snapshot: Arc<capsec_semantics::arming::ArmedSnapshot>,
    ) -> capsec_semantics::Result<Self> {
        if config.mode != SecurityMode::Enforce {
            return Err(capsec_semantics::Error::ArmRefused(
                "an armed host requires enforce mode".into(),
            ));
        }
        if config.policy.is_some()
            || config.policy_path.is_some()
            || !config.allow.is_empty()
            || !config.deny.is_empty()
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "legacy policy and allow/deny overrides are forbidden on an armed host".into(),
            ));
        }
        let profile = capsec_semantics::registry::ValidatedProfile::from_json(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/capsec/registry/capability-definitions.json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/capsec/registry/policy-rules.json"
            )),
        )?;
        let decision_context = Arc::new(armed_snapshot.decision_context(profile.definitions)?);
        let mut host = Self::new(config);
        host.armed_snapshot = Some(armed_snapshot);
        host.decision_context = Some(decision_context);
        Ok(host)
    }

    pub fn armed_snapshot(&self) -> Option<&Arc<capsec_semantics::arming::ArmedSnapshot>> {
        self.armed_snapshot.as_ref()
    }

    pub fn decision_context(
        &self,
    ) -> Option<&Arc<capsec_semantics::decision::VerifiedDecisionContext>> {
        self.decision_context.as_ref()
    }

    /// Evaluate one complete typed effect set against the immutable authority
    /// context. Armed execution never falls back to the legacy string manager.
    pub fn evaluate_typed_decision(
        &self,
        set: &capsec_semantics::model::DecisionSet,
        gates: &[capsec_semantics::decision::EffectGate],
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        let context = self.decision_context.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed decision requested without an armed context".into(),
            )
        })?;
        let decision = capsec_semantics::decision::evaluate_decision_set(
            context,
            set,
            gates,
            capsec_semantics::decision::Workflow::ProductionEnforce,
            &classify_network_peer,
        )?;
        let evidence =
            capsec_semantics::decision::structure_decision_evidence(context, set, &decision);
        if let Ok(mut rows) = self.typed_evidence.write() {
            if rows.len() == MAX_TYPED_EVIDENCE_ENTRIES {
                rows.pop_front();
            }
            rows.push_back(evidence);
        }
        Ok(decision)
    }

    /// Strict JSON ingress for engine/host adapters. Duplicate keys and unsafe
    /// I-JSON values are rejected before typed deserialization.
    pub fn evaluate_typed_decision_json(
        &self,
        decision_set_json: &[u8],
        gates_json: &[u8],
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        let set_text = std::str::from_utf8(decision_set_json).map_err(|error| {
            capsec_semantics::Error::InvalidJson(format!("decision set is not UTF-8: {error}"))
        })?;
        let gates_text = std::str::from_utf8(gates_json).map_err(|error| {
            capsec_semantics::Error::InvalidJson(format!("effect gates are not UTF-8: {error}"))
        })?;
        let set_value = capsec_semantics::strict_json::parse_strict(set_text)?;
        let gates_value = capsec_semantics::strict_json::parse_strict(gates_text)?;
        let set: capsec_semantics::model::DecisionSet = serde_json::from_value(set_value)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        let gates: Vec<capsec_semantics::decision::EffectGate> =
            serde_json::from_value(gates_value)
                .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        self.evaluate_typed_decision(&set, &gates)
    }

    pub fn typed_evidence(&self) -> Vec<capsec_semantics::decision::StructuredDecisionEvidence> {
        self.typed_evidence
            .read()
            .map(|rows| rows.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The authority-bearing handle registry. @ref LLP 0013#delegation-and-authority-flow
    pub fn handles(&self) -> &handles::HandleRegistry {
        &self.handles
    }

    /// Runtime-grant a capability to the root principal, bounded by the static
    /// ceiling. Returns whether it was applied. @ref LLP 0013 — §dynamic permissions
    pub fn runtime_grant_root(&self, capability: &str) -> bool {
        if self.decision_context.is_some() {
            return false;
        }
        self.capability_manager.runtime_grant_root(capability)
    }

    /// Runtime-revoke a runtime-granted root capability.
    pub fn runtime_revoke_root(&self, capability: &str) {
        if self.decision_context.is_some() {
            return;
        }
        self.capability_manager.runtime_revoke_root(capability)
    }

    /// Tri-state grant status (1 granted / 2 prompt / 0 denied) for root.
    pub fn grant_status(&self, capability: &str) -> u8 {
        if self.decision_context.is_some() {
            return 0;
        }
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
    ///
    /// It must ALSO return false when a host-boundary fence (`root_dir` /
    /// `allowed_hosts`) is configured, even in Permissive mode: the C++
    /// boundary short-circuits every capability check when this returns true,
    /// which would silently skip the fence the embedder asked for. (ENG-23876)
    pub fn is_allow_all(&self) -> bool {
        self.config.mode == SecurityMode::Permissive
            && self.config.root_dir.is_none()
            && self.config.allowed_hosts.is_none()
    }

    /// The active security mode.
    pub fn security_mode(&self) -> SecurityMode {
        self.config.mode
    }

    /// Check if a capability is granted
    pub fn check_capability(&self, module_id: &str, capability: &str) -> bool {
        if self.decision_context.is_some() {
            return false;
        }
        self.capability_manager.check(module_id, capability)
    }

    /// Check whether a principal may mint a passable authority-bearing handle.
    pub fn check_handle_mint(&self, module_id: &str, capability: &str) -> bool {
        if self.decision_context.is_some() {
            return false;
        }
        self.capability_manager
            .check_handle_mint(module_id, capability)
    }

    /// Check a capability for a symlink-owning filesystem operation. This uses
    /// no-follow-final normalization while preserving normal audit/enforce
    /// semantics.
    pub fn check_capability_no_follow_final(&self, module_id: &str, capability: &str) -> bool {
        if self.decision_context.is_some() {
            return false;
        }
        self.capability_manager
            .check_no_follow_final(module_id, capability)
    }

    /// Stack-intersection check for deputy-sensitive capability classes: the
    /// effective grant is the AND of every principal on the call stack
    /// (innermost-first). @ref LLP 0013#phase-5
    pub fn check_capability_stack(&self, stack: &[&str], capability: &str) -> bool {
        if self.decision_context.is_some() {
            return false;
        }
        self.capability_manager.check_stack(stack, capability)
    }

    pub fn check_capability_stack_no_follow_final(&self, stack: &[&str], capability: &str) -> bool {
        if self.decision_context.is_some() {
            return false;
        }
        self.capability_manager
            .check_stack_no_follow_final(stack, capability)
    }

    /// Whether any deputy capability classes are configured. When none are, the
    /// engine skips the (slightly more expensive) stack collection and uses the
    /// single-frame check. @ref LLP 0013#phase-5
    pub fn has_deputy_classes(&self) -> bool {
        if self.decision_context.is_some() {
            return true;
        }
        self.capability_manager.has_deputy_classes()
    }

    /// Bridge the numeric module principal to a package selector so per-package
    /// policy can be resolved at the host boundary.
    ///
    /// @ref LLP 0013#mechanism-3 — the loader registers this mapping; with the
    /// carried Hermes patch stack the principal it keys on is the executing
    /// frame's Domain packageId (engine truth, not a forgeable thread-local).
    pub fn register_module_package(&self, module_id: &str, package: &str, locator: Option<&str>) {
        if self.decision_context.is_some() {
            return;
        }
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
        if self.decision_context.is_some() {
            return false;
        }
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
        let meta = self.resolve_module_meta(specifier, referrer)?;
        self.module_loader.load_source(meta)
    }

    /// Resolve a module to its metadata only — the resolved absolute path plus
    /// package fields — WITHOUT reading or transpiling the module body. Backs
    /// `require.resolve`, which needs only the path and discards the source: the
    /// full `resolve_module` used to read the target off disk, transpile it,
    /// JSON-escape the entire body, and hand it to JS just for the loader to
    /// throw it away and keep `rec.path`. This skips that per-resolve read +
    /// transpile + alloc churn on hot plugin/config-discovery paths. (ENG-23007)
    ///
    /// The `fs:read:<path>` capability gate is preserved so a metadata-only
    /// resolve carries the same authority as the full load path — this is a pure
    /// performance optimization, not a loosening of the capability model. The
    /// resolution itself (statting, reading `package.json`) already runs here
    /// exactly as it did inside `resolve_module` before `load_source`.
    pub fn resolve_module_meta(
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
        Ok(meta)
    }
}

fn classify_network_peer(
    address: capsec_semantics::model::IpAddress,
) -> Option<capsec_semantics::model::PeerClass> {
    use capsec_semantics::model::PeerClass;

    let address = address.get();
    if is_metadata_peer(address) {
        return Some(PeerClass::Metadata);
    }
    Some(match address {
        IpAddr::V4(address) if address.is_unspecified() => PeerClass::Unspecified,
        IpAddr::V6(address) if address.is_unspecified() => PeerClass::Unspecified,
        IpAddr::V4(address) if address.is_loopback() => PeerClass::Loopback,
        IpAddr::V6(address) if address.is_loopback() => PeerClass::Loopback,
        IpAddr::V4(address) if address.is_link_local() => PeerClass::LinkLocal,
        IpAddr::V6(address) if address.is_unicast_link_local() => PeerClass::LinkLocal,
        IpAddr::V4(address) if address.is_multicast() => PeerClass::Multicast,
        IpAddr::V6(address) if address.is_multicast() => PeerClass::Multicast,
        IpAddr::V4(address) if is_carrier_grade_nat(address) => PeerClass::CarrierGradeNat,
        IpAddr::V6(address) if is_unique_local(address) => PeerClass::UniqueLocal,
        IpAddr::V4(address) if address.is_private() => PeerClass::Private,
        IpAddr::V4(address) if is_reserved_v4(address) => PeerClass::Reserved,
        IpAddr::V6(address) if is_reserved_v6(address) => PeerClass::Reserved,
        _ => PeerClass::Public,
    })
}

fn is_metadata_peer(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => matches!(
            address.octets(),
            [169, 254, 169, 254] | [169, 254, 170, 2] | [100, 100, 100, 200] | [168, 63, 129, 16]
        ),
        IpAddr::V6(address) => {
            address == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
                || address == Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe)
        }
    }
}

fn is_carrier_grade_nat(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_unique_local(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}

fn is_reserved_v4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_documentation()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
}

fn is_reserved_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_armed_host() -> Host {
        use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
        use capsec_semantics::model::Digest;

        let source = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        ));
        let mut value: serde_json::Value = serde_json::from_slice(source).unwrap();
        value["workflow"] = serde_json::Value::String("production".into());
        value["effectiveMode"] = serde_json::Value::String("enforce".into());
        let digest = capsec_semantics::digest::compute_domain_digest(
            capsec_semantics::digest::ARMED_SNAPSHOT_DOMAIN,
            &value,
            &["armedSnapshotDigest".to_string()],
        )
        .unwrap();
        value["armedSnapshotDigest"] = serde_json::Value::String(digest);
        let bytes = serde_json::to_vec(&value).unwrap();
        let digest_at = |path: &[&str]| {
            let value = path
                .iter()
                .fold(&value, |current, segment| &current[*segment]);
            Digest::new(value.as_str().unwrap()).unwrap()
        };
        let expected = ExpectedArmingIdentity {
            profile: value["capsVocab"].as_str().unwrap().into(),
            semantic_core: value["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest_at(&["vocabDigest"]),
            registry_digest: digest_at(&["registryDigest"]),
            policy_digest: digest_at(&["policyDigest"]),
            target: value["engine"]["target"].as_str().unwrap().into(),
            engine_binary_digest: digest_at(&["engine", "binaryDigest"]),
            features: value["engine"]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            target_complete_and_advertised: true,
        };
        let snapshot = ArmedSnapshot::load(&bytes, &expected).unwrap();
        Host::new_armed(HostConfig::default(), Arc::new(snapshot)).unwrap()
    }

    // ENG-23876 — an embedder constructing `HostConfig { root_dir,
    // allowed_hosts, .. }` must actually get the restriction it asked for, in
    // every mode. These are Host-level (embedding API) assertions; the
    // manager-level fence matrix lives in capability.rs.
    #[test]
    fn embedder_host_boundary_fields_are_enforced() {
        for mode in [
            SecurityMode::Permissive,
            SecurityMode::Audit,
            SecurityMode::Enforce,
        ] {
            let host = Host::new(HostConfig {
                mode,
                root_dir: Some(std::path::PathBuf::from("/fence-root")),
                allowed_hosts: Some(vec!["api.example.com".to_string()]),
                ..Default::default()
            });

            // The C++ boundary short-circuits on is_allow_all: it must be
            // false whenever a fence is configured, even in Permissive mode.
            assert!(!host.is_allow_all(), "fence skipped under {mode:?}");

            assert!(host.check_capability("0", "fs:read:/fence-root/data.txt"));
            assert!(!host.check_capability("0", "fs:read:/outside/data.txt"));
            assert!(host.check_capability("0", "network:fetch:api.example.com"));
            assert!(!host.check_capability("0", "network:fetch:evil.example.com"));
        }
    }

    // A fence-less permissive host must stay allow-all (the legacy fast path
    // the iOS/Swift embedding relies on).
    #[test]
    fn permissive_host_without_boundary_stays_allow_all() {
        let host = Host::default_legacy();
        assert!(host.is_allow_all());
        assert!(host.check_capability("0", "fs:read:/outside/data.txt"));
    }

    #[test]
    fn typed_ingress_rejects_duplicate_keys_before_context_lookup() {
        let host = Host::strict();
        let result = host.evaluate_typed_decision_json(
            br#"{"decisionSetSchema":"ibex/capsec-decision-set/1","decisionSetSchema":"ibex/capsec-decision-set/1"}"#,
            b"[]",
        );
        assert!(matches!(
            result,
            Err(capsec_semantics::Error::DuplicateKey { .. })
        ));
        assert!(host.typed_evidence().is_empty());
    }

    #[test]
    fn peer_classifier_distinguishes_protected_and_nonpublic_ranges() {
        use capsec_semantics::model::{IpAddress, PeerClass};
        let classify = |address: &str| {
            classify_network_peer(IpAddress::new(address.parse().unwrap())).unwrap()
        };
        assert_eq!(classify("169.254.169.254"), PeerClass::Metadata);
        assert_eq!(classify("100.100.100.200"), PeerClass::Metadata);
        assert_eq!(classify("10.0.0.1"), PeerClass::Private);
        assert_eq!(classify("100.64.0.1"), PeerClass::CarrierGradeNat);
        assert_eq!(classify("127.0.0.1"), PeerClass::Loopback);
        assert_eq!(classify("fe80::a9fe:a9fe"), PeerClass::Metadata);
        assert_eq!(classify("fd00::1"), PeerClass::UniqueLocal);
        assert_eq!(classify("2001:db8::1"), PeerClass::Reserved);
        assert_eq!(classify("8.8.8.8"), PeerClass::Public);
    }

    #[test]
    fn armed_host_evaluates_typed_authority_and_records_structured_evidence() {
        use capsec_semantics::decision::{DecisionOutcome, EffectGate};
        use capsec_semantics::model::DecisionSet;

        let host = example_armed_host();
        assert!(!host.check_capability("0", "fs:read:/anything"));
        assert!(!host.check_capability_stack(&["0"], "fs:read:/anything"));
        assert!(!host.check_import("0", "node:fs"));
        assert!(!host.runtime_grant_root("fs:read:/anything"));
        assert_eq!(host.grant_status("fs:read:/anything"), 0);
        let principal = serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
            "locator": "image-lib@2.4.1"
        });
        let decision = |path: &str| {
            serde_json::from_value::<DecisionSet>(serde_json::json!({
                "decisionSetSchema": "ibex/capsec-decision-set/1",
                "operationId": format!("read-{path}"),
                "atomicityGroup": "test.fs.read",
                "combination": "conjunction",
                "context": {
                    "stage": "commit",
                    "actor": principal,
                    "constrainedPrincipals": [principal]
                },
                "effects": [{
                    "cap": "fs:read",
                    "effectOwner": principal,
                    "resource": {
                        "kind": "path-occurrence",
                        "requested": {
                            "root": "project",
                            "components": [
                                {"encoding": "utf8", "value": "images"},
                                {"encoding": "utf8", "value": path}
                            ]
                        },
                        "followMode": "follow-final",
                        "objectState": "existing",
                        "parentObject": {"platform": "unix", "volume": "dev-test", "file": "parent"},
                        "finalObject": {"platform": "unix", "volume": "dev-test", "file": "file"},
                        "retainedHandle": "test-fd"
                    }
                }]
            }))
            .unwrap()
        };
        let gates: Vec<EffectGate> = serde_json::from_value(serde_json::json!([{
            "coverageEdgeId": "test.fs.read",
            "targetCell": "complete",
            "definitionAndEdgePredicatesSatisfied": true
        }]))
        .unwrap();

        let allowed = host
            .evaluate_typed_decision(&decision("photo.jpg"), &gates)
            .unwrap();
        assert_eq!(allowed.outcome, DecisionOutcome::Allow, "{allowed:?}");

        let denied_set: DecisionSet = serde_json::from_value(serde_json::json!({
            "decisionSetSchema": "ibex/capsec-decision-set/1",
            "operationId": "read-outside",
            "atomicityGroup": "test.fs.read",
            "combination": "conjunction",
            "context": {
                "stage": "commit",
                "actor": principal,
                "constrainedPrincipals": [principal]
            },
            "effects": [{
                "cap": "fs:read",
                "effectOwner": principal,
                "resource": {
                    "kind": "path-occurrence",
                    "requested": {
                        "root": "project",
                        "components": [
                            {"encoding": "utf8", "value": "secrets"},
                            {"encoding": "utf8", "value": "token.txt"}
                        ]
                    },
                    "followMode": "follow-final",
                    "objectState": "existing",
                    "parentObject": {"platform": "unix", "volume": "dev-test", "file": "parent"},
                    "finalObject": {"platform": "unix", "volume": "dev-test", "file": "secret"},
                    "retainedHandle": "test-fd-2"
                }
            }]
        }))
        .unwrap();
        let denied = host.evaluate_typed_decision(&denied_set, &gates).unwrap();
        assert_eq!(denied.outcome, DecisionOutcome::Deny);
        let evidence = host.typed_evidence();
        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[0].outcome, DecisionOutcome::Allow);
        assert_eq!(evidence[1].outcome, DecisionOutcome::Deny);
        assert_eq!(
            evidence[0].identity.armed_snapshot_digest,
            host.armed_snapshot().unwrap().digest().clone()
        );
    }
}
