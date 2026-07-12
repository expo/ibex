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
use anyhow::Context as _;
#[cfg(test)]
use std::collections::VecDeque;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

#[cfg(test)]
const MAX_TYPED_EVIDENCE_ENTRIES: usize = 1024;

/// Reject every startup environment input classified `closed` by the checked
/// coverage registry. This is intentionally registry-derived so a newly closed
/// control cannot be forgotten in a handwritten deny list.
/// @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
pub fn reject_closed_startup_environment() -> anyhow::Result<()> {
    let mut present = crate::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES
        .iter()
        .copied()
        .filter(|name| std::env::var_os(name).is_some())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    present.sort();
    present.dedup();
    if !present.is_empty() {
        anyhow::bail!(
            "production capability startup rejects closed environment controls: {}",
            present.join(", ")
        );
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TypedDynamicGrantRequest {
    grant_id: capsec_semantics::model::NonEmptyString,
    principal: capsec_semantics::model::Principal,
    authority: capsec_semantics::model::AuthoritySelector,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TypedHandleMintRequest {
    actor: capsec_semantics::model::Principal,
    holder: capsec_semantics::model::Principal,
    authority: capsec_semantics::model::AuthoritySelector,
    #[serde(default)]
    parent_handle_id: Option<capsec_semantics::model::NonEmptyString>,
    #[serde(default)]
    operation_id: Option<capsec_semantics::model::NonEmptyString>,
}

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
    decision_context: Option<Arc<RwLock<capsec_semantics::decision::VerifiedDecisionContext>>>,
    typed_decision_count: Arc<AtomicUsize>,
    #[cfg(test)]
    typed_evidence: Arc<RwLock<VecDeque<capsec_semantics::decision::StructuredDecisionEvidence>>>,
    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    conformance_typed_observer: Arc<RwLock<TypedConformanceObserver>>,
    typed_imports: Arc<
        BTreeMap<
            capsec_semantics::model::Principal,
            capsec_semantics::arming::PrincipalImportPolicy,
        >,
    >,
    typed_module_principals: Arc<RwLock<HashMap<String, capsec_semantics::model::Principal>>>,
    /// Exact authenticated disposition for every coverage edge on the armed
    /// target. Call sites never manufacture `Complete` locally.
    target_cells: Arc<BTreeMap<String, capsec_semantics::decision::TargetCellDisposition>>,
    unarmed_closed: bool,
}

#[derive(Clone, Debug)]
pub struct TypedDecisionResult {
    pub decision: capsec_semantics::decision::Decision,
    pub evidence: capsec_semantics::decision::StructuredDecisionEvidence,
}

#[cfg(any(test, feature = "capsec-conformance-observer"))]
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedTypedDecision {
    pub terminal_branch_id: String,
    pub decision_set: capsec_semantics::model::DecisionSet,
    pub gates: Vec<capsec_semantics::decision::EffectGate>,
    pub evidence: capsec_semantics::decision::StructuredDecisionEvidence,
}

#[cfg(any(test, feature = "capsec-conformance-observer"))]
#[derive(Default)]
struct TypedConformanceObserver {
    terminal_branch_id: Option<String>,
    decisions: Vec<ObservedTypedDecision>,
}

impl Host {
    /// Create a new host with the given configuration
    pub fn new(config: HostConfig) -> Self {
        // The legacy string-policy plane is diagnostic/test-only. Production
        // hosts arm an authenticated typed snapshot through `new_armed`; this
        // constructor never reads a policy path and only accepts an already
        // parsed legacy artifact for the separately named Audit workflow.
        // @ref LLP 0021#wp11--reconcile-the-corpus-and-remove-the-legacy-plane
        let policy_file = (config.mode == SecurityMode::Audit)
            .then(|| config.policy.clone())
            .flatten();

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
            typed_decision_count: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            typed_evidence: Arc::new(RwLock::new(VecDeque::with_capacity(
                MAX_TYPED_EVIDENCE_ENTRIES,
            ))),
            #[cfg(any(test, feature = "capsec-conformance-observer"))]
            conformance_typed_observer: Arc::new(RwLock::new(TypedConformanceObserver::default())),
            typed_imports: Arc::new(BTreeMap::new()),
            typed_module_principals: Arc::new(RwLock::new(HashMap::new())),
            target_cells: Arc::new(BTreeMap::new()),
            unarmed_closed: false,
        }
    }

    /// Construct an explicitly armed host. Embedders must authenticate the
    /// snapshot before creating the engine; there is no permissive fallback.
    pub fn new_armed(
        config: HostConfig,
        armed_snapshot: Arc<capsec_semantics::arming::ArmedSnapshot>,
    ) -> capsec_semantics::Result<Self> {
        validate_loaded_engine_identity(&armed_snapshot)?;
        let target_cells = authenticated_target_cells(&armed_snapshot)?;
        validate_snapshot_root_bindings(&armed_snapshot)?;
        Self::new_armed_with_target_cells(config, armed_snapshot, target_cells)
    }

    fn new_armed_with_target_cells(
        config: HostConfig,
        armed_snapshot: Arc<capsec_semantics::arming::ArmedSnapshot>,
        target_cells: BTreeMap<String, capsec_semantics::decision::TargetCellDisposition>,
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
        if config.root_dir.is_some() || config.allowed_hosts.is_some() {
            return Err(capsec_semantics::Error::ArmRefused(
                "HostConfig fences are not yet representable in the typed armed ceiling".into(),
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
        let decision_context = Arc::new(RwLock::new(
            armed_snapshot.decision_context(profile.definitions)?,
        ));
        let typed_imports = Arc::new(armed_snapshot.import_policies()?);
        let mut host = Self::new(config);
        host.armed_snapshot = Some(armed_snapshot);
        host.decision_context = Some(decision_context);
        host.typed_imports = typed_imports;
        host.target_cells = Arc::new(target_cells);
        Ok(host)
    }

    /// Test-harness escape hatch for debug builds only. Production/release
    /// embedders cannot bypass the checked target registry.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub unsafe fn new_armed_for_test(
        config: HostConfig,
        armed_snapshot: Arc<capsec_semantics::arming::ArmedSnapshot>,
    ) -> capsec_semantics::Result<Self> {
        let cells = crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS
            .iter()
            .map(|edge| {
                (
                    (*edge).to_owned(),
                    capsec_semantics::decision::TargetCellDisposition::Complete,
                )
            })
            .collect();
        Self::new_armed_with_target_cells(config, armed_snapshot, cells)
    }

    fn target_cell(&self, edge: &str) -> capsec_semantics::decision::TargetCellDisposition {
        self.target_cells
            .get(edge)
            .copied()
            .unwrap_or(capsec_semantics::decision::TargetCellDisposition::Incomplete)
    }

    pub fn armed_snapshot(&self) -> Option<&Arc<capsec_semantics::arming::ArmedSnapshot>> {
        self.armed_snapshot.as_ref()
    }

    pub fn decision_context(
        &self,
    ) -> Option<&Arc<RwLock<capsec_semantics::decision::VerifiedDecisionContext>>> {
        self.decision_context.as_ref()
    }

    pub fn typed_principal_for_module(
        &self,
        module_id: &str,
    ) -> Option<capsec_semantics::model::Principal> {
        self.decision_context.as_ref()?;
        if module_id == "0" {
            return self
                .typed_imports
                .keys()
                .find(|principal| principal.is_root())
                .cloned();
        }
        self.typed_module_principals
            .read()
            .ok()
            .and_then(|mappings| mappings.get(module_id).cloned())
    }

    pub fn typed_logical_path(
        &self,
        principal: &capsec_semantics::model::Principal,
        path: &std::path::Path,
    ) -> capsec_semantics::Result<capsec_semantics::model::LogicalPath> {
        let snapshot = self.armed_snapshot.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed path normalization requested without an armed snapshot".into(),
            )
        })?;
        let path = normalize_host_path_for_binding(path)?;
        let components = host_path_components(&path)?;
        let binding = snapshot.root_binding_for_host_components(principal, &components)?;
        validate_armed_binding_object(&binding)?;
        snapshot.logical_path_for_host_components(principal, &components)
    }

    /// Prove that the directory descriptor retained by the native adapter is
    /// actually below the root object authenticated for this path. A lexical
    /// `/proc/self/fd`/`F_GETPATH` spelling is insufficient: an attacker can
    /// swap root A for B while the adapter opens B and restore A before the
    /// Host re-resolves the spelling. Walking `..` from the descriptor and
    /// comparing object identities closes that A/B/A window.
    #[cfg(unix)]
    pub(crate) fn validate_typed_parent_fd_ancestry(
        &self,
        principal: &capsec_semantics::model::Principal,
        path: &std::path::Path,
        parent_fd: std::os::fd::RawFd,
    ) -> capsec_semantics::Result<bool> {
        let snapshot = self.armed_snapshot.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "filesystem descriptor ancestry requested without an armed snapshot".into(),
            )
        })?;
        let path = normalize_host_path_for_binding(path)?;
        let components = host_path_components(&path)?;
        let binding = snapshot.root_binding_for_host_components(principal, &components)?;
        fd_descends_from_object(parent_fd, &binding.object)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_typed_fs_open_stage(
        &self,
        module_id: &str,
        operation_key: &str,
        coverage_edge_id: &str,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        path: &std::path::Path,
        stage: capsec_semantics::model::Stage,
        object_state: capsec_semantics::model::ObjectState,
        follow_mode: capsec_semantics::model::FollowMode,
        disclosure_only: bool,
        resolved_parent_path: Option<&std::path::Path>,
        needs_read: bool,
        needs_write: bool,
        parent_object: Option<capsec_semantics::model::ObjectIdentity>,
        final_object: Option<capsec_semantics::model::ObjectIdentity>,
        retained_handle: Option<capsec_semantics::model::NonEmptyString>,
        presented_handle_ids: Vec<capsec_semantics::model::NonEmptyString>,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::EffectGate;
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            OccurrenceResource, StableId,
        };

        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "filesystem operation has no authenticated typed principal".into(),
            )
        })?;
        let requested = self.typed_logical_path(&principal, path)?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "filesystem principal stack is empty, noncanonical, or omits the actor".into(),
            ));
        }
        if let Some(resolved_parent_path) = resolved_parent_path {
            // A committed descriptor retains object identity and authority
            // even if its directory is subsequently renamed. Re-resolving
            // the old lexical parent at Repeat would make legitimate open fds
            // permanently unusable (and broke macOS's /tmp alias). Commit and
            // discovery still bind the retained parent to the requested path.
            let parent_matches = if stage == capsec_semantics::model::Stage::Repeat {
                true
            } else if requested.components.is_empty() {
                self.armed_snapshot
                    .as_deref()
                    .ok_or_else(|| {
                        capsec_semantics::Error::ArmRefused(
                            "root-object validation requires an armed snapshot".into(),
                        )
                    })?
                    .root_bindings()?
                    .iter()
                    .any(|binding| {
                        binding.logical_root == requested.root
                            && match binding.logical_root {
                                capsec_semantics::model::LogicalRoot::Package => {
                                    binding.owner.as_ref() == Some(&principal)
                                }
                                _ => binding.owner.is_none(),
                            }
                            && final_object.as_ref() == Some(&binding.object)
                    })
            } else {
                let mut expected_parent = requested.clone();
                expected_parent.components.pop();
                self.typed_logical_path(&principal, resolved_parent_path)? == expected_parent
            };
            if !parent_matches {
                return Err(capsec_semantics::Error::ArmRefused(
                    "retained filesystem parent escaped its authenticated logical root".into(),
                ));
            }
        } else if stage != capsec_semantics::model::Stage::Requested {
            return Err(capsec_semantics::Error::ArmRefused(
                "staged filesystem authorization is missing a resolved retained parent".into(),
            ));
        }
        let actions: Vec<&str> = if disclosure_only {
            vec!["fs:list"]
        } else {
            [
                needs_read.then_some("fs:read"),
                needs_write.then_some("fs:write"),
            ]
            .into_iter()
            .flatten()
            .collect()
        };
        if actions.is_empty() {
            return Err(capsec_semantics::Error::ArmRefused(
                "filesystem open has no typed effect".into(),
            ));
        }
        let operation_resource = serde_json::to_string(&requested)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        let resource = OccurrenceResource::PathOccurrence {
            requested,
            follow_mode,
            object_state,
            parent_object,
            final_object,
            retained_handle,
        };
        let effects = actions
            .iter()
            .map(|action| {
                Ok(Effect {
                    action: ActionId::new(*action)
                        .map_err(capsec_semantics::Error::InvalidModel)?,
                    effect_owner: principal.clone(),
                    resource: resource.clone(),
                })
            })
            .collect::<capsec_semantics::Result<Vec<_>>>()?;
        let operation_id = capsec_semantics::model::NonEmptyString::new(format!(
            "{}:{}:{}",
            operation_key, module_id, operation_resource
        ))
        .map_err(capsec_semantics::Error::InvalidModel)?;
        let set = DecisionSet {
            decision_set_schema: DecisionSetSchema::V1,
            operation_id,
            atomicity_group: StableId::new(format!("{coverage_edge_id}.decision"))
                .map_err(capsec_semantics::Error::InvalidModel)?,
            combination: EffectCombination::Conjunction,
            context: DecisionContext {
                stage,
                actor: principal.clone(),
                constrained_principals,
                presented_handle_ids,
            },
            effects,
        };
        let gates = actions
            .iter()
            .map(|_| {
                Ok(EffectGate {
                    coverage_edge_id: StableId::new(coverage_edge_id)
                        .map_err(capsec_semantics::Error::InvalidModel)?,
                    target_cell: self.target_cell(coverage_edge_id),
                    definition_and_edge_predicates_satisfied: true,
                })
            })
            .collect::<capsec_semantics::Result<Vec<_>>>()?;
        self.evaluate_typed_decision(&set, &gates)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_typed_fetch_stage(
        &self,
        module_id: &str,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        scheme: capsec_semantics::model::FetchScheme,
        host: capsec_semantics::model::ConcreteHost,
        port: capsec_semantics::model::Port,
        stage: capsec_semantics::model::Stage,
        candidates: Vec<capsec_semantics::model::IpAddress>,
        selected_candidate: Option<capsec_semantics::model::IpAddress>,
        verified_peer: Option<capsec_semantics::model::VerifiedPeer>,
        connection_id: Option<capsec_semantics::model::NonEmptyString>,
        redirect_index: Option<capsec_semantics::model::SafeUint>,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::EffectGate;
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            NetworkRequest, OccurrenceResource, PeerClass, Route, StableId,
        };

        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "fetch operation has no authenticated typed principal".into(),
            )
        })?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "fetch principal stack is empty, noncanonical, or omits the actor".into(),
            ));
        }
        for address in candidates
            .iter()
            .chain(selected_candidate.iter())
            .chain(verified_peer.iter().map(|peer| &peer.address))
        {
            if matches!(
                classify_network_peer(*address),
                Some(PeerClass::Metadata | PeerClass::Unspecified) | None
            ) {
                return Err(capsec_semantics::Error::ArmRefused(
                    "protected metadata or unspecified network peer is always denied".into(),
                ));
            }
        }
        let requested = NetworkRequest::FetchEndpoint { scheme, host, port };
        let operation_resource = serde_json::to_string(&requested)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        let set = DecisionSet {
            decision_set_schema: DecisionSetSchema::V1,
            operation_id: capsec_semantics::model::NonEmptyString::new(format!(
                "fetch:{module_id}:{operation_resource}"
            ))
            .map_err(capsec_semantics::Error::InvalidModel)?,
            atomicity_group: StableId::new(
                "surface.native.op.nativefetch.17pv6n3.decision".to_owned(),
            )
            .map_err(capsec_semantics::Error::InvalidModel)?,
            combination: EffectCombination::Conjunction,
            context: DecisionContext {
                stage,
                actor: principal.clone(),
                constrained_principals,
                presented_handle_ids: Vec::new(),
            },
            effects: vec![Effect {
                action: ActionId::new("network:fetch")
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                effect_owner: principal,
                resource: OccurrenceResource::NetworkOccurrence {
                    requested,
                    route: Route::Direct,
                    candidates,
                    selected_candidate,
                    verified_peer,
                    redirect_index,
                    connection_id,
                },
            }],
        };
        self.evaluate_typed_decision(
            &set,
            &[EffectGate {
                coverage_edge_id: StableId::new("surface.native.op.nativefetch.17pv6n3")
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                target_cell: self.target_cell("surface.native.op.nativefetch.17pv6n3"),
                definition_and_edge_predicates_satisfied: true,
            }],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_typed_connect_stage(
        &self,
        module_id: &str,
        operation_key: &str,
        coverage_edge_id: &str,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        transport: capsec_semantics::model::ConnectTransport,
        host: capsec_semantics::model::ConcreteHost,
        port: capsec_semantics::model::Port,
        stage: capsec_semantics::model::Stage,
        candidates: Vec<capsec_semantics::model::IpAddress>,
        selected_candidate: Option<capsec_semantics::model::IpAddress>,
        verified_peer: Option<capsec_semantics::model::VerifiedPeer>,
        connection_id: Option<capsec_semantics::model::NonEmptyString>,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::EffectGate;
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            NetworkRequest, OccurrenceResource, PeerClass, Route, StableId,
        };

        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "connect operation has no authenticated typed principal".into(),
            )
        })?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "connect principal stack is empty, noncanonical, or omits the actor".into(),
            ));
        }
        for address in candidates
            .iter()
            .chain(selected_candidate.iter())
            .chain(verified_peer.iter().map(|peer| &peer.address))
        {
            if matches!(
                classify_network_peer(*address),
                Some(PeerClass::Metadata | PeerClass::Unspecified) | None
            ) {
                return Err(capsec_semantics::Error::ArmRefused(
                    "protected metadata or unspecified network peer is always denied".into(),
                ));
            }
        }
        let requested = NetworkRequest::ConnectEndpoint {
            transport,
            host,
            port,
        };
        let operation_resource = serde_json::to_string(&requested)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        let set = DecisionSet {
            decision_set_schema: DecisionSetSchema::V1,
            operation_id: capsec_semantics::model::NonEmptyString::new(format!(
                "{operation_key}:{module_id}:{operation_resource}"
            ))
            .map_err(capsec_semantics::Error::InvalidModel)?,
            atomicity_group: StableId::new(format!("{coverage_edge_id}.decision"))
                .map_err(capsec_semantics::Error::InvalidModel)?,
            combination: EffectCombination::Conjunction,
            context: DecisionContext {
                stage,
                actor: principal.clone(),
                constrained_principals,
                presented_handle_ids: Vec::new(),
            },
            effects: vec![Effect {
                action: ActionId::new("network:connect")
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                effect_owner: principal,
                resource: OccurrenceResource::NetworkOccurrence {
                    requested,
                    route: Route::Direct,
                    candidates,
                    selected_candidate,
                    verified_peer,
                    redirect_index: None,
                    connection_id,
                },
            }],
        };
        self.evaluate_typed_decision(
            &set,
            &[EffectGate {
                coverage_edge_id: StableId::new(coverage_edge_id)
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                target_cell: self.target_cell(coverage_edge_id),
                definition_and_edge_predicates_satisfied: true,
            }],
        )
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
        let context = context.read().map_err(|_| {
            capsec_semantics::Error::ArmRefused("typed decision context lock is poisoned".into())
        })?;
        let decision = capsec_semantics::decision::evaluate_decision_set(
            &context,
            set,
            gates,
            capsec_semantics::decision::Workflow::ProductionEnforce,
            &classify_network_peer,
        )?;
        self.typed_decision_count.fetch_add(1, Ordering::Relaxed);
        #[cfg(any(test, feature = "capsec-conformance-observer"))]
        {
            let evidence =
                capsec_semantics::decision::structure_decision_evidence(&context, set, &decision);
            #[cfg(test)]
            self.record_typed_decision_for_tests(evidence.clone());
            self.record_typed_conformance_decision(set, gates, evidence);
        }
        Ok(decision)
    }

    /// Evaluate and return the exact evidence envelope produced by that same
    /// operation. Callers that need evidence must use this atomic result
    /// rather than consulting the shared bounded history afterward.
    pub fn evaluate_typed_decision_with_evidence(
        &self,
        set: &capsec_semantics::model::DecisionSet,
        gates: &[capsec_semantics::decision::EffectGate],
    ) -> capsec_semantics::Result<TypedDecisionResult> {
        let context = self.decision_context.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed decision requested without an armed context".into(),
            )
        })?;
        let context = context.read().map_err(|_| {
            capsec_semantics::Error::ArmRefused("typed decision context lock is poisoned".into())
        })?;
        let decision = capsec_semantics::decision::evaluate_decision_set(
            &context,
            set,
            gates,
            capsec_semantics::decision::Workflow::ProductionEnforce,
            &classify_network_peer,
        )?;
        let evidence =
            capsec_semantics::decision::structure_decision_evidence(&context, set, &decision);
        self.typed_decision_count.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        self.record_typed_decision_for_tests(evidence.clone());
        #[cfg(any(test, feature = "capsec-conformance-observer"))]
        self.record_typed_conformance_decision(set, gates, evidence.clone());
        Ok(TypedDecisionResult { decision, evidence })
    }

    #[cfg(test)]
    fn record_typed_decision_for_tests(
        &self,
        evidence: capsec_semantics::decision::StructuredDecisionEvidence,
    ) {
        if let Ok(mut rows) = self.typed_evidence.write() {
            if rows.len() == MAX_TYPED_EVIDENCE_ENTRIES {
                rows.pop_front();
            }
            rows.push_back(evidence);
        }
    }

    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    fn record_typed_conformance_decision(
        &self,
        set: &capsec_semantics::model::DecisionSet,
        gates: &[capsec_semantics::decision::EffectGate],
        evidence: capsec_semantics::decision::StructuredDecisionEvidence,
    ) {
        let Ok(mut observer) = self.conformance_typed_observer.write() else {
            return;
        };
        let Some(terminal_branch_id) = observer.terminal_branch_id.clone() else {
            return;
        };
        observer.decisions.push(ObservedTypedDecision {
            terminal_branch_id,
            decision_set: set.clone(),
            gates: gates.to_vec(),
            evidence,
        });
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

    pub fn evaluate_typed_decision_json_with_evidence(
        &self,
        decision_set_json: &[u8],
        gates_json: &[u8],
    ) -> capsec_semantics::Result<TypedDecisionResult> {
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
        self.evaluate_typed_decision_with_evidence(&set, &gates)
    }

    #[cfg(test)]
    pub fn typed_evidence(&self) -> Vec<capsec_semantics::decision::StructuredDecisionEvidence> {
        self.typed_evidence
            .read()
            .map(|rows| rows.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn typed_decision_count(&self) -> usize {
        self.typed_decision_count.load(Ordering::Relaxed)
    }

    /// Invalidation identity for retained resources still implemented by the
    /// legacy capability adapter. Armed typed resources use the three semantic
    /// generations instead.
    pub fn legacy_authorization_generation(&self) -> u64 {
        self.capability_manager.authorization_generation()
    }

    pub fn legacy_authorization_cacheable(&self) -> bool {
        self.decision_context.is_none() && self.config.mode == SecurityMode::Enforce
    }

    #[doc(hidden)]
    pub fn legacy_authorization_check_count(&self) -> usize {
        self.capability_manager.authorization_check_count()
    }

    pub fn typed_generations(&self) -> Option<capsec_semantics::cache::GenerationSet> {
        let context = self.decision_context.as_deref()?.read().ok()?;
        Some(context.authority().generations)
    }

    pub fn grant_typed_dynamic(
        &self,
        grant_id: capsec_semantics::model::NonEmptyString,
        principal: capsec_semantics::model::Principal,
        selector: capsec_semantics::model::AuthoritySelector,
    ) -> capsec_semantics::Result<bool> {
        use capsec_semantics::decision::{BoundAuthority, DynamicGrant};

        let context = self.decision_context.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed dynamic grant requested without an armed context".into(),
            )
        })?;
        let mut current = context.write().map_err(|_| {
            capsec_semantics::Error::ArmRefused("typed decision context lock is poisoned".into())
        })?;
        let mut authority = current.authority().clone();
        if authority
            .dynamic_grants
            .iter()
            .any(|grant| grant.grant_id == grant_id)
        {
            return Ok(false);
        }
        let next_dynamic = authority
            .generations
            .dynamic
            .checked_increment()
            .ok_or_else(|| {
                capsec_semantics::Error::ArmRefused(
                    "dynamic generation cannot be incremented".into(),
                )
            })?;
        let package_root_owner = selector
            .resource
            .contains_package_logical_root()
            .then(|| principal.is_package().then(|| principal.clone()))
            .flatten();
        authority.dynamic_grants.push(DynamicGrant {
            grant_id: grant_id.clone(),
            principal,
            authority: BoundAuthority {
                source_id: capsec_semantics::model::NonEmptyString::new(format!(
                    "dynamic.{}",
                    grant_id.as_str()
                ))
                .map_err(capsec_semantics::Error::InvalidModel)?,
                selector,
                armed_snapshot_digest: current.identity().armed_snapshot_digest.clone(),
                package_root_owner,
            },
            observed_negative_generation: authority.generations.negative,
            published_dynamic_generation: next_dynamic,
        });
        authority
            .dynamic_grants
            .sort_by(|left, right| left.grant_id.cmp(&right.grant_id));
        for grant in &mut authority.dynamic_grants {
            grant.observed_negative_generation = authority.generations.negative;
            grant.published_dynamic_generation = next_dynamic;
        }
        authority.generations.dynamic = next_dynamic;
        *current = current.with_authority(authority)?;
        Ok(true)
    }

    pub fn grant_typed_dynamic_json(&self, request_json: &[u8]) -> capsec_semantics::Result<bool> {
        let text = std::str::from_utf8(request_json).map_err(|error| {
            capsec_semantics::Error::InvalidJson(format!(
                "dynamic grant request is not UTF-8: {error}"
            ))
        })?;
        let value = capsec_semantics::strict_json::parse_strict(text)?;
        let request: TypedDynamicGrantRequest = serde_json::from_value(value)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        self.grant_typed_dynamic(request.grant_id, request.principal, request.authority)
    }

    pub fn grant_typed_dynamic_json_for_principal(
        &self,
        principal: capsec_semantics::model::Principal,
        request_json: &[u8],
    ) -> capsec_semantics::Result<bool> {
        let text = std::str::from_utf8(request_json).map_err(|error| {
            capsec_semantics::Error::InvalidJson(format!(
                "dynamic grant request is not UTF-8: {error}"
            ))
        })?;
        let value = capsec_semantics::strict_json::parse_strict(text)?;
        let request: TypedDynamicGrantRequest = serde_json::from_value(value)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        if request.principal != principal {
            return Err(capsec_semantics::Error::ArmRefused(
                "dynamic grant principal does not match the executing principal".into(),
            ));
        }
        self.grant_typed_dynamic(request.grant_id, principal, request.authority)
    }

    pub fn revoke_typed_dynamic(
        &self,
        grant_id: &capsec_semantics::model::NonEmptyString,
    ) -> capsec_semantics::Result<bool> {
        let context = self.decision_context.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed dynamic revocation requested without an armed context".into(),
            )
        })?;
        let mut current = context.write().map_err(|_| {
            capsec_semantics::Error::ArmRefused("typed decision context lock is poisoned".into())
        })?;
        let mut authority = current.authority().clone();
        let original_len = authority.dynamic_grants.len();
        authority
            .dynamic_grants
            .retain(|grant| &grant.grant_id != grant_id);
        if authority.dynamic_grants.len() == original_len {
            return Ok(false);
        }
        let next_negative = authority
            .generations
            .negative
            .checked_increment()
            .ok_or_else(|| {
                capsec_semantics::Error::ArmRefused(
                    "negative generation cannot be incremented".into(),
                )
            })?;
        let next_dynamic = authority
            .generations
            .dynamic
            .checked_increment()
            .ok_or_else(|| {
                capsec_semantics::Error::ArmRefused(
                    "dynamic generation cannot be incremented".into(),
                )
            })?;
        authority.generations.negative = next_negative;
        authority.generations.dynamic = next_dynamic;
        for grant in &mut authority.dynamic_grants {
            grant.observed_negative_generation = next_negative;
            grant.published_dynamic_generation = next_dynamic;
        }
        for handle in &mut authority.handles {
            handle.observed_negative_generation = next_negative;
        }
        for revocation in &mut authority.revocations {
            revocation.generation = next_negative;
        }
        *current = current.with_authority(authority)?;
        Ok(true)
    }

    pub fn revoke_typed_dynamic_json(&self, request_json: &[u8]) -> capsec_semantics::Result<bool> {
        let text = std::str::from_utf8(request_json).map_err(|error| {
            capsec_semantics::Error::InvalidJson(format!(
                "dynamic revocation request is not UTF-8: {error}"
            ))
        })?;
        let value = capsec_semantics::strict_json::parse_strict(text)?;
        let grant_id: capsec_semantics::model::NonEmptyString = serde_json::from_value(value)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        self.revoke_typed_dynamic(&grant_id)
    }

    pub fn revoke_typed_dynamic_json_for_principal(
        &self,
        principal: &capsec_semantics::model::Principal,
        request_json: &[u8],
    ) -> capsec_semantics::Result<bool> {
        let text = std::str::from_utf8(request_json).map_err(|error| {
            capsec_semantics::Error::InvalidJson(format!(
                "dynamic revocation request is not UTF-8: {error}"
            ))
        })?;
        let value = capsec_semantics::strict_json::parse_strict(text)?;
        let grant_id: capsec_semantics::model::NonEmptyString = serde_json::from_value(value)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        let context = self.decision_context.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed dynamic revocation requested without an armed context".into(),
            )
        })?;
        let current = context.read().map_err(|_| {
            capsec_semantics::Error::ArmRefused("typed decision context lock is poisoned".into())
        })?;
        let authorized = current
            .authority()
            .dynamic_grants
            .iter()
            .any(|grant| grant.grant_id == grant_id && &grant.principal == principal);
        drop(current);
        if !authorized {
            return Err(capsec_semantics::Error::ArmRefused(
                "only the grant principal may revoke a dynamic grant".into(),
            ));
        }
        self.revoke_typed_dynamic(&grant_id)
    }

    pub fn mint_typed_handle(
        &self,
        actor: capsec_semantics::model::Principal,
        constrained_principals: &[capsec_semantics::model::Principal],
        holder: capsec_semantics::model::Principal,
        selector: capsec_semantics::model::AuthoritySelector,
        parent_handle_id: Option<&capsec_semantics::model::NonEmptyString>,
        operation_id: Option<capsec_semantics::model::NonEmptyString>,
    ) -> capsec_semantics::Result<capsec_semantics::model::NonEmptyString> {
        use capsec_semantics::containment::{
            try_compare_authority_containment, Containment, ContainmentContext,
        };
        use capsec_semantics::decision::{BearerHandle, BoundAuthority};

        let context = self.decision_context.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed handle mint requested without an armed context".into(),
            )
        })?;
        let mut current = context.write().map_err(|_| {
            capsec_semantics::Error::ArmRefused("typed decision context lock is poisoned".into())
        })?;
        let mut authority = current.authority().clone();
        let (owner, package_root_owner, ancestor_ids) = if let Some(parent_handle_id) =
            parent_handle_id
        {
            let parent = authority
                .handles
                .iter()
                .find(|handle| &handle.handle_id == parent_handle_id)
                .ok_or_else(|| {
                    capsec_semantics::Error::ArmRefused("parent handle is absent or revoked".into())
                })?;
            if parent.holder != actor {
                return Err(capsec_semantics::Error::ArmRefused(
                    "only the current holder may re-attenuate a handle".into(),
                ));
            }
            let same_package_root_owner = matches!(
                (
                    &parent.authority.package_root_owner,
                    selector.resource.contains_package_logical_root(),
                ),
                (Some(_), true) | (None, false)
            );
            if !matches!(
                try_compare_authority_containment(
                    &parent.authority.selector,
                    &selector,
                    &ContainmentContext {
                        same_snapshot: true,
                        same_package_root_owner,
                    },
                )?,
                Containment::Equal | Containment::StrictSubset
            ) {
                return Err(capsec_semantics::Error::ArmRefused(
                    "child handle would widen its parent authority".into(),
                ));
            }
            let mut ancestors = parent.ancestor_ids.clone();
            ancestors.push(parent.handle_id.clone());
            ancestors.sort();
            ancestors.dedup();
            (
                parent.owner.clone(),
                parent.authority.package_root_owner.clone(),
                ancestors,
            )
        } else {
            let package_owner = selector
                .resource
                .contains_package_logical_root()
                .then(|| actor.is_package().then(|| actor.clone()))
                .flatten();
            if constrained_principals.is_empty()
                || !constrained_principals
                    .iter()
                    .any(|principal| principal == &actor)
            {
                return Err(capsec_semantics::Error::ArmRefused(
                    "handle mint requires the authenticated actor in its constrained stack".into(),
                ));
            }
            for principal in constrained_principals {
                let principal_package_owner = selector
                    .resource
                    .contains_package_logical_root()
                    .then(|| principal.is_package().then(|| principal.clone()))
                    .flatten();
                if !current.static_authority_covers(
                    principal,
                    &selector,
                    principal_package_owner.as_ref(),
                )? {
                    return Err(capsec_semantics::Error::ArmRefused(
                        "handle authority is not covered by every constrained principal's static floor"
                            .into(),
                    ));
                }
            }
            if !current.static_authority_covers(&actor, &selector, package_owner.as_ref())? {
                return Err(capsec_semantics::Error::ArmRefused(
                    "handle authority is not covered by the owner's static floor".into(),
                ));
            }
            (actor, package_owner, Vec::new())
        };

        let handle_id = fresh_typed_handle_id(&authority.handles)?;
        let next_handle = authority
            .generations
            .handle
            .checked_increment()
            .ok_or_else(|| {
                capsec_semantics::Error::ArmRefused(
                    "handle generation cannot be incremented".into(),
                )
            })?;
        for handle in &mut authority.handles {
            handle.published_handle_generation = next_handle;
        }
        authority.handles.push(BearerHandle {
            handle_id: handle_id.clone(),
            owner,
            holder,
            authority: BoundAuthority {
                source_id: capsec_semantics::model::NonEmptyString::new(format!(
                    "handle.{}",
                    handle_id.as_str()
                ))
                .map_err(capsec_semantics::Error::InvalidModel)?,
                selector,
                armed_snapshot_digest: current.identity().armed_snapshot_digest.clone(),
                package_root_owner,
            },
            observed_negative_generation: authority.generations.negative,
            published_handle_generation: next_handle,
            ancestor_ids,
            operation_id,
        });
        authority
            .handles
            .sort_by(|left, right| left.handle_id.cmp(&right.handle_id));
        authority.generations.handle = next_handle;
        *current = current.with_authority(authority)?;
        Ok(handle_id)
    }

    pub fn mint_typed_handle_json(
        &self,
        request_json: &[u8],
    ) -> capsec_semantics::Result<capsec_semantics::model::NonEmptyString> {
        let text = std::str::from_utf8(request_json).map_err(|error| {
            capsec_semantics::Error::InvalidJson(format!(
                "handle mint request is not UTF-8: {error}"
            ))
        })?;
        let value = capsec_semantics::strict_json::parse_strict(text)?;
        let request: TypedHandleMintRequest = serde_json::from_value(value)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        self.mint_typed_handle(
            request.actor.clone(),
            &[request.actor],
            request.holder,
            request.authority,
            request.parent_handle_id.as_ref(),
            request.operation_id,
        )
    }

    pub fn mint_typed_handle_json_for_actor(
        &self,
        actor: capsec_semantics::model::Principal,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        request_json: &[u8],
    ) -> capsec_semantics::Result<capsec_semantics::model::NonEmptyString> {
        let text = std::str::from_utf8(request_json).map_err(|error| {
            capsec_semantics::Error::InvalidJson(format!(
                "handle mint request is not UTF-8: {error}"
            ))
        })?;
        let value = capsec_semantics::strict_json::parse_strict(text)?;
        let request: TypedHandleMintRequest = serde_json::from_value(value)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        if request.actor != actor {
            return Err(capsec_semantics::Error::ArmRefused(
                "handle mint actor differs from the authenticated engine principal".into(),
            ));
        }
        self.mint_typed_handle(
            actor,
            &constrained_principals,
            request.holder,
            request.authority,
            request.parent_handle_id.as_ref(),
            request.operation_id,
        )
    }

    pub fn revoke_typed_handle(
        &self,
        handle_id: &capsec_semantics::model::NonEmptyString,
    ) -> capsec_semantics::Result<bool> {
        let context = self.decision_context.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed handle revocation requested without an armed context".into(),
            )
        })?;
        let mut current = context.write().map_err(|_| {
            capsec_semantics::Error::ArmRefused("typed decision context lock is poisoned".into())
        })?;
        let mut authority = current.authority().clone();
        let original_len = authority.handles.len();
        authority.handles.retain(|handle| {
            &handle.handle_id != handle_id && !handle.ancestor_ids.contains(handle_id)
        });
        if authority.handles.len() == original_len {
            return Ok(false);
        }
        let next_negative = authority
            .generations
            .negative
            .checked_increment()
            .ok_or_else(|| {
                capsec_semantics::Error::ArmRefused(
                    "negative generation cannot be incremented".into(),
                )
            })?;
        let next_handle = authority
            .generations
            .handle
            .checked_increment()
            .ok_or_else(|| {
                capsec_semantics::Error::ArmRefused(
                    "handle generation cannot be incremented".into(),
                )
            })?;
        authority.generations.negative = next_negative;
        authority.generations.handle = next_handle;
        for handle in &mut authority.handles {
            handle.observed_negative_generation = next_negative;
            handle.published_handle_generation = next_handle;
        }
        for grant in &mut authority.dynamic_grants {
            grant.observed_negative_generation = next_negative;
        }
        for revocation in &mut authority.revocations {
            revocation.generation = next_negative;
        }
        *current = current.with_authority(authority)?;
        Ok(true)
    }

    pub fn revoke_typed_handle_json(&self, request_json: &[u8]) -> capsec_semantics::Result<bool> {
        let text = std::str::from_utf8(request_json).map_err(|error| {
            capsec_semantics::Error::InvalidJson(format!(
                "handle revocation request is not UTF-8: {error}"
            ))
        })?;
        let value = capsec_semantics::strict_json::parse_strict(text)?;
        let handle_id: capsec_semantics::model::NonEmptyString = serde_json::from_value(value)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        self.revoke_typed_handle(&handle_id)
    }

    pub fn revoke_typed_handle_json_for_actor(
        &self,
        actor: &capsec_semantics::model::Principal,
        request_json: &[u8],
    ) -> capsec_semantics::Result<bool> {
        let text = std::str::from_utf8(request_json).map_err(|error| {
            capsec_semantics::Error::InvalidJson(format!(
                "handle revocation request is not UTF-8: {error}"
            ))
        })?;
        let value = capsec_semantics::strict_json::parse_strict(text)?;
        let handle_id: capsec_semantics::model::NonEmptyString = serde_json::from_value(value)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        let context = self.decision_context.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed handle revocation requested without an armed context".into(),
            )
        })?;
        let current = context.read().map_err(|_| {
            capsec_semantics::Error::ArmRefused("typed decision context lock is poisoned".into())
        })?;
        let authorized = current
            .authority()
            .handles
            .iter()
            .find(|handle| handle.handle_id == handle_id)
            .is_some_and(|handle| &handle.owner == actor || &handle.holder == actor);
        drop(current);
        if !authorized {
            return Err(capsec_semantics::Error::ArmRefused(
                "only the authenticated handle owner or holder may revoke it".into(),
            ));
        }
        self.revoke_typed_handle(&handle_id)
    }

    /// The authority-bearing handle registry. @ref LLP 0013#delegation-and-authority-flow
    pub fn handles(&self) -> &handles::HandleRegistry {
        &self.handles
    }

    /// Runtime-grant a capability to the root principal, bounded by the static
    /// ceiling. Returns whether it was applied. @ref LLP 0013 — §dynamic permissions
    pub fn runtime_grant_root(&self, capability: &str) -> bool {
        if self.unarmed_closed || self.decision_context.is_some() {
            return false;
        }
        self.capability_manager.runtime_grant_root(capability)
    }

    /// Runtime-revoke a runtime-granted root capability.
    pub fn runtime_revoke_root(&self, capability: &str) {
        if self.unarmed_closed || self.decision_context.is_some() {
            return;
        }
        self.capability_manager.runtime_revoke_root(capability)
    }

    /// Tri-state grant status (1 granted / 2 prompt / 0 denied) for root.
    pub fn grant_status(&self, capability: &str) -> u8 {
        if self.unarmed_closed || self.decision_context.is_some() {
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

    pub fn closed_unarmed() -> Self {
        let mut host = Self::new(HostConfig::default());
        host.unarmed_closed = true;
        host
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
        !self.unarmed_closed
            && self.config.mode == SecurityMode::Permissive
            && self.config.root_dir.is_none()
            && self.config.allowed_hosts.is_none()
    }

    /// The active security mode.
    pub fn security_mode(&self) -> SecurityMode {
        self.config.mode
    }

    /// Check if a capability is granted
    pub fn check_capability(&self, module_id: &str, capability: &str) -> bool {
        if self.unarmed_closed || self.decision_context.is_some() {
            return false;
        }
        self.capability_manager.check(module_id, capability)
    }

    /// Check whether a principal may mint a passable authority-bearing handle.
    pub fn check_handle_mint(&self, module_id: &str, capability: &str) -> bool {
        if self.unarmed_closed || self.decision_context.is_some() {
            return false;
        }
        self.capability_manager
            .check_handle_mint(module_id, capability)
    }

    /// Check a capability for a symlink-owning filesystem operation. This uses
    /// no-follow-final normalization while preserving normal audit/enforce
    /// semantics.
    pub fn check_capability_no_follow_final(&self, module_id: &str, capability: &str) -> bool {
        if self.unarmed_closed || self.decision_context.is_some() {
            return false;
        }
        self.capability_manager
            .check_no_follow_final(module_id, capability)
    }

    /// Stack-intersection check for deputy-sensitive capability classes: the
    /// effective grant is the AND of every principal on the call stack
    /// (innermost-first). @ref LLP 0013#phase-5
    pub fn check_capability_stack(&self, stack: &[&str], capability: &str) -> bool {
        if self.unarmed_closed || self.decision_context.is_some() {
            return false;
        }
        self.capability_manager.check_stack(stack, capability)
    }

    pub fn check_capability_stack_no_follow_final(&self, stack: &[&str], capability: &str) -> bool {
        if self.unarmed_closed || self.decision_context.is_some() {
            return false;
        }
        self.capability_manager
            .check_stack_no_follow_final(stack, capability)
    }

    /// Whether any deputy capability classes are configured. When none are, the
    /// engine skips the (slightly more expensive) stack collection and uses the
    /// single-frame check. @ref LLP 0013#phase-5
    pub fn has_deputy_classes(&self) -> bool {
        if self.unarmed_closed {
            return true;
        }
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
    pub fn register_module_package(
        &self,
        module_id: &str,
        package: &str,
        locator: Option<&str>,
        integrity: Option<&str>,
    ) {
        if self.unarmed_closed {
            return;
        }
        if self.decision_context.is_some() {
            let matched = self.typed_imports.keys().find(|principal| match principal {
                capsec_semantics::model::Principal::Package {
                    name,
                    locator: armed_locator,
                    integrity: armed_integrity,
                } => {
                    name.as_str() == package
                        && locator.is_some_and(|value| value == armed_locator.as_str())
                        && integrity.is_some_and(|value| value == armed_integrity.as_str())
                }
                _ => false,
            });
            if let (Some(principal), Ok(mut mappings)) =
                (matched, self.typed_module_principals.write())
            {
                mappings.insert(module_id.to_owned(), principal.clone());
            }
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
        if self.unarmed_closed {
            return false;
        }
        if self.decision_context.is_some() {
            let principal = if module_id == "0" {
                self.typed_imports
                    .keys()
                    .find(|principal| principal.is_root())
                    .cloned()
            } else {
                self.typed_module_principals
                    .read()
                    .ok()
                    .and_then(|mappings| mappings.get(module_id).cloned())
            };
            let Some(principal) = principal else {
                return false;
            };
            let Some(policy) = self.typed_imports.get(&principal) else {
                return false;
            };
            if is_module_path_specifier(specifier) {
                // A raw relative/absolute spelling has no trustworthy target
                // principal yet. Defer (without granting an edge) to
                // `resolve_module_meta_for_principal`, which authenticates the
                // exact resolved root/object and permits only same-principal
                // paths or an explicit graph edge. Returning false here broke
                // every package's own `require('./submodule')` before that
                // authoritative post-resolution check could run.
                return true;
            }
            return typed_import_allowed(policy, specifier);
        }
        self.capability_manager.check_import(module_id, specifier)
    }

    /// Render a human-readable audit report of would-deny decisions. Empty
    /// string when nothing was flagged.
    pub fn audit_report(&self) -> String {
        self.capability_manager.audit_report()
    }

    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    pub fn begin_conformance_observation(&self, terminal_branch_id: &str) {
        self.capability_manager
            .begin_conformance_observation(terminal_branch_id);
        if let Ok(mut observer) = self.conformance_typed_observer.write() {
            observer.terminal_branch_id = Some(terminal_branch_id.to_string());
            observer.decisions.clear();
        }
    }

    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    pub fn take_conformance_observations(&self) -> Vec<capability::ObservedCapabilityDecision> {
        self.capability_manager.take_conformance_observations()
    }

    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    pub fn take_typed_conformance_observations(&self) -> Vec<ObservedTypedDecision> {
        let Ok(mut observer) = self.conformance_typed_observer.write() else {
            return Vec::new();
        };
        observer.terminal_branch_id = None;
        std::mem::take(&mut observer.decisions)
    }

    /// Resolve and load a module (basic loader).
    pub fn resolve_module(
        &self,
        specifier: &str,
        referrer: Option<&std::path::Path>,
    ) -> anyhow::Result<ResolvedModule> {
        let meta = self.resolve_module_meta_for_principal(specifier, referrer, None)?;
        self.load_authenticated_module_source(meta)
    }

    pub fn resolve_module_for_principal(
        &self,
        specifier: &str,
        referrer: Option<&std::path::Path>,
        requester_module_id: Option<&str>,
    ) -> anyhow::Result<ResolvedModule> {
        let meta =
            self.resolve_module_meta_for_principal(specifier, referrer, requester_module_id)?;
        self.load_authenticated_module_source(meta)
    }

    fn load_authenticated_module_source(
        &self,
        meta: ResolvedModule,
    ) -> anyhow::Result<ResolvedModule> {
        if let Some(snapshot) = self.armed_snapshot.as_deref() {
            if let Some(expected_integrity) = meta.package_integrity.as_deref() {
                let path = meta
                    .path
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("authenticated package module has no path"))?;
                let root = meta.package_root.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("authenticated package module has no package root")
                })?;
                let components = host_path_components(path)?;
                let principal = snapshot
                    .owner_for_host_components(&components)?
                    .ok_or_else(|| anyhow::anyhow!("authenticated package source has no owner"))?;
                let binding = snapshot.root_binding_for_host_components(&principal, &components)?;
                let bytes = crate::module_loader::authenticated_package_source(
                    root,
                    path,
                    expected_integrity,
                    &binding.object,
                )
                .with_context(|| {
                    format!("failed to reauthenticate package source {}", path.display())
                })?;
                return self.module_loader.load_source_bytes(meta, bytes);
            }
            if let Some(path) = meta.path.as_deref() {
                let components = host_path_components(path)?;
                let root_principal = self
                    .typed_imports
                    .keys()
                    .find(|principal| principal.is_root())
                    .ok_or_else(|| anyhow::anyhow!("armed root principal is absent"))?;
                let target_principal = snapshot
                    .owner_for_host_components(&components)?
                    .unwrap_or_else(|| root_principal.clone());
                let binding =
                    snapshot.root_binding_for_host_components(&target_principal, &components)?;
                let bytes =
                    authenticated_source_beneath_binding(&binding, path).with_context(|| {
                        format!(
                            "failed to authenticate first-party source {}",
                            path.display()
                        )
                    })?;
                return self.module_loader.load_source_bytes(meta, bytes);
            }
        }
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
        self.resolve_module_meta_for_principal(specifier, referrer, None)
    }

    pub fn resolve_module_meta_for_principal(
        &self,
        specifier: &str,
        referrer: Option<&std::path::Path>,
        requester_module_id: Option<&str>,
    ) -> anyhow::Result<ResolvedModule> {
        if self.unarmed_closed {
            anyhow::bail!("unarmed host cannot resolve executable modules");
        }
        let armed_resolution = if let Some(snapshot) = self.armed_snapshot.as_deref() {
            let root_principal = self
                .typed_imports
                .keys()
                .find(|principal| principal.is_root())
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("armed root principal is absent"))?;
            let requester = if let Some(module) = requester_module_id {
                self.typed_principal_for_module(module).ok_or_else(|| {
                    anyhow::anyhow!("module resolution has no authenticated requesting principal")
                })?
            } else if let Some(referrer) = referrer {
                let absolute = lexical_absolute_path(referrer)?;
                let components = host_path_components(&absolute)?;
                let principal = snapshot
                    .owner_for_host_components(&components)?
                    .unwrap_or_else(|| root_principal.clone());
                let binding = snapshot.root_binding_for_host_components(&principal, &components)?;
                validate_armed_binding_object(&binding)?;
                principal
            } else {
                root_principal.clone()
            };
            let plan = preflight_armed_module_resolution(
                snapshot,
                &self.typed_imports,
                &root_principal,
                &requester,
                specifier,
                referrer,
                self.module_loader.is_builtin_specifier(specifier),
            )?;
            Some((snapshot, root_principal, requester, plan))
        } else {
            None
        };

        // No filesystem/package-manifest probing is allowed before the armed
        // preflight above authenticates the requester and constrains the
        // lexical target to a bound root or exact graph edge. In particular,
        // require.resolve must not reveal existent-vs-missing unauthorized
        // targets through resolver errors or timing.
        let mut meta = match armed_resolution.as_ref().map(|(_, _, _, plan)| plan) {
            Some(ArmedModuleResolution::BoundPackage { name, root }) => self
                .module_loader
                .resolve_meta_from_bound_package(specifier, name, root)?,
            _ => self.module_loader.resolve_meta(specifier, referrer)?,
        };
        if let Some(path) = meta.path.as_ref() {
            if let Some((snapshot, root_principal, requester, _)) = armed_resolution.as_ref() {
                let canonical = std::fs::canonicalize(path).with_context(|| {
                    format!("failed to authenticate module path {}", path.display())
                })?;
                let components = host_path_components(&canonical)?;
                let target_principal = snapshot
                    .owner_for_host_components(&components)?
                    .unwrap_or_else(|| root_principal.clone());
                let binding =
                    snapshot.root_binding_for_host_components(&target_principal, &components)?;
                validate_armed_binding_object(&binding)?;

                if *requester != target_principal {
                    let allowed = match &target_principal {
                        capsec_semantics::model::Principal::Package { locator, .. } => {
                            self.typed_imports.get(&requester).is_some_and(|policy| {
                                policy
                                    .packages
                                    .iter()
                                    .any(|allowed| allowed == locator.as_str())
                            })
                        }
                        _ => false,
                    };
                    if !allowed {
                        anyhow::bail!("Permission denied for {}", path.display());
                    }
                }

                match &target_principal {
                    capsec_semantics::model::Principal::Package {
                        name,
                        locator,
                        integrity,
                    } => {
                        let resolved_package_root = meta
                            .package_root
                            .as_deref()
                            .map(std::fs::canonicalize)
                            .transpose()
                            .with_context(|| {
                                format!(
                                    "failed to authenticate resolved package root for {}",
                                    path.display()
                                )
                            })?;
                        if meta.package_name.as_deref() != Some(name.as_str())
                            || resolved_package_root.as_deref()
                                != Some(host_path_from_binding(&binding)?.as_path())
                        {
                            anyhow::bail!(
                                "resolved package metadata differs from authenticated graph for {}",
                                path.display()
                            );
                        }
                        meta.package_version = locator
                            .as_str()
                            .strip_prefix(&format!("{}@", name.as_str()))
                            .map(str::to_owned);
                        meta.package_integrity = Some(integrity.as_str().to_owned());
                        meta.package_root = Some(host_path_from_binding(&binding)?);
                    }
                    _ => {
                        if meta.package_name.is_some() || meta.package_root.is_some() {
                            anyhow::bail!(
                                "unbound package metadata cannot be stamped as trusted root for {}",
                                path.display()
                            );
                        }
                    }
                }
                meta.path = Some(canonical);
            } else {
                let cap = format!("fs:read:{}", path.to_string_lossy());
                if !self.check_capability("module-loader", &cap) {
                    anyhow::bail!("Permission denied for {}", path.display());
                }
            }
        }
        Ok(meta)
    }
}

fn lexical_absolute_path(path: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = std::path::PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR.to_string()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    anyhow::bail!("module path escapes above its absolute root");
                }
            }
            std::path::Component::Normal(component) => normalized.push(component),
        }
    }
    Ok(normalized)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ArmedModuleResolution {
    Generic,
    BoundPackage {
        name: String,
        root: std::path::PathBuf,
    },
}

fn preflight_armed_module_resolution(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
    imports: &BTreeMap<
        capsec_semantics::model::Principal,
        capsec_semantics::arming::PrincipalImportPolicy,
    >,
    root_principal: &capsec_semantics::model::Principal,
    requester: &capsec_semantics::model::Principal,
    specifier: &str,
    referrer: Option<&std::path::Path>,
    builtin: bool,
) -> anyhow::Result<ArmedModuleResolution> {
    let requester_policy = imports
        .get(requester)
        .ok_or_else(|| anyhow::anyhow!("requester has no authenticated import policy"))?;

    if specifier.starts_with('#') {
        let referrer =
            referrer.ok_or_else(|| anyhow::anyhow!("package import alias requires a referrer"))?;
        let referrer = lexical_absolute_path(referrer)?;
        let components = host_path_components(&referrer)?;
        let binding = snapshot.root_binding_for_host_components(requester, &components)?;
        validate_armed_binding_object(&binding)?;
        return Ok(ArmedModuleResolution::Generic);
    }

    if !is_module_path_specifier(specifier) {
        if !typed_import_allowed(requester_policy, specifier) {
            anyhow::bail!("Import denied by authenticated package graph");
        }
        if builtin {
            return Ok(ArmedModuleResolution::Generic);
        }
        let requested_name = package_name_from_specifier(specifier);
        let candidates = imports
            .keys()
            .filter(|principal| match principal {
                capsec_semantics::model::Principal::Package { name, locator, .. } => {
                    name.as_str() == requested_name
                        && requester_policy
                            .packages
                            .iter()
                            .any(|allowed| allowed == locator.as_str())
                }
                _ => false,
            })
            .collect::<Vec<_>>();
        // A bare spelling cannot select between two authenticated locators of
        // the same package name without consulting ambient filesystem layout.
        // Reject that ambiguous graph instead of reintroducing ambient search.
        if candidates.len() != 1 {
            anyhow::bail!("Import denied by authenticated package graph");
        }
        let principal = candidates[0];
        let bindings = snapshot
            .root_bindings()?
            .into_iter()
            .filter(|binding| {
                binding.logical_root == capsec_semantics::model::LogicalRoot::Package
                    && binding.owner.as_ref() == Some(principal)
            })
            .collect::<Vec<_>>();
        if bindings.len() != 1 {
            anyhow::bail!("allowed package lacks one exact authenticated root");
        }
        validate_armed_binding_object(&bindings[0])?;
        return Ok(ArmedModuleResolution::BoundPackage {
            name: requested_name.to_owned(),
            root: host_path_from_binding(&bindings[0])?,
        });
    }

    let target = if std::path::Path::new(specifier).is_absolute() {
        lexical_absolute_path(std::path::Path::new(specifier))?
    } else {
        let base = referrer
            .and_then(std::path::Path::parent)
            .map(std::path::Path::to_path_buf)
            .unwrap_or(std::env::current_dir()?);
        lexical_absolute_path(&base.join(specifier))?
    };
    let components = host_path_components(&target)?;
    let target_principal = snapshot
        .owner_for_host_components(&components)?
        .unwrap_or_else(|| root_principal.clone());
    let binding = snapshot.root_binding_for_host_components(&target_principal, &components)?;
    validate_armed_binding_object(&binding)?;
    if requester != &target_principal {
        let allowed = match &target_principal {
            capsec_semantics::model::Principal::Package { locator, .. } => requester_policy
                .packages
                .iter()
                .any(|allowed| allowed == locator.as_str()),
            _ => false,
        };
        if !allowed {
            anyhow::bail!("Import denied by authenticated package graph");
        }
    }
    Ok(ArmedModuleResolution::Generic)
}

fn normalize_host_path_for_binding(
    path: &std::path::Path,
) -> capsec_semantics::Result<std::path::PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| {
                capsec_semantics::Error::ArmRefused(format!(
                    "cannot resolve current directory for typed path: {error}"
                ))
            })?
            .join(path)
    };
    // Bind lexical aliases through the directory object they actually
    // traverse while preserving the final component for no-follow and
    // absent-create decisions. This makes `/tmp` -> `/private/tmp` and other
    // symlinked parents agree with the authenticated canonical root.
    Ok(match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => std::fs::canonicalize(parent)
            .map(|parent| parent.join(name))
            .unwrap_or(path),
        _ => std::fs::canonicalize(&path).unwrap_or(path),
    })
}

fn host_path_components(
    path: &std::path::Path,
) -> capsec_semantics::Result<Vec<capsec_semantics::model::PathComponent>> {
    use std::path::Component;

    let mut result = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => result.push(host_path_component(prefix.as_os_str())?),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if result.pop().is_none() {
                    return Err(capsec_semantics::Error::ArmRefused(
                        "typed host path escapes above its absolute root".into(),
                    ));
                }
            }
            Component::Normal(value) => result.push(host_path_component(value)?),
        }
    }
    Ok(result)
}

#[cfg(unix)]
fn fd_descends_from_object(
    fd: std::os::fd::RawFd,
    expected_root: &capsec_semantics::model::ObjectIdentity,
) -> capsec_semantics::Result<bool> {
    use std::os::fd::{AsRawFd, FromRawFd};

    if fd < 0 {
        return Ok(false);
    }
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Ok(false);
    }
    let mut current = unsafe { std::fs::File::from_raw_fd(duplicate) };
    for _ in 0..1024 {
        let metadata = current.metadata().map_err(|error| {
            capsec_semantics::Error::ArmRefused(format!(
                "cannot inspect retained filesystem parent: {error}"
            ))
        })?;
        let current_object = object_identity_for_metadata(&metadata)?;
        if &current_object == expected_root {
            return Ok(true);
        }
        if !metadata.is_dir() {
            return Ok(false);
        }

        let parent_fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                b"..\0".as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if parent_fd < 0 {
            return Ok(false);
        }
        let parent = unsafe { std::fs::File::from_raw_fd(parent_fd) };
        let parent_object = object_identity_for_metadata(&parent.metadata().map_err(|error| {
            capsec_semantics::Error::ArmRefused(format!(
                "cannot inspect retained filesystem ancestry: {error}"
            ))
        })?)?;
        if parent_object == current_object {
            return Ok(false);
        }
        current = parent;
    }
    Err(capsec_semantics::Error::ArmRefused(
        "retained filesystem ancestry exceeds the supported depth".into(),
    ))
}

/// Authenticate the snapshot's exact target claim against the checked product
/// registry and return the disposition used by every live effect gate.  The
/// snapshot/launcher cannot assert completeness with a boolean: the target
/// must be advertised and every generated edge must have one non-unsupported
/// cell for the exact canonical feature set.
/// @ref LLP 0021#default-and-target-claim
fn authenticated_target_cells(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
) -> capsec_semantics::Result<BTreeMap<String, capsec_semantics::decision::TargetCellDisposition>> {
    use capsec_semantics::decision::TargetCellDisposition;
    use capsec_semantics::Error;

    let rules: serde_json::Value = serde_json::from_str(
        crate::capsec_registry_generated::CAPSEC_POLICY_RULES_JSON,
    )
    .map_err(|error| Error::InvalidModel(format!("invalid checked policy rules: {error}")))?;
    let cells: serde_json::Value = serde_json::from_str(
        crate::capsec_registry_generated::CAPSEC_TARGET_CELLS_JSON,
    )
    .map_err(|error| Error::InvalidModel(format!("invalid checked target cells: {error}")))?;
    let target = snapshot.engine_target()?;
    let features = snapshot.engine_features()?;
    if features.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::ArmRefused(
            "engine feature set is not canonical, sorted, and unique".into(),
        ));
    }
    let feature_values = features
        .iter()
        .cloned()
        .map(serde_json::Value::String)
        .collect::<Vec<_>>();
    let advertised = rules
        .pointer("/initialProfile/advertisedTargets")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|targets| {
            targets.iter().any(|candidate| {
                candidate.get("triple").and_then(serde_json::Value::as_str) == Some(target.as_str())
                    && candidate
                        .get("features")
                        .and_then(serde_json::Value::as_array)
                        == Some(&feature_values)
            })
        });
    if !advertised {
        return Err(Error::ArmRefused(format!(
            "engine target {target} with its exact features is not advertised"
        )));
    }

    let rows = cells
        .get("cells")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::InvalidModel("checked target cells are missing cells".into()))?;
    let mut result = BTreeMap::new();
    for edge in crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS {
        let matching = rows
            .iter()
            .filter(|row| {
                row.get("edgeId").and_then(serde_json::Value::as_str) == Some(*edge)
                    && row
                        .pointer("/target/triple")
                        .and_then(serde_json::Value::as_str)
                        == Some(target.as_str())
                    && row
                        .pointer("/target/features")
                        .and_then(serde_json::Value::as_array)
                        == Some(&feature_values)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(Error::ArmRefused(format!(
                "target has no unique cell for coverage edge {edge}"
            )));
        }
        let disposition = match matching[0]
            .get("disposition")
            .and_then(serde_json::Value::as_str)
        {
            Some("enforced" | "non-capability") => TargetCellDisposition::Complete,
            Some("closed" | "absent") => TargetCellDisposition::Closed,
            Some("unsupported") => {
                return Err(Error::ArmRefused(format!(
                    "target coverage edge {edge} remains unsupported"
                )))
            }
            Some(other) => {
                return Err(Error::InvalidModel(format!(
                    "unknown target-cell disposition {other}"
                )))
            }
            None => return Err(Error::InvalidModel("target cell lacks disposition".into())),
        };
        result.insert((*edge).to_owned(), disposition);
    }
    Ok(result)
}

fn host_path_component(
    value: &std::ffi::OsStr,
) -> capsec_semantics::Result<capsec_semantics::model::PathComponent> {
    use capsec_semantics::model::PathComponent;
    if let Some(value) = value.to_str() {
        return PathComponent::utf8(value.to_owned())
            .map_err(capsec_semantics::Error::InvalidModel);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathComponent::binary(value.as_bytes().to_vec())
            .map_err(capsec_semantics::Error::InvalidModel)
    }
    #[cfg(not(unix))]
    Err(capsec_semantics::Error::ArmRefused(
        "non-Unicode host path cannot be represented on this target".into(),
    ))
}

fn host_path_from_binding(
    binding: &capsec_semantics::arming::ArmedRootBinding,
) -> capsec_semantics::Result<std::path::PathBuf> {
    if binding.host_path.root != capsec_semantics::model::LogicalRoot::Absolute
        || binding.host_path.host_bound != Some(true)
    {
        return Err(capsec_semantics::Error::ArmRefused(
            "armed root binding is not an absolute host binding".into(),
        ));
    }
    let mut path = std::path::PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
    for component in &binding.host_path.components {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            path.push(std::ffi::OsStr::from_bytes(component.bytes()));
        }
        #[cfg(not(unix))]
        {
            let text = std::str::from_utf8(component.bytes()).map_err(|_| {
                capsec_semantics::Error::ArmRefused(
                    "non-Unicode armed root cannot be represented on this target".into(),
                )
            })?;
            path.push(text);
        }
    }
    Ok(path)
}

fn object_identity_for_host_path(
    path: &std::path::Path,
) -> capsec_semantics::Result<capsec_semantics::model::ObjectIdentity> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        capsec_semantics::Error::ArmRefused(format!(
            "cannot revalidate armed root {}: {error}",
            path.display()
        ))
    })?;
    object_identity_for_metadata(&metadata)
}

fn object_identity_for_metadata(
    metadata: &std::fs::Metadata,
) -> capsec_semantics::Result<capsec_semantics::model::ObjectIdentity> {
    use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(ObjectIdentity {
            platform: if cfg!(any(target_os = "macos", target_os = "ios")) {
                ObjectPlatform::Apple
            } else if cfg!(target_os = "android") {
                ObjectPlatform::Android
            } else {
                ObjectPlatform::Unix
            },
            volume: NonEmptyString::new(format!("dev:{}", metadata.dev()))
                .map_err(capsec_semantics::Error::InvalidModel)?,
            file: NonEmptyString::new(format!("ino:{}", metadata.ino()))
                .map_err(capsec_semantics::Error::InvalidModel)?,
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(ObjectIdentity {
            platform: ObjectPlatform::Windows,
            volume: NonEmptyString::new(format!(
                "volume:{}",
                metadata.volume_serial_number().unwrap_or(0)
            ))
            .map_err(capsec_semantics::Error::InvalidModel)?,
            file: NonEmptyString::new(format!("file:{}", metadata.file_index().unwrap_or(0)))
                .map_err(capsec_semantics::Error::InvalidModel)?,
        })
    }
}

fn validate_armed_binding_object(
    binding: &capsec_semantics::arming::ArmedRootBinding,
) -> capsec_semantics::Result<()> {
    let path = host_path_from_binding(binding)?;
    if object_identity_for_host_path(&path)? != binding.object {
        return Err(capsec_semantics::Error::ArmRefused(format!(
            "armed root object changed after arming: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
static ROOT_SOURCE_OPEN_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<(std::path::PathBuf, std::sync::Arc<std::sync::Barrier>)>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn pause_before_authenticated_root_open(path: &std::path::Path) {
    let hook = ROOT_SOURCE_OPEN_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .and_then(|hook| hook.as_ref().cloned());
    if let Some((target, barrier)) = hook {
        if target == path {
            barrier.wait();
            barrier.wait();
        }
    }
}

/// Read a first-party source through the exact authenticated root directory
/// object. Each component is opened relative to a pinned directory descriptor
/// with no-follow semantics, so renaming or replacing the root between module
/// resolution and source read cannot redirect the load.
fn authenticated_source_beneath_binding(
    binding: &capsec_semantics::arming::ArmedRootBinding,
    source_path: &std::path::Path,
) -> anyhow::Result<Vec<u8>> {
    let root = host_path_from_binding(binding)?;
    let relative = source_path.strip_prefix(&root).with_context(|| {
        format!(
            "module source {} is outside authenticated root {}",
            source_path.display(),
            root.display()
        )
    })?;
    let components = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => Ok(value.to_owned()),
            _ => Err(anyhow::anyhow!(
                "module source has a non-relative component beneath its authenticated root"
            )),
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if components.is_empty() {
        anyhow::bail!("authenticated module source resolves to a root directory");
    }

    #[cfg(test)]
    pause_before_authenticated_root_open(&root);

    #[cfg(unix)]
    {
        use std::io::Read as _;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut current = options
            .open(&root)
            .with_context(|| format!("cannot open authenticated root {}", root.display()))?;
        let actual_root = object_identity_for_metadata(&current.metadata()?)?;
        if actual_root != binding.object {
            anyhow::bail!(
                "authenticated root object changed before module source read: {}",
                root.display()
            );
        }

        for (index, component) in components.iter().enumerate() {
            let component = std::ffi::CString::new(component.as_bytes())
                .map_err(|_| anyhow::anyhow!("module source contains a NUL path component"))?;
            let last = index + 1 == components.len();
            let flags = if last {
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
            } else {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
            };
            let fd = unsafe { libc::openat(current.as_raw_fd(), component.as_ptr(), flags) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "cannot open authenticated module source {}",
                        source_path.display()
                    )
                });
            }
            let opened = unsafe { std::fs::File::from_raw_fd(fd) };
            if last {
                if !opened.metadata()?.is_file() {
                    anyhow::bail!(
                        "authenticated module source is not a regular file: {}",
                        source_path.display()
                    );
                }
                let mut bytes = Vec::new();
                let mut opened = opened;
                opened.read_to_end(&mut bytes).with_context(|| {
                    format!(
                        "cannot read authenticated module source {}",
                        source_path.display()
                    )
                })?;
                return Ok(bytes);
            }
            current = opened;
        }
        unreachable!("nonempty authenticated source path returns on its final component")
    }

    #[cfg(not(unix))]
    {
        let _ = (binding, source_path);
        anyhow::bail!(
            "armed module source authentication requires descriptor-relative no-follow opens on this target"
        )
    }
}

fn validate_snapshot_root_bindings(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
) -> capsec_semantics::Result<()> {
    let bindings = snapshot.root_bindings()?;
    for binding in &bindings {
        validate_armed_binding_object(binding)?;
    }
    for principal in snapshot
        .import_policies()?
        .keys()
        .filter(|principal| principal.is_package())
    {
        let matches = bindings
            .iter()
            .filter(|binding| {
                binding.logical_root == capsec_semantics::model::LogicalRoot::Package
                    && binding.owner.as_ref() == Some(principal)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(capsec_semantics::Error::ArmRefused(
                "package principal lacks one exact authenticated root binding".into(),
            ));
        }
        let capsec_semantics::model::Principal::Package { integrity, .. } = principal else {
            unreachable!();
        };
        let root = host_path_from_binding(matches[0])?;
        let actual = crate::module_loader::package_tree_integrity(&root).map_err(|error| {
            capsec_semantics::Error::ArmRefused(format!(
                "failed to authenticate package content {}: {error}",
                root.display()
            ))
        })?;
        if actual != integrity.as_str() {
            return Err(capsec_semantics::Error::ArmRefused(format!(
                "installed package content differs from armed integrity at {}",
                root.display()
            )));
        }
    }
    Ok(())
}

fn validate_loaded_engine_identity(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
) -> capsec_semantics::Result<()> {
    let identity = crate::engine::loaded_engine_binary_identity()
        .map_err(capsec_semantics::Error::ArmRefused)?;
    if snapshot.document()["engine"]["binaryDigest"].as_str()
        != Some(identity.binary_digest.as_str())
    {
        return Err(capsec_semantics::Error::ArmRefused(
            "armed engine digest does not identify the loaded Hermes artifact".into(),
        ));
    }
    let protected = snapshot.document()["protectedObjects"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["role"].as_str() == Some("engine-binary"))
        })
        .and_then(|row| serde_json::from_value(row["object"].clone()).ok());
    if protected.as_ref() != Some(&identity.object) {
        return Err(capsec_semantics::Error::ArmRefused(
            "protected engine object does not identify the loaded Hermes artifact".into(),
        ));
    }
    Ok(())
}

fn classify_network_peer(
    address: capsec_semantics::model::IpAddress,
) -> Option<capsec_semantics::model::PeerClass> {
    network_classifier_rules()?.classify(address.get())
}

#[derive(Debug)]
struct NetworkClassifierRules {
    classes: Vec<(capsec_semantics::model::PeerClass, Vec<IpCidr>)>,
    fallback: capsec_semantics::model::PeerClass,
}

impl NetworkClassifierRules {
    fn classify(&self, address: IpAddr) -> Option<capsec_semantics::model::PeerClass> {
        // @ref LLP 0021#default-and-target-claim — IPv4-mapped IPv6 is
        // classified through its embedded IPv4 address and may never fall
        // through to a broader IPv6/public class.
        let address = match address {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
            address => address,
        };
        self.classes
            .iter()
            .find_map(|(class, cidrs)| {
                cidrs
                    .iter()
                    .any(|cidr| cidr.contains(address))
                    .then_some(*class)
            })
            .or(Some(self.fallback))
    }
}

#[derive(Debug)]
enum IpCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpCidr {
    fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = text.split_once('/')?;
        let prefix = prefix.parse::<u8>().ok()?;
        match address.parse::<IpAddr>().ok()? {
            IpAddr::V4(address) if prefix <= 32 => {
                let mask = prefix_mask_v4(prefix);
                let address = u32::from(address);
                (address & mask == address).then_some(Self::V4 {
                    network: address,
                    prefix,
                })
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let mask = prefix_mask_v6(prefix);
                let address = u128::from(address);
                (address & mask == address).then_some(Self::V6 {
                    network: address,
                    prefix,
                })
            }
            _ => None,
        }
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                u32::from(address) & prefix_mask_v4(*prefix) == *network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                u128::from(address) & prefix_mask_v6(*prefix) == *network
            }
            _ => false,
        }
    }
}

fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn network_classifier_rules() -> Option<&'static NetworkClassifierRules> {
    static RULES: OnceLock<Option<NetworkClassifierRules>> = OnceLock::new();
    RULES
        .get_or_init(|| {
            let document: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/capsec/registry/policy-rules.json"
            )))
            .ok()?;
            let network = document.get("classifierRules")?.get("network")?;
            let precedence = network.get("precedence")?.as_array()?;
            let class_rows = network.get("classes")?.as_array()?;
            let mut by_name = BTreeMap::new();
            for row in class_rows {
                let name = row.get("class")?.as_str()?.to_owned();
                let cidrs = row
                    .get("cidrs")?
                    .as_array()?
                    .iter()
                    .map(|cidr| IpCidr::parse(cidr.as_str()?))
                    .collect::<Option<Vec<_>>>()?;
                // A duplicate class must not be silently overwritten: doing
                // so would make runtime classification depend on JSON row
                // order while the digest-bound registry claims one rule set.
                if by_name.insert(name, cidrs).is_some() {
                    return None;
                }
            }
            let classes = precedence
                .iter()
                .map(|name| {
                    let name = name.as_str()?;
                    Some((peer_class_from_rule(name)?, by_name.remove(name)?))
                })
                .collect::<Option<Vec<_>>>()?;
            if !by_name.is_empty() {
                return None;
            }
            Some(NetworkClassifierRules {
                classes,
                fallback: peer_class_from_rule(network.get("fallback")?.as_str()?)?,
            })
        })
        .as_ref()
}

fn peer_class_from_rule(text: &str) -> Option<capsec_semantics::model::PeerClass> {
    use capsec_semantics::model::PeerClass;
    Some(match text {
        "public" => PeerClass::Public,
        "private" => PeerClass::Private,
        "loopback" => PeerClass::Loopback,
        "link-local" => PeerClass::LinkLocal,
        "carrier-grade-nat" => PeerClass::CarrierGradeNat,
        "unique-local" => PeerClass::UniqueLocal,
        "unspecified" => PeerClass::Unspecified,
        "multicast" => PeerClass::Multicast,
        "metadata" => PeerClass::Metadata,
        "reserved" => PeerClass::Reserved,
        _ => return None,
    })
}

fn typed_import_allowed(
    policy: &capsec_semantics::arming::PrincipalImportPolicy,
    specifier: &str,
) -> bool {
    let without_node = specifier.strip_prefix("node:").unwrap_or(specifier);
    let builtin_root = without_node.split('/').next().unwrap_or(without_node);
    // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces — Terminal builtins remain absent even if an authenticated artifact erroneously lists them.
    if matches!(
        builtin_root,
        "async_hooks" | "inspector" | "vm" | "wasi" | "worker_threads"
    ) {
        return false;
    }
    if crate::module_loader::RUNTIME_GATED_NODE_BUILTINS.contains(&builtin_root) {
        return policy.builtins.iter().any(|allowed| {
            let allowed = allowed.strip_prefix("node:").unwrap_or(allowed);
            allowed.split('/').next().unwrap_or(allowed) == builtin_root
        });
    }

    let requested_package = package_name_from_specifier(specifier);
    policy.packages.iter().any(|allowed| {
        allowed == specifier || package_name_from_specifier(allowed) == requested_package
    })
}

fn is_module_path_specifier(specifier: &str) -> bool {
    specifier.starts_with("./")
        || specifier.starts_with("../")
        || std::path::Path::new(specifier).is_absolute()
}

fn fresh_typed_handle_id(
    handles: &[capsec_semantics::decision::BearerHandle],
) -> capsec_semantics::Result<capsec_semantics::model::NonEmptyString> {
    for _ in 0..32 {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|error| {
            capsec_semantics::Error::ArmRefused(format!(
                "OS randomness unavailable for handle mint: {error}"
            ))
        })?;
        let id = capsec_semantics::model::NonEmptyString::new(format!(
            "h-{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
        .map_err(capsec_semantics::Error::InvalidModel)?;
        if handles.iter().all(|handle| handle.handle_id != id) {
            return Ok(id);
        }
    }
    Err(capsec_semantics::Error::ArmRefused(
        "could not allocate a unique handle id".into(),
    ))
}

fn package_name_from_specifier(specifier: &str) -> &str {
    if specifier.starts_with('@') {
        let Some(slash) = specifier.find('/') else {
            return specifier;
        };
        let package_end = specifier[slash + 1..]
            .find(['/', '@'])
            .map(|relative| slash + 1 + relative)
            .unwrap_or(specifier.len());
        return &specifier[..package_end];
    }
    let root = specifier.split('/').next().unwrap_or(specifier);
    if let Some(version) = root.find('@') {
        &root[..version]
    } else {
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn retained_parent_ancestry_rejects_root_a_b_a_substitution() {
        use std::os::unix::fs::OpenOptionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let original = temp.path().join("original");
        let substitute = temp.path().join("substitute");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::create_dir_all(substitute.join("nested")).unwrap();
        let expected = object_identity_for_host_path(&root).unwrap();
        let open_dir = |path: &std::path::Path| {
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW);
            options.open(path).unwrap()
        };
        let authentic_parent = open_dir(&root.join("nested"));

        std::fs::rename(&root, &original).unwrap();
        std::fs::rename(&substitute, &root).unwrap();
        let substituted_parent = open_dir(&root.join("nested"));
        std::fs::rename(&root, &substitute).unwrap();
        std::fs::rename(&original, &root).unwrap();

        use std::os::fd::AsRawFd;
        assert!(fd_descends_from_object(authentic_parent.as_raw_fd(), &expected).unwrap());
        assert!(!fd_descends_from_object(substituted_parent.as_raw_fd(), &expected).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn first_party_source_read_rejects_root_swap_at_open() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let original = temp.path().join("original");
        let substitute = temp.path().join("substitute");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(substitute.join("src")).unwrap();
        std::fs::write(root.join("src/main.js"), b"authentic").unwrap();
        std::fs::write(substitute.join("src/main.js"), b"substitute").unwrap();
        let binding = capsec_semantics::arming::ArmedRootBinding {
            logical_root: capsec_semantics::model::LogicalRoot::Project,
            owner: None,
            logical_path: None,
            host_path: capsec_semantics::model::LogicalPath {
                root: capsec_semantics::model::LogicalRoot::Absolute,
                components: host_path_components(&root).unwrap(),
                host_bound: Some(true),
            },
            object: object_identity_for_host_path(&root).unwrap(),
        };
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        *ROOT_SOURCE_OPEN_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((root.clone(), barrier.clone()));
        let source = root.join("src/main.js");
        let worker =
            std::thread::spawn(move || authenticated_source_beneath_binding(&binding, &source));

        barrier.wait();
        std::fs::rename(&root, &original).unwrap();
        std::fs::rename(&substitute, &root).unwrap();
        barrier.wait();
        let result = worker.join().unwrap();
        *ROOT_SOURCE_OPEN_HOOK.get().unwrap().lock().unwrap() = None;
        assert!(result.is_err());
    }

    fn test_project_root() -> &'static std::path::Path {
        static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        ROOT.get_or_init(|| {
            let root =
                std::env::temp_dir().join(format!("ibex-armed-host-tests-{}", std::process::id()));
            std::fs::create_dir_all(root.join("images")).unwrap();
            std::fs::write(root.join("images/photo.jpg"), b"test image").unwrap();
            // macOS exposes /var as a symlink to /private/var. Model the
            // authenticated binding with the same canonical host spelling
            // that the production path mapper validates.
            std::fs::canonicalize(root).unwrap()
        })
    }

    fn example_armed_host() -> Host {
        example_armed_host_with(|_| {})
    }

    fn example_armed_host_with(mutator: impl FnOnce(&mut serde_json::Value)) -> Host {
        use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
        use capsec_semantics::model::Digest;

        let source = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        ));
        let mut value: serde_json::Value = serde_json::from_slice(source).unwrap();
        value["workflow"] = serde_json::Value::String("production".into());
        value["effectiveMode"] = serde_json::Value::String("enforce".into());
        mutator(&mut value);
        let project_root = test_project_root();
        value["rootBindings"][1]["hostPath"]["components"] =
            serde_json::to_value(host_path_components(project_root).unwrap()).unwrap();
        value["rootBindings"][1]["object"] =
            serde_json::to_value(object_identity_for_host_path(project_root).unwrap()).unwrap();
        let digest = capsec_semantics::digest::compute_checked_contract_digest(
            capsec_semantics::digest::DigestKind::ArmedSnapshot,
            &value,
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
        };
        let snapshot = ArmedSnapshot::load(&bytes, &expected).unwrap();
        unsafe { Host::new_armed_for_test(HostConfig::default(), Arc::new(snapshot)).unwrap() }
    }

    #[test]
    fn every_generated_closed_startup_environment_name_is_rejected_even_when_empty() {
        struct EnvironmentRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for EnvironmentRestore {
            fn drop(&mut self) {
                for (name, value) in &self.0 {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }

        let _lock = crate::host::abi::host_test_lock();
        let names = crate::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES;
        let _restore = EnvironmentRestore(
            names
                .iter()
                .map(|name| (*name, std::env::var_os(name)))
                .collect(),
        );
        for name in names {
            for other in names {
                std::env::remove_var(other);
            }
            std::env::set_var(name, "");
            let error = reject_closed_startup_environment().unwrap_err();
            assert!(error.to_string().contains(name), "{name}: {error:#}");
        }
        for name in names {
            std::env::remove_var(name);
        }
        reject_closed_startup_environment()
            .expect("a clean caller environment must permit normal production startup");
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
        assert_eq!(classify("168.63.129.16"), PeerClass::Metadata);
        assert_eq!(classify("169.254.170.2"), PeerClass::Metadata);
        assert_eq!(classify("fd00:ec2::254"), PeerClass::Metadata);
        assert_eq!(classify("10.0.0.1"), PeerClass::Private);
        assert_eq!(classify("100.64.0.1"), PeerClass::CarrierGradeNat);
        assert_eq!(classify("127.0.0.1"), PeerClass::Loopback);
        assert_eq!(classify("fe80::a9fe:a9fe"), PeerClass::Metadata);
        assert_eq!(classify("fd00::1"), PeerClass::UniqueLocal);
        assert_eq!(classify("2001:db8::1"), PeerClass::Reserved);
        // Public stays closed until a pinned IANA snapshot is admitted to the
        // digest-bound registry. Unmatched addresses therefore fail closed.
        assert_eq!(classify("8.8.8.8"), PeerClass::Reserved);
    }

    #[test]
    fn peer_classifier_routes_ipv4_mapped_ipv6_through_embedded_ipv4() {
        use capsec_semantics::model::{IpAddress, PeerClass};
        let classify = |address: &str| {
            classify_network_peer(IpAddress::new(address.parse().unwrap())).unwrap()
        };
        for (address, expected) in [
            ("::ffff:169.254.169.254", PeerClass::Metadata),
            ("::ffff:0.0.0.0", PeerClass::Unspecified),
            ("::ffff:127.0.0.1", PeerClass::Loopback),
            ("::ffff:169.254.1.1", PeerClass::LinkLocal),
            ("::ffff:100.64.0.1", PeerClass::CarrierGradeNat),
            ("::ffff:10.0.0.1", PeerClass::Private),
            ("::ffff:224.0.0.1", PeerClass::Multicast),
            ("::ffff:192.0.2.1", PeerClass::Reserved),
            ("::ffff:8.8.8.8", PeerClass::Reserved),
        ] {
            assert_eq!(classify(address), expected, "{address}");
        }
    }

    #[test]
    fn armed_host_evaluates_typed_authority_and_records_structured_evidence() {
        use capsec_semantics::decision::{DecisionOutcome, EffectGate};
        use capsec_semantics::model::DecisionSet;

        let host = example_armed_host();
        let root = host.typed_principal_for_module("0").unwrap();
        let photo = test_project_root().join("images/photo.jpg");
        let mapped = host.typed_logical_path(&root, &photo).unwrap();
        assert_eq!(mapped.root, capsec_semantics::model::LogicalRoot::Project);
        assert_eq!(mapped.components.len(), 2);
        assert!(host.typed_principal_for_module("999").is_none());
        let open_path = photo.as_path();
        let requested_open = host
            .authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![host.typed_principal_for_module("0").unwrap()],
                open_path,
                capsec_semantics::model::Stage::Requested,
                capsec_semantics::model::ObjectState::Existing,
                capsec_semantics::model::FollowMode::FollowFinal,
                true,
                None,
                true,
                false,
                None,
                None,
                None,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            requested_open.outcome,
            capsec_semantics::decision::DecisionOutcome::Allow
        );
        let object = |file: &str| capsec_semantics::model::ObjectIdentity {
            platform: capsec_semantics::model::ObjectPlatform::Apple,
            volume: capsec_semantics::model::NonEmptyString::new("dev:test").unwrap(),
            file: capsec_semantics::model::NonEmptyString::new(file).unwrap(),
        };
        let discovered_open = host
            .authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![host.typed_principal_for_module("0").unwrap()],
                open_path,
                capsec_semantics::model::Stage::Discovery,
                capsec_semantics::model::ObjectState::Existing,
                capsec_semantics::model::FollowMode::FollowFinal,
                true,
                Some(test_project_root().join("images").as_path()),
                true,
                false,
                Some(object("parent")),
                Some(object("photo")),
                None,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            discovered_open.outcome,
            capsec_semantics::decision::DecisionOutcome::Allow
        );
        let committed_open = host
            .authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![host.typed_principal_for_module("0").unwrap()],
                open_path,
                capsec_semantics::model::Stage::Commit,
                capsec_semantics::model::ObjectState::Existing,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                Some(test_project_root().join("images").as_path()),
                true,
                false,
                Some(object("parent")),
                Some(object("photo")),
                Some(capsec_semantics::model::NonEmptyString::new("fd:7").unwrap()),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            committed_open.outcome,
            capsec_semantics::decision::DecisionOutcome::Allow
        );
        let repeated_open = host
            .authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![host.typed_principal_for_module("0").unwrap()],
                open_path,
                capsec_semantics::model::Stage::Repeat,
                capsec_semantics::model::ObjectState::Existing,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                Some(test_project_root().join("images").as_path()),
                true,
                false,
                Some(object("parent")),
                Some(object("photo")),
                Some(capsec_semantics::model::NonEmptyString::new("fd:7").unwrap()),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            repeated_open.outcome,
            capsec_semantics::decision::DecisionOutcome::Allow
        );
        assert!(!host.check_capability("0", "fs:read:/anything"));
        assert!(!host.check_capability_stack(&["0"], "fs:read:/anything"));
        assert!(!host.check_import("0", "node:fs"));
        assert!(host.check_import("0", "image-lib"));
        assert!(host.check_import("0", "image-lib/subpath"));
        assert!(!host.check_import("0", "other-lib"));
        host.register_module_package(
            "7",
            "image-lib",
            Some("image-lib@2.4.1"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        let deputy_principals = vec![
            host.typed_principal_for_module("0").unwrap(),
            host.typed_principal_for_module("7").unwrap(),
        ];
        let deputy_principals =
            capsec_semantics::model::canonicalize_principal_set(deputy_principals).unwrap();
        let deputy_write = host
            .authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                deputy_principals,
                open_path,
                capsec_semantics::model::Stage::Commit,
                capsec_semantics::model::ObjectState::Existing,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                Some(test_project_root().join("images").as_path()),
                false,
                true,
                Some(object("parent")),
                Some(object("photo")),
                Some(capsec_semantics::model::NonEmptyString::new("fd:9").unwrap()),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(
            deputy_write.outcome,
            capsec_semantics::decision::DecisionOutcome::Deny
        );
        assert!(host.check_import("7", "node:fs"));
        assert!(host.check_import("7", "node:fs/promises"));
        assert!(!host.check_import("7", "node:http"));
        assert!(!host.check_import("7", "other-lib"));
        host.register_module_package(
            "8",
            "image-lib",
            Some("image-lib@9.9.9"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        assert!(!host.check_import("8", "node:fs"));
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

        host.begin_conformance_observation("enforcement.test.fs.read");
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
        assert_eq!(evidence.len(), 7);
        assert_eq!(evidence[5].outcome, DecisionOutcome::Allow);
        assert_eq!(evidence[6].outcome, DecisionOutcome::Deny);
        assert_eq!(
            evidence[5].identity.armed_snapshot_digest,
            host.armed_snapshot().unwrap().digest().clone()
        );
        let observed = host.take_typed_conformance_observations();
        assert_eq!(observed.len(), 2);
        assert!(observed
            .iter()
            .all(|row| row.terminal_branch_id == "enforcement.test.fs.read"));
        assert_eq!(
            observed[0].decision_set.operation_id.as_str(),
            "read-photo.jpg"
        );
        assert_eq!(observed[0].gates, gates);
        assert_eq!(observed[0].evidence.outcome, DecisionOutcome::Allow);
        assert_eq!(observed[1].decision_set, denied_set);
        assert_eq!(observed[1].evidence.outcome, DecisionOutcome::Deny);
        assert!(host.take_typed_conformance_observations().is_empty());
    }

    #[test]
    fn concurrent_typed_decisions_keep_their_own_atomic_evidence() {
        use capsec_semantics::decision::EffectGate;
        use capsec_semantics::model::DecisionSet;
        use std::sync::{Arc, Barrier};

        let host = example_armed_host();
        let gate: EffectGate = serde_json::from_value(serde_json::json!({
            "coverageEdgeId": "test.fs.concurrent-read",
            "targetCell": "complete",
            "definitionAndEdgePredicatesSatisfied": true
        }))
        .unwrap();
        let make_set = |operation: &str| -> DecisionSet {
            serde_json::from_value(serde_json::json!({
                "decisionSetSchema": "ibex/capsec-decision-set/1",
                "operationId": operation,
                "atomicityGroup": "test.fs.concurrent-read",
                "combination": "conjunction",
                "context": {
                    "stage": "commit",
                    "actor": {"kind": "root", "identity": "project-root"},
                    "constrainedPrincipals": [{"kind": "root", "identity": "project-root"}]
                },
                "effects": [{
                    "cap": "fs:read",
                    "effectOwner": {"kind": "root", "identity": "project-root"},
                    "resource": {
                        "kind": "path-occurrence",
                        "requested": {"root": "project", "components": [
                            {"encoding": "utf8", "value": "concurrent.txt"}
                        ]},
                        "followMode": "follow-final",
                        "objectState": "existing",
                        "parentObject": {"platform": "unix", "volume": "dev-test", "file": "parent-concurrent"},
                        "finalObject": {"platform": "unix", "volume": "dev-test", "file": "file-concurrent"},
                        "retainedHandle": "fd:concurrent"
                    }
                }]
            }))
            .unwrap()
        };
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for operation in ["concurrent-a", "concurrent-b"] {
            let host = host.clone();
            let gate = gate.clone();
            let set = make_set(operation);
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let result = host
                    .evaluate_typed_decision_with_evidence(&set, &[gate])
                    .unwrap();
                assert_eq!(result.evidence.operation_id.as_str(), operation);
                assert_eq!(result.evidence.actor, set.context.actor);
                barrier.wait();
            }));
        }
        barrier.wait();
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn typed_fetch_stages_bind_candidates_and_always_reject_metadata_peers() {
        use capsec_semantics::decision::DecisionOutcome;
        use capsec_semantics::model::{
            ConcreteHost, DnsName, FetchScheme, IpAddress, NonEmptyString, Port, Stage,
            VerifiedPeer,
        };

        let host = example_armed_host_with(|value| {
            value["principals"][0]["floor"] = serde_json::json!([{
                "cap": "network:fetch",
                "resource": {
                    "kind": "fetch-endpoint",
                    "schemes": ["https"],
                    "host": {"kind": "dns-name", "name": "api.example.com"},
                    "port": {"kind": "exact", "value": 443},
                    "peerClasses": ["reserved"],
                    "route": {"kind": "direct"}
                }
            }]);
            value["principals"][0]["denials"] = serde_json::json!([]);
        });
        let principal = host.typed_principal_for_module("0").unwrap();
        let requested_host = ConcreteHost::DnsName {
            name: DnsName::new("api.example.com").unwrap(),
        };
        let port = Port::new(443).unwrap();

        let requested = host
            .authorize_typed_fetch_stage(
                "0",
                vec![principal.clone()],
                FetchScheme::Https,
                requested_host.clone(),
                port,
                Stage::Requested,
                vec![],
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(requested.outcome, DecisionOutcome::Allow);

        let candidate_address = IpAddress::new("93.184.216.34".parse().unwrap());
        let candidate = host
            .authorize_typed_fetch_stage(
                "0",
                vec![principal.clone()],
                FetchScheme::Https,
                requested_host.clone(),
                port,
                Stage::Candidate,
                vec![candidate_address],
                Some(candidate_address),
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(candidate.outcome, DecisionOutcome::Allow);

        let committed = host
            .authorize_typed_fetch_stage(
                "0",
                vec![principal.clone()],
                FetchScheme::Https,
                requested_host.clone(),
                port,
                Stage::Commit,
                vec![candidate_address],
                Some(candidate_address),
                Some(VerifiedPeer {
                    address: candidate_address,
                    port,
                }),
                Some(NonEmptyString::new("connection-1").unwrap()),
                None,
            )
            .unwrap();
        assert_eq!(committed.outcome, DecisionOutcome::Allow);

        for protected in [
            "169.254.169.254",
            "169.254.170.2",
            "100.100.100.200",
            "168.63.129.16",
            "fd00:ec2::254",
            "fe80::a9fe:a9fe",
            "::ffff:169.254.169.254",
        ] {
            let protected = IpAddress::new(protected.parse().unwrap());
            let error = host
                .authorize_typed_fetch_stage(
                    "0",
                    vec![principal.clone()],
                    FetchScheme::Https,
                    requested_host.clone(),
                    port,
                    Stage::Candidate,
                    vec![protected],
                    Some(protected),
                    None,
                    None,
                    None,
                )
                .unwrap_err();
            assert!(error.to_string().contains("always denied"), "{error}");
        }

        let metadata = IpAddress::new("169.254.169.254".parse().unwrap());
        let mixed_error = host
            .authorize_typed_fetch_stage(
                "0",
                vec![principal],
                FetchScheme::Https,
                requested_host,
                port,
                Stage::Candidate,
                vec![candidate_address, metadata],
                Some(candidate_address),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            mixed_error.to_string().contains("always denied"),
            "{mixed_error}"
        );
    }

    #[test]
    fn armed_terminal_builtins_stay_closed_even_if_snapshot_lists_them() {
        let host = example_armed_host_with(|value| {
            value["principals"][1]["imports"]["builtins"] = serde_json::json!([
                "node:async_hooks",
                "node:fs",
                "node:inspector",
                "node:inspector/promises",
                "node:vm",
                "node:wasi",
                "node:worker_threads"
            ]);
        });
        host.register_module_package(
            "7",
            "image-lib",
            Some("image-lib@2.4.1"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        assert!(host.check_import("7", "node:fs"));
        for specifier in [
            "async_hooks",
            "node:async_hooks",
            "inspector",
            "node:inspector/promises",
            "vm",
            "node:wasi",
            "worker_threads",
        ] {
            assert!(!host.check_import("7", specifier), "{specifier}");
        }
    }

    #[test]
    fn typed_connect_is_distinct_from_fetch_and_binds_the_verified_peer() {
        use capsec_semantics::decision::DecisionOutcome;
        use capsec_semantics::model::{
            ConcreteHost, ConnectTransport, DnsName, IpAddress, NonEmptyString, Port, Stage,
            VerifiedPeer,
        };

        let selector = serde_json::json!({
            "cap": "network:connect",
            "resource": {
                "kind": "connect-endpoint",
                "transport": "tcp",
                "host": {"kind": "dns-name", "name": "api.example.com"},
                "port": {"kind": "exact", "value": 443},
                "peerClasses": ["reserved"],
                "route": {"kind": "direct"}
            }
        });
        let connect_host = example_armed_host_with(|value| {
            value["principals"][1]["floor"] = serde_json::json!([selector]);
            value["principals"][1]["denials"] = serde_json::json!([]);
        });
        connect_host.register_module_package(
            "7",
            "image-lib",
            Some("image-lib@2.4.1"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        let principal = connect_host.typed_principal_for_module("7").unwrap();
        let requested_host = ConcreteHost::DnsName {
            name: DnsName::new("api.example.com").unwrap(),
        };
        let port = Port::new(443).unwrap();
        let candidate_address = IpAddress::new("93.184.216.34".parse().unwrap());
        let decision = connect_host
            .authorize_typed_connect_stage(
                "7",
                "tcp-connect",
                "surface.native.op.exacttcpconnect.1cs9rhu",
                vec![principal],
                ConnectTransport::Tcp,
                requested_host.clone(),
                port,
                Stage::Commit,
                vec![candidate_address],
                Some(candidate_address),
                Some(VerifiedPeer {
                    address: candidate_address,
                    port,
                }),
                Some(NonEmptyString::new("tcp-connection-1").unwrap()),
            )
            .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Allow);

        let fetch_only_host = example_armed_host_with(|value| {
            value["principals"][1]["floor"] = serde_json::json!([{
                "cap": "network:fetch",
                "resource": {
                    "kind": "fetch-endpoint",
                    "schemes": ["https"],
                    "host": {"kind": "dns-name", "name": "api.example.com"},
                    "port": {"kind": "exact", "value": 443},
                    "peerClasses": ["public"],
                    "route": {"kind": "direct"}
                }
            }]);
            value["principals"][1]["denials"] = serde_json::json!([]);
        });
        fetch_only_host.register_module_package(
            "7",
            "image-lib",
            Some("image-lib@2.4.1"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        let principal = fetch_only_host.typed_principal_for_module("7").unwrap();
        let denied = fetch_only_host
            .authorize_typed_connect_stage(
                "7",
                "tcp-connect",
                "surface.native.op.exacttcpconnect.1cs9rhu",
                vec![principal],
                ConnectTransport::Tcp,
                requested_host,
                port,
                Stage::Requested,
                vec![],
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(denied.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn typed_dynamic_grant_is_ceiling_bounded_and_revocation_invalidates_it() {
        use capsec_semantics::decision::{DecisionOutcome, EffectGate};
        use capsec_semantics::model::{AuthoritySelector, DecisionSet, NonEmptyString, Principal};

        let host = example_armed_host();
        let principal_value = serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
            "locator": "image-lib@2.4.1"
        });
        let principal: Principal = serde_json::from_value(principal_value.clone()).unwrap();
        let selector: AuthoritySelector = serde_json::from_value(serde_json::json!({
            "cap": "device:location",
            "resource": {
                "kind": "device-location",
                "usage": "foreground",
                "precision": "coarse"
            }
        }))
        .unwrap();
        let decision: DecisionSet = serde_json::from_value(serde_json::json!({
            "decisionSetSchema": "ibex/capsec-decision-set/1",
            "operationId": "location-delivery",
            "atomicityGroup": "test.device.location",
            "combination": "conjunction",
            "context": {
                "stage": "delivery",
                "actor": principal_value,
                "constrainedPrincipals": [principal_value]
            },
            "effects": [{
                "cap": "device:location",
                "effectOwner": principal_value,
                "resource": {
                    "kind": "device-occurrence",
                    "requested": {
                        "kind": "device-location",
                        "usage": "foreground",
                        "precision": "coarse"
                    },
                    "brokerGeneration": 1,
                    "deviceIdentity": "test-location-provider"
                }
            }]
        }))
        .unwrap();
        let gates: Vec<EffectGate> = serde_json::from_value(serde_json::json!([{
            "coverageEdgeId": "test.device.location",
            "targetCell": "complete",
            "definitionAndEdgePredicatesSatisfied": true
        }]))
        .unwrap();

        assert_eq!(
            host.evaluate_typed_decision(&decision, &gates)
                .unwrap()
                .outcome,
            DecisionOutcome::Deny
        );
        let grant_id = NonEmptyString::new("location-session").unwrap();
        let grant_request = serde_json::to_vec(&serde_json::json!({
            "grantId": grant_id.as_str(),
            "principal": principal,
            "authority": selector
        }))
        .unwrap();
        let initial_generations = host.typed_generations().unwrap();
        assert!(host.grant_typed_dynamic_json(&grant_request).unwrap());
        let granted_generations = host.typed_generations().unwrap();
        assert_eq!(granted_generations.negative, initial_generations.negative);
        assert!(granted_generations.dynamic > initial_generations.dynamic);
        assert_eq!(granted_generations.handle, initial_generations.handle);
        assert!(!host.grant_typed_dynamic_json(&grant_request).unwrap());
        assert_eq!(
            host.evaluate_typed_decision(&decision, &gates)
                .unwrap()
                .outcome,
            DecisionOutcome::Allow
        );
        assert!(host
            .revoke_typed_dynamic_json(br#""location-session""#)
            .unwrap());
        let revoked_generations = host.typed_generations().unwrap();
        assert!(revoked_generations.negative > granted_generations.negative);
        assert!(revoked_generations.dynamic > granted_generations.dynamic);
        assert_eq!(revoked_generations.handle, granted_generations.handle);
        assert_eq!(
            host.evaluate_typed_decision(&decision, &gates)
                .unwrap()
                .outcome,
            DecisionOutcome::Deny
        );

        let too_precise: AuthoritySelector = serde_json::from_value(serde_json::json!({
            "cap": "device:location",
            "resource": {
                "kind": "device-location",
                "usage": "foreground",
                "precision": "precise"
            }
        }))
        .unwrap();
        let principal: Principal = serde_json::from_value(principal_value).unwrap();
        assert!(host
            .grant_typed_dynamic(
                NonEmptyString::new("too-precise").unwrap(),
                principal,
                too_precise,
            )
            .is_err());
        assert!(matches!(
            host.grant_typed_dynamic_json(
                br#"{"grantId":"a","grantId":"b","principal":{},"authority":{}}"#
            ),
            Err(capsec_semantics::Error::DuplicateKey { .. })
        ));
    }

    #[test]
    fn typed_handles_attenuate_delegate_and_revoke_as_a_cascade() {
        use capsec_semantics::decision::{DecisionOutcome, EffectGate};
        use capsec_semantics::model::{AuthoritySelector, DecisionSet, Principal};

        let host = example_armed_host();
        let owner_value = serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
            "locator": "image-lib@2.4.1"
        });
        let holder_value = serde_json::json!({"kind": "runtime", "identity": "delegated-consumer"});
        let owner: Principal = serde_json::from_value(owner_value).unwrap();
        let holder: Principal = serde_json::from_value(holder_value.clone()).unwrap();
        let tree: AuthoritySelector = serde_json::from_value(serde_json::json!({
            "cap": "fs:read",
            "resource": {
                "kind": "path-tree",
                "path": {
                    "root": "project",
                    "components": [{"encoding": "utf8", "value": "images"}]
                }
            }
        }))
        .unwrap();
        let photo: AuthoritySelector = serde_json::from_value(serde_json::json!({
            "cap": "fs:read",
            "resource": {
                "kind": "path-exact",
                "path": {
                    "root": "project",
                    "components": [
                        {"encoding": "utf8", "value": "images"},
                        {"encoding": "utf8", "value": "photo.jpg"}
                    ]
                }
            }
        }))
        .unwrap();
        let mut decision: DecisionSet = serde_json::from_value(serde_json::json!({
            "decisionSetSchema": "ibex/capsec-decision-set/1",
            "operationId": "delegated-photo-read",
            "atomicityGroup": "test.handle.fs.read",
            "combination": "conjunction",
            "context": {
                "stage": "commit",
                "actor": holder_value,
                "constrainedPrincipals": [holder_value]
            },
            "effects": [{
                "cap": "fs:read",
                "effectOwner": holder_value,
                "resource": {
                    "kind": "path-occurrence",
                    "requested": {
                        "root": "project",
                        "components": [
                            {"encoding": "utf8", "value": "images"},
                            {"encoding": "utf8", "value": "photo.jpg"}
                        ]
                    },
                    "followMode": "follow-final",
                    "objectState": "existing",
                    "parentObject": {"platform": "unix", "volume": "dev-test", "file": "images"},
                    "finalObject": {"platform": "unix", "volume": "dev-test", "file": "photo"},
                    "retainedHandle": "delegated-fd"
                }
            }]
        }))
        .unwrap();
        let gates: Vec<EffectGate> = serde_json::from_value(serde_json::json!([{
            "coverageEdgeId": "test.handle.fs.read",
            "targetCell": "complete",
            "definitionAndEdgePredicatesSatisfied": true
        }]))
        .unwrap();

        assert_eq!(
            host.evaluate_typed_decision(&decision, &gates)
                .unwrap()
                .outcome,
            DecisionOutcome::Deny
        );
        let parent_request = serde_json::to_vec(&serde_json::json!({
            "actor": owner.clone(),
            "holder": holder.clone(),
            "authority": tree.clone()
        }))
        .unwrap();
        let ungranted_deputy: Principal = serde_json::from_value(serde_json::json!({
            "kind": "runtime",
            "identity": "ungranted-deputy"
        }))
        .unwrap();
        assert!(host
            .mint_typed_handle_json_for_actor(
                owner.clone(),
                vec![owner.clone(), ungranted_deputy],
                &parent_request,
            )
            .is_err());
        let parent = host.mint_typed_handle_json(&parent_request).unwrap();
        let wrong_holder: Principal = serde_json::from_value(serde_json::json!({
            "kind": "runtime",
            "identity": "unrelated-runtime"
        }))
        .unwrap();
        assert!(host
            .revoke_typed_handle_json_for_actor(
                &wrong_holder,
                serde_json::to_string(parent.as_str()).unwrap().as_bytes(),
            )
            .is_err());
        assert_eq!(
            host.evaluate_typed_decision(&decision, &gates)
                .unwrap()
                .outcome,
            DecisionOutcome::Deny,
            "an unpresented bearer must not become ambient holder authority"
        );
        decision.context.presented_handle_ids = vec![parent.clone()];
        assert_eq!(
            host.evaluate_typed_decision(&decision, &gates)
                .unwrap()
                .outcome,
            DecisionOutcome::Allow
        );
        let child = host
            .mint_typed_handle(
                holder.clone(),
                std::slice::from_ref(&holder),
                holder.clone(),
                photo,
                Some(&parent),
                None,
            )
            .unwrap();
        assert_ne!(parent, child);
        decision.context.presented_handle_ids = vec![parent.clone(), child];
        decision.context.presented_handle_ids.sort();
        decision.context.presented_handle_ids.reverse();
        let unsorted = host.evaluate_typed_decision(&decision, &gates).unwrap();
        assert_eq!(unsorted.outcome, DecisionOutcome::Deny);
        assert_eq!(
            unsorted.evidence[0].reason,
            capsec_semantics::decision::DecisionReason::InvalidAttribution
        );
        decision.context.presented_handle_ids = vec![parent.clone()];
        assert!(host
            .revoke_typed_handle_json(serde_json::to_string(parent.as_str()).unwrap().as_bytes())
            .unwrap());
        assert_eq!(
            host.evaluate_typed_decision(&decision, &gates)
                .unwrap()
                .outcome,
            DecisionOutcome::Deny
        );

        let outside: AuthoritySelector = serde_json::from_value(serde_json::json!({
            "cap": "fs:read",
            "resource": {
                "kind": "path-tree",
                "path": {
                    "root": "project",
                    "components": [{"encoding": "utf8", "value": "secrets"}]
                }
            }
        }))
        .unwrap();
        assert!(host
            .mint_typed_handle(owner.clone(), &[owner], holder, outside, None, None)
            .is_err());
    }

    #[test]
    fn typed_dynamic_revocation_denies_the_next_retained_repeat() {
        use capsec_semantics::decision::DecisionOutcome;
        use capsec_semantics::model::{AuthoritySelector, NonEmptyString, Principal};

        let authority_value = serde_json::json!({
            "cap": "fs:write",
            "resource": {
                "kind": "path-exact",
                "path": {
                    "root": "project",
                    "components": [
                        {"encoding": "utf8", "value": "images"},
                        {"encoding": "utf8", "value": "photo.jpg"}
                    ]
                }
            }
        });
        let ceiling = authority_value.clone();
        let host = example_armed_host_with(|value| {
            value["principals"][1]["escalationCeiling"] = serde_json::Value::Array(vec![ceiling]);
        });
        host.register_module_package(
            "7",
            "image-lib",
            Some("image-lib@2.4.1"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        let principal: Principal = serde_json::from_value(serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
            "locator": "image-lib@2.4.1"
        }))
        .unwrap();
        let authority: AuthoritySelector = serde_json::from_value(authority_value).unwrap();
        let grant_id = NonEmptyString::new("queued-write").unwrap();
        assert!(host
            .grant_typed_dynamic(grant_id.clone(), principal.clone(), authority,)
            .unwrap());
        let object = |file: &str| capsec_semantics::model::ObjectIdentity {
            platform: capsec_semantics::model::ObjectPlatform::Apple,
            volume: NonEmptyString::new("dev:test").unwrap(),
            file: NonEmptyString::new(file).unwrap(),
        };
        let authorize = |stage| {
            let photo = test_project_root().join("images/photo.jpg");
            let images = test_project_root().join("images");
            host.authorize_typed_fs_open_stage(
                "7",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![principal.clone()],
                &photo,
                stage,
                capsec_semantics::model::ObjectState::Existing,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                Some(&images),
                false,
                true,
                Some(object("images")),
                Some(object("photo")),
                Some(NonEmptyString::new("fd:42").unwrap()),
                Vec::new(),
            )
            .unwrap()
        };
        assert_eq!(
            authorize(capsec_semantics::model::Stage::Commit).outcome,
            DecisionOutcome::Allow
        );
        let before = host.typed_generations().unwrap();
        assert!(host.revoke_typed_dynamic(&grant_id).unwrap());
        let after = host.typed_generations().unwrap();
        assert!(after.negative > before.negative);
        assert!(after.dynamic > before.dynamic);
        assert_eq!(
            authorize(capsec_semantics::model::Stage::Repeat).outcome,
            DecisionOutcome::Deny
        );
    }

    #[test]
    fn multiple_dynamic_grants_publish_as_one_generation_consistent_overlay() {
        use capsec_semantics::model::{AuthoritySelector, NonEmptyString, Principal};

        let ceiling = serde_json::json!({
            "cap": "fs:write",
            "resource": {
                "kind": "path-tree",
                "path": {
                    "root": "project",
                    "components": [{"encoding": "utf8", "value": "images"}]
                }
            }
        });
        let host = example_armed_host_with(|value| {
            value["principals"][1]["escalationCeiling"] = serde_json::Value::Array(vec![ceiling]);
        });
        let principal: Principal = serde_json::from_value(serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
            "locator": "image-lib@2.4.1"
        }))
        .unwrap();
        let selector = |name: &str| -> AuthoritySelector {
            serde_json::from_value(serde_json::json!({
                "cap": "fs:write",
                "resource": {
                    "kind": "path-exact",
                    "path": {
                        "root": "project",
                        "components": [
                            {"encoding": "utf8", "value": "images"},
                            {"encoding": "utf8", "value": name}
                        ]
                    }
                }
            }))
            .unwrap()
        };
        let first = NonEmptyString::new("grant-a").unwrap();
        let second = NonEmptyString::new("grant-b").unwrap();
        assert!(host
            .grant_typed_dynamic(first.clone(), principal.clone(), selector("a.jpg"))
            .unwrap());
        let after_first = host.typed_generations().unwrap();
        assert!(host
            .grant_typed_dynamic(second.clone(), principal.clone(), selector("b.jpg"))
            .unwrap());
        let after_second = host.typed_generations().unwrap();
        assert!(after_second.dynamic > after_first.dynamic);
        {
            let current = host.decision_context.as_ref().unwrap().read().unwrap();
            assert_eq!(current.authority().dynamic_grants.len(), 2);
            assert!(current.authority().dynamic_grants.iter().all(|grant| {
                grant.observed_negative_generation == after_second.negative
                    && grant.published_dynamic_generation == after_second.dynamic
            }));
        }

        let before_duplicate = host.typed_generations().unwrap();
        assert!(!host
            .grant_typed_dynamic(second.clone(), principal.clone(), selector("b.jpg"))
            .unwrap());
        assert_eq!(host.typed_generations().unwrap(), before_duplicate);

        assert!(host.revoke_typed_dynamic(&first).unwrap());
        let after_revoke = host.typed_generations().unwrap();
        {
            let current = host.decision_context.as_ref().unwrap().read().unwrap();
            assert_eq!(current.authority().dynamic_grants.len(), 1);
            let remaining = &current.authority().dynamic_grants[0];
            assert_eq!(remaining.grant_id, second);
            assert_eq!(
                remaining.observed_negative_generation,
                after_revoke.negative
            );
            assert_eq!(remaining.published_dynamic_generation, after_revoke.dynamic);
        }
        assert!(host
            .grant_typed_dynamic(first, principal.clone(), selector("a.jpg"))
            .unwrap());

        let before_failure = host.typed_generations().unwrap();
        let rows_before = host
            .decision_context
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .authority()
            .dynamic_grants
            .len();
        let outside: AuthoritySelector = serde_json::from_value(serde_json::json!({
            "cap": "fs:write",
            "resource": {
                "kind": "path-exact",
                "path": {
                    "root": "project",
                    "components": [{"encoding": "utf8", "value": "outside.jpg"}]
                }
            }
        }))
        .unwrap();
        assert!(host
            .grant_typed_dynamic(NonEmptyString::new("outside").unwrap(), principal, outside,)
            .is_err());
        assert_eq!(host.typed_generations().unwrap(), before_failure);
        assert_eq!(
            host.decision_context
                .as_ref()
                .unwrap()
                .read()
                .unwrap()
                .authority()
                .dynamic_grants
                .len(),
            rows_before
        );
    }
}
