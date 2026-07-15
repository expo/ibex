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
#[cfg(any(test, feature = "capsec-conformance-observer"))]
use std::collections::VecDeque;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

#[cfg(any(test, feature = "capsec-conformance-observer"))]
const MAX_TYPED_EVIDENCE_ENTRIES: usize = 1024;

static NEXT_MODULE_RESOLVER_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Resolve one exact surface through the committed generated registry.
///
/// Stateful adapters select only a closed ABI enum; this lookup supplies the
/// corresponding generated edge identity without copying hash-derived ids
/// into handwritten call sites. Malformed or duplicate registry rows poison
/// the cache and every caller fails closed.
pub(crate) fn generated_coverage_edge_id(kind: &str, name: &str) -> Option<&'static str> {
    static EDGES: OnceLock<Option<BTreeMap<String, String>>> = OnceLock::new();
    let edges = EDGES.get_or_init(|| {
        let value: serde_json::Value =
            serde_json::from_str(crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGES_JSON)
                .ok()?;
        let rows = value.get("edges")?.as_array()?;
        let mut result = BTreeMap::new();
        for row in rows {
            let id = row.get("id")?.as_str()?;
            let surface = row.get("surface")?;
            let surface_kind = surface.get("kind")?.as_str()?;
            let surface_name = surface.get("name")?.as_str()?;
            if !crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS.contains(&id) {
                return None;
            }
            let key = format!("{surface_kind}\0{surface_name}");
            if result.insert(key, id.to_owned()).is_some() {
                return None;
            }
        }
        Some(result)
    });
    edges
        .as_ref()?
        .get(&format!("{kind}\0{name}"))
        .map(String::as_str)
}

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
    /// Host-boundary fence for outbound network access: when set, outbound
    /// `network:*` capability values must name one of these remote hosts
    /// (`host` or `host:port` entries; a port-less entry covers the host across
    /// ports) or they are denied. `network:listen` is intentionally outside
    /// this legacy remote-host fence and remains governed by its own policy.
    /// Same hard-fence semantics as `root_dir`: all modes, all principals, not
    /// widenable by policy grants. An empty list denies all outbound network
    /// access. (ENG-23876, ENG-24285) @ref LLP 0002#host-boundary-constraints
    pub allowed_hosts: Option<Vec<String>>,
    /// Optional supervisor-owned lifecycle port. Supplying one makes the Host
    /// ABI and terminal owner share one authoritative exit-code mirror and
    /// cooperative-request event.
    pub session_lifecycle: Option<crate::session_lifecycle::SessionLifecyclePort>,
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
            session_lifecycle: None,
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
    /// One process-local identity for the lifetime of this armed Host and all
    /// of its clones. Repeated callers receive opaque clones of this token;
    /// they cannot fork the native/Rust submission ordinal sequence.
    /// @ref LLP 0024#1-the-in-memory-source-api — a session has
    /// one monotonic submission sequence shared by every ingress path.
    armed_session_token: Arc<Mutex<Option<crate::engine::evaluation::ArmedSessionToken>>>,
    /// Typed, validated authority state decoded from the immutable snapshot.
    /// Legacy `PolicyFile` data never enters this context.
    /// @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence
    decision_context: Option<Arc<RwLock<capsec_semantics::decision::VerifiedDecisionContext>>>,
    /// Exact package source objects authenticated by the arming-time integrity
    /// walk. On platforms without a reliable inode generation the associated
    /// state also retains one descriptor per unique object for this Host's
    /// lifetime, making the fallback generation non-reusable.
    /// @ref LLP 0023#42-authenticated-package-source-is-immutable
    authenticated_package_sources: Arc<AuthenticatedPackageSourceState>,
    typed_decision_count: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "capsec-conformance-observer"))]
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
    /// Process-local, Host-lifetime identity carried by resolver records. It
    /// prevents a typed logical record or unarmed opaque handle from being
    /// replayed after the active Host/session is replaced.
    resolver_session_handle: Arc<str>,
    /// Unarmed/dev resolver backing paths keyed by opaque process-local
    /// handles. Armed resolvers never use this compatibility registry.
    private_resolver_paths: Arc<RwLock<PrivateResolverRegistry>>,
    private_resolver_sequence: Arc<AtomicU64>,
    /// In-process supervisor-authoritative orderly-exit mirror. The native
    /// accessor can observe or mutate it only after a typed lifecycle decision.
    /// Every newly installed Host begins at Node-compatible status zero.
    // @ref LLP 0025#8-exit-and-lifecycle — exitCode is synchronously mirrored
    // outside JavaScript so later wedged code cannot hide the selected status.
    session_lifecycle: crate::session_lifecycle::SessionLifecyclePort,
    /// Exact authenticated disposition for every coverage edge on the armed
    /// target. Call sites never manufacture `Complete` locally.
    target_cells: Arc<BTreeMap<String, capsec_semantics::decision::TargetCellDisposition>>,
    unarmed_closed: bool,
}

#[derive(Default)]
struct PrivateResolverRegistry {
    by_handle: HashMap<String, std::path::PathBuf>,
    by_path: HashMap<std::path::PathBuf, String>,
}

#[derive(Default)]
struct AuthenticatedPackageSourceState {
    generations:
        BTreeMap<capsec_semantics::model::ObjectIdentity, capsec_semantics::model::NonEmptyString>,
    #[cfg(unix)]
    retained_descriptors: Vec<std::fs::File>,
}

impl AuthenticatedPackageSourceState {
    fn guards(
        &self,
    ) -> capsec_semantics::Result<Vec<capsec_semantics::decision::ProtectedObjectGuard>> {
        let action = capsec_semantics::model::ActionId::new("fs:write")
            .map_err(capsec_semantics::Error::InvalidModel)?;
        Ok(self
            .generations
            .iter()
            .map(
                |(object, generation)| capsec_semantics::decision::ProtectedObjectGuard {
                    action: action.clone(),
                    object: object.clone(),
                    verification_generation: Some(generation.clone()),
                },
            )
            .collect())
    }
}

#[derive(Debug)]
struct AuthenticatedSessionEntry {
    kind: crate::engine::evaluation::EntryKind,
    identity: Arc<str>,
    mode: crate::engine::evaluation::ExecutionMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthenticatedVfsSourceRoute {
    LoadScript,
    FileModule,
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

fn authenticated_session_entry(
    entry: &capsec_semantics::arming::ArmedEntry,
) -> capsec_semantics::Result<AuthenticatedSessionEntry> {
    use crate::engine::evaluation::{EntryKind, ExecutionMode};
    use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

    entry.validate()?;
    let (kind, mode) = match (entry.kind, entry.mode) {
        (ArmedEntryKind::File, ArmedExecutionMode::Program) => {
            (EntryKind::File, ExecutionMode::Program)
        }
        (ArmedEntryKind::Stdin, ArmedExecutionMode::Program) => {
            (EntryKind::Stdin, ExecutionMode::Program)
        }
        (ArmedEntryKind::Repl, ArmedExecutionMode::Interactive) => {
            (EntryKind::Repl, ExecutionMode::Interactive)
        }
        (ArmedEntryKind::Repl, ArmedExecutionMode::Transcript) => {
            (EntryKind::Repl, ExecutionMode::Transcript)
        }
        (ArmedEntryKind::Eval, ArmedExecutionMode::OneShot) => {
            (EntryKind::Eval, ExecutionMode::OneShot)
        }
        _ => {
            return Err(capsec_semantics::Error::ArmRefused(
                "authenticated armed snapshot entry kind and mode are not a permitted pair".into(),
            ))
        }
    };
    Ok(AuthenticatedSessionEntry {
        kind,
        identity: Arc::from(entry.identity.as_str()),
        mode,
    })
}

fn digest_authenticated_projection(domain: &[u8], bytes: &[u8]) -> capsec_semantics::model::Digest {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    capsec_semantics::model::Digest::new(format!(
        "sha256-{}",
        URL_SAFE_NO_PAD.encode(hash.finalize())
    ))
    .expect("SHA-256 always produces a canonical digest")
}

impl Host {
    /// Create a new host with the given configuration
    pub fn new(config: HostConfig) -> Self {
        let session_lifecycle = config.session_lifecycle.clone().unwrap_or_default();
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

        let resolver_session_ordinal = NEXT_MODULE_RESOLVER_SESSION_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("module resolver session handle space is exhausted");
        Self {
            capability_manager: manager,
            config,
            module_loader: loader,
            handles: Arc::new(handles::HandleRegistry::new()),
            armed_snapshot: None,
            armed_session_token: Arc::new(Mutex::new(None)),
            decision_context: None,
            authenticated_package_sources: Arc::new(AuthenticatedPackageSourceState::default()),
            typed_decision_count: Arc::new(AtomicUsize::new(0)),
            #[cfg(any(test, feature = "capsec-conformance-observer"))]
            typed_evidence: Arc::new(RwLock::new(VecDeque::with_capacity(
                MAX_TYPED_EVIDENCE_ENTRIES,
            ))),
            #[cfg(any(test, feature = "capsec-conformance-observer"))]
            conformance_typed_observer: Arc::new(RwLock::new(TypedConformanceObserver::default())),
            typed_imports: Arc::new(BTreeMap::new()),
            typed_module_principals: Arc::new(RwLock::new(HashMap::new())),
            resolver_session_handle: Arc::from(format!("mrs{resolver_session_ordinal:016x}")),
            private_resolver_paths: Arc::new(RwLock::new(PrivateResolverRegistry::default())),
            private_resolver_sequence: Arc::new(AtomicU64::new(1)),
            session_lifecycle,
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
        validate_snapshot_protected_artifacts(&armed_snapshot)?;
        let target_cells = authenticated_target_cells(&armed_snapshot)?;
        let authenticated_package_sources = validate_snapshot_root_bindings(&armed_snapshot)?;
        Self::new_armed_with_target_cells(
            config,
            armed_snapshot,
            target_cells,
            authenticated_package_sources,
        )
    }

    fn new_armed_with_target_cells(
        config: HostConfig,
        armed_snapshot: Arc<capsec_semantics::arming::ArmedSnapshot>,
        target_cells: BTreeMap<String, capsec_semantics::decision::TargetCellDisposition>,
        authenticated_package_sources: AuthenticatedPackageSourceState,
    ) -> capsec_semantics::Result<Self> {
        validate_armed_alias_volume_topology(&armed_snapshot)?;
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
        // `ArmedSnapshot::load` authenticates the claimed target identity, but
        // only the checked advertisement/cell join proves that this exact
        // engine+feature target is complete. The test-only constructor supplies
        // the same exhaustive cell map explicitly; every partial map refuses.
        // @ref LLP 0021#default-and-target-claim
        let target_arm_state = if target_cells.len()
            == crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS.len()
            && crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS
                .iter()
                .all(|edge| {
                    matches!(
                        target_cells.get(*edge),
                        Some(
                            capsec_semantics::decision::TargetCellDisposition::Complete
                                | capsec_semantics::decision::TargetCellDisposition::Closed
                        )
                    )
                }) {
            capsec_semantics::decision::TargetArmState::CompleteAdvertised
        } else {
            capsec_semantics::decision::TargetArmState::Incomplete
        };
        let decision_context = Arc::new(RwLock::new(
            armed_snapshot.decision_context_with_package_objects(
                profile.definitions,
                target_arm_state,
                authenticated_package_sources.guards()?,
            )?,
        ));
        let typed_imports = Arc::new(armed_snapshot.import_policies()?);
        let mut host = Self::new(config);
        host.armed_snapshot = Some(armed_snapshot);
        host.decision_context = Some(decision_context);
        host.authenticated_package_sources = Arc::new(authenticated_package_sources);
        host.typed_imports = typed_imports;
        host.target_cells = Arc::new(target_cells);
        Ok(host)
    }

    /// Test-harness escape hatch compiled only into unit tests or the explicit
    /// conformance-observer profile. Ordinary downstream debug embedders must
    /// not be able to bypass the checked target registry.
    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    #[doc(hidden)]
    pub unsafe fn new_armed_for_test(
        config: HostConfig,
        armed_snapshot: Arc<capsec_semantics::arming::ArmedSnapshot>,
    ) -> capsec_semantics::Result<Self> {
        Self::new_armed_with_target_cells(
            config,
            armed_snapshot,
            complete_test_target_cells(),
            AuthenticatedPackageSourceState::default(),
        )
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

    /// Construct the session-local VFS exclusively from this Host's immutable
    /// authenticated snapshot. Construction itself performs no host lookup.
    pub fn virtual_file_system(
        &self,
    ) -> Result<crate::vfs::VirtualFileSystem, crate::vfs::VfsError> {
        let snapshot = self
            .armed_snapshot
            .as_deref()
            .ok_or_else(|| crate::vfs::VfsError::stale_session("mount", None))?;
        crate::vfs::VirtualFileSystem::from_armed_snapshot(snapshot)
    }

    /// Bind this exact authenticated Host snapshot to one native runtime
    /// generation. The initial `/project` cwd is derived from snapshot identity
    /// only; runtime creation performs no backing-store lookup.
    /// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
    pub(crate) fn runtime_vfs_session(
        &self,
        runtime_nonce: std::num::NonZeroU64,
    ) -> Result<crate::vfs::RuntimeVfsSession, crate::vfs::VfsError> {
        crate::vfs::RuntimeVfsSession::new(runtime_nonce, self.virtual_file_system()?)
    }

    /// Consume a minted `.load` submission through requested/discovery
    /// metadata decisions and commit/repeat read decisions, then bind the
    /// immutable bytes to that exact evidence before returning an engine capsule.
    /// @ref LLP 0024#1-the-in-memory-source-api — a typed read and its evidence
    /// advance the linear submission credential before bytes reach the engine.
    pub fn authenticated_vfs_script_read(
        &self,
        vfs: &crate::vfs::VirtualFileSystem,
        namespace: crate::vfs::NamespacePath,
        submission: crate::engine::evaluation::MintedSubmission,
    ) -> Result<crate::vfs::AuthenticatedVfsScriptRead, crate::vfs::VfsError> {
        self.authenticated_vfs_source_read(
            vfs,
            namespace,
            submission,
            crate::vfs::SourceUse::Script,
            AuthenticatedVfsSourceRoute::LoadScript,
        )
    }

    /// Consume the one authenticated file-entry submission through the same
    /// requested/discovery/commit/repeat decision route as `.load`, but retain
    /// module SourceId evidence and require the VFS's canonical final label to
    /// equal the digest-bound armed entry identity.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    /// @ref LLP 0024#1-the-in-memory-source-api
    pub fn authenticated_vfs_file_read(
        &self,
        vfs: &crate::vfs::VirtualFileSystem,
        namespace: crate::vfs::NamespacePath,
        submission: crate::engine::evaluation::MintedSubmission,
    ) -> Result<crate::vfs::AuthenticatedVfsScriptRead, crate::vfs::VfsError> {
        self.authenticated_vfs_source_read(
            vfs,
            namespace,
            submission,
            crate::vfs::SourceUse::Module,
            AuthenticatedVfsSourceRoute::FileModule,
        )
    }

    fn authenticated_vfs_source_read(
        &self,
        vfs: &crate::vfs::VirtualFileSystem,
        namespace: crate::vfs::NamespacePath,
        submission: crate::engine::evaluation::MintedSubmission,
        source_use: crate::vfs::SourceUse,
        route: AuthenticatedVfsSourceRoute,
    ) -> Result<crate::vfs::AuthenticatedVfsScriptRead, crate::vfs::VfsError> {
        use capsec_semantics::decision::DecisionOutcome;

        let snapshot = self.armed_snapshot.as_deref().ok_or_else(|| {
            crate::vfs::VfsError::stale_session("read", Some(Arc::from(namespace.virtual_path())))
        })?;
        if vfs.snapshot_digest() != Some(snapshot.digest())
            || self.typed_principal_for_module("0").as_ref() != Some(vfs.root_principal())
        {
            return Err(crate::vfs::VfsError::stale_session(
                "read",
                Some(Arc::from(namespace.virtual_path())),
            ));
        }
        let host_session = self.mint_armed_session_token().map_err(|_| {
            crate::vfs::VfsError::stale_session("read", Some(Arc::from(namespace.virtual_path())))
        })?;
        if !submission.authenticates_for(&host_session) {
            return Err(crate::vfs::VfsError::stale_session(
                "read",
                Some(Arc::from(namespace.virtual_path())),
            ));
        }
        if namespace.caller() != vfs.root_principal() {
            return Err(crate::vfs::VfsError::policy_denied(
                "read",
                Arc::from(namespace.virtual_path()),
                "submission-principal-mismatch",
            ));
        }
        let expected_referrer = namespace.logical_referrer()?;
        if submission.logical_referrer() != &expected_referrer {
            return Err(crate::vfs::VfsError::policy_denied(
                "read",
                Arc::from(namespace.virtual_path()),
                "submission-referrer-mismatch",
            ));
        }
        let requested_source_label = crate::vfs::SourceLabel::file(&namespace)?;
        let canonical_submission = match route {
            AuthenticatedVfsSourceRoute::LoadScript => {
                submission.is_canonical_load_for(namespace.virtual_path())
            }
            AuthenticatedVfsSourceRoute::FileModule => submission
                .is_canonical_file_for(namespace.virtual_path(), requested_source_label.as_str()),
        };
        if !canonical_submission {
            return Err(crate::vfs::VfsError::policy_denied(
                "read",
                Arc::from(namespace.virtual_path()),
                "submission-source-mismatch",
            ));
        }

        let read = vfs.read_authenticated(namespace, source_use, |stage| {
            let path = Arc::<str>::from(match stage {
                crate::vfs::ReadAuthorization::Requested(path) => path.virtual_path(),
                crate::vfs::ReadAuthorization::Discovery(path) => path.namespace().virtual_path(),
                crate::vfs::ReadAuthorization::Commit(path) => path.namespace().virtual_path(),
                crate::vfs::ReadAuthorization::Repeat(path) => path.namespace().virtual_path(),
            });
            let result = self.authorize_vfs_script_read_stage(stage).map_err(|_| {
                crate::vfs::VfsError::policy_denied(
                    "read",
                    path.clone(),
                    "typed-read-evaluation-refused",
                )
            })?;
            let receipt =
                crate::vfs::AuthorizationReceipt::from_structured_decision(&result.evidence)?;
            match result.decision.outcome {
                DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence => Ok(receipt),
                DecisionOutcome::Deny | DecisionOutcome::RefuseArming => {
                    Err(crate::vfs::VfsError::policy_denied(
                        "read",
                        path,
                        Arc::<str>::from(receipt.evidence_digest().as_str()),
                    ))
                }
            }
        })?;
        let evidence = read.evidence().clone();
        let logical_referrer = read.logical_referrer().clone();
        let source_id = read.source_id().cloned();
        let file_source_label = read.source_label().clone();
        if route == AuthenticatedVfsSourceRoute::FileModule && source_id.is_none() {
            return Err(crate::vfs::VfsError::policy_denied(
                "read",
                Arc::from(requested_source_label.as_str()),
                "authenticated-entry-identity-mismatch",
            ));
        }
        let bytes = read.bytes().as_ref().to_vec();
        let (submission, authenticated_file_namespace) =
            if route == AuthenticatedVfsSourceRoute::FileModule {
                let authenticated_namespace = vfs
                    .resolve_root_file_url(file_source_label.as_str(), None)
                    .map_err(|_| {
                        crate::vfs::VfsError::policy_denied(
                            "read",
                            Arc::from(requested_source_label.as_str()),
                            "authenticated-entry-label-refused",
                        )
                    })?;
                let submission = submission
                    .with_authenticated_file_source(
                        authenticated_namespace.virtual_path(),
                        file_source_label.as_str(),
                    )
                    .map_err(|_| {
                        crate::vfs::VfsError::policy_denied(
                            "read",
                            Arc::from(requested_source_label.as_str()),
                            "authenticated-entry-label-refused",
                        )
                    })?;
                (submission, Some(authenticated_namespace))
            } else {
                (submission, None)
            };
        let pending_file_resolution = if submission.awaits_authenticated_file_module_kind() {
            let namespace = authenticated_file_namespace.as_ref().ok_or_else(|| {
                crate::vfs::VfsError::policy_denied(
                    "read",
                    Arc::from(requested_source_label.as_str()),
                    "file-module-kind-path-refused",
                )
            })?;
            Some((
                namespace.logical_path().ok_or_else(|| {
                    crate::vfs::VfsError::policy_denied(
                        "read",
                        Arc::from(requested_source_label.as_str()),
                        "file-module-kind-path-refused",
                    )
                })?,
                namespace
                    .binding_owner()
                    .cloned()
                    .unwrap_or_else(|| vfs.root_principal().clone()),
            ))
        } else {
            None
        };
        let submission = if let Some((logical_path, defining_principal)) =
            pending_file_resolution.as_ref()
        {
            let host_path = authenticated_host_path_for_logical_path(
                snapshot,
                defining_principal,
                logical_path,
                "authenticated direct file",
            )
            .map_err(|_| {
                crate::vfs::VfsError::policy_denied(
                    "read",
                    Arc::from(requested_source_label.as_str()),
                    "file-module-kind-resolution-refused",
                )
            })?;
            let current_object = object_identity_for_host_path(&host_path).map_err(|_| {
                crate::vfs::VfsError::policy_denied(
                    "read",
                    Arc::from(requested_source_label.as_str()),
                    "file-module-kind-resolution-refused",
                )
            })?;
            if &current_object != read.evidence().final_object() {
                return Err(crate::vfs::VfsError::policy_denied(
                    "read",
                    Arc::from(requested_source_label.as_str()),
                    "file-module-kind-object-changed",
                ));
            }
            let resolved = self
                .module_loader
                .resolve_direct_file_meta(&host_path)
                .map_err(|_| {
                    crate::vfs::VfsError::policy_denied(
                        "read",
                        Arc::from(requested_source_label.as_str()),
                        "file-module-kind-resolution-refused",
                    )
                })?;
            let after_resolution_object =
                object_identity_for_host_path(&host_path).map_err(|_| {
                    crate::vfs::VfsError::policy_denied(
                        "read",
                        Arc::from(requested_source_label.as_str()),
                        "file-module-kind-resolution-refused",
                    )
                })?;
            if &after_resolution_object != read.evidence().final_object() {
                return Err(crate::vfs::VfsError::policy_denied(
                    "read",
                    Arc::from(requested_source_label.as_str()),
                    "file-module-kind-object-changed",
                ));
            }
            let module_kind = match resolved.kind {
                crate::module_loader::ModuleKind::Esm => crate::engine::evaluation::ModuleKind::Esm,
                crate::module_loader::ModuleKind::CommonJs => {
                    crate::engine::evaluation::ModuleKind::CommonJs
                }
                crate::module_loader::ModuleKind::Json
                | crate::module_loader::ModuleKind::Builtin => {
                    return Err(crate::vfs::VfsError::policy_denied(
                        "read",
                        Arc::from(requested_source_label.as_str()),
                        "file-module-kind-resolution-refused",
                    ));
                }
            };
            submission
                .with_authenticated_file_module_kind(module_kind)
                .map_err(|_| {
                    crate::vfs::VfsError::policy_denied(
                        "read",
                        Arc::from(requested_source_label.as_str()),
                        "file-module-kind-shape-refused",
                    )
                })?
        } else {
            submission
        };
        let authorized = submission
            .with_authenticated_referrer(logical_referrer.clone())
            .authorize_typed_read(evidence.digest().clone());
        let capsule = match source_id.as_ref() {
            Some(source_id) => authorized.bind_module_bytes(bytes, source_id.clone()),
            None => authorized.bind_bytes(bytes),
        };
        Ok(crate::vfs::AuthenticatedVfsScriptRead::new(
            capsule,
            logical_referrer,
            source_id,
            file_source_label,
            evidence,
        ))
    }

    fn authorize_vfs_script_read_stage(
        &self,
        authorization: crate::vfs::ReadAuthorization<'_>,
    ) -> capsec_semantics::Result<TypedDecisionResult> {
        use capsec_semantics::decision::{EffectGate, PrincipalPathProjections};
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            FollowMode, NonEmptyString, ObjectState, OccurrenceResource, StableId, Stage,
        };

        const COVERAGE_EDGE: &str = "surface.native.op.exactreadfile.1cmzco7";
        let snapshot = self.armed_snapshot.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed VFS read has no armed alias canonicalizer".into(),
            )
        })?;
        validate_armed_alias_volume_topology(snapshot)?;
        let principal = self.typed_principal_for_module("0").ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed VFS read has no authenticated session-root principal".into(),
            )
        })?;
        let (namespace, stage, parent_object, final_object, retained_handle) = match authorization {
            crate::vfs::ReadAuthorization::Requested(namespace) => {
                (namespace, Stage::Requested, None, None, None)
            }
            crate::vfs::ReadAuthorization::Discovery(discovered) => (
                discovered.namespace(),
                Stage::Discovery,
                Some(discovered.parent_object().clone()),
                discovered.witnessed_object().cloned(),
                None,
            ),
            crate::vfs::ReadAuthorization::Commit(committed) => (
                committed.namespace(),
                Stage::Commit,
                Some(committed.discovered().parent_object().clone()),
                Some(committed.final_object().clone()),
                Some(
                    NonEmptyString::new(format!(
                        "vfs:{}:{}",
                        committed.namespace().session_generation(),
                        committed.retained_handle_id()
                    ))
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                ),
            ),
            crate::vfs::ReadAuthorization::Repeat(committed) => (
                committed.namespace(),
                Stage::Repeat,
                Some(committed.discovered().parent_object().clone()),
                Some(committed.final_object().clone()),
                Some(
                    NonEmptyString::new(format!(
                        "vfs:{}:{}",
                        committed.namespace().session_generation(),
                        committed.retained_handle_id()
                    ))
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                ),
            ),
        };
        let requested = namespace.logical_path().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed VFS read cannot target the synthetic namespace root".into(),
            )
        })?;
        let requested = snapshot.canonicalize_authorization_path(&principal, &requested)?;

        // Requested carries no speculative existence fact; discovery replaces
        // `Unknown` with the descriptor-observed state.
        // @ref LLP 0023#21-staged-authorization-identity
        let resource = OccurrenceResource::PathOccurrence {
            requested: requested.clone(),
            follow_mode: FollowMode::FollowFinal,
            object_state: if stage == Stage::Requested {
                ObjectState::Unknown
            } else {
                ObjectState::Existing
            },
            parent_object,
            final_object,
            final_object_generation: None,
            retained_handle,
        };
        let action = if matches!(stage, Stage::Requested | Stage::Discovery) {
            "fs:list"
        } else {
            "fs:read"
        };
        let operation_resource = serde_json::to_string(&requested)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        let set = DecisionSet {
            decision_set_schema: DecisionSetSchema::V1,
            operation_id: NonEmptyString::new(format!("vfs-script-read:0:{operation_resource}"))
                .map_err(capsec_semantics::Error::InvalidModel)?,
            atomicity_group: StableId::new(format!("{COVERAGE_EDGE}.decision"))
                .map_err(capsec_semantics::Error::InvalidModel)?,
            combination: EffectCombination::Conjunction,
            context: DecisionContext {
                stage,
                actor: principal.clone(),
                constrained_principals: vec![principal.clone()],
                presented_handle_ids: Vec::new(),
            },
            effects: vec![Effect {
                action: ActionId::new(action).map_err(capsec_semantics::Error::InvalidModel)?,
                effect_owner: principal.clone(),
                resource,
            }],
        };
        let projections =
            PrincipalPathProjections::new(vec![BTreeMap::from([(principal, requested)])]);
        self.evaluate_typed_path_decision_with_evidence(
            &set,
            &[EffectGate {
                coverage_edge_id: StableId::new(COVERAGE_EDGE)
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                target_cell: self.target_cell(COVERAGE_EDGE),
                definition_and_edge_predicates_satisfied: true,
            }],
            &projections,
        )
    }

    /// Mint an opaque engine-session token exclusively from the immutable,
    /// authenticated armed snapshot retained by this Host.
    ///
    /// Callers cannot supply or override any security-relevant session field;
    /// the closed entry tuple was already matched against the independent
    /// launcher identity while the snapshot was loaded.
    /// @ref LLP 0022#2-startup-project-identity-and-session-arming — the entry
    /// kind, identity, mode, Root identity, run nonce, and authority projection
    /// are authenticated snapshot facts rather than CLI/session suggestions.
    pub fn mint_armed_session_token(
        &self,
    ) -> capsec_semantics::Result<crate::engine::evaluation::ArmedSessionToken> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use capsec_semantics::model::Principal;

        let mut cached_token = match self.armed_session_token.lock() {
            Ok(token) => token,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(token) = cached_token.as_ref() {
            return Ok(token.clone());
        }

        let snapshot = self.armed_snapshot.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "session-token minting requires an authenticated armed snapshot".into(),
            )
        })?;
        let entry = authenticated_session_entry(snapshot.entry())?;

        let run_nonce = snapshot
            .document()
            .get("runNonce")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                capsec_semantics::Error::ArmRefused(
                    "authenticated armed snapshot has no string runNonce".into(),
                )
            })?;
        let decoded_nonce = URL_SAFE_NO_PAD.decode(run_nonce).map_err(|_| {
            capsec_semantics::Error::ArmRefused(
                "authenticated armed snapshot runNonce is not canonical base64url".into(),
            )
        })?;
        if decoded_nonce.is_empty() || URL_SAFE_NO_PAD.encode(&decoded_nonce) != run_nonce {
            return Err(capsec_semantics::Error::ArmRefused(
                "authenticated armed snapshot runNonce is not canonical nonempty base64url".into(),
            ));
        }

        let root_principal: Principal = serde_json::from_value(
            snapshot
                .document()
                .get("rootIdentity")
                .cloned()
                .ok_or_else(|| {
                    capsec_semantics::Error::ArmRefused(
                        "authenticated armed snapshot has no rootIdentity".into(),
                    )
                })?,
        )
        .map_err(|error| {
            capsec_semantics::Error::ArmRefused(format!(
                "authenticated armed snapshot rootIdentity is invalid: {error}"
            ))
        })?;
        if !root_principal.is_root() {
            return Err(capsec_semantics::Error::ArmRefused(
                "authenticated armed snapshot rootIdentity is not Root".into(),
            ));
        }

        let endowment_projection = snapshot.compartment_endowments_json()?;
        let endowment_projection_digest = digest_authenticated_projection(
            b"ibex/session-endowment-projection/1\0",
            endowment_projection.as_bytes(),
        );
        let token = crate::engine::evaluation::ArmedSessionToken::from_authenticated_snapshot(
            snapshot.digest().clone(),
            Arc::from(run_nonce),
            root_principal,
            entry.kind,
            entry.identity,
            entry.mode,
            endowment_projection_digest,
        )
        .map_err(|error| {
            capsec_semantics::Error::ArmRefused(format!(
                "OS randomness unavailable while minting armed session token: {error}"
            ))
        })?;
        *cached_token = Some(token.clone());
        Ok(token)
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
        validate_armed_alias_volume_topology(snapshot)?;
        let path = normalize_host_path_for_binding(path)?;
        let components = host_path_components(&path)?;
        let binding = snapshot.root_binding_for_host_components(principal, &components)?;
        validate_armed_binding_object(&binding)?;
        let logical = snapshot.logical_path_for_host_components(principal, &components)?;
        snapshot.canonicalize_authorization_path(principal, &logical)
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
        validate_armed_alias_volume_topology(snapshot)?;
        let path = normalize_host_path_for_binding(path)?;
        let components = host_path_components(&path)?;
        let binding = snapshot.root_binding_for_host_components(principal, &components)?;
        fd_descends_from_object(parent_fd, &binding.object)
    }

    fn typed_logical_paths(
        &self,
        principals: &[capsec_semantics::model::Principal],
        path: &std::path::Path,
    ) -> capsec_semantics::Result<
        BTreeMap<capsec_semantics::model::Principal, capsec_semantics::model::LogicalPath>,
    > {
        let snapshot = self.armed_snapshot.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed path normalization requested without an armed snapshot".into(),
            )
        })?;
        validate_armed_alias_volume_topology(snapshot)?;
        let path = normalize_host_path_for_binding(path)?;
        let components = host_path_components(&path)?;
        for principal in principals {
            let binding = snapshot.root_binding_for_host_components(principal, &components)?;
            validate_armed_binding_object(&binding)?;
        }
        snapshot
            .logical_paths_for_host_components(principals, &components)?
            .into_iter()
            .map(|(principal, path)| {
                Ok((
                    principal.clone(),
                    snapshot.canonicalize_authorization_path(&principal, &path)?,
                ))
            })
            .collect()
    }

    /// Project a requested path using only authenticated bindings and lexical
    /// components. In particular this does not canonicalize the target's
    /// parent or re-stat a binding before the requested decision.
    fn typed_requested_logical_paths(
        &self,
        principals: &[capsec_semantics::model::Principal],
        path: &std::path::Path,
    ) -> capsec_semantics::Result<
        BTreeMap<capsec_semantics::model::Principal, capsec_semantics::model::LogicalPath>,
    > {
        let snapshot = self.armed_snapshot.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed path normalization requested without an armed snapshot".into(),
            )
        })?;
        validate_armed_alias_volume_topology(snapshot)?;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| {
                    capsec_semantics::Error::ArmRefused(format!(
                        "cannot resolve current directory for requested typed path: {error}"
                    ))
                })?
                .join(path)
        };
        let components = host_path_components(&absolute)?;
        snapshot
            .logical_paths_for_host_components(principals, &components)?
            .into_iter()
            .map(|(principal, path)| {
                Ok((
                    principal.clone(),
                    snapshot.canonicalize_authorization_path(&principal, &path)?,
                ))
            })
            .collect()
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
        final_object_generation: Option<capsec_semantics::model::NonEmptyString>,
        retained_handle: Option<capsec_semantics::model::NonEmptyString>,
        presented_handle_ids: Vec<capsec_semantics::model::NonEmptyString>,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::{EffectGate, PrincipalPathProjections};
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            ObjectState, OccurrenceResource, StableId, Stage,
        };

        // The requested decision precedes lookup, so it must not speculate
        // about existence. Every later stage must carry an observed state.
        // @ref LLP 0023#21-staged-authorization-identity
        if (stage == Stage::Requested) != (object_state == ObjectState::Unknown) {
            return Err(capsec_semantics::Error::ArmRefused(
                "filesystem object state must be unknown exactly at requested stage".into(),
            ));
        }

        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "filesystem operation has no authenticated typed principal".into(),
            )
        })?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "filesystem principal stack is empty, noncanonical, or omits the actor".into(),
            ));
        }
        // @ref LLP 0021#decision-staging-and-principal-semantics — a logical
        // package root is principal-relative. Project the host path separately
        // for every constrained dimension before any containment check.
        let requested_paths = if stage == Stage::Requested {
            self.typed_requested_logical_paths(&constrained_principals, path)?
        } else {
            self.typed_logical_paths(&constrained_principals, path)?
        };
        let requested = requested_paths.get(&principal).cloned().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "filesystem actor is missing its authenticated path projection".into(),
            )
        })?;
        if let Some(resolved_parent_path) = resolved_parent_path {
            // A committed descriptor retains object identity and authority
            // even if its directory is subsequently renamed. Re-resolving
            // the old lexical parent at Repeat would make legitimate open fds
            // permanently unusable (and broke macOS's /tmp alias). Commit and
            // discovery still bind the retained physical parent before
            // projecting it. A
            // foreign nested package is a logical mount boundary: the target
            // can correctly be Project-rooted for an outer package while its
            // immediate parent is Package-rooted. Re-projecting the two paths
            // independently would reject that valid boundary crossing.
            // @ref LLP 0021#decision-staging-and-principal-semantics
            if stage != capsec_semantics::model::Stage::Repeat {
                let normalized = normalize_host_path_for_binding(path)?;
                let expected_parent = normalized.parent().ok_or_else(|| {
                    capsec_semantics::Error::ArmRefused(
                        "filesystem target has no physical parent".into(),
                    )
                })?;
                if absolute_host_path_components(resolved_parent_path)?
                    != absolute_host_path_components(expected_parent)?
                {
                    return Err(capsec_semantics::Error::ArmRefused(
                        "retained filesystem parent is not the requested path's physical parent"
                            .into(),
                    ));
                }
            }
            let bindings = self
                .armed_snapshot
                .as_deref()
                .ok_or_else(|| {
                    capsec_semantics::Error::ArmRefused(
                        "root-object validation requires an armed snapshot".into(),
                    )
                })?
                .root_bindings()?;
            let all_root_objects_match = constrained_principals.iter().all(|constrained| {
                let Some(requested) = requested_paths.get(constrained) else {
                    return false;
                };
                if requested.components.is_empty() {
                    bindings.iter().any(|binding| {
                        binding.logical_root == requested.root
                            && match binding.logical_root {
                                capsec_semantics::model::LogicalRoot::Package => {
                                    binding.owner.as_ref() == Some(constrained)
                                }
                                _ => binding.owner.is_none(),
                            }
                            && final_object.as_ref() == Some(&binding.object)
                    })
                } else {
                    true
                }
            });
            if !all_root_objects_match {
                return Err(capsec_semantics::Error::ArmRefused(
                    "filesystem root object differs from its authenticated binding".into(),
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
        if needs_write {
            if let Some(expected_generation) = final_object
                .as_ref()
                .and_then(|object| self.authenticated_package_sources.generations.get(object))
            {
                if final_object_generation.as_ref() != Some(expected_generation) {
                    return Err(capsec_semantics::Error::ArmRefused(
                        "package source commit lacks its authenticated verification generation"
                            .into(),
                    ));
                }
            }
        }
        let operation_resource = serde_json::to_string(&requested)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        let resource = OccurrenceResource::PathOccurrence {
            requested,
            follow_mode,
            object_state,
            parent_object,
            final_object,
            final_object_generation,
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
        let path_projections =
            PrincipalPathProjections::new(vec![requested_paths.clone(); actions.len()]);
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
        self.evaluate_typed_decision_inner(&set, &gates, Some(&path_projections))
    }

    /// Authorize one staged read of an explicit system-information kind.
    ///
    /// The native adapter supplies a closed, reviewed coverage-edge id and a
    /// frame-derived principal set.  Callers cannot provide either value from
    /// JavaScript as free-form text: the C ABI maps compact enum tags to both
    /// before entering this method.
    /// @ref LLP 0021#decision-staging-and-principal-semantics — system reads use
    /// exact selectors and every declared stage is evaluated fail-closed.
    pub fn authorize_typed_system_info_stage(
        &self,
        module_id: &str,
        operation_key: &str,
        coverage_edge_id: &str,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        name: capsec_semantics::model::SystemInfoName,
        stage: capsec_semantics::model::Stage,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::EffectGate;
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            OccurrenceResource, SelectorResource, StableId,
        };

        if !matches!(
            stage,
            capsec_semantics::model::Stage::Requested | capsec_semantics::model::Stage::Commit
        ) {
            return Err(capsec_semantics::Error::ArmRefused(
                "system information supports only requested and commit stages".into(),
            ));
        }
        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "system-information read has no authenticated typed principal".into(),
            )
        })?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "system-information principal stack is empty, noncanonical, or omits the actor"
                    .into(),
            ));
        }
        let requested = SelectorResource::SystemInfo { name };
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
                action: ActionId::new("sys:read").map_err(capsec_semantics::Error::InvalidModel)?,
                effect_owner: principal,
                resource: OccurrenceResource::SystemInfoOccurrence {
                    requested: Box::new(requested),
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

    /// Authorize one virtual-cwd observation. The resource is the sealed
    /// runtime-generation state, not an ambient process directory. v1's
    /// package-wide static floor is authored by the policy generator; root is
    /// admitted by ordinary ambient-root authority.
    // @ref LLP 0023#53-cwd-visibility-is-an-explicit-information-grant
    pub fn authorize_typed_cwd_observe_stage(
        &self,
        module_id: &str,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        stage: capsec_semantics::model::Stage,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::EffectGate;
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            OccurrenceResource, SelectorResource, SessionStateName, StableId, Stage,
        };

        if !matches!(stage, Stage::Requested | Stage::Commit) {
            return Err(capsec_semantics::Error::ArmRefused(
                "cwd observation supports only requested and commit stages".into(),
            ));
        }
        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "cwd observation has no authenticated typed principal".into(),
            )
        })?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "cwd observation principal stack is noncanonical or omits the actor".into(),
            ));
        }
        let requested = SelectorResource::SessionState {
            name: SessionStateName::Cwd,
        };
        let set = DecisionSet {
            decision_set_schema: DecisionSetSchema::V1,
            operation_id: capsec_semantics::model::NonEmptyString::new(format!(
                "cwd-observe:{module_id}:cwd"
            ))
            .map_err(capsec_semantics::Error::InvalidModel)?,
            atomicity_group: StableId::new("surface.native.op.exactgetcwd.1bhagb7.decision")
                .map_err(capsec_semantics::Error::InvalidModel)?,
            combination: EffectCombination::Conjunction,
            context: DecisionContext {
                stage,
                actor: principal.clone(),
                constrained_principals,
                presented_handle_ids: Vec::new(),
            },
            effects: vec![Effect {
                action: ActionId::new("path:cwd-observe")
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                effect_owner: principal,
                resource: OccurrenceResource::SessionStateOccurrence {
                    requested: Box::new(requested),
                },
            }],
        };
        let edge = "surface.native.op.exactgetcwd.1bhagb7";
        self.evaluate_typed_decision(
            &set,
            &[EffectGate {
                coverage_edge_id: StableId::new(edge)
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                target_cell: self.target_cell(edge),
                definition_and_edge_predicates_satisfied: true,
            }],
        )
    }

    /// Authorize an atomic virtual-cwd replacement as one conjunction: the
    /// core-enforced root-only mutation action and directory metadata access
    /// over the same staged retained object.
    // @ref LLP 0023#52-chdir-is-root-only
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_typed_cwd_mutate_stage(
        &self,
        module_id: &str,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        path: &std::path::Path,
        stage: capsec_semantics::model::Stage,
        final_object: Option<capsec_semantics::model::ObjectIdentity>,
        retained_handle: Option<capsec_semantics::model::NonEmptyString>,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::{EffectGate, PrincipalPathProjections};
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            FollowMode, ObjectState, OccurrenceResource, StableId, Stage,
        };

        if !matches!(stage, Stage::Requested | Stage::Commit) {
            return Err(capsec_semantics::Error::ArmRefused(
                "cwd mutation supports only requested and commit stages".into(),
            ));
        }
        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "cwd mutation has no authenticated typed principal".into(),
            )
        })?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "cwd mutation principal stack is noncanonical or omits the actor".into(),
            ));
        }
        let projections = if stage == Stage::Requested {
            self.typed_requested_logical_paths(&constrained_principals, path)?
        } else {
            self.typed_logical_paths(&constrained_principals, path)?
        };
        let requested = projections.get(&principal).cloned().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "cwd mutation actor lacks an authenticated path projection".into(),
            )
        })?;
        let resource = OccurrenceResource::PathOccurrence {
            requested: requested.clone(),
            follow_mode: FollowMode::FollowFinal,
            object_state: if stage == Stage::Requested {
                ObjectState::Unknown
            } else {
                ObjectState::Existing
            },
            parent_object: None,
            final_object,
            final_object_generation: None,
            retained_handle,
        };
        let edge = "surface.native.op.exactsetcwd.0nm1ccf";
        let actions = ["path:cwd-mutate", "fs:list"];
        let set = DecisionSet {
            decision_set_schema: DecisionSetSchema::V1,
            operation_id: capsec_semantics::model::NonEmptyString::new(format!(
                "cwd-mutate:{module_id}:{}",
                serde_json::to_string(&requested)
                    .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?
            ))
            .map_err(capsec_semantics::Error::InvalidModel)?,
            atomicity_group: StableId::new(format!("{edge}.decision"))
                .map_err(capsec_semantics::Error::InvalidModel)?,
            combination: EffectCombination::Conjunction,
            context: DecisionContext {
                stage,
                actor: principal.clone(),
                constrained_principals,
                presented_handle_ids: Vec::new(),
            },
            effects: actions
                .iter()
                .map(|action| {
                    Ok(Effect {
                        action: ActionId::new(*action)
                            .map_err(capsec_semantics::Error::InvalidModel)?,
                        effect_owner: principal.clone(),
                        resource: resource.clone(),
                    })
                })
                .collect::<capsec_semantics::Result<Vec<_>>>()?,
        };
        let path_projections =
            PrincipalPathProjections::new(vec![projections.clone(), projections]);
        let gates = actions
            .iter()
            .map(|_| {
                Ok(EffectGate {
                    coverage_edge_id: StableId::new(edge)
                        .map_err(capsec_semantics::Error::InvalidModel)?,
                    target_cell: self.target_cell(edge),
                    definition_and_edge_predicates_satisfied: true,
                })
            })
            .collect::<capsec_semantics::Result<Vec<_>>>()?;
        self.evaluate_typed_decision_inner(&set, &gates, Some(&path_projections))
    }

    /// Authorize one exact lifecycle disposition. The complete constrained
    /// frame set is carried into the typed evaluator, whose action-level
    /// root-only predicate runs before any positive authority source.
    // @ref LLP 0025#8-exit-and-lifecycle — lifecycle requests and exit-code
    // access are cooperative, root-only, and staged before state access.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_typed_lifecycle_stage(
        &self,
        module_id: &str,
        operation_key: &str,
        coverage_edge_id: &str,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        disposition: capsec_semantics::model::LifecycleDisposition,
        stage: capsec_semantics::model::Stage,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::EffectGate;
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            OccurrenceResource, SelectorResource, StableId,
        };

        if !matches!(
            stage,
            capsec_semantics::model::Stage::Requested | capsec_semantics::model::Stage::Commit
        ) {
            return Err(capsec_semantics::Error::ArmRefused(
                "lifecycle access supports only requested and commit stages".into(),
            ));
        }
        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "lifecycle access has no authenticated typed principal".into(),
            )
        })?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "lifecycle principal stack is empty, noncanonical, or omits the actor".into(),
            ));
        }
        let requested = SelectorResource::SessionLifecycle { disposition };
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
                action: ActionId::new("lifecycle:exit")
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                effect_owner: principal,
                resource: OccurrenceResource::LifecycleOccurrence {
                    requested: Box::new(requested),
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

    pub fn lifecycle_exit_code(&self) -> i32 {
        match self
            .session_lifecycle
            .get_exit_code(crate::session_lifecycle::LifecyclePrincipal::Root)
        {
            crate::session_lifecycle::LifecycleGetDisposition::Value(code) => code,
            crate::session_lifecycle::LifecycleGetDisposition::Denied => {
                crate::session_constants::EXIT_STATUS_ORDERLY_DEFAULT
            }
        }
    }

    pub fn set_lifecycle_exit_code(&self, code: i32) {
        let _ = self
            .session_lifecycle
            .set_exit_code(crate::session_lifecycle::LifecyclePrincipal::Root, code);
    }

    /// Clone the supervisor-owned lifecycle port paired with this Host.
    pub fn session_lifecycle(&self) -> crate::session_lifecycle::SessionLifecyclePort {
        self.session_lifecycle.clone()
    }

    /// Authorize the canonical operator `.exit` route without accepting a
    /// caller-selected principal, constrained-frame set, disposition, or gate.
    /// Aliases are normalized to this command id by the generated REPL parser.
    pub fn request_operator_exit(&self) -> crate::session_lifecycle::LifecycleRequestDisposition {
        use capsec_semantics::decision::DecisionOutcome;
        use capsec_semantics::model::{LifecycleDisposition, Stage};

        let Some(root) = self.typed_principal_for_module("0") else {
            return crate::session_lifecycle::LifecycleRequestDisposition::Denied;
        };
        let Some(edge) = generated_coverage_edge_id("cli", "repl-command:exit") else {
            return crate::session_lifecycle::LifecycleRequestDisposition::Denied;
        };
        for stage in [Stage::Requested, Stage::Commit] {
            let decision = self.authorize_typed_lifecycle_stage(
                "0",
                "operator-repl-exit",
                edge,
                vec![root.clone()],
                LifecycleDisposition::ExitRequest,
                stage,
            );
            if !matches!(decision, Ok(decision) if decision.outcome == DecisionOutcome::Allow) {
                return crate::session_lifecycle::LifecycleRequestDisposition::Denied;
            }
        }
        self.session_lifecycle.request_exit(
            crate::session_lifecycle::LifecyclePrincipal::Root,
            self.lifecycle_exit_code(),
        )
    }

    /// Authorize one exact broker-base environment disclosure before the
    /// native adapter reads the process environment.
    // @ref LLP 0021#typed-resources-and-initial-vocabulary — environment
    // authority is exact-name and target-specific; there is no wildcard read.
    pub fn authorize_typed_environment_read_stage(
        &self,
        module_id: &str,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        name: capsec_semantics::model::EnvironmentName,
        stage: capsec_semantics::model::Stage,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::EffectGate;
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            EnvironmentTarget, EnvironmentValueOrigin, OccurrenceResource, SelectorResource,
            StableId,
        };

        if !matches!(
            stage,
            capsec_semantics::model::Stage::Requested | capsec_semantics::model::Stage::Commit
        ) {
            return Err(capsec_semantics::Error::ArmRefused(
                "environment reads support only requested and commit stages".into(),
            ));
        }
        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "environment read has no authenticated typed principal".into(),
            )
        })?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "environment principal stack is empty, noncanonical, or omits the actor".into(),
            ));
        }
        let requested = SelectorResource::EnvironmentName {
            target: EnvironmentTarget::BrokerBase,
            name,
        };
        let operation_resource = serde_json::to_string(&requested)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        let coverage_edge_id = "surface.native.op.exactgetenv.0k6bv7a";
        let set = DecisionSet {
            decision_set_schema: DecisionSetSchema::V1,
            operation_id: capsec_semantics::model::NonEmptyString::new(format!(
                "environment-read:{module_id}:{operation_resource}"
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
                action: ActionId::new("env:read").map_err(capsec_semantics::Error::InvalidModel)?,
                effect_owner: principal,
                resource: OccurrenceResource::EnvironmentOccurrence {
                    requested: Box::new(requested),
                    value_origin: EnvironmentValueOrigin::BrokerBase,
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

    /// Authorize one direct `print()` write into the host's bounded stdout
    /// console broker before the line is enqueued.
    // @ref LLP 0021#typed-resources-and-initial-vocabulary — stdio authority
    // binds both the stream and its exact source identity.
    pub fn authorize_typed_print_stage(
        &self,
        module_id: &str,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        stage: capsec_semantics::model::Stage,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::EffectGate;
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            NonEmptyString, OccurrenceResource, SelectorResource, StableId, StdioSource,
            StdioSourceKind, StdioStream,
        };

        if !matches!(
            stage,
            capsec_semantics::model::Stage::Requested
                | capsec_semantics::model::Stage::Commit
                | capsec_semantics::model::Stage::Repeat
        ) {
            return Err(capsec_semantics::Error::ArmRefused(
                "direct print supports only requested, commit, and repeat stages".into(),
            ));
        }
        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "direct print has no authenticated typed principal".into(),
            )
        })?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "stdio principal stack is empty, noncanonical, or omits the actor".into(),
            ));
        }
        let requested = SelectorResource::Stdio {
            stream: StdioStream::Stdout,
            source: StdioSource {
                kind: StdioSourceKind::Broker,
                identity: NonEmptyString::new("ibex:console:stdout")
                    .map_err(capsec_semantics::Error::InvalidModel)?,
            },
        };
        let operation_resource = serde_json::to_string(&requested)
            .map_err(|error| capsec_semantics::Error::InvalidModel(error.to_string()))?;
        let coverage_edge_id = "surface.native.op.global.print.0zmmm8e";
        let set = DecisionSet {
            decision_set_schema: DecisionSetSchema::V1,
            operation_id: NonEmptyString::new(format!(
                "direct-print:{module_id}:{operation_resource}"
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
                action: ActionId::new("stdio:write")
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                effect_owner: principal,
                resource: OccurrenceResource::StdioOccurrence {
                    requested: Box::new(requested),
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

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_typed_listen_stage(
        &self,
        module_id: &str,
        operation_key: &str,
        coverage_edge_id: &str,
        constrained_principals: Vec<capsec_semantics::model::Principal>,
        transport: capsec_semantics::model::ListenTransport,
        bind: capsec_semantics::model::ListenBind,
        port: capsec_semantics::model::ListenPort,
        dual_stack: bool,
        peer_classes: Vec<capsec_semantics::model::PeerClass>,
        stage: capsec_semantics::model::Stage,
        bound_endpoints: Option<Vec<capsec_semantics::model::BoundEndpoint>>,
        listener_id: Option<capsec_semantics::model::NonEmptyString>,
        accepted_peer: Option<capsec_semantics::model::AcceptedPeer>,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        use capsec_semantics::decision::EffectGate;
        use capsec_semantics::model::{
            ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination,
            OccurrenceResource, SelectorResource, StableId,
        };

        let principal = self.typed_principal_for_module(module_id).ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "listen operation has no authenticated typed principal".into(),
            )
        })?;
        if !constrained_principals.contains(&principal)
            || !capsec_semantics::model::principal_set_is_canonical(&constrained_principals)
        {
            return Err(capsec_semantics::Error::ArmRefused(
                "listen principal stack is empty, noncanonical, or omits the actor".into(),
            ));
        }
        let requested = SelectorResource::ListenInet {
            transport,
            bind,
            port,
            dual_stack,
            peer_classes,
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
                action: ActionId::new("network:listen")
                    .map_err(capsec_semantics::Error::InvalidModel)?,
                effect_owner: principal,
                resource: OccurrenceResource::ListenOccurrence {
                    requested: Box::new(requested),
                    bound_endpoints,
                    bound_unix_object: None,
                    listener_id,
                    accepted_peer,
                    accepted_unix_peer: None,
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
        self.evaluate_typed_decision_inner(set, gates, None)
    }

    fn evaluate_typed_decision_inner(
        &self,
        set: &capsec_semantics::model::DecisionSet,
        gates: &[capsec_semantics::decision::EffectGate],
        projections: Option<&capsec_semantics::decision::PrincipalPathProjections>,
    ) -> capsec_semantics::Result<capsec_semantics::decision::Decision> {
        let context = self.decision_context.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed decision requested without an armed context".into(),
            )
        })?;
        let context = context.read().map_err(|_| {
            capsec_semantics::Error::ArmRefused("typed decision context lock is poisoned".into())
        })?;
        let decision = match projections {
            Some(projections) => {
                capsec_semantics::decision::evaluate_decision_set_with_path_projections(
                    &context,
                    set,
                    gates,
                    projections,
                    capsec_semantics::decision::Workflow::ProductionEnforce,
                    &classify_network_peer,
                )?
            }
            None => capsec_semantics::decision::evaluate_decision_set(
                &context,
                set,
                gates,
                capsec_semantics::decision::Workflow::ProductionEnforce,
                &classify_network_peer,
            )?,
        };
        self.typed_decision_count.fetch_add(1, Ordering::Relaxed);
        #[cfg(any(test, feature = "capsec-conformance-observer"))]
        {
            let evidence =
                capsec_semantics::decision::structure_decision_evidence(&context, set, &decision);
            #[cfg(any(test, feature = "capsec-conformance-observer"))]
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
        #[cfg(any(test, feature = "capsec-conformance-observer"))]
        self.record_typed_decision_for_tests(evidence.clone());
        #[cfg(any(test, feature = "capsec-conformance-observer"))]
        self.record_typed_conformance_decision(set, gates, evidence.clone());
        Ok(TypedDecisionResult { decision, evidence })
    }

    fn evaluate_typed_path_decision_with_evidence(
        &self,
        set: &capsec_semantics::model::DecisionSet,
        gates: &[capsec_semantics::decision::EffectGate],
        projections: &capsec_semantics::decision::PrincipalPathProjections,
    ) -> capsec_semantics::Result<TypedDecisionResult> {
        let context = self.decision_context.as_deref().ok_or_else(|| {
            capsec_semantics::Error::ArmRefused(
                "typed path decision requested without an armed context".into(),
            )
        })?;
        let context = context.read().map_err(|_| {
            capsec_semantics::Error::ArmRefused("typed decision context lock is poisoned".into())
        })?;
        let decision = capsec_semantics::decision::evaluate_decision_set_with_path_projections(
            &context,
            set,
            gates,
            projections,
            capsec_semantics::decision::Workflow::ProductionEnforce,
            &classify_network_peer,
        )?;
        let evidence =
            capsec_semantics::decision::structure_decision_evidence(&context, set, &decision);
        self.typed_decision_count.fetch_add(1, Ordering::Relaxed);
        #[cfg(any(test, feature = "capsec-conformance-observer"))]
        self.record_typed_decision_for_tests(evidence.clone());
        #[cfg(any(test, feature = "capsec-conformance-observer"))]
        self.record_typed_conformance_decision(set, gates, evidence.clone());
        Ok(TypedDecisionResult { decision, evidence })
    }

    #[cfg(any(test, feature = "capsec-conformance-observer"))]
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

    #[cfg(any(test, feature = "capsec-conformance-observer"))]
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
        let meta =
            self.resolve_module_meta_for_principal_inner(specifier, referrer, None, false)?;
        self.load_authenticated_module_source(meta)
    }

    /// Decode the loader's versioned logical referrer back into private native
    /// resolver state. Armed callers may never submit a host spelling: the
    /// binding owner, logical components, and virtual spelling are all checked
    /// against the immutable VFS mount table before a `PathBuf` is derived.
    /// The returned path stays in Rust and is never serialized back to JS.
    /// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
    pub fn module_referrer_path(&self, encoded: &str) -> anyhow::Result<std::path::PathBuf> {
        let value = capsec_semantics::strict_json::parse_strict(encoded)
            .map_err(|error| anyhow::anyhow!("invalid logical module referrer: {error}"))?;
        let Some(snapshot) = self.armed_snapshot.as_deref() else {
            let record: crate::module_loader::PrivateResolverPath =
                serde_json::from_value(value)
                    .map_err(|error| anyhow::anyhow!("invalid private module referrer: {error}"))?;
            record.validate()?;
            if record.session_handle() != self.resolver_session_handle.as_ref() {
                anyhow::bail!("private module referrer belongs to another session");
            }
            if record.virtual_path() != format!("/project/.ibex-resolver/{}", record.handle()) {
                anyhow::bail!("private module referrer display identity is invalid");
            }
            return self
                .private_resolver_paths
                .read()
                .map_err(|_| anyhow::anyhow!("private resolver registry is poisoned"))?
                .by_handle
                .get(record.handle())
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("private module referrer is stale"));
        };
        if value.get("schema").and_then(serde_json::Value::as_str)
            == Some("ibex/virtual-referrer/1")
        {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase", deny_unknown_fields)]
            struct VirtualReferrer {
                schema: String,
                virtual_path: String,
            }
            let syntax: VirtualReferrer = serde_json::from_value(value)
                .map_err(|error| anyhow::anyhow!("invalid virtual module referrer: {error}"))?;
            if syntax.schema != "ibex/virtual-referrer/1" {
                anyhow::bail!("unsupported virtual module referrer schema");
            }
            let vfs = self.virtual_file_system()?;
            let namespace = vfs
                .resolve_root_bytes(syntax.virtual_path.as_bytes(), None)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            if namespace.virtual_path() != syntax.virtual_path {
                anyhow::bail!("virtual module referrer is not canonical");
            }
            // Convert the untrusted virtual spelling into the same typed
            // binding-relative record accepted below, then make that path take
            // the ordinary snapshot-validation route. This matters for linked
            // package mounts whose backing root is not physically beneath the
            // project binding.
            let logical = vfs
                .resolver_logical_path_for_authenticated_entry(
                    &namespace,
                    &self.resolver_session_handle,
                )
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            vfs.close();
            let encoded = serde_json::to_string(&logical).map_err(|error| {
                anyhow::anyhow!("logical module referrer encode failed: {error}")
            })?;
            return self.module_referrer_path(&encoded);
        }
        let record: crate::vfs::ResolverLogicalPath = serde_json::from_value(value)
            .map_err(|error| anyhow::anyhow!("invalid logical module referrer: {error}"))?;
        record
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid logical module referrer: {error}"))?;
        if record.session_handle() != self.resolver_session_handle.as_ref() {
            anyhow::bail!("logical module referrer belongs to another session");
        }

        let candidates = snapshot
            .root_bindings()?
            .iter()
            .filter(|binding| {
                binding.logical_root == record.logical_path().root
                    && match record.binding_owner() {
                        Some(owner) => binding.owner.as_ref() == Some(owner),
                        None => binding.owner.is_none(),
                    }
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            anyhow::bail!("logical module referrer has no unique authenticated binding");
        }
        let binding = candidates[0];
        validate_armed_binding_object(binding)?;
        let mut host_path = binding.host_path.clone();
        host_path
            .components
            .extend(record.logical_path().components.iter().cloned());
        let private_path = host_path_from_logical_path(&host_path, "logical module referrer")?;

        // Re-derive the whole public record from the authenticated mount. This
        // catches forged owner/root combinations and virtual aliases rather
        // than trusting the redundant display spelling.
        let vfs = self.virtual_file_system()?;
        let namespace = vfs
            .namespace_for_authenticated_project_path(&private_path)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let expected = vfs
            .resolver_logical_path_for_authenticated_entry(
                &namespace,
                &self.resolver_session_handle,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        vfs.close();
        if expected != record {
            anyhow::bail!("logical module referrer does not match its authenticated binding");
        }
        Ok(private_path)
    }

    /// Resolve one structured-session static edge from the authenticated
    /// logical directory captured in its source credential. The caller cannot
    /// provide a host spelling: this method derives it from the immutable
    /// armed root graph, validates the binding object, round-trips the mapping,
    /// runs import-graph preflight, and only then permits the authenticated
    /// module-source read.
    ///
    /// The synthetic basename is never opened. The existing resolver accepts
    /// file referrers, while LLP 0023 credentials intentionally retain the
    /// containing logical directory; appending a fixed private basename makes
    /// relative and package-`imports` resolution use that exact directory.
    /// @ref LLP 0023#73-referrer-capture
    /// @ref LLP 0024#73-evaluation-phases-collisions-and-the-cross-kind-matrix
    pub fn resolve_session_static_import(
        &self,
        specifier: &str,
        logical_referrer: &capsec_semantics::model::LogicalPath,
    ) -> anyhow::Result<ResolvedModule> {
        let snapshot = self
            .armed_snapshot
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("static imports require an armed snapshot"))?;
        let requester = self
            .typed_imports
            .keys()
            .find(|principal| principal.is_root())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("armed root principal is absent"))?;
        let directory = authenticated_host_directory_for_logical_referrer(
            snapshot,
            &requester,
            logical_referrer,
        )?;
        let synthetic_referrer = directory.join(".ibex-session-static-import.mjs");
        let module =
            self.resolve_module_for_principal(specifier, Some(&synthetic_referrer), Some("0"))?;
        let authenticated_esm = module.kind == crate::module_loader::ModuleKind::Esm
            || module.path.as_deref().is_some_and(|path| {
                path.extension()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("mjs"))
            });
        if authenticated_esm
            && module
                .source
                .as_deref()
                .is_some_and(crate::engine::session_syntax::module_source_has_top_level_await)
        {
            anyhow::bail!(
                "IBEX_DEPENDENCY_TOP_LEVEL_AWAIT: static dependency top-level await is unavailable"
            );
        }
        Ok(module)
    }

    /// Resolve one authenticated session-root edge without reading the target
    /// module body. Direct CommonJS `require.resolve()` uses this route: it
    /// authenticates and round-trips the same logical referrer as a real load,
    /// applies the resolve-only disclosure gates, and returns only metadata.
    /// @ref LLP 0023#72-the-structured-result-and-its-error-classes
    pub fn resolve_session_static_import_meta(
        &self,
        specifier: &str,
        logical_referrer: &capsec_semantics::model::LogicalPath,
    ) -> anyhow::Result<ResolvedModule> {
        let snapshot = self
            .armed_snapshot
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("session-root resolution requires an armed snapshot"))?;
        let requester = self
            .typed_imports
            .keys()
            .find(|principal| principal.is_root())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("armed root principal is absent"))?;
        let directory = authenticated_host_directory_for_logical_referrer(
            snapshot,
            &requester,
            logical_referrer,
        )?;
        let synthetic_referrer = directory.join(".ibex-session-static-import.mjs");
        self.resolve_module_meta_for_principal(specifier, Some(&synthetic_referrer), Some("0"))
    }

    pub fn resolve_module_for_principal(
        &self,
        specifier: &str,
        referrer: Option<&std::path::Path>,
        requester_module_id: Option<&str>,
    ) -> anyhow::Result<ResolvedModule> {
        let meta = self.resolve_module_meta_for_principal_inner(
            specifier,
            referrer,
            requester_module_id,
            false,
        )?;
        self.load_authenticated_module_source(meta)
    }

    /// Resolve one dependency of a manifest-authored builtin without treating
    /// that private implementation edge as a package import. Both the requested
    /// spelling and the resolved record must belong to the generated builtin
    /// manifest; package/path resolution is never reachable through this path.
    /// The engine exposes this only to the module loader's captured bootstrap
    /// closure while an exact builtin body is synchronously evaluating.
    /// @ref LLP 0013#policy — package-facing imports remain graph-gated while
    /// trusted builtin implementation fan-out is not a package-authored edge.
    pub fn resolve_manifest_builtin_internal(
        &self,
        specifier: &str,
    ) -> anyhow::Result<ResolvedModule> {
        if self.unarmed_closed {
            anyhow::bail!("unarmed host cannot resolve executable modules");
        }
        if !self.module_loader.is_builtin_specifier(specifier) {
            anyhow::bail!("internal builtin resolution requires an exact manifest specifier");
        }
        let meta = self.module_loader.resolve_meta(specifier, None)?;
        if meta.kind != crate::module_loader::ModuleKind::Builtin {
            anyhow::bail!("internal builtin resolution escaped the generated manifest");
        }
        self.load_authenticated_module_source(meta)
    }

    fn load_authenticated_module_source(
        &self,
        meta: ResolvedModule,
    ) -> anyhow::Result<ResolvedModule> {
        let loaded = if let Some(snapshot) = self.armed_snapshot.as_deref() {
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
                self.module_loader.load_source_bytes(meta, bytes)?
            } else if let Some(path) = meta.path.as_deref() {
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
                self.module_loader.load_source_bytes(meta, bytes)?
            } else {
                self.module_loader.load_source(meta)?
            }
        } else {
            self.module_loader.load_source(meta)?
        };
        self.attach_authenticated_module_identity(loaded)
    }

    /// Stamp an armed file record with the same VFS `SourceId`, label, and
    /// virtual path used by direct file ingress. The module loader receives the
    /// native host path only as resolver-local state; cache keys and project
    /// observables use these authenticated virtual values.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    fn attach_authenticated_module_identity(
        &self,
        mut module: ResolvedModule,
    ) -> anyhow::Result<ResolvedModule> {
        if module.kind == crate::module_loader::ModuleKind::Builtin {
            return Ok(module);
        }
        if self.armed_snapshot.is_none() {
            let path = module
                .path
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("resolved file module has no private path"))?;
            module.private_resolver_path = Some(self.retain_private_resolver_path(path)?);
            module.private_resolver_package_root = module
                .package_root
                .as_deref()
                .map(|root| self.retain_private_resolver_path(root))
                .transpose()?;
            return Ok(module);
        }
        let path = module
            .path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("authenticated file module has no canonical path"))?;
        let vfs = self
            .virtual_file_system()
            .context("failed to derive authenticated module VFS identity")?;
        let namespace = vfs
            .namespace_for_authenticated_project_path(path)
            .context("authenticated module path is outside the virtual project namespace")?;
        let source_id = vfs
            .source_id_for_authenticated_module(&namespace)
            .context("authenticated module has no VFS SourceId")?;
        let source_label = crate::vfs::SourceLabel::file(&namespace)
            .context("authenticated module has no virtual source label")?;
        let resolver_path = vfs
            .resolver_logical_path_for_authenticated_entry(
                &namespace,
                &self.resolver_session_handle,
            )
            .context("authenticated module has no logical resolver path")?;
        let resolver_package_root = module
            .package_root
            .as_deref()
            .map(|package_root| {
                let namespace = vfs
                    .namespace_for_authenticated_project_path(package_root)
                    .context("authenticated package root is outside the virtual namespace")?;
                vfs.resolver_logical_path_for_authenticated_entry(
                    &namespace,
                    &self.resolver_session_handle,
                )
                .context("authenticated package root has no logical resolver identity")
            })
            .transpose()?;
        module.virtual_path = Some(namespace.virtual_path().to_owned());
        module.source_id = Some(source_id);
        module.source_label = Some(source_label);
        module.resolver_path = Some(resolver_path);
        module.resolver_package_root = resolver_package_root;
        vfs.close();
        Ok(module)
    }

    fn retain_private_resolver_path(
        &self,
        path: &std::path::Path,
    ) -> anyhow::Result<crate::module_loader::PrivateResolverPath> {
        const MAX_PRIVATE_RESOLVER_PATHS: usize = 65_536;
        let mut registry = self
            .private_resolver_paths
            .write()
            .map_err(|_| anyhow::anyhow!("private resolver registry is poisoned"))?;
        if let Some(handle) = registry.by_path.get(path).cloned() {
            return crate::module_loader::PrivateResolverPath::new(
                self.resolver_session_handle.to_string(),
                handle.clone(),
                format!("/project/.ibex-resolver/{handle}"),
            );
        }
        if registry.by_handle.len() >= MAX_PRIVATE_RESOLVER_PATHS {
            anyhow::bail!("private resolver registry is full");
        }
        let ordinal = self
            .private_resolver_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("private resolver handle space is exhausted"))?;
        let handle = format!("r{ordinal:016x}");
        let path = path.to_path_buf();
        registry.by_handle.insert(handle.clone(), path.clone());
        registry.by_path.insert(path, handle.clone());
        crate::module_loader::PrivateResolverPath::new(
            self.resolver_session_handle.to_string(),
            handle.clone(),
            format!("/project/.ibex-resolver/{handle}"),
        )
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
        let meta = self.resolve_module_meta_for_principal_inner(
            specifier,
            referrer,
            requester_module_id,
            true,
        )?;
        self.attach_authenticated_module_identity(meta)
    }

    fn resolve_module_meta_for_principal_inner(
        &self,
        specifier: &str,
        referrer: Option<&std::path::Path>,
        requester_module_id: Option<&str>,
        authorize_path_disclosure: bool,
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
            let requester_key = requester_module_id
                .map(str::to_owned)
                .or_else(|| requester.is_root().then(|| "0".to_owned()));
            Some((snapshot, root_principal, requester, requester_key, plan))
        } else {
            None
        };

        if authorize_path_disclosure {
            if let Some((_, _, _, requester_key, plan)) = armed_resolution.as_ref() {
                if let Some(requested_path) = plan.requested_path() {
                    let requester_key = requester_key.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "module metadata disclosure has no authenticated requester identity"
                        )
                    })?;
                    self.authorize_require_resolve_stage(
                        requester_key,
                        requested_path,
                        capsec_semantics::model::Stage::Requested,
                        true,
                        None,
                        None,
                        None,
                    )?;
                }
            }
        }

        // No filesystem/package-manifest probing is allowed before the armed
        // preflight above authenticates the requester and constrains the
        // lexical target to a bound root or exact graph edge. In particular,
        // require.resolve must not reveal existent-vs-missing unauthorized
        // targets through resolver errors or timing.
        let mut meta = match armed_resolution.as_ref().map(|(_, _, _, _, plan)| plan) {
            Some(ArmedModuleResolution::BoundPackage { name, root }) => self
                .module_loader
                .resolve_meta_from_bound_package(specifier, name, root)?,
            _ => self.module_loader.resolve_meta(specifier, referrer)?,
        };
        if let Some(path) = meta.path.as_ref() {
            if let Some((snapshot, root_principal, requester, requester_key, plan)) =
                armed_resolution.as_ref()
            {
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
                if authorize_path_disclosure {
                    let requester_key = requester_key.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "module metadata disclosure has no authenticated requester identity"
                        )
                    })?;
                    self.authorize_require_resolve_path(
                        requester_key,
                        plan.requested_path(),
                        &canonical,
                    )?;
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

    /// Gate an armed metadata-only module resolution through the typed
    /// filesystem plane before the resolved path is returned to JavaScript.
    /// The preflight requested stage runs before resolver probing; discovery,
    /// commit, and repeat bind the final canonical object and ensure a repeated
    /// `require.resolve` cannot bypass current authority through loader caches.
    /// @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
    fn authorize_require_resolve_path(
        &self,
        requester_module_id: &str,
        preflight_path: Option<&std::path::Path>,
        canonical_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        if preflight_path != Some(canonical_path) {
            self.authorize_require_resolve_stage(
                requester_module_id,
                canonical_path,
                capsec_semantics::model::Stage::Requested,
                true,
                None,
                None,
                None,
            )?;
        }

        let parent = canonical_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("resolved module has no parent directory"))?;
        let parent_object = object_identity_for_host_path(parent)?;
        let final_object = object_identity_for_host_path(canonical_path)?;
        self.authorize_require_resolve_stage(
            requester_module_id,
            canonical_path,
            capsec_semantics::model::Stage::Discovery,
            true,
            Some(parent),
            Some(parent_object.clone()),
            Some(final_object.clone()),
        )?;

        let retained_handle = capsec_semantics::model::NonEmptyString::new(format!(
            "module-resolution:{}:{}",
            final_object.volume.as_str(),
            final_object.file.as_str()
        ))
        .map_err(capsec_semantics::Error::InvalidModel)?;
        self.authorize_require_resolve_stage_with_handle(
            requester_module_id,
            canonical_path,
            capsec_semantics::model::Stage::Commit,
            false,
            Some(parent),
            Some(parent_object.clone()),
            Some(final_object.clone()),
            Some(retained_handle.clone()),
        )?;

        let repeated_parent = object_identity_for_host_path(parent)?;
        let repeated_final = object_identity_for_host_path(canonical_path)?;
        if repeated_parent != parent_object || repeated_final != final_object {
            anyhow::bail!("module metadata object changed during authorization");
        }
        self.authorize_require_resolve_stage_with_handle(
            requester_module_id,
            canonical_path,
            capsec_semantics::model::Stage::Repeat,
            false,
            Some(parent),
            Some(repeated_parent),
            Some(repeated_final),
            Some(retained_handle),
        )
    }

    fn authorize_require_resolve_stage(
        &self,
        requester_module_id: &str,
        path: &std::path::Path,
        stage: capsec_semantics::model::Stage,
        disclosure_only: bool,
        resolved_parent: Option<&std::path::Path>,
        parent_object: Option<capsec_semantics::model::ObjectIdentity>,
        final_object: Option<capsec_semantics::model::ObjectIdentity>,
    ) -> anyhow::Result<()> {
        self.authorize_require_resolve_stage_with_handle(
            requester_module_id,
            path,
            stage,
            disclosure_only,
            resolved_parent,
            parent_object,
            final_object,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_require_resolve_stage_with_handle(
        &self,
        requester_module_id: &str,
        path: &std::path::Path,
        stage: capsec_semantics::model::Stage,
        disclosure_only: bool,
        resolved_parent: Option<&std::path::Path>,
        parent_object: Option<capsec_semantics::model::ObjectIdentity>,
        final_object: Option<capsec_semantics::model::ObjectIdentity>,
        retained_handle: Option<capsec_semantics::model::NonEmptyString>,
    ) -> anyhow::Result<()> {
        use capsec_semantics::decision::DecisionOutcome;

        let principal = self
            .typed_principal_for_module(requester_module_id)
            .ok_or_else(|| anyhow::anyhow!("module metadata requester is not authenticated"))?;
        let decision = self.authorize_typed_fs_open_stage(
            requester_module_id,
            "loader-require-resolve",
            "surface.loader.require.resolve.12c9l9i",
            vec![principal],
            path,
            stage,
            if stage == capsec_semantics::model::Stage::Requested {
                capsec_semantics::model::ObjectState::Unknown
            } else {
                capsec_semantics::model::ObjectState::Existing
            },
            capsec_semantics::model::FollowMode::FollowFinal,
            disclosure_only,
            resolved_parent,
            !disclosure_only,
            false,
            parent_object,
            final_object,
            None,
            retained_handle,
            Vec::new(),
        )?;
        if matches!(
            decision.outcome,
            DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
        ) {
            Ok(())
        } else {
            anyhow::bail!("module metadata disclosure denied by typed filesystem policy")
        }
    }
}

#[cfg(any(test, feature = "capsec-conformance-observer"))]
fn complete_test_target_cells(
) -> BTreeMap<String, capsec_semantics::decision::TargetCellDisposition> {
    crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS
        .iter()
        .map(|edge| {
            (
                (*edge).to_owned(),
                capsec_semantics::decision::TargetCellDisposition::Complete,
            )
        })
        .collect()
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
    Generic {
        requested_path: Option<std::path::PathBuf>,
    },
    BoundPackage {
        name: String,
        root: std::path::PathBuf,
    },
}

impl ArmedModuleResolution {
    fn requested_path(&self) -> Option<&std::path::Path> {
        match self {
            Self::Generic { requested_path } => requested_path.as_deref(),
            Self::BoundPackage { root, .. } => Some(root.as_path()),
        }
    }
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
        return Ok(ArmedModuleResolution::Generic {
            requested_path: Some(host_path_from_binding(&binding)?),
        });
    }

    if !is_module_path_specifier(specifier) {
        if !typed_import_allowed(requester_policy, specifier) {
            anyhow::bail!("Import denied by authenticated package graph");
        }
        if builtin {
            return Ok(ArmedModuleResolution::Generic {
                requested_path: None,
            });
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
    Ok(ArmedModuleResolution::Generic {
        requested_path: Some(target),
    })
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

fn absolute_host_path_components(
    path: &std::path::Path,
) -> capsec_semantics::Result<Vec<capsec_semantics::model::PathComponent>> {
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
    host_path_components(&path)
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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use capsec_semantics::decision::TargetCellDisposition;
    use capsec_semantics::Error;
    use sha2::{Digest as _, Sha256};

    let cells_text = crate::capsec_registry_generated::CAPSEC_TARGET_CELLS_JSON;
    let cells: serde_json::Value = serde_json::from_str(cells_text)
        .map_err(|error| Error::InvalidModel(format!("invalid checked target cells: {error}")))?;
    let advertisements: serde_json::Value =
        serde_json::from_str(crate::capsec_registry_generated::CAPSEC_TARGET_ADVERTISEMENTS_JSON)
            .map_err(|error| {
            Error::InvalidModel(format!("invalid checked target advertisements: {error}"))
        })?;
    let target_cells_digest = format!(
        "sha256-{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(cells_text.as_bytes()))
    );
    if advertisements
        .get("targetCellsRawContentDigest")
        .and_then(serde_json::Value::as_str)
        != Some(target_cells_digest.as_str())
    {
        return Err(Error::ArmRefused(
            "target advertisement does not bind the checked target-cell bytes".into(),
        ));
    }
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
    let advertised = advertisements
        .get("advertisements")
        .and_then(serde_json::Value::as_array)
        .map(|targets| {
            targets
                .iter()
                .filter(|candidate| {
                    candidate
                        .pointer("/target/triple")
                        .and_then(serde_json::Value::as_str)
                        == Some(target.as_str())
                        && candidate
                            .pointer("/target/features")
                            .and_then(serde_json::Value::as_array)
                            == Some(&feature_values)
                })
                .collect::<Vec<_>>()
        })
        .ok_or_else(|| Error::InvalidModel("target advertisements lack rows".into()))?;
    if advertised.len() != 1 {
        return Err(Error::ArmRefused(format!(
            "engine target {target} with its exact features has no unique verified advertisement"
        )));
    }
    let loaded_engine = crate::engine::loaded_engine_binary_identity()
        .map_err(Error::ArmRefused)
        .and_then(|identity| {
            serde_json::to_value(identity).map_err(|error| {
                Error::InvalidModel(format!("cannot encode loaded engine identity: {error}"))
            })
        })?;
    if advertised[0].get("engine") != Some(&loaded_engine) {
        return Err(Error::ArmRefused(
            "target conformance report does not identify the exact loaded engine artifact".into(),
        ));
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

fn host_path_from_logical_path(
    host_path: &capsec_semantics::model::LogicalPath,
    label: &str,
) -> capsec_semantics::Result<std::path::PathBuf> {
    if host_path.root != capsec_semantics::model::LogicalRoot::Absolute
        || host_path.host_bound != Some(true)
    {
        return Err(capsec_semantics::Error::ArmRefused(format!(
            "{label} is not an absolute host binding"
        )));
    }
    let mut path = std::path::PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
    for component in &host_path.components {
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

/// The macOS candidate deliberately implements a single-volume-subtree seam:
/// a root binding may not acquire a nested mount whose alias rules differ from
/// the algorithm bound at arming. This is checked both when the Host is built
/// and before path projection; staged occurrences independently reject an
/// observed parent/final object on another volume.
/// @ref LLP 0023#3-path-grammar-normalization-aliasing-and-containment
#[doc(hidden)]
pub fn validate_armed_alias_volume_topology(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
) -> capsec_semantics::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let mounts = mounted_volume_roots()?;
        validate_alias_volume_topology_bindings(snapshot.root_bindings()?, &mounts)?;
    }
    Ok(())
}

fn validate_alias_volume_topology_bindings(
    bindings: &[capsec_semantics::arming::ArmedRootBinding],
    mounts: &[(std::path::PathBuf, String)],
) -> capsec_semantics::Result<()> {
    for binding in bindings {
        if binding.logical_root == capsec_semantics::model::LogicalRoot::Absolute {
            continue;
        }
        let root = host_path_from_binding(binding)?;
        for (mount, volume) in mounts {
            if mount != &root
                && mount.starts_with(&root)
                && volume.as_str() != binding.object.volume.as_str()
            {
                return Err(capsec_semantics::Error::AliasCanonicalizationRefused(
                    format!(
                        "bound root {} contains nested volume {} at {}",
                        root.display(),
                        volume,
                        mount.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn mounted_volume_roots() -> capsec_semantics::Result<Vec<(std::path::PathBuf, String)>> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let mut raw: *mut libc::statfs = std::ptr::null_mut();
    let count = unsafe { libc::getmntinfo(&mut raw, libc::MNT_NOWAIT) };
    if count <= 0 || raw.is_null() {
        return Err(capsec_semantics::Error::AliasCanonicalizationRefused(
            "cannot enumerate macOS mount topology".into(),
        ));
    }
    let rows = unsafe { std::slice::from_raw_parts(raw, count as usize) };
    let mut mounts = Vec::with_capacity(rows.len());
    for row in rows {
        let mount = unsafe { std::ffi::CStr::from_ptr(row.f_mntonname.as_ptr()) };
        let mount = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(mount.to_bytes()));
        let metadata = std::fs::metadata(&mount).map_err(|error| {
            capsec_semantics::Error::AliasCanonicalizationRefused(format!(
                "cannot identify mounted volume {}: {error}",
                mount.display()
            ))
        })?;
        mounts.push((mount, format!("dev:{}", metadata.dev())));
    }
    mounts.sort();
    mounts.dedup();
    Ok(mounts)
}

fn host_path_from_binding(
    binding: &capsec_semantics::arming::ArmedRootBinding,
) -> capsec_semantics::Result<std::path::PathBuf> {
    host_path_from_logical_path(&binding.host_path, "armed root binding")
}

fn authenticated_host_directory_for_logical_referrer(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
    requester: &capsec_semantics::model::Principal,
    logical_referrer: &capsec_semantics::model::LogicalPath,
) -> anyhow::Result<std::path::PathBuf> {
    authenticated_host_path_for_logical_path(
        snapshot,
        requester,
        logical_referrer,
        "session static-import referrer",
    )
}

fn authenticated_host_path_for_logical_path(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
    requester: &capsec_semantics::model::Principal,
    logical_path: &capsec_semantics::model::LogicalPath,
    label: &str,
) -> anyhow::Result<std::path::PathBuf> {
    use capsec_semantics::model::LogicalRoot;

    if !logical_path.is_canonical() {
        anyhow::bail!("{label} is not canonical");
    }
    let candidates = snapshot
        .root_bindings()?
        .iter()
        .filter(|binding| {
            if binding.logical_root != logical_path.root {
                return false;
            }
            if binding.logical_root == LogicalRoot::Absolute {
                return binding.logical_path.as_ref() == Some(logical_path);
            }
            if binding.logical_root == LogicalRoot::Package {
                return binding.owner.as_ref() == Some(requester);
            }
            binding.owner.is_none()
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        anyhow::bail!("{label} has no unique authenticated root binding");
    }
    let binding = candidates[0];
    validate_armed_binding_object(binding)?;

    let mut host_path = binding.host_path.clone();
    if logical_path.root != LogicalRoot::Absolute {
        host_path
            .components
            .extend(logical_path.components.iter().cloned());
    }
    let resolved = host_path_from_logical_path(&host_path, label)?;
    let components = host_path_components(&resolved)?;
    let round_trip = snapshot.logical_path_for_host_components(requester, &components)?;
    if &round_trip != logical_path {
        anyhow::bail!("{label} escaped its authenticated logical root");
    }
    Ok(resolved)
}

fn validate_snapshot_protected_artifacts(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
) -> capsec_semantics::Result<()> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;

    for artifact in snapshot.protected_artifacts() {
        let path = host_path_from_logical_path(&artifact.host_path, "protected artifact path")?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
        }
        let mut file = options.open(&path).map_err(|error| {
            capsec_semantics::Error::ArmRefused(format!(
                "cannot pin protected artifact {}: {error}",
                path.display()
            ))
        })?;
        let before = file.metadata().map_err(|error| {
            capsec_semantics::Error::ArmRefused(format!(
                "cannot inspect protected artifact {}: {error}",
                path.display()
            ))
        })?;
        if !before.is_file() || object_identity_for_metadata(&before)? != artifact.object {
            return Err(capsec_semantics::Error::ArmRefused(format!(
                "protected artifact path does not identify its authenticated object: {}",
                path.display()
            )));
        }
        #[cfg(unix)]
        if artifact.role != capsec_semantics::arming::ProtectedArtifactRole::EngineBinary {
            use std::os::unix::fs::PermissionsExt;
            if before.permissions().mode() & 0o222 != 0 {
                return Err(capsec_semantics::Error::ArmRefused(format!(
                    "protected artifact remains writable: {}",
                    path.display()
                )));
            }
        }
        #[cfg(not(unix))]
        if artifact.role != capsec_semantics::arming::ProtectedArtifactRole::EngineBinary
            && !before.permissions().readonly()
        {
            return Err(capsec_semantics::Error::ArmRefused(format!(
                "protected artifact remains writable: {}",
                path.display()
            )));
        }

        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|error| {
                capsec_semantics::Error::ArmRefused(format!(
                    "cannot hash protected artifact {}: {error}",
                    path.display()
                ))
            })?;
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
        }
        let observed = format!("sha256-{}", URL_SAFE_NO_PAD.encode(hash.finalize()));
        if observed != artifact.content_digest.as_str() {
            return Err(capsec_semantics::Error::ArmRefused(format!(
                "protected artifact content digest changed: {}",
                path.display()
            )));
        }
        let after = file.metadata().map_err(|error| {
            capsec_semantics::Error::ArmRefused(format!(
                "cannot revalidate protected artifact {}: {error}",
                path.display()
            ))
        })?;
        if object_identity_for_metadata(&after)? != artifact.object || after.len() != before.len() {
            return Err(capsec_semantics::Error::ArmRefused(format!(
                "protected artifact changed while it was authenticated: {}",
                path.display()
            )));
        }
    }
    Ok(())
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
) -> capsec_semantics::Result<AuthenticatedPackageSourceState> {
    use capsec_semantics::model::LogicalRoot;

    let bindings = snapshot.root_bindings()?;
    for binding in bindings {
        validate_armed_binding_object(binding)?;
    }
    let project_bindings = bindings
        .iter()
        .filter(|binding| binding.logical_root == LogicalRoot::Project && binding.owner.is_none())
        .collect::<Vec<_>>();
    if project_bindings.len() != 1 {
        return Err(capsec_semantics::Error::ArmRefused(
            "package immutability requires one authenticated project binding".into(),
        ));
    }
    let project_root = host_path_from_binding(project_bindings[0])?;
    let package_roots = bindings
        .iter()
        .filter(|binding| binding.logical_root == LogicalRoot::Package)
        .map(host_path_from_binding)
        .collect::<capsec_semantics::Result<Vec<_>>>()?;
    let membership =
        crate::module_loader::AuthenticatedPackageMembership::new(&project_root, &package_roots)
            .map_err(|error| {
                capsec_semantics::Error::ArmRefused(format!(
                    "failed to authenticate package binding membership: {error}"
                ))
            })?;
    let mut authenticated = AuthenticatedPackageSourceState::default();
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
        let mut inventory = crate::module_loader::authenticated_package_inventory(
            &root,
            &matches[0].object,
            &membership,
        )
        .map_err(|error| {
            capsec_semantics::Error::ArmRefused(format!(
                "failed to authenticate package content {}: {error}",
                root.display()
            ))
        })?;
        if inventory.integrity != integrity.as_str() {
            return Err(capsec_semantics::Error::ArmRefused(format!(
                "installed package content differs from armed integrity at {}",
                root.display()
            )));
        }
        for source in inventory.objects {
            if authenticated
                .generations
                .insert(source.object, source.verification_generation.clone())
                .is_some_and(|existing| existing != source.verification_generation)
            {
                return Err(capsec_semantics::Error::ArmRefused(
                    "one package object reported inconsistent verification generations".into(),
                ));
            }
        }
        #[cfg(unix)]
        authenticated
            .retained_descriptors
            .append(&mut inventory.retained_descriptors);
    }
    refuse_package_first_party_shared_objects(snapshot, &authenticated)?;
    Ok(authenticated)
}

/// A package/first-party hard link has no unique defining principal. Refuse it
/// at arming instead of freezing root-owned source or letting an alias escape
/// the package exact-object set.
/// @ref LLP 0023#42-authenticated-package-source-is-immutable
fn refuse_package_first_party_shared_objects(
    snapshot: &capsec_semantics::arming::ArmedSnapshot,
    packages: &AuthenticatedPackageSourceState,
) -> capsec_semantics::Result<()> {
    use capsec_semantics::model::LogicalRoot;

    if packages.generations.is_empty() {
        return Ok(());
    }
    let bindings = snapshot.root_bindings()?;
    let project = bindings
        .iter()
        .filter(|binding| binding.logical_root == LogicalRoot::Project && binding.owner.is_none())
        .collect::<Vec<_>>();
    if project.len() != 1 {
        return Err(capsec_semantics::Error::ArmRefused(
            "package immutability requires one authenticated project binding".into(),
        ));
    }
    let project_root = host_path_from_binding(project[0])?;
    let package_roots = bindings
        .iter()
        .filter(|binding| binding.logical_root == LogicalRoot::Package)
        .map(host_path_from_binding)
        .collect::<capsec_semantics::Result<Vec<_>>>()?;

    refuse_shared_package_objects_beneath_project(
        &project_root,
        &package_roots,
        &packages.generations,
    )
}

fn refuse_shared_package_objects_beneath_project(
    project_root: &std::path::Path,
    package_roots: &[std::path::PathBuf],
    package_objects: &BTreeMap<
        capsec_semantics::model::ObjectIdentity,
        capsec_semantics::model::NonEmptyString,
    >,
) -> capsec_semantics::Result<()> {
    fn walk(
        path: &std::path::Path,
        package_roots: &[std::path::PathBuf],
        package_objects: &BTreeMap<
            capsec_semantics::model::ObjectIdentity,
            capsec_semantics::model::NonEmptyString,
        >,
    ) -> capsec_semantics::Result<()> {
        if package_roots.iter().any(|root| path == root) {
            return Ok(());
        }
        let mut entries = std::fs::read_dir(path)
            .map_err(|error| {
                capsec_semantics::Error::ArmRefused(format!(
                    "cannot enumerate first-party project source {}: {error}",
                    path.display()
                ))
            })?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|error| {
                capsec_semantics::Error::ArmRefused(format!(
                    "cannot enumerate first-party project source {}: {error}",
                    path.display()
                ))
            })?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let child = entry.path();
            if package_roots.iter().any(|root| &child == root) {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&child).map_err(|error| {
                capsec_semantics::Error::ArmRefused(format!(
                    "cannot inspect first-party project source {}: {error}",
                    child.display()
                ))
            })?;
            if metadata.is_file() || metadata.file_type().is_symlink() {
                let object = object_identity_for_metadata(&metadata)?;
                if package_objects.contains_key(&object) {
                    return Err(capsec_semantics::Error::ArmRefused(format!(
                        "package source and first-party source share one authenticated object: {}",
                        child.display()
                    )));
                }
            }
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                walk(&child, package_roots, package_objects)?;
            }
        }
        Ok(())
    }

    walk(project_root, package_roots, package_objects)
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
    if crate::module_loader::is_registered_builtin_specifier(specifier) {
        if !crate::module_loader::RUNTIME_GATED_NODE_BUILTINS.contains(&builtin_root) {
            return policy.builtins.iter().any(|allowed| allowed == specifier);
        }
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

    #[test]
    fn alias_volume_topology_refuses_a_nested_cross_volume_mount() {
        let binding: capsec_semantics::arming::ArmedRootBinding =
            serde_json::from_value(serde_json::json!({
                "logicalRoot": "project",
                "hostPath": {
                    "root": "absolute",
                    "components": [{"encoding": "utf8", "value": "project"}],
                    "hostBound": true
                },
                "object": {"platform": "apple", "volume": "dev:1", "file": "file:1"}
            }))
            .unwrap();
        let mounts = vec![
            (std::path::PathBuf::from("/project"), "dev:1".to_owned()),
            (
                std::path::PathBuf::from("/project/mounted"),
                "dev:2".to_owned(),
            ),
        ];
        let error = validate_alias_volume_topology_bindings(&[binding], &mounts).unwrap_err();
        assert!(error.to_string().contains("contains nested volume"));
    }

    #[test]
    fn defining_principal_refuses_shared_package_and_first_party_object_only() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let package = project.join("node_modules/pkg");
        let first_party = project.join("src");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::create_dir_all(&first_party).unwrap();
        let package_source = package.join("index.js");
        let first_party_source = first_party.join("app.js");
        let ambiguous_alias = first_party.join("package-alias.js");
        std::fs::write(&package_source, "module.exports = 1;\n").unwrap();
        std::fs::write(&first_party_source, "module.exports = 2;\n").unwrap();
        std::fs::hard_link(&package_source, &ambiguous_alias).unwrap();

        let mut package_objects = BTreeMap::new();
        package_objects.insert(
            object_identity_for_host_path(&package_source).unwrap(),
            capsec_semantics::model::NonEmptyString::new("test-generation").unwrap(),
        );
        let package_roots = vec![package];
        let error = refuse_shared_package_objects_beneath_project(
            &project,
            &package_roots,
            &package_objects,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("package source and first-party source share one authenticated object"),
            "unexpected arming refusal: {error}"
        );

        std::fs::remove_file(ambiguous_alias).unwrap();
        refuse_shared_package_objects_beneath_project(&project, &package_roots, &package_objects)
            .expect("unrelated first-party source must remain writable");
        std::fs::write(&first_party_source, "module.exports = 3;\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(first_party_source).unwrap(),
            "module.exports = 3;\n"
        );
    }

    #[test]
    fn exact_package_object_guard_denies_a_post_arming_alias_outside_the_package() {
        use capsec_semantics::decision::{DecisionOutcome, DecisionReason};
        use capsec_semantics::model::{FollowMode, NonEmptyString, ObjectState, Stage};

        let package_root = test_project_root().join("node_modules/image-lib");
        std::fs::create_dir_all(&package_root).unwrap();
        let fixture = tempfile::Builder::new()
            .prefix("package-object-alias-")
            .tempdir_in(test_project_root())
            .unwrap();
        let package_source = package_root.join(format!(
            "guarded-{}-{}.js",
            std::process::id(),
            fixture.path().file_name().unwrap().to_string_lossy()
        ));
        let alias = fixture.path().join("outside-package-alias.js");
        let first_party = fixture.path().join("first-party.js");
        std::fs::write(&package_source, "module.exports = 'package';\n").unwrap();
        std::fs::write(&first_party, "module.exports = 'first-party';\n").unwrap();
        let package_object = object_identity_for_host_path(&package_source).unwrap();
        let generation = NonEmptyString::new("test-package-generation").unwrap();

        let snapshot = Arc::new(example_armed_snapshot_with(|value| {
            value["principals"][0]["floor"] = serde_json::json!([{
                "cap": "fs:write",
                "resource": {
                    "kind": "path-tree",
                    "path": {"root": "project", "components": []}
                }
            }]);
            value["principals"][0]["denials"] = serde_json::json!([]);
            value["rootBindings"][0]["hostPath"]["components"] =
                serde_json::to_value(host_path_components(&package_root).unwrap()).unwrap();
            value["rootBindings"][0]["object"] =
                serde_json::to_value(object_identity_for_host_path(&package_root).unwrap())
                    .unwrap();
        }));
        let mut package_sources = AuthenticatedPackageSourceState::default();
        package_sources
            .generations
            .insert(package_object.clone(), generation.clone());
        let host = Host::new_armed_with_target_cells(
            HostConfig::default(),
            snapshot,
            complete_test_target_cells(),
            package_sources,
        )
        .unwrap();
        let root = host.typed_principal_for_module("0").unwrap();

        // The alias is introduced only after the exact package set has been
        // sealed into the decision context, modeling a spelling outside every
        // package lexical subtree.
        std::fs::hard_link(&package_source, &alias).unwrap();
        let authorize_alias = |observed_generation| {
            host.authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![root.clone()],
                &alias,
                Stage::Commit,
                ObjectState::Existing,
                FollowMode::FollowFinal,
                false,
                Some(fixture.path()),
                false,
                true,
                Some(object_identity_for_host_path(fixture.path()).unwrap()),
                Some(object_identity_for_host_path(&alias).unwrap()),
                observed_generation,
                Some(NonEmptyString::new("fd:package-alias").unwrap()),
                Vec::new(),
            )
        };
        let missing_generation = authorize_alias(None).unwrap_err();
        assert!(
            missing_generation
                .to_string()
                .contains("lacks its authenticated verification generation"),
            "unexpected fail-closed generation error: {missing_generation}"
        );
        let alias_decision = authorize_alias(Some(generation.clone())).unwrap();
        assert_eq!(alias_decision.outcome, DecisionOutcome::Deny);
        assert!(alias_decision
            .evidence
            .iter()
            .any(|entry| entry.reason == DecisionReason::ProtectedResource));
        assert_eq!(
            std::fs::read_to_string(&package_source).unwrap(),
            "module.exports = 'package';\n"
        );

        let first_party_decision = host
            .authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![root],
                &first_party,
                Stage::Commit,
                ObjectState::Existing,
                FollowMode::FollowFinal,
                false,
                Some(fixture.path()),
                false,
                true,
                Some(object_identity_for_host_path(fixture.path()).unwrap()),
                Some(object_identity_for_host_path(&first_party).unwrap()),
                Some(NonEmptyString::new("test-first-party-generation").unwrap()),
                Some(NonEmptyString::new("fd:first-party").unwrap()),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(first_party_decision.outcome, DecisionOutcome::Allow);
        std::fs::write(&first_party, "module.exports = 'changed';\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(first_party).unwrap(),
            "module.exports = 'changed';\n"
        );

        std::fs::remove_file(package_source).unwrap();
    }

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

    pub(super) fn test_project_root() -> &'static std::path::Path {
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
        let snapshot = example_armed_snapshot_with(mutator);
        unsafe { Host::new_armed_for_test(HostConfig::default(), Arc::new(snapshot)).unwrap() }
    }

    pub(super) fn example_vfs_armed_host() -> Host {
        example_vfs_armed_host_with(|_| {})
    }

    pub(super) fn example_vfs_armed_host_with(
        mutator: impl FnOnce(&mut serde_json::Value),
    ) -> Host {
        example_armed_host_with(|value| {
            let package_root = test_project_root().join("node_modules/image-lib");
            std::fs::create_dir_all(&package_root).unwrap();
            value["rootBindings"][0]["hostPath"]["components"] =
                serde_json::to_value(host_path_components(&package_root).unwrap()).unwrap();
            value["rootBindings"][0]["object"] =
                serde_json::to_value(object_identity_for_host_path(&package_root).unwrap())
                    .unwrap();
            mutator(value);
        })
    }

    fn session_static_import_referrer(components: &[&str]) -> capsec_semantics::model::LogicalPath {
        capsec_semantics::model::LogicalPath {
            root: capsec_semantics::model::LogicalRoot::Project,
            components: components
                .iter()
                .map(|component| capsec_semantics::model::PathComponent::utf8(*component).unwrap())
                .collect(),
            host_bound: None,
        }
    }

    fn example_static_import_package_host() -> (Host, std::path::PathBuf, String) {
        static PACKAGE: std::sync::OnceLock<(std::path::PathBuf, String)> =
            std::sync::OnceLock::new();
        let (package_root, integrity) = PACKAGE.get_or_init(|| {
            let package_root = test_project_root().join("session-static-import-package");
            std::fs::create_dir_all(&package_root).unwrap();
            std::fs::write(
                package_root.join("package.json"),
                br#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
            )
            .unwrap();
            std::fs::write(
                package_root.join("index.js"),
                b"module.exports = { authenticatedPackage: true };\n",
            )
            .unwrap();
            let integrity = crate::module_loader::package_tree_integrity(&package_root).unwrap();
            (std::fs::canonicalize(package_root).unwrap(), integrity)
        });
        let package_root = package_root.clone();
        let integrity = integrity.clone();
        let host = example_armed_host_with(|value| {
            fn replace_integrity(value: &mut serde_json::Value, expected: &str, replacement: &str) {
                match value {
                    serde_json::Value::String(text) if text == expected => {
                        *text = replacement.to_owned();
                    }
                    serde_json::Value::Array(values) => {
                        for value in values {
                            replace_integrity(value, expected, replacement);
                        }
                    }
                    serde_json::Value::Object(values) => {
                        for value in values.values_mut() {
                            replace_integrity(value, expected, replacement);
                        }
                    }
                    _ => {}
                }
            }

            replace_integrity(
                value,
                "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
                &integrity,
            );
            value["rootBindings"][0]["hostPath"]["components"] =
                serde_json::to_value(host_path_components(&package_root).unwrap()).unwrap();
            value["rootBindings"][0]["object"] =
                serde_json::to_value(object_identity_for_host_path(&package_root).unwrap())
                    .unwrap();
        });
        (host, package_root, integrity)
    }

    #[test]
    fn session_static_import_uses_authenticated_logical_referrer_and_rejects_dependency_tla() {
        let directory = test_project_root().join("images");
        let dependency = directory.join("session-static-dependency.mjs");
        let dependency_source = "export const answer = 42;\n";
        std::fs::write(&dependency, dependency_source).unwrap();
        let tla_dependency = directory.join("session-static-tla.mjs");
        std::fs::write(&tla_dependency, "await Promise.resolve();\n").unwrap();

        // Module identity is now stamped through the authenticated VFS, so
        // this resolver fixture must carry a package binding contained by its
        // project mount just like an executable armed snapshot.
        let host = example_vfs_armed_host();
        let referrer = session_static_import_referrer(&["images"]);
        let resolved = host
            .resolve_session_static_import("./session-static-dependency.mjs", &referrer)
            .unwrap();
        assert_eq!(
            resolved.path.as_deref(),
            Some(std::fs::canonicalize(&dependency).unwrap().as_path())
        );
        assert_eq!(resolved.source.as_deref(), Some(dependency_source));
        assert_eq!(resolved.package_name, None);
        assert_eq!(resolved.package_integrity, None);
        let vfs = host.virtual_file_system().unwrap();
        let dependency_namespace = vfs
            .resolve_root_bytes(b"/project/images/session-static-dependency.mjs", None)
            .unwrap();
        let expected_source_id = vfs
            .source_id_for_authenticated_module(&dependency_namespace)
            .unwrap();
        assert_eq!(resolved.source_id.as_ref(), Some(&expected_source_id));
        assert_eq!(
            resolved.source_label.as_ref().map(|label| label.as_str()),
            Some("file:///project/images/session-static-dependency.mjs")
        );
        assert_eq!(
            resolved.virtual_path.as_deref(),
            Some("/project/images/session-static-dependency.mjs")
        );
        let resolver_path = resolved.resolver_path.as_ref().unwrap();
        assert_eq!(
            resolver_path.virtual_path(),
            "/project/images/session-static-dependency.mjs"
        );
        let encoded_referrer = serde_json::to_string(resolver_path).unwrap();
        assert!(!encoded_referrer.contains(test_project_root().to_str().unwrap()));
        assert_eq!(
            host.module_referrer_path(&encoded_referrer).unwrap(),
            std::fs::canonicalize(&dependency).unwrap()
        );
        assert!(example_vfs_armed_host()
            .module_referrer_path(&encoded_referrer)
            .is_err());
        let mut forged: serde_json::Value = serde_json::from_str(&encoded_referrer).unwrap();
        forged["virtualPath"] = serde_json::json!("/project/images/forged.mjs");
        assert!(host.module_referrer_path(&forged.to_string()).is_err());
        vfs.close();

        let error = host
            .resolve_session_static_import("./session-static-tla.mjs", &referrer)
            .unwrap_err()
            .to_string();
        assert!(error.contains("IBEX_DEPENDENCY_TOP_LEVEL_AWAIT"), "{error}");
    }

    #[test]
    fn session_root_metadata_resolve_authenticates_referrer_without_reading_body() {
        let directory = test_project_root().join("images");
        let dependency = directory.join("session-resolve-only.mjs");
        std::fs::write(&dependency, [0xff, 0xfe]).unwrap();

        let host = example_vfs_armed_host();
        let referrer = session_static_import_referrer(&["images"]);
        let resolved = host
            .resolve_session_static_import_meta("./session-resolve-only.mjs", &referrer)
            .unwrap();
        assert_eq!(
            resolved.path.as_deref(),
            Some(std::fs::canonicalize(&dependency).unwrap().as_path())
        );
        assert_eq!(resolved.source, None);
        assert_eq!(
            resolved.virtual_path.as_deref(),
            Some("/project/images/session-resolve-only.mjs")
        );

        let body_error = host
            .resolve_session_static_import("./session-resolve-only.mjs", &referrer)
            .unwrap_err()
            .to_string();
        assert!(body_error.contains("not valid UTF-8"), "{body_error}");

        let mut noncanonical_referrer = referrer;
        noncanonical_referrer.host_bound = Some(true);
        let referrer_error = host
            .resolve_session_static_import_meta(
                "./session-resolve-only.mjs",
                &noncanonical_referrer,
            )
            .unwrap_err()
            .to_string();
        assert!(referrer_error.contains("not canonical"), "{referrer_error}");
    }

    #[test]
    fn unarmed_resolver_referrers_round_trip_only_through_opaque_retained_state() {
        let host = Host::default_legacy();
        let physical = std::path::PathBuf::from(
            "/private/host/checkout/node_modules/private-package/index.js",
        );
        let record = host.retain_private_resolver_path(&physical).unwrap();
        let encoded = serde_json::to_string(&record).unwrap();

        assert_eq!(record.schema(), "ibex/private-resolver-ref/1");
        assert!(record
            .virtual_path()
            .starts_with("/project/.ibex-resolver/r"));
        assert!(!encoded.contains("/private/host"));
        assert_eq!(host.module_referrer_path(&encoded).unwrap(), physical);
        assert!(Host::default_legacy()
            .module_referrer_path(&encoded)
            .is_err());

        let mut forged: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        forged["handle"] = serde_json::json!("rffffffffffffffff");
        forged["virtualPath"] = serde_json::json!("/project/.ibex-resolver/rffffffffffffffff");
        assert!(host.module_referrer_path(&forged.to_string()).is_err());

        let mut mismatched: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        mismatched["virtualPath"] = serde_json::json!("/project/.ibex-resolver/r0000000000000000");
        assert!(host.module_referrer_path(&mismatched.to_string()).is_err());
    }

    #[test]
    fn session_static_import_refuses_graph_and_root_escape_before_source_read() {
        let root = test_project_root();
        let denied_package = root.join("node_modules/session-static-denied");
        std::fs::create_dir_all(&denied_package).unwrap();
        std::fs::write(
            denied_package.join("package.json"),
            br#"{"name":"session-static-denied","main":"index.js"}"#,
        )
        .unwrap();
        // If graph preflight accidentally reaches the source read, this gives a
        // distinct UTF-8 failure instead of the authenticated-graph refusal.
        std::fs::write(denied_package.join("index.js"), [0xff, 0xfe]).unwrap();

        let outside = root
            .parent()
            .unwrap()
            .join("ibex-session-static-outside.mjs");
        std::fs::write(&outside, [0xff, 0xfe]).unwrap();
        let host = example_vfs_armed_host();
        let referrer = session_static_import_referrer(&["images"]);

        let graph_error = host
            .resolve_session_static_import("session-static-denied", &referrer)
            .unwrap_err()
            .to_string();
        assert_eq!(graph_error, "Import denied by authenticated package graph");
        assert!(!graph_error.contains("UTF-8"));

        let escape_error = host
            .resolve_session_static_import("../../ibex-session-static-outside.mjs", &referrer)
            .unwrap_err()
            .to_string();
        assert!(
            escape_error.contains("authenticated logical-root binding"),
            "{escape_error}"
        );
        assert!(!escape_error.contains("UTF-8"));
    }

    #[test]
    fn session_static_import_stamps_authenticated_package_attribution() {
        let (host, package_root, integrity) = example_static_import_package_host();
        let resolved = host
            .resolve_session_static_import(
                "image-lib",
                &session_static_import_referrer(&["images"]),
            )
            .unwrap();
        assert_eq!(resolved.package_name.as_deref(), Some("image-lib"));
        assert_eq!(resolved.package_version.as_deref(), Some("2.4.1"));
        assert_eq!(
            resolved.package_root.as_deref(),
            Some(package_root.as_path())
        );
        assert_eq!(
            resolved.package_integrity.as_deref(),
            Some(integrity.as_str())
        );
        assert!(resolved
            .source
            .as_deref()
            .is_some_and(|source| source.contains("authenticatedPackage")));
        let package_record = resolved.resolver_package_root.as_ref().unwrap();
        assert_eq!(
            package_record.schema(),
            crate::vfs::ResolverLogicalPathSchema::V1
        );
        assert_eq!(
            package_record.logical_path().root,
            capsec_semantics::model::LogicalRoot::Package
        );
        assert!(package_record
            .binding_owner()
            .is_some_and(|owner| owner.is_package()));
        assert!(!serde_json::to_string(package_record)
            .unwrap()
            .contains(package_root.to_str().unwrap()));
        let virtual_referrer = serde_json::json!({
            "schema": "ibex/virtual-referrer/1",
            "virtualPath": resolved.virtual_path.as_deref().unwrap(),
        });
        assert_eq!(
            host.module_referrer_path(&virtual_referrer.to_string())
                .unwrap(),
            resolved.path.unwrap()
        );
    }

    #[test]
    fn typed_lifecycle_is_root_only_and_keeps_an_authoritative_exit_code() {
        use capsec_semantics::decision::DecisionOutcome;
        use capsec_semantics::model::{canonicalize_principal_set, LifecycleDisposition, Stage};

        let host = example_armed_host();
        let root = host.typed_principal_for_module("0").unwrap();
        let package = host
            .typed_imports
            .keys()
            .find(|principal| principal.is_package())
            .cloned()
            .unwrap();
        assert_eq!(host.lifecycle_exit_code(), 0);

        let process_exit = generated_coverage_edge_id("native-op", "global:process.exit").unwrap();
        let exact_exit = generated_coverage_edge_id("native-op", "__exactExit").unwrap();
        let exit_code = generated_coverage_edge_id("native-op", "global:process.exitCode").unwrap();
        let cases = [
            (LifecycleDisposition::ExitRequest, process_exit),
            (LifecycleDisposition::ExitRequest, exact_exit),
            (LifecycleDisposition::ExitCodeGet, exit_code),
            (LifecycleDisposition::ExitCodeSet, exit_code),
        ];
        for (disposition, edge) in cases {
            for stage in [Stage::Requested, Stage::Commit] {
                let decision = host
                    .authorize_typed_lifecycle_stage(
                        "0",
                        "lifecycle-test",
                        edge,
                        vec![root.clone()],
                        disposition,
                        stage,
                    )
                    .unwrap();
                assert_eq!(decision.outcome, DecisionOutcome::Allow);

                let mixed = canonicalize_principal_set([root.clone(), package.clone()]).unwrap();
                let decision = host
                    .authorize_typed_lifecycle_stage(
                        "0",
                        "lifecycle-mixed-test",
                        edge,
                        mixed,
                        disposition,
                        stage,
                    )
                    .unwrap();
                assert_eq!(decision.outcome, DecisionOutcome::Deny);
            }
        }

        host.set_lifecycle_exit_code(73);
        assert_eq!(host.lifecycle_exit_code(), 73);
        let clone = host.clone();
        clone.set_lifecycle_exit_code(-9);
        assert_eq!(
            host.lifecycle_exit_code(),
            crate::session_lifecycle::normalize_exit_status(-9)
        );
    }

    #[test]
    fn host_config_shares_one_supervisor_lifecycle_port() {
        use crate::session_lifecycle::{
            LifecycleGetDisposition, LifecyclePrincipal, LifecycleRequestDisposition,
            SessionLifecyclePort,
        };

        let supervisor = SessionLifecyclePort::default();
        let host = Host::new(HostConfig {
            session_lifecycle: Some(supervisor.clone()),
            ..HostConfig::default()
        });
        host.set_lifecycle_exit_code(7);
        assert_eq!(
            supervisor.get_exit_code(LifecyclePrincipal::Root),
            LifecycleGetDisposition::Value(7)
        );
        assert!(matches!(
            host.session_lifecycle()
                .request_exit(LifecyclePrincipal::Root, 9),
            LifecycleRequestDisposition::Accepted { .. }
        ));
        assert_eq!(supervisor.take_pending_request().unwrap().status, 9);
    }

    #[test]
    fn lifecycle_c_abi_is_exact_root_only_and_denial_has_no_mutation() {
        use crate::session_lifecycle::normalize_exit_status;

        let _guard = crate::host::abi::host_test_lock();

        // An omitted process.exit argument resolves inside the exit-request
        // adapter. It emits exactly requested+commit decisions, not the public
        // exitCode getter disposition, and publishes one supervisor event.
        let host = example_armed_host();
        host.set_lifecycle_exit_code(263);
        let port = host.session_lifecycle();
        crate::host::abi::install_host(host.clone());
        let root = [0_u64];
        let before = host.typed_decision_count();
        let mut out = i32::MIN;
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_authorize_typed_lifecycle_exit_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    1,
                    99,
                    0,
                    &mut out,
                )
            },
            1
        );
        assert_eq!(out, normalize_exit_status(263));
        assert_eq!(host.typed_decision_count() - before, 2);
        let request = port.take_pending_request().unwrap();
        assert_eq!(request.status, out);

        // The second exact surface is independently gated but the shared port
        // retains the first request and does not publish it twice.
        let mut repeated = i32::MIN;
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_authorize_typed_lifecycle_exit_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    2,
                    9,
                    1,
                    &mut repeated,
                )
            },
            1
        );
        assert_eq!(repeated, request.status);
        assert_eq!(port.take_pending_request(), None);

        // Package, mixed, unknown, and malformed projections all deny. The
        // output sentinel, authoritative code, and event cell remain intact.
        let denied = example_armed_host();
        let package = denied
            .typed_imports
            .keys()
            .find(|principal| principal.is_package())
            .cloned()
            .unwrap();
        if let capsec_semantics::model::Principal::Package {
            name,
            locator,
            integrity,
        } = &package
        {
            denied.register_module_package(
                "1",
                name.as_str(),
                Some(locator.as_str()),
                Some(integrity.as_str()),
            );
        }
        denied.set_lifecycle_exit_code(7);
        let denied_port = denied.session_lifecycle();
        crate::host::abi::install_host(denied.clone());
        for (actor, principals) in [(1, vec![1]), (0, vec![0, 1]), (999, vec![999])] {
            let mut untouched = 0x1357_2468;
            assert_eq!(
                unsafe {
                    crate::host::abi::ex_host_authorize_typed_lifecycle_exit_stack(
                        actor,
                        principals.as_ptr(),
                        principals.len(),
                        1,
                        42,
                        1,
                        &mut untouched,
                    )
                },
                0
            );
            assert_eq!(untouched, 0x1357_2468);
        }
        let mut untouched = 0x1357_2468;
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_authorize_typed_lifecycle_exit_stack(
                    0,
                    std::ptr::null(),
                    0,
                    1,
                    42,
                    1,
                    &mut untouched,
                )
            },
            0
        );
        assert_eq!(untouched, 0x1357_2468);
        assert_eq!(denied.lifecycle_exit_code(), 7);
        assert_eq!(denied_port.latched_request(), None);
    }

    #[test]
    fn lifecycle_exit_code_c_abi_keeps_get_and_set_dispositions_independent() {
        let _guard = crate::host::abi::host_test_lock();
        let host = example_armed_host();
        crate::host::abi::install_host(host.clone());
        let root = [0_u64];

        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_lifecycle_exit_code_set_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    73,
                )
            },
            1
        );
        let mut code = i32::MIN;
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_lifecycle_exit_code_get_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    &mut code,
                )
            },
            1
        );
        assert_eq!(code, 73);
        assert_eq!(host.typed_decision_count(), 4);
    }

    #[test]
    fn worker_lifecycle_bridge_runs_after_authorization_and_never_falls_back() {
        use crate::host::abi::{AuthenticatedWorkerLifecyclePort, WorkerLifecycleAcknowledgement};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let _lock = crate::host::abi::host_test_lock();
        let host = example_armed_host();
        let package = host
            .typed_imports
            .keys()
            .find(|principal| principal.is_package())
            .cloned()
            .unwrap();
        if let capsec_semantics::model::Principal::Package {
            name,
            locator,
            integrity,
        } = &package
        {
            host.register_module_package(
                "1",
                name.as_str(),
                Some(locator.as_str()),
                Some(integrity.as_str()),
            );
        }
        crate::host::abi::install_host(host.clone());

        let acknowledge_mirror = Arc::new(AtomicBool::new(true));
        let mirrored = Arc::new(Mutex::new(Vec::new()));
        let commit_calls = Arc::new(AtomicUsize::new(0));
        let acknowledge = Arc::clone(&acknowledge_mirror);
        let mirror_sink = Arc::clone(&mirrored);
        let commit_count = Arc::clone(&commit_calls);
        let guard = crate::host::abi::install_authenticated_worker_lifecycle_port(
            AuthenticatedWorkerLifecyclePort::new(
                move |mutation| {
                    mirror_sink.lock().unwrap().push(mutation.status());
                    if acknowledge.load(Ordering::Acquire) {
                        WorkerLifecycleAcknowledgement::Acknowledged
                    } else {
                        WorkerLifecycleAcknowledgement::Unacknowledged
                    }
                },
                move |_| {
                    commit_count.fetch_add(1, Ordering::Relaxed);
                    WorkerLifecycleAcknowledgement::Unacknowledged
                },
            ),
        )
        .unwrap();

        let root = [0_u64];
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_lifecycle_exit_code_set_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    73,
                )
            },
            1
        );
        assert_eq!(&*mirrored.lock().unwrap(), &[73]);
        assert_eq!(host.lifecycle_exit_code(), 73);

        // A missing acknowledgement refuses the setter and leaves the local
        // mirror unchanged; it never silently takes the in-process branch.
        acknowledge_mirror.store(false, Ordering::Release);
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_lifecycle_exit_code_set_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    99,
                )
            },
            0
        );
        assert_eq!(&*mirrored.lock().unwrap(), &[73, 99]);
        assert_eq!(host.lifecycle_exit_code(), 73);

        // Package attribution is denied before either native callback sees a
        // record, for both setter and cooperative-commit surfaces.
        let package_stack = [1_u64];
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_lifecycle_exit_code_set_stack(
                    1,
                    package_stack.as_ptr(),
                    package_stack.len(),
                    7,
                )
            },
            0
        );
        let mut untouched = i32::MIN;
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_authorize_typed_lifecycle_exit_stack(
                    1,
                    package_stack.as_ptr(),
                    package_stack.len(),
                    1,
                    7,
                    1,
                    &mut untouched,
                )
            },
            0
        );
        assert_eq!(untouched, i32::MIN);
        assert_eq!(&*mirrored.lock().unwrap(), &[73, 99]);
        assert_eq!(commit_calls.load(Ordering::Relaxed), 0);

        drop(guard);
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_lifecycle_exit_code_set_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    42,
                )
            },
            1
        );
        assert_eq!(host.lifecycle_exit_code(), 42);
        assert_eq!(&*mirrored.lock().unwrap(), &[73, 99]);
    }

    #[test]
    fn authenticated_session_entry_accepts_only_the_closed_entry_matrix() {
        use crate::engine::evaluation::{EntryKind, ExecutionMode};
        use capsec_semantics::arming::{ArmedEntry, ArmedEntryKind, ArmedExecutionMode};
        use capsec_semantics::model::NonEmptyString;

        let cases = [
            (
                ArmedEntry {
                    kind: ArmedEntryKind::File,
                    identity: NonEmptyString::new("file:///project/app.js").unwrap(),
                    mode: ArmedExecutionMode::Program,
                },
                EntryKind::File,
                ExecutionMode::Program,
            ),
            (
                ArmedEntry {
                    kind: ArmedEntryKind::Stdin,
                    identity: NonEmptyString::new("ibex:stdin").unwrap(),
                    mode: ArmedExecutionMode::Program,
                },
                EntryKind::Stdin,
                ExecutionMode::Program,
            ),
            (
                ArmedEntry {
                    kind: ArmedEntryKind::Repl,
                    identity: NonEmptyString::new("ibex:repl").unwrap(),
                    mode: ArmedExecutionMode::Interactive,
                },
                EntryKind::Repl,
                ExecutionMode::Interactive,
            ),
            (
                ArmedEntry {
                    kind: ArmedEntryKind::Repl,
                    identity: NonEmptyString::new("ibex:repl").unwrap(),
                    mode: ArmedExecutionMode::Transcript,
                },
                EntryKind::Repl,
                ExecutionMode::Transcript,
            ),
            (
                ArmedEntry {
                    kind: ArmedEntryKind::Eval,
                    identity: NonEmptyString::new("ibex:eval").unwrap(),
                    mode: ArmedExecutionMode::OneShot,
                },
                EntryKind::Eval,
                ExecutionMode::OneShot,
            ),
        ];
        for (entry, expected_kind, expected_mode) in cases {
            let expected_identity = entry.identity.as_str().to_owned();
            let parsed = authenticated_session_entry(&entry).unwrap();
            assert_eq!(parsed.kind, expected_kind);
            assert_eq!(parsed.mode, expected_mode);
            assert_eq!(&*parsed.identity, expected_identity);
        }
    }

    #[test]
    fn authenticated_session_entry_rejects_missing_extra_and_cross_paired_fields() {
        use capsec_semantics::arming::ArmedEntry;

        let refused = [
            serde_json::json!({"kind":"repl","identity":"ibex:repl"}),
            serde_json::json!({"kind":"repl","identity":"ibex:repl","mode":"interactive","extra":true}),
        ];
        for entry in refused {
            assert!(
                serde_json::from_value::<ArmedEntry>(entry.clone()).is_err(),
                "{entry}"
            );
        }

        let cross_paired = [
            serde_json::json!({"kind":"repl","identity":"ibex:stdin","mode":"interactive"}),
            serde_json::json!({"kind":"repl","identity":"ibex:repl","mode":"program"}),
            serde_json::json!({"kind":"stdin","identity":"ibex:stdin","mode":"transcript"}),
            serde_json::json!({"kind":"eval","identity":"ibex:eval","mode":"program"}),
            serde_json::json!({"kind":"file","identity":"/host/private/app.js","mode":"program"}),
        ];
        for entry in cross_paired {
            let entry: ArmedEntry = serde_json::from_value(entry).unwrap();
            assert!(authenticated_session_entry(&entry).is_err());
        }
    }

    #[test]
    fn session_token_minting_requires_an_authenticated_armed_snapshot() {
        let error = Host::new(HostConfig::default())
            .mint_armed_session_token()
            .expect_err("unarmed hosts cannot mint session tokens")
            .to_string();
        assert!(error.contains("authenticated armed snapshot"), "{error}");
    }

    #[test]
    fn armed_host_mints_only_an_opaque_snapshot_derived_session_token() {
        let host = example_vfs_armed_host();
        let token = host.mint_armed_session_token().unwrap();
        assert_eq!(format!("{token:?}"), "ArmedSessionToken(<opaque>)");
        let repeated = host.mint_armed_session_token().unwrap();
        let cloned_host_token = host.clone().mint_armed_session_token().unwrap();
        assert!(token.same_session(&repeated));
        assert!(token.same_session(&cloned_host_token));
    }

    #[test]
    fn authenticated_vfs_script_read_binds_staged_evidence_to_capsule() {
        use crate::engine::evaluation::SubmissionSequence;
        use capsec_semantics::model::Stage;

        let source = test_project_root().join("images/vfs-capsule-no-reopen.js");
        std::fs::write(&source, b"answer = 42;\n").unwrap();
        let host = example_vfs_armed_host();
        let vfs = host.virtual_file_system().unwrap();
        let namespace = vfs
            .resolve_root_bytes(b"/project/images/vfs-capsule-no-reopen.js", None)
            .unwrap();
        let mut submissions =
            SubmissionSequence::new(host.mint_armed_session_token().unwrap()).unwrap();
        let submission = submissions
            .mint_load(
                Arc::from(namespace.virtual_path()),
                namespace.logical_referrer().unwrap(),
            )
            .unwrap();
        let read = host
            .authenticated_vfs_script_read(&vfs, namespace, submission)
            .unwrap();
        assert_eq!(
            read.file_source_label().as_str(),
            "file:///project/images/vfs-capsule-no-reopen.js"
        );
        assert_eq!(read.logical_referrer().components[0].bytes(), b"images");
        assert!(read.evidence().digest().as_str().starts_with("sha256-"));
        std::fs::remove_file(&source).unwrap();
        // The result is a byte capsule, not a path lease: evaluation succeeds
        // after the directory entry has gone and has no API that can reopen it.
        assert!(read.into_capsule().into_request().is_ok());
        let stages = host
            .typed_evidence()
            .into_iter()
            .rev()
            .take(4)
            .map(|evidence| evidence.stage)
            .collect::<Vec<_>>();
        assert_eq!(
            stages,
            [
                Stage::Repeat,
                Stage::Commit,
                Stage::Discovery,
                Stage::Requested
            ]
        );
    }

    #[test]
    fn authenticated_vfs_file_read_binds_exact_entry_bytes_and_source_identity() {
        use crate::engine::evaluation::{SourceGoal, SourceRequest, SubmissionSequence};
        use capsec_semantics::model::Stage;

        let identity = "file:///project/images/authenticated-entry.mts";
        let source = test_project_root().join("images/authenticated-entry.mts");
        let bytes = b"export const answer: number = 42;\n";
        std::fs::write(&source, bytes).unwrap();
        let host = example_vfs_armed_host_with(|value| {
            value["entry"] = serde_json::json!({
                "kind": "file",
                "identity": identity,
                "mode": "program",
            });
        });
        let vfs = host.virtual_file_system().unwrap();
        let namespace = vfs.resolve_root_file_url(identity, None).unwrap();
        let mut submissions =
            SubmissionSequence::new(host.mint_armed_session_token().unwrap()).unwrap();
        let submission = submissions
            .mint_file(
                namespace.logical_referrer().unwrap(),
                &["--operator-data".to_owned(), String::new()],
            )
            .unwrap();
        let read = host
            .authenticated_vfs_file_read(&vfs, namespace, submission)
            .unwrap();

        assert_eq!(read.file_source_label().as_str(), identity);
        assert_eq!(read.logical_referrer().components[0].bytes(), b"images");
        let source_id = read
            .source_id()
            .cloned()
            .expect("file modules retain SourceId");
        assert_eq!(format!("{source_id:?}"), "SourceId(<authenticated>)");
        assert!(source_id.defining_principal().unwrap().is_root());
        assert!(read.evidence().digest().as_str().starts_with("sha256-"));

        std::fs::remove_file(&source).unwrap();
        let request = read.into_capsule().into_request().unwrap();
        assert_eq!(request.text().as_bytes(), bytes);
        assert_eq!(request.source_label().as_str(), identity);
        assert_eq!(
            request.source_id().map(crate::vfs::SourceId::cache_key),
            Some(source_id.cache_key())
        );
        assert_eq!(request.virtual_referrer().components[0].bytes(), b"images");
        assert_eq!(
            request
                .file_arguments()
                .unwrap()
                .iter()
                .map(|argument| argument.as_ref())
                .collect::<Vec<_>>(),
            vec![
                "ibex:runtime",
                "/project/images/authenticated-entry.mts",
                "--operator-data",
                "",
            ]
        );
        let SourceRequest::Program(program) = request else {
            panic!("file entry was relabeled as JSON")
        };
        assert_eq!(program.goal(), SourceGoal::Module);
        assert!(program.is_main());

        let stages = host
            .typed_evidence()
            .into_iter()
            .rev()
            .take(4)
            .map(|evidence| evidence.stage)
            .collect::<Vec<_>>();
        assert_eq!(
            stages,
            [
                Stage::Repeat,
                Stage::Commit,
                Stage::Discovery,
                Stage::Requested,
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_direct_symlink_entry_rebinds_to_final_source_identity() {
        use crate::engine::evaluation::SubmissionSequence;
        use std::os::unix::fs::symlink;

        let project = test_project_root();
        let target = project.join("images/direct-symlink-target.mts");
        let alias = project.join("direct-symlink-entry.mts");
        let _ = std::fs::remove_file(&alias);
        std::fs::write(&target, b"export const answer: number = 42;\n").unwrap();
        symlink("images/direct-symlink-target.mts", &alias).unwrap();

        let entry_identity = "file:///project/direct-symlink-entry.mts";
        let target_identity = "file:///project/images/direct-symlink-target.mts";
        let host = example_vfs_armed_host_with(|value| {
            value["entry"] = serde_json::json!({
                "kind": "file",
                "identity": entry_identity,
                "mode": "program",
            });
        });
        let vfs = host.virtual_file_system().unwrap();
        let namespace = vfs.resolve_root_file_url(entry_identity, None).unwrap();
        let mut submissions =
            SubmissionSequence::new(host.mint_armed_session_token().unwrap()).unwrap();
        let submission = submissions
            .mint_file(namespace.logical_referrer().unwrap(), &[])
            .unwrap();
        let read = host
            .authenticated_vfs_file_read(&vfs, namespace, submission)
            .unwrap();
        assert_eq!(read.file_source_label().as_str(), target_identity);
        let request = read.into_capsule().into_request().unwrap();
        assert_eq!(request.source_label().as_str(), target_identity);
        assert_eq!(request.virtual_referrer().components[0].bytes(), b"images");
        assert_eq!(
            request.file_arguments().unwrap()[1].as_ref(),
            "/project/direct-symlink-entry.mts"
        );
        assert!(request.source_id().is_some());

        std::fs::remove_file(&alias).unwrap();
        std::fs::remove_file(&target).unwrap();
    }

    #[test]
    fn authenticated_vfs_file_read_closes_js_kind_from_package_metadata() {
        use crate::engine::evaluation::{
            ModuleKind, SourceGoal, SourceRequest, SubmissionSequence,
        };

        for (directory, package_type, expected_kind, expected_goal) in [
            (
                "authenticated-direct-esm",
                "module",
                ModuleKind::Esm,
                SourceGoal::Module,
            ),
            (
                "authenticated-direct-cjs",
                "commonjs",
                ModuleKind::CommonJs,
                SourceGoal::ScriptWithExtensions,
            ),
        ] {
            let root = test_project_root().join("images").join(directory);
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(
                root.join("package.json"),
                format!(r#"{{"type":"{package_type}"}}"#),
            )
            .unwrap();
            std::fs::write(root.join("entry.js"), b"module.exports = 1;\n").unwrap();
            let identity = format!("file:///project/images/{directory}/entry.js");
            let host = example_vfs_armed_host_with(|value| {
                value["entry"] = serde_json::json!({
                    "kind": "file",
                    "identity": identity,
                    "mode": "program",
                });
            });
            let vfs = host.virtual_file_system().unwrap();
            let namespace = vfs.resolve_root_file_url(&identity, None).unwrap();
            let mut submissions =
                SubmissionSequence::new(host.mint_armed_session_token().unwrap()).unwrap();
            let submission = submissions
                .mint_file(namespace.logical_referrer().unwrap(), &[])
                .unwrap();
            assert!(submission.awaits_authenticated_file_module_kind());
            let request = host
                .authenticated_vfs_file_read(&vfs, namespace, submission)
                .unwrap()
                .into_capsule()
                .into_request()
                .unwrap();
            let SourceRequest::Program(program) = request else {
                panic!("authenticated .js file became JSON data")
            };
            assert_eq!(program.module_kind(), Some(expected_kind));
            assert_eq!(program.goal(), expected_goal);
            vfs.close();
            std::fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn authenticated_vfs_file_read_closes_js_kind_inside_package_binding() {
        use crate::engine::evaluation::{ModuleKind, SourceRequest, SubmissionSequence};

        let scope =
            test_project_root().join("node_modules/image-lib/authenticated-direct-entry-scope");
        std::fs::create_dir_all(&scope).unwrap();
        std::fs::write(scope.join("package.json"), r#"{"type":"module"}"#).unwrap();
        std::fs::write(scope.join("entry.js"), b"export default 1;\n").unwrap();
        let identity =
            "file:///project/node_modules/image-lib/authenticated-direct-entry-scope/entry.js";
        let host = example_vfs_armed_host_with(|value| {
            value["entry"] = serde_json::json!({
                "kind": "file",
                "identity": identity,
                "mode": "program",
            });
        });
        let vfs = host.virtual_file_system().unwrap();
        let namespace = vfs.resolve_root_file_url(identity, None).unwrap();
        let mut submissions =
            SubmissionSequence::new(host.mint_armed_session_token().unwrap()).unwrap();
        let submission = submissions
            .mint_file(namespace.logical_referrer().unwrap(), &[])
            .unwrap();
        let read = host
            .authenticated_vfs_file_read(&vfs, namespace, submission)
            .unwrap();
        assert!(read
            .source_id()
            .and_then(crate::vfs::SourceId::defining_principal)
            .is_some_and(|principal| principal.is_package()));
        let request = read.into_capsule().into_request().unwrap();
        let SourceRequest::Program(program) = request else {
            panic!("authenticated package .js file became JSON data")
        };
        assert_eq!(program.module_kind(), Some(ModuleKind::Esm));
        vfs.close();
        std::fs::remove_dir_all(scope).unwrap();
    }

    #[test]
    fn authenticated_vfs_file_read_preserves_commonjs_and_json_shapes() {
        use crate::engine::evaluation::{
            ModuleKind, SourceGoal, SourceRequest, SubmissionSequence,
        };

        for (name, bytes) in [
            (
                "authenticated-entry.cjs",
                b"module.exports = 1;\n".as_slice(),
            ),
            ("authenticated-entry.json", br#"{"answer":42}"#.as_slice()),
        ] {
            let identity = format!("file:///project/images/{name}");
            let source = test_project_root().join("images").join(name);
            std::fs::write(&source, bytes).unwrap();
            let host = example_vfs_armed_host_with(|value| {
                value["entry"] = serde_json::json!({
                    "kind": "file",
                    "identity": identity,
                    "mode": "program",
                });
            });
            let vfs = host.virtual_file_system().unwrap();
            let namespace = vfs.resolve_root_file_url(&identity, None).unwrap();
            let mut submissions =
                SubmissionSequence::new(host.mint_armed_session_token().unwrap()).unwrap();
            let submission = submissions
                .mint_file(namespace.logical_referrer().unwrap(), &[])
                .unwrap();
            let request = host
                .authenticated_vfs_file_read(&vfs, namespace, submission)
                .unwrap()
                .into_capsule()
                .into_request()
                .unwrap();
            match name.rsplit_once('.').unwrap().1 {
                "cjs" => {
                    let SourceRequest::Program(program) = request else {
                        panic!("authenticated .cjs file became JSON data")
                    };
                    assert_eq!(program.module_kind(), Some(ModuleKind::CommonJs));
                    assert_eq!(program.goal(), SourceGoal::ScriptWithExtensions);
                }
                "json" => assert!(matches!(request, SourceRequest::JsonData(_))),
                _ => unreachable!(),
            }
            vfs.close();
            std::fs::remove_file(&source).unwrap();
        }
    }

    #[test]
    fn authenticated_vfs_file_read_rejects_another_path_before_lookup() {
        use crate::engine::evaluation::SubmissionSequence;

        let identity = "file:///project/images/authenticated-main.mjs";
        let host = example_vfs_armed_host_with(|value| {
            value["entry"] = serde_json::json!({
                "kind": "file",
                "identity": identity,
                "mode": "program",
            });
        });
        let vfs = host.virtual_file_system().unwrap();
        let namespace = vfs
            .resolve_root_bytes(b"/project/images/not-the-entry.mjs", None)
            .unwrap();
        let mut submissions =
            SubmissionSequence::new(host.mint_armed_session_token().unwrap()).unwrap();
        let submission = submissions
            .mint_file(namespace.logical_referrer().unwrap(), &[])
            .unwrap();

        let error = host
            .authenticated_vfs_file_read(&vfs, namespace, submission)
            .unwrap_err();
        assert_eq!(error.reason(), crate::vfs::VfsReason::PolicyDenied);
        assert_eq!(error.safe_decision_id(), Some("submission-source-mismatch"));
        assert_eq!(host.typed_decision_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_vfs_script_read_rebinds_referrer_after_contained_symlink() {
        use std::os::unix::fs::symlink;

        use crate::engine::evaluation::SubmissionSequence;
        use capsec_semantics::model::Stage;

        let canonical_dir = test_project_root().join("images/vfs-canonical");
        let alias_dir = test_project_root().join("images/vfs-aliases");
        std::fs::create_dir_all(&canonical_dir).unwrap();
        std::fs::create_dir_all(&alias_dir).unwrap();
        let target = canonical_dir.join("loaded.js");
        let alias = alias_dir.join("loaded.js");
        let _ = std::fs::remove_file(&alias);
        std::fs::write(&target, b"import './dependency.js';\n").unwrap();
        symlink("../vfs-canonical/loaded.js", &alias).unwrap();

        let host = example_vfs_armed_host();
        let vfs = host.virtual_file_system().unwrap();
        let namespace = vfs
            .resolve_root_bytes(b"/project/images/vfs-aliases/loaded.js", None)
            .unwrap();
        let mut submissions =
            SubmissionSequence::new(host.mint_armed_session_token().unwrap()).unwrap();
        let submission = submissions
            .mint_load(
                Arc::from(namespace.virtual_path()),
                namespace.logical_referrer().unwrap(),
            )
            .unwrap();
        let read = host
            .authenticated_vfs_script_read(&vfs, namespace, submission)
            .unwrap();
        assert_eq!(
            read.file_source_label().as_str(),
            "file:///project/images/vfs-canonical/loaded.js"
        );
        assert_eq!(
            read.logical_referrer().components,
            vec![
                capsec_semantics::model::PathComponent::utf8("images").unwrap(),
                capsec_semantics::model::PathComponent::utf8("vfs-canonical").unwrap(),
            ]
        );
        let request = read.into_capsule().into_request().unwrap();
        assert_eq!(
            request.source_label().as_str(),
            "repl:1:/project/images/vfs-aliases/loaded.js"
        );
        assert_eq!(
            request.virtual_referrer().components[1].bytes(),
            b"vfs-canonical"
        );
        let stages = host
            .typed_evidence()
            .into_iter()
            .rev()
            .take(6)
            .map(|evidence| evidence.stage)
            .collect::<Vec<_>>();
        assert_eq!(
            stages,
            [
                Stage::Repeat,
                Stage::Commit,
                Stage::Discovery,
                Stage::Requested,
                Stage::Discovery,
                Stage::Requested,
            ]
        );

        std::fs::remove_file(&alias).unwrap();
        std::fs::remove_file(&target).unwrap();
    }

    #[test]
    fn authenticated_vfs_read_rejects_mismatched_submission_before_decision_or_lookup() {
        use crate::engine::evaluation::SubmissionSequence;

        let host = example_vfs_armed_host();
        let vfs = host.virtual_file_system().unwrap();
        let namespace = vfs
            .resolve_root_bytes(b"/project/images/does-not-exist.js", None)
            .unwrap();
        let mut submissions =
            SubmissionSequence::new(host.mint_armed_session_token().unwrap()).unwrap();
        let submission = submissions
            .mint_load(
                Arc::from("/project/images/different.js"),
                namespace.logical_referrer().unwrap(),
            )
            .unwrap();
        let error = host
            .authenticated_vfs_script_read(&vfs, namespace, submission)
            .unwrap_err();
        assert_eq!(error.reason(), crate::vfs::VfsReason::PolicyDenied);
        assert_eq!(error.safe_decision_id(), Some("submission-source-mismatch"));
        assert_eq!(host.typed_decision_count(), 0);
        assert!(!error
            .to_string()
            .contains(test_project_root().to_str().unwrap()));
    }

    #[test]
    fn authenticated_vfs_read_rejects_same_snapshot_foreign_session_before_lookup() {
        use crate::engine::evaluation::SubmissionSequence;

        let host = example_vfs_armed_host();
        let foreign = unsafe {
            Host::new_armed_for_test(
                HostConfig::default(),
                host.armed_snapshot().unwrap().clone(),
            )
            .unwrap()
        };
        let vfs = host.virtual_file_system().unwrap();
        let namespace = vfs
            .resolve_root_bytes(b"/project/images/does-not-exist.js", None)
            .unwrap();
        let mut foreign_submissions =
            SubmissionSequence::new(foreign.mint_armed_session_token().unwrap()).unwrap();
        let submission = foreign_submissions
            .mint_load(
                Arc::from(namespace.virtual_path()),
                namespace.logical_referrer().unwrap(),
            )
            .unwrap();

        let error = host
            .authenticated_vfs_script_read(&vfs, namespace, submission)
            .unwrap_err();
        assert_eq!(error.reason(), crate::vfs::VfsReason::StaleSession);
        assert_eq!(host.typed_decision_count(), 0);
    }

    #[test]
    fn authenticated_vfs_read_rejects_non_root_namespace_before_lookup() {
        use crate::engine::evaluation::SubmissionSequence;

        let host = example_vfs_armed_host();
        let package = host
            .armed_snapshot()
            .unwrap()
            .root_bindings()
            .unwrap()
            .into_iter()
            .find_map(|binding| binding.owner.clone())
            .unwrap();
        let vfs = host.virtual_file_system().unwrap();
        let namespace = vfs
            .resolve_bytes(&package, b"/project/images/does-not-exist.js", None)
            .unwrap();
        let mut submissions =
            SubmissionSequence::new(host.mint_armed_session_token().unwrap()).unwrap();
        let submission = submissions
            .mint_load(
                Arc::from(namespace.virtual_path()),
                namespace.logical_referrer().unwrap(),
            )
            .unwrap();

        let error = host
            .authenticated_vfs_script_read(&vfs, namespace, submission)
            .unwrap_err();
        assert_eq!(error.reason(), crate::vfs::VfsReason::PolicyDenied);
        assert_eq!(
            error.safe_decision_id(),
            Some("submission-principal-mismatch")
        );
        assert_eq!(host.typed_decision_count(), 0);
    }

    fn example_armed_snapshot_with(
        mutator: impl FnOnce(&mut serde_json::Value),
    ) -> capsec_semantics::arming::ArmedSnapshot {
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
        let project_path = serde_json::json!({
            "root": "absolute",
            "components": host_path_components(project_root).unwrap(),
            "hostBound": true,
        });
        value["rootBindings"][1]["hostPath"] = project_path.clone();
        value["rootBindings"][1]["object"] =
            serde_json::to_value(object_identity_for_host_path(project_root).unwrap()).unwrap();
        value["projectRootDiscovery"] = serde_json::json!({
            "origin": project_path,
            "selectedRoot": value["rootBindings"][1]["hostPath"].clone(),
            "markerKind": "explicit-project",
            "markerPath": value["rootBindings"][1]["hostPath"].clone(),
            "markerSetVersion": capsec_semantics::arming::PROJECT_ROOT_MARKER_SET_VERSION,
        });
        let fixture_bindings: Vec<capsec_semantics::arming::ArmedRootBinding> =
            serde_json::from_value(value["rootBindings"].clone()).unwrap();
        value["pathCanonicalizers"] = serde_json::to_value(
            capsec_semantics::path_alias::contract_fixture_canonicalizer_rows(
                fixture_bindings
                    .iter()
                    .map(|binding| (binding.object.platform, binding.object.volume.clone())),
            )
            .unwrap(),
        )
        .unwrap();
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
            armed_snapshot_digest: digest_at(&["armedSnapshotDigest"]),
            target: value["engine"]["target"].as_str().unwrap().into(),
            engine_binary_digest: digest_at(&["engine", "binaryDigest"]),
            features: value["engine"]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            entry: serde_json::from_value(value["entry"].clone()).unwrap(),
            project_root_discovery: serde_json::from_value(value["projectRootDiscovery"].clone())
                .unwrap(),
            path_canonicalizers: serde_json::from_value(value["pathCanonicalizers"].clone())
                .unwrap(),
            protected_artifacts: value["protectedObjects"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let role: capsec_semantics::arming::ProtectedArtifactRole =
                        serde_json::from_value(row["role"].clone()).unwrap();
                    let content_digest = match role {
                        capsec_semantics::arming::ProtectedArtifactRole::EngineBinary => {
                            digest_at(&["engine", "binaryDigest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::ArmedPolicy => {
                            digest_at(&["policyDigest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::PackageGraph => {
                            digest_at(&["packageGraph", "digest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::Registry => {
                            digest_at(&["registryDigest"])
                        }
                    };
                    capsec_semantics::arming::ExpectedProtectedArtifact {
                        role,
                        host_path: serde_json::from_value(serde_json::json!({
                            "root": "absolute",
                            "components": [
                                {"encoding": "utf8", "value": "fixture"},
                                {"encoding": "utf8", "value": row["role"].as_str().unwrap()}
                            ],
                            "hostBound": true
                        }))
                        .unwrap(),
                        object: serde_json::from_value(row["object"].clone()).unwrap(),
                        content_digest,
                    }
                })
                .collect(),
        };
        ArmedSnapshot::load(&bytes, &expected).unwrap()
    }

    #[test]
    fn every_protected_artifact_denies_write_replace_and_rename_before_mutation() {
        use capsec_semantics::decision::{DecisionOutcome, DecisionReason};
        use capsec_semantics::model::{FollowMode, NonEmptyString, ObjectState, Stage};
        use capsec_semantics::registry::DecisionStratumId;
        use std::io::Write as _;

        #[derive(Clone, Copy, Debug)]
        enum Mutation {
            Write,
            Replace,
            Rename,
        }

        impl Mutation {
            fn authorization(self) -> (&'static str, &'static str, Stage, Option<&'static str>) {
                match self {
                    Self::Write => (
                        "protected-artifact-write",
                        "surface.native.op.exactfsopen.05ao6wa",
                        Stage::Commit,
                        Some("fd:protected-artifact"),
                    ),
                    Self::Replace => (
                        "protected-artifact-replace",
                        "surface.native.op.exactwritefile.1h0gy8u",
                        Stage::Discovery,
                        None,
                    ),
                    Self::Rename => (
                        "protected-artifact-rename",
                        "surface.native.op.exactrename.10zwbcv",
                        Stage::Discovery,
                        None,
                    ),
                }
            }
        }

        let fixture = tempfile::Builder::new()
            .prefix("protected-artifact-guards-")
            .tempdir_in(test_project_root())
            .unwrap();
        let roles = ["armed-policy", "engine-binary", "package-graph", "registry"];
        let artifacts = roles
            .iter()
            .map(|role| {
                let path = fixture.path().join(role);
                let contents = format!("authenticated {role} contents").into_bytes();
                std::fs::write(&path, &contents).unwrap();
                let object = object_identity_for_host_path(&path).unwrap();
                (*role, path, contents, object)
            })
            .collect::<Vec<_>>();

        let host = example_armed_host_with(|value| {
            for (role, _, _, object) in &artifacts {
                let row = value["protectedObjects"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|row| row["role"] == *role)
                    .unwrap();
                row["object"] = serde_json::to_value(object).unwrap();
            }
        });
        let root = host.typed_principal_for_module("0").unwrap();
        let parent_object = object_identity_for_host_path(fixture.path()).unwrap();

        // @ref LLP 0021#decision-staging-and-principal-semantics — every
        // protected object is a deny stratum ahead of ambient root, and each
        // effect must authorize before its first irreversible mutation.
        for (role, path, original, object) in &artifacts {
            for mutation in [Mutation::Write, Mutation::Replace, Mutation::Rename] {
                let (operation, edge, stage, retained_handle) = mutation.authorization();
                let decision = host
                    .authorize_typed_fs_open_stage(
                        "0",
                        operation,
                        edge,
                        vec![root.clone()],
                        path,
                        stage,
                        ObjectState::Existing,
                        FollowMode::FollowFinal,
                        false,
                        Some(fixture.path()),
                        false,
                        true,
                        Some(parent_object.clone()),
                        Some(object.clone()),
                        None,
                        retained_handle.map(|handle| NonEmptyString::new(handle).unwrap()),
                        Vec::new(),
                    )
                    .unwrap();
                let replacement = fixture.path().join(format!("{role}.replacement"));
                let renamed = fixture.path().join(format!("{role}.renamed"));
                std::fs::write(&replacement, b"attacker replacement").unwrap();
                let mut mutation_reached = false;
                if matches!(
                    decision.outcome,
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                ) {
                    mutation_reached = true;
                    match mutation {
                        Mutation::Write => {
                            let mut file =
                                std::fs::OpenOptions::new().append(true).open(path).unwrap();
                            file.write_all(b" attacker append").unwrap();
                        }
                        Mutation::Replace => std::fs::rename(&replacement, path).unwrap(),
                        Mutation::Rename => std::fs::rename(path, &renamed).unwrap(),
                    }
                }

                assert_eq!(
                    decision.outcome,
                    DecisionOutcome::Deny,
                    "{role} {mutation:?} unexpectedly received write authority"
                );
                assert_eq!(
                    decision.decisive_stratum,
                    Some(DecisionStratumId::ProtectedResourceGuards),
                    "{role} {mutation:?} was not decided by the protected-object guard"
                );
                assert!(
                    decision
                        .evidence
                        .iter()
                        .any(|entry| entry.reason == DecisionReason::ProtectedResource),
                    "{role} {mutation:?} lacks protected-resource evidence"
                );
                assert!(
                    !mutation_reached,
                    "{role} {mutation:?} reached the filesystem mutation"
                );
                assert_eq!(
                    std::fs::read(path).unwrap().as_slice(),
                    original.as_slice(),
                    "{role} {mutation:?} changed protected bytes"
                );
                assert!(
                    replacement.exists(),
                    "{role} {mutation:?} consumed the replacement file"
                );
                assert!(
                    !renamed.exists(),
                    "{role} {mutation:?} renamed the protected object"
                );
                std::fs::remove_file(replacement).unwrap();
            }
        }
    }

    #[test]
    fn production_target_claim_requires_a_verified_report_advertisement() {
        let snapshot = example_armed_snapshot_with(|_| {});
        let error = authenticated_target_cells(&snapshot).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("has no unique verified advertisement"),
            "unexpected refusal: {error}"
        );
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
                capsec_semantics::model::ObjectState::Unknown,
                capsec_semantics::model::FollowMode::FollowFinal,
                true,
                None,
                true,
                false,
                None,
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
        let parent_object = object_identity_for_host_path(&test_project_root().join("images"))
            .expect("test images directory has an authenticated identity");
        let photo_object = object_identity_for_host_path(&photo)
            .expect("test image has an authenticated identity");
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
                Some(parent_object.clone()),
                Some(photo_object.clone()),
                None,
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
                Some(parent_object.clone()),
                Some(photo_object.clone()),
                None,
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
                Some(parent_object.clone()),
                Some(photo_object.clone()),
                None,
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
                Some(parent_object.clone()),
                Some(photo_object.clone()),
                None,
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
                        "parentObject": parent_object.clone(),
                        "finalObject": photo_object.clone(),
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
                    "parentObject": parent_object.clone(),
                    "finalObject": photo_object.clone(),
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
        let parent_object = object_identity_for_host_path(&test_project_root().join("images"))
            .expect("test images directory has an authenticated identity");
        let final_object =
            object_identity_for_host_path(&test_project_root().join("images/concurrent.txt"))
                .unwrap_or_else(|_| {
                    object_identity_for_host_path(&test_project_root().join("images/photo.jpg"))
                        .expect("test image has an authenticated identity")
                });
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
                        "parentObject": parent_object.clone(),
                        "finalObject": final_object.clone(),
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
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn typed_fs_projects_deputy_paths_and_protects_package_source() {
        use capsec_semantics::decision::{DecisionOutcome, DecisionReason};
        use capsec_semantics::model::{NonEmptyString, ObjectIdentity};

        let second_principal = serde_json::json!({
            "kind": "package",
            "name": "codec",
            "integrity": "sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA",
            "locator": "codec@1.0.0"
        });
        let package_floor = serde_json::json!([
            {
                "cap": "fs:read",
                "resource": {
                    "kind": "path-tree",
                    "path": {"root": "package", "components": []}
                }
            },
            {
                "cap": "fs:write",
                "resource": {
                    "kind": "path-tree",
                    "path": {"root": "package", "components": []}
                }
            }
        ]);
        let mut image_floor = package_floor.clone();
        image_floor.as_array_mut().unwrap().push(serde_json::json!({
            "cap": "fs:read",
            "resource": {
                "kind": "path-tree",
                "path": {
                    "root": "project",
                    "components": [
                        {"encoding": "utf8", "value": "node_modules"},
                        {"encoding": "utf8", "value": "image-lib"},
                        {"encoding": "utf8", "value": "node_modules"},
                        {"encoding": "utf8", "value": "codec"}
                    ]
                }
            }
        }));
        let project_root = test_project_root().to_path_buf();
        let image_root = project_root.join("node_modules/image-lib");
        let image_lib_dir = image_root.join("lib");
        let codec_root = image_root.join("node_modules/codec");
        std::fs::create_dir_all(&image_lib_dir).unwrap();
        std::fs::create_dir_all(&codec_root).unwrap();
        std::fs::create_dir_all(project_root.join("src")).unwrap();
        std::fs::write(image_lib_dir.join("index.js"), b"image").unwrap();
        std::fs::write(codec_root.join("index.js"), b"codec").unwrap();
        std::fs::write(project_root.join("src/main.js"), b"main").unwrap();
        std::fs::write(project_root.join("app.js"), b"app").unwrap();
        let image_root_object = object_identity_for_host_path(&image_root).unwrap();
        let codec_root_object = object_identity_for_host_path(&codec_root).unwrap();
        let project_root_object = object_identity_for_host_path(&project_root).unwrap();
        let host = example_armed_host_with(|value| {
            value["principals"][1]["floor"] = image_floor;
            let image_principal = value["principals"][1]["principal"].clone();
            value["principals"][1]["imports"]["packages"] = serde_json::json!(["codec@1.0.0"]);
            let mut second_row = value["principals"][1].clone();
            second_row["principal"] = second_principal.clone();
            second_row["floor"] = package_floor;
            second_row["imports"]["packages"] = serde_json::json!([]);
            value["principals"].as_array_mut().unwrap().push(second_row);
            value["packageGraph"]["nodes"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"principal": second_principal.clone()}));
            value["packageGraph"]["importEdges"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "importer": image_principal,
                    "imported": second_principal.clone()
                }));
            value["rootBindings"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "logicalRoot": "package",
                    "owner": second_principal.clone(),
                    "hostPath": {
                        "root": "absolute",
                        "components": host_path_components(&codec_root).unwrap(),
                        "hostBound": true
                    },
                    "object": codec_root_object.clone()
                }));
            value["rootBindings"][0]["hostPath"]["components"] =
                serde_json::to_value(host_path_components(&image_root).unwrap()).unwrap();
            value["rootBindings"][0]["object"] =
                serde_json::to_value(image_root_object.clone()).unwrap();
        });
        host.register_module_package(
            "7",
            "image-lib",
            Some("image-lib@2.4.1"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        host.register_module_package(
            "8",
            "codec",
            Some("codec@1.0.0"),
            Some("sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA"),
        );
        let image = host.typed_principal_for_module("7").unwrap();
        let codec = host.typed_principal_for_module("8").unwrap();
        let mut deputy = vec![image.clone(), codec.clone()];
        assert!(
            serde_json::to_vec(&codec).unwrap() < serde_json::to_vec(&image).unwrap(),
            "fixture must expose serde field-order sorting disagreement"
        );
        capsec_semantics::model::sort_and_dedup_principals(&mut deputy).unwrap();
        assert_eq!(deputy, vec![image.clone(), codec.clone()]);
        let object = |file: &str| ObjectIdentity {
            platform: project_root_object.platform,
            volume: project_root_object.volume.clone(),
            file: NonEmptyString::new(file).unwrap(),
        };

        let image_path = image_lib_dir.join("index.js");
        let image_only = host
            .authorize_typed_fs_open_stage(
                "7",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![image.clone()],
                &image_path,
                capsec_semantics::model::Stage::Requested,
                capsec_semantics::model::ObjectState::Unknown,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                None,
                true,
                false,
                None,
                None,
                None,
                None,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(image_only.outcome, DecisionOutcome::Allow);

        let cross_package = host
            .authorize_typed_fs_open_stage(
                "7",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                deputy.clone(),
                &image_path,
                capsec_semantics::model::Stage::Commit,
                capsec_semantics::model::ObjectState::Existing,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                Some(&image_lib_dir),
                true,
                false,
                Some(object("image-lib-parent")),
                Some(object("shared-source-inode")),
                None,
                Some(NonEmptyString::new("fd:77").unwrap()),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(cross_package.outcome, DecisionOutcome::Deny);
        assert_eq!(
            cross_package.evidence[0].reason,
            DecisionReason::MissingAuthority
        );
        assert_eq!(cross_package.evidence[0].principal.as_ref(), Some(&codec));

        let codec_path = codec_root.join("index.js");
        let reverse = host
            .authorize_typed_fs_open_stage(
                "8",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                deputy.clone(),
                &codec_path,
                capsec_semantics::model::Stage::Requested,
                capsec_semantics::model::ObjectState::Unknown,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                None,
                true,
                false,
                None,
                None,
                None,
                None,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(reverse.outcome, DecisionOutcome::Allow);

        let nested_boundary = host
            .authorize_typed_fs_open_stage(
                "8",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                deputy,
                &codec_root,
                capsec_semantics::model::Stage::Commit,
                capsec_semantics::model::ObjectState::Existing,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                Some(image_root.join("node_modules").as_path()),
                true,
                false,
                Some(object("image-lib-node-modules-parent")),
                Some(codec_root_object.clone()),
                None,
                Some(NonEmptyString::new("fd:boundary").unwrap()),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(nested_boundary.outcome, DecisionOutcome::Allow);

        // Model a content-addressed store alias: codec is authorized to write
        // its own package-relative path, but that path resolves to the same
        // inode as image-lib source. The lexical package-tree guard must deny
        // before the exact-object identity can make the alias look harmless.
        let protected_write = host
            .authorize_typed_fs_open_stage(
                "8",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![codec.clone()],
                &codec_path,
                capsec_semantics::model::Stage::Commit,
                capsec_semantics::model::ObjectState::Existing,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                Some(&codec_root),
                false,
                true,
                Some(object("codec-parent")),
                Some(object("shared-source-inode")),
                None,
                Some(NonEmptyString::new("fd:78").unwrap()),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(protected_write.outcome, DecisionOutcome::Deny);
        assert_eq!(
            protected_write.evidence[0].reason,
            DecisionReason::ProtectedResource
        );

        let root = host.typed_principal_for_module("0").unwrap();
        let first_party_write = host
            .authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![root.clone()],
                project_root.join("src/main.js").as_path(),
                capsec_semantics::model::Stage::Requested,
                capsec_semantics::model::ObjectState::Unknown,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                None,
                false,
                true,
                None,
                None,
                None,
                None,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(first_party_write.outcome, DecisionOutcome::Allow);

        let first_party_direct_child = project_root.join("app.js");
        let first_party_commit = host
            .authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![root.clone()],
                &first_party_direct_child,
                capsec_semantics::model::Stage::Commit,
                capsec_semantics::model::ObjectState::Existing,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                Some(&project_root),
                false,
                true,
                Some(project_root_object.clone()),
                Some(object("first-party-app")),
                None,
                Some(NonEmptyString::new("fd:first-party-app").unwrap()),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(first_party_commit.outcome, DecisionOutcome::Allow);

        let first_party_create = host
            .authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![root.clone()],
                &first_party_direct_child,
                capsec_semantics::model::Stage::Discovery,
                capsec_semantics::model::ObjectState::AbsentCreate,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                Some(&project_root),
                false,
                true,
                Some(project_root_object),
                None,
                None,
                None,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(first_party_create.outcome, DecisionOutcome::Allow);

        let package_create = host
            .authorize_typed_fs_open_stage(
                "8",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![codec.clone()],
                codec_root.join("new.js").as_path(),
                capsec_semantics::model::Stage::Discovery,
                capsec_semantics::model::ObjectState::AbsentCreate,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                Some(&codec_root),
                false,
                true,
                Some(codec_root_object),
                None,
                None,
                None,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(package_create.outcome, DecisionOutcome::Deny);
        assert_eq!(
            package_create.evidence[0].reason,
            DecisionReason::ProtectedResource
        );

        let root_package_write = host
            .authorize_typed_fs_open_stage(
                "0",
                "fs-open",
                "surface.native.op.exactfsopen.05ao6wa",
                vec![root],
                &image_path,
                capsec_semantics::model::Stage::Requested,
                capsec_semantics::model::ObjectState::Unknown,
                capsec_semantics::model::FollowMode::FollowFinal,
                false,
                None,
                false,
                true,
                None,
                None,
                None,
                None,
                Vec::new(),
            )
            .unwrap();
        assert_eq!(root_package_write.outcome, DecisionOutcome::Deny);
        assert_eq!(
            root_package_write.evidence[0].reason,
            DecisionReason::ProtectedResource
        );
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
    fn armed_import_axis_recognizes_every_exact_generated_builtin_alias() {
        let allowed = [
            "bun:sqlite",
            "exact:clipboard",
            "exact:sqlite",
            "internal/fs/utils",
            "ws",
        ];
        let host = example_armed_host_with(|value| {
            value["principals"][1]["imports"]["builtins"] = serde_json::json!([
                "bun:sqlite",
                "exact:clipboard",
                "exact:sqlite",
                "internal/fs/utils",
                "made-up-builtin",
                "ws"
            ]);
        });
        host.register_module_package(
            "7",
            "image-lib",
            Some("image-lib@2.4.1"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        for specifier in allowed {
            assert!(host.check_import("7", specifier), "{specifier}");
        }
        for specifier in [
            "exact:clipboard/subpath",
            "internal/fs/unknown",
            "made-up-builtin",
        ] {
            assert!(!host.check_import("7", specifier), "{specifier}");
        }

        let denied = example_armed_host_with(|_| {});
        denied.register_module_package(
            "7",
            "image-lib",
            Some("image-lib@2.4.1"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        for specifier in allowed {
            assert!(!denied.check_import("7", specifier), "{specifier}");
        }
    }

    #[test]
    fn internal_builtin_resolver_cannot_escape_the_generated_manifest() {
        let host = example_armed_host_with(|_| {});
        let resolved = host
            .resolve_manifest_builtin_internal("node:util")
            .expect("exact manifest builtin should resolve internally");
        assert_eq!(resolved.kind, crate::module_loader::ModuleKind::Builtin);
        assert!(resolved.path.is_none());
        assert!(resolved.source.is_some());

        for specifier in ["image-lib", "./node:util", "/tmp/node:util", "node:made-up"] {
            assert!(
                host.resolve_manifest_builtin_internal(specifier).is_err(),
                "{specifier}"
            );
        }
    }

    #[test]
    fn armed_require_resolve_runs_typed_list_and_read_stages_on_every_lookup() {
        use capsec_semantics::model::Stage;

        let root = test_project_root();
        let fixture = root.join("resolve-meta-eng24234");
        std::fs::create_dir_all(&fixture).unwrap();
        let referrer = root.join("entry-eng24234.js");
        let target = fixture.join("target.js");
        std::fs::write(&referrer, "module.exports = 1;\n").unwrap();
        std::fs::write(&target, "module.exports = 2;\n").unwrap();

        let host = example_vfs_armed_host();
        host.begin_conformance_observation("enforcement.test.require-resolve");
        for _ in 0..2 {
            let resolved = host
                .resolve_module_meta_for_principal(
                    "./resolve-meta-eng24234/target.js",
                    Some(&referrer),
                    Some("0"),
                )
                .unwrap();
            assert_eq!(resolved.path.as_deref(), Some(target.as_path()));
            assert!(resolved.source.is_none());
        }
        let observed = host.take_typed_conformance_observations();
        assert_eq!(
            observed.len(),
            8,
            "each lookup, including the cache-hot lookup, must run four stages"
        );
        for lookup in observed.chunks_exact(4) {
            assert_eq!(
                lookup
                    .iter()
                    .map(|row| row.decision_set.context.stage)
                    .collect::<Vec<_>>(),
                vec![
                    Stage::Requested,
                    Stage::Discovery,
                    Stage::Commit,
                    Stage::Repeat
                ]
            );
            for (index, row) in lookup.iter().enumerate() {
                let expected_object_state = if index == 0 {
                    capsec_semantics::model::ObjectState::Unknown
                } else {
                    capsec_semantics::model::ObjectState::Existing
                };
                assert!(row.decision_set.effects.iter().all(|effect| matches!(
                    &effect.resource,
                    capsec_semantics::model::OccurrenceResource::PathOccurrence {
                        object_state,
                        ..
                    } if *object_state == expected_object_state
                )));
                assert!(row.gates.iter().all(|gate| {
                    gate.coverage_edge_id.as_str() == "surface.loader.require.resolve.12c9l9i"
                }));
                let actions = row
                    .decision_set
                    .effects
                    .iter()
                    .map(|effect| effect.action.as_str())
                    .collect::<Vec<_>>();
                assert_eq!(actions, vec![if index < 2 { "fs:list" } else { "fs:read" }]);
            }
        }

        let denied = example_vfs_armed_host_with(|value| {
            value["principals"][0]["denials"] = serde_json::json!([{
                "cap": "fs:read",
                "resource": {
                    "kind": "path-tree",
                    "path": {
                        "root": "project",
                        "components": [
                            {"encoding": "utf8", "value": "resolve-meta-eng24234"}
                        ]
                    }
                }
            }]);
        });
        let error = denied
            .resolve_module_meta_for_principal(
                "./resolve-meta-eng24234/target.js",
                Some(&referrer),
                Some("0"),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("module metadata disclosure denied"),
            "unexpected typed denial: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn armed_require_resolve_canonicalizes_in_root_symlinks_and_refuses_escapes() {
        use std::os::unix::fs::symlink;

        let root = test_project_root();
        let fixture = root.join("resolve-meta-symlink-eng24234");
        std::fs::create_dir_all(&fixture).unwrap();
        let referrer = root.join("entry-symlink-eng24234.js");
        let target = fixture.join("target.js");
        let in_root_link = fixture.join("in-root.js");
        let outside_link = fixture.join("outside.js");
        std::fs::write(&referrer, "module.exports = 1;\n").unwrap();
        std::fs::write(&target, "module.exports = 2;\n").unwrap();
        let _ = std::fs::remove_file(&in_root_link);
        let _ = std::fs::remove_file(&outside_link);
        symlink(&target, &in_root_link).unwrap();

        let host = example_vfs_armed_host();
        host.begin_conformance_observation("enforcement.test.require-resolve-symlink");
        let resolved = host
            .resolve_module_meta_for_principal(
                "./resolve-meta-symlink-eng24234/in-root.js",
                Some(&referrer),
                Some("0"),
            )
            .unwrap();
        assert_eq!(resolved.path.as_deref(), Some(target.as_path()));
        let observed = host.take_typed_conformance_observations();
        assert_eq!(observed.len(), 5);
        assert_eq!(
            observed
                .iter()
                .map(|row| row.decision_set.context.stage)
                .collect::<Vec<_>>(),
            vec![
                capsec_semantics::model::Stage::Requested,
                capsec_semantics::model::Stage::Requested,
                capsec_semantics::model::Stage::Discovery,
                capsec_semantics::model::Stage::Commit,
                capsec_semantics::model::Stage::Repeat,
            ]
        );

        let outside = tempfile::tempdir().unwrap();
        let outside_target = outside.path().join("secret.js");
        std::fs::write(&outside_target, "module.exports = 'secret';\n").unwrap();
        symlink(&outside_target, &outside_link).unwrap();
        host.begin_conformance_observation("enforcement.test.require-resolve-escape");
        assert!(host
            .resolve_module_meta_for_principal(
                "./resolve-meta-symlink-eng24234/outside.js",
                Some(&referrer),
                Some("0"),
            )
            .is_err());
        let escaped = host.take_typed_conformance_observations();
        assert!(escaped.iter().all(|row| {
            !matches!(
                row.decision_set.context.stage,
                capsec_semantics::model::Stage::Commit | capsec_semantics::model::Stage::Repeat
            )
        }));
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
    fn typed_listen_allows_denies_and_binds_the_exact_committed_endpoint() {
        use capsec_semantics::decision::DecisionOutcome;
        use capsec_semantics::model::{
            BoundEndpoint, IpAddress, ListenBind, ListenPort, ListenTransport, NonEmptyString,
            OccurrenceResource, PeerClass, Port, SelectorResource, Stage,
        };

        let selector = serde_json::json!({
            "cap": "network:listen",
            "resource": {
                "kind": "listen-inet",
                "transport": "tcp",
                "bind": {"kind": "loopback"},
                "port": {"kind": "ephemeral"},
                "dualStack": false,
                "peerClasses": ["loopback"]
            }
        });
        let host = example_armed_host_with(|value| {
            value["principals"][1]["floor"] = serde_json::json!([selector]);
            value["principals"][1]["denials"] = serde_json::json!([]);
        });
        host.register_module_package(
            "7",
            "image-lib",
            Some("image-lib@2.4.1"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        let principal = host.typed_principal_for_module("7").unwrap();
        let requested_address = IpAddress::new("127.0.0.1".parse().unwrap());
        let bound_port = Port::new(43127).unwrap();
        let listener_id = NonEmptyString::new("listener:test:1").unwrap();

        host.begin_conformance_observation("enforcement.test.typed-listen");
        let requested = host
            .authorize_typed_listen_stage(
                "7",
                "tcp-listen",
                "surface.native.op.exacttcplisten.0mfz04n",
                vec![principal.clone()],
                ListenTransport::Tcp,
                ListenBind::Address {
                    address: requested_address,
                },
                ListenPort::Ephemeral,
                false,
                vec![PeerClass::Loopback],
                Stage::Requested,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(requested.outcome, DecisionOutcome::Allow);

        let committed = host
            .authorize_typed_listen_stage(
                "7",
                "tcp-listen",
                "surface.native.op.exacttcplisten.0mfz04n",
                vec![principal.clone()],
                ListenTransport::Tcp,
                ListenBind::Address {
                    address: requested_address,
                },
                ListenPort::Ephemeral,
                false,
                vec![PeerClass::Loopback],
                Stage::Commit,
                Some(vec![BoundEndpoint {
                    address: requested_address,
                    port: bound_port,
                    interface: None,
                }]),
                Some(listener_id.clone()),
                None,
            )
            .unwrap();
        assert_eq!(committed.outcome, DecisionOutcome::Allow);

        let observed = host.take_typed_conformance_observations();
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0].decision_set.context.stage, Stage::Requested);
        assert_eq!(observed[1].decision_set.context.stage, Stage::Commit);
        for row in &observed {
            assert_eq!(
                row.gates[0].coverage_edge_id.as_str(),
                "surface.native.op.exacttcplisten.0mfz04n"
            );
            let OccurrenceResource::ListenOccurrence { requested, .. } =
                &row.decision_set.effects[0].resource
            else {
                panic!("typed listen emitted a non-listen occurrence")
            };
            assert!(matches!(
                requested.as_ref(),
                SelectorResource::ListenInet {
                    bind: ListenBind::Address { address },
                    port: ListenPort::Ephemeral,
                    ..
                } if *address == requested_address
            ));
        }
        let OccurrenceResource::ListenOccurrence {
            bound_endpoints,
            listener_id: observed_listener_id,
            ..
        } = &observed[1].decision_set.effects[0].resource
        else {
            unreachable!()
        };
        assert_eq!(
            bound_endpoints.as_deref(),
            Some(
                [BoundEndpoint {
                    address: requested_address,
                    port: bound_port,
                    interface: None,
                }]
                .as_slice()
            )
        );
        assert_eq!(observed_listener_id.as_ref(), Some(&listener_id));

        let mismatched = host.authorize_typed_listen_stage(
            "7",
            "tcp-listen",
            "surface.native.op.exacttcplisten.0mfz04n",
            vec![principal],
            ListenTransport::Tcp,
            ListenBind::Address {
                address: requested_address,
            },
            ListenPort::Ephemeral,
            false,
            vec![PeerClass::Loopback],
            Stage::Commit,
            Some(vec![BoundEndpoint {
                address: IpAddress::new("0.0.0.0".parse().unwrap()),
                port: bound_port,
                interface: None,
            }]),
            Some(listener_id),
            None,
        );
        assert!(!matches!(
            mismatched,
            Ok(ref decision)
                if matches!(
                    decision.outcome,
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                )
        ));

        let denied_host = example_armed_host_with(|value| {
            value["principals"][1]["floor"] = serde_json::json!([]);
            value["principals"][1]["denials"] = serde_json::json!([]);
        });
        denied_host.register_module_package(
            "7",
            "image-lib",
            Some("image-lib@2.4.1"),
            Some("sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"),
        );
        let denied_principal = denied_host.typed_principal_for_module("7").unwrap();
        let denied = denied_host
            .authorize_typed_listen_stage(
                "7",
                "tcp-listen",
                "surface.native.op.exacttcplisten.0mfz04n",
                vec![denied_principal],
                ListenTransport::Tcp,
                ListenBind::Address {
                    address: requested_address,
                },
                ListenPort::Ephemeral,
                false,
                vec![PeerClass::Loopback],
                Stage::Requested,
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
        let parent_object = object_identity_for_host_path(&test_project_root().join("images"))
            .expect("test images directory has an authenticated identity");
        let photo_object =
            object_identity_for_host_path(&test_project_root().join("images/photo.jpg"))
                .expect("test image has an authenticated identity");
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
                    "parentObject": parent_object,
                    "finalObject": photo_object,
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
        let photo = test_project_root().join("images/photo.jpg");
        let images = test_project_root().join("images");
        let parent_object = object_identity_for_host_path(&images)
            .expect("test images directory has an authenticated identity");
        let photo_object = object_identity_for_host_path(&photo)
            .expect("test image has an authenticated identity");
        let authorize = |stage| {
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
                Some(parent_object.clone()),
                Some(photo_object.clone()),
                None,
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
