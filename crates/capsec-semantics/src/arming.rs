//! Strict immutable armed-snapshot ingestion.
//!
//! The caller supplies facts observed from the execution it is about to start;
//! this module authenticates the serialized snapshot against those facts and
//! returns an immutable value. No authored policy path or environment input is
//! retained. @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cache::GenerationSet;
use crate::decision::{
    ArmInputs, AuthorityCeiling, BoundAuthority, DecisionAuthorityState, PrincipalPolicy,
    ProtectedObjectGuard, SemanticIdentity, TargetArmState, VerifiedDecisionContext,
};
use crate::digest::{compute_checked_contract_digest, DigestKind};
use crate::model::{
    ActionId, AuthoritySelector, Digest, Generation, LogicalPath, LogicalRoot, NonEmptyString,
    ObjectIdentity, PathComponent, Principal, SafeUint, SelectorResource,
};
use crate::path_alias::{
    BoundVolumePathCanonicalizer, PathAliasCanonicalizers, PathCanonicalizerRootBinding,
};
use crate::registry::DefinitionSet;
use crate::strict_json::parse_strict;
use crate::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedArmingIdentity {
    pub profile: String,
    pub semantic_core: String,
    pub vocab_digest: Digest,
    pub registry_digest: Digest,
    pub policy_digest: Digest,
    pub armed_snapshot_digest: Digest,
    pub target: String,
    pub engine_binary_digest: Digest,
    pub features: Vec<String>,
    pub package_graph_digest: Digest,
    /// Launcher-observed execution entry. This is compared exactly with the
    /// digest-bound snapshot so a file, stdin program, REPL, or one-shot route
    /// cannot borrow another route's source identity or execution semantics.
    pub entry: ArmedEntry,
    /// Launcher-observed project-root discovery evidence. The record is
    /// compared exactly with the digest-bound snapshot before either one can
    /// establish the runtime's authority boundary.
    pub project_root_discovery: ArmedProjectRootDiscovery,
    /// Launcher-observed bound-volume canonicalizer identities. The exact
    /// sorted table is compared with the digest-bound snapshot before any
    /// authored selector is interpreted.
    pub path_canonicalizers: Vec<BoundVolumePathCanonicalizer>,
    /// Independently authenticated artifact paths, object identities, and
    /// content hashes. The snapshot's role labels are accepted only when they
    /// exactly match this launcher-supplied set.
    pub protected_artifacts: Vec<ExpectedProtectedArtifact>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArmedEntryKind {
    File,
    Stdin,
    Repl,
    Eval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArmedExecutionMode {
    Interactive,
    Transcript,
    Program,
    OneShot,
}

/// Digest-bound entry facts for one armed execution.
///
/// This is intentionally a closed tuple. In particular, the identity is not a
/// caller-selected source label: synthetic identities have exact spellings and
/// a file identity is confined to the virtual project namespace.
/// @ref LLP 0022#2-startup-project-identity-and-session-arming
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArmedEntry {
    pub kind: ArmedEntryKind,
    pub identity: NonEmptyString,
    pub mode: ArmedExecutionMode,
}

impl ArmedEntry {
    pub fn validate(&self) -> Result<()> {
        let identity = self.identity.as_str();
        let valid = match (self.kind, self.mode) {
            (ArmedEntryKind::File, ArmedExecutionMode::Program) => {
                valid_virtual_file_entry_identity(identity)
            }
            (ArmedEntryKind::Stdin, ArmedExecutionMode::Program) => identity == "ibex:stdin",
            (ArmedEntryKind::Repl, ArmedExecutionMode::Interactive)
            | (ArmedEntryKind::Repl, ArmedExecutionMode::Transcript) => identity == "ibex:repl",
            (ArmedEntryKind::Eval, ArmedExecutionMode::OneShot) => identity == "ibex:eval",
            _ => false,
        };
        if !valid {
            return refused("armed entry kind, identity, and mode are inconsistent");
        }
        Ok(())
    }
}

pub const PROJECT_ROOT_MARKER_SET_VERSION: &str = "ibex/project-root-markers/1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArmedProjectRootMarkerKind {
    ExplicitProject,
    PnpmWorkspace,
    PackageWorkspace,
    Lockfile,
    PackageManifest,
    OriginFallback,
}

/// Digest-bound evidence explaining how the authenticated project binding was
/// selected. Host paths use the same lossless component encoding as root
/// bindings; no display-string round trip participates in identity.
/// @ref LLP 0023#11-project-root-discovery — discovery is part of armed identity
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArmedProjectRootDiscovery {
    pub origin: LogicalPath,
    pub selected_root: LogicalPath,
    pub marker_kind: ArmedProjectRootMarkerKind,
    pub marker_path: Option<LogicalPath>,
    pub marker_set_version: String,
}

fn valid_virtual_file_entry_identity(identity: &str) -> bool {
    let Some(path) = identity.strip_prefix("file:///project/") else {
        return false;
    };
    if path.is_empty() || path.ends_with('/') || identity.contains(['\0', '\\', '?', '#']) {
        return false;
    }
    path.split('/').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && valid_percent_encoding(component.as_bytes())
    })
}

fn valid_percent_encoding(component: &[u8]) -> bool {
    let mut index = 0;
    while index < component.len() {
        let byte = component[index];
        if byte < 0x20 || byte == 0x7f {
            return false;
        }
        if byte != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= component.len() {
            return false;
        }
        let Some(high) = uppercase_hex(component[index + 1]) else {
            return false;
        };
        let Some(low) = uppercase_hex(component[index + 2]) else {
            return false;
        };
        let decoded = high << 4 | low;
        // Encoded path separators are ambiguous across platforms. Percent
        // escapes of RFC 3986 unreserved bytes are non-canonical spellings,
        // so they cannot manufacture a second authenticated entry identity.
        if decoded == b'/'
            || decoded.is_ascii_alphanumeric()
            || matches!(decoded, b'-' | b'.' | b'_' | b'~')
        {
            return false;
        }
        index += 3;
    }
    true
}

fn uppercase_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectedArtifactRole {
    ArmedPolicy,
    EngineBinary,
    ExactOperationManifest,
    PackageGraph,
    Registry,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedProtectedArtifact {
    pub role: ProtectedArtifactRole,
    pub host_path: LogicalPath,
    pub object: ObjectIdentity,
    pub content_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactEmbedderEndowments {
    pub app: Vec<u32>,
    pub agent_isolate: Vec<u32>,
    pub ui_worklet: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactEmbedderBinding {
    pub schema: String,
    pub operation_manifest_digest: Digest,
    pub endowments: ExactEmbedderEndowments,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotGenerations {
    pub policy: Generation,
    pub negative: Generation,
    pub dynamic: Generation,
    pub handle: Generation,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalImportPolicy {
    pub builtins: Vec<String>,
    pub packages: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArmedRootBinding {
    pub logical_root: LogicalRoot,
    #[serde(default)]
    pub owner: Option<Principal>,
    #[serde(default)]
    pub logical_path: Option<LogicalPath>,
    pub host_path: LogicalPath,
    pub object: ObjectIdentity,
}

#[derive(Clone, Debug)]
pub struct ArmedSnapshot {
    document: Arc<Value>,
    entry: ArmedEntry,
    project_root_discovery: ArmedProjectRootDiscovery,
    root_bindings: Arc<[ArmedRootBinding]>,
    path_canonicalizers: PathAliasCanonicalizers,
    protected_artifacts: Arc<[ExpectedProtectedArtifact]>,
    armed_snapshot_digest: Digest,
    generations: SnapshotGenerations,
}

impl ArmedSnapshot {
    pub fn load(bytes: &[u8], expected: &ExpectedArmingIdentity) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|error| Error::InvalidIJson {
            path: "$".into(),
            message: format!("armed snapshot is not UTF-8: {error}"),
        })?;
        let document = parse_strict(text)?;
        require_string(&document, "snapshotSchema", "ibex/capsec-armed/1")?;
        require_string(&document, "capsVocab", &expected.profile)?;
        require_string(&document, "semanticCore", &expected.semantic_core)?;
        require_string(&document, "vocabDigest", expected.vocab_digest.as_str())?;
        require_string(
            &document,
            "registryDigest",
            expected.registry_digest.as_str(),
        )?;
        require_string(&document, "policyDigest", expected.policy_digest.as_str())?;
        require_string(&document, "workflow", "production")?;
        require_string(&document, "effectiveMode", "enforce")?;
        require_string_at(&document, &["engine", "target"], &expected.target)?;
        require_string_at(
            &document,
            &["engine", "binaryDigest"],
            expected.engine_binary_digest.as_str(),
        )?;
        require_string_at(
            &document,
            &["packageGraph", "digest"],
            expected.package_graph_digest.as_str(),
        )?;
        let features = value_at(&document, &["engine", "features"])?
            .as_array()
            .ok_or_else(|| invalid("engine.features must be an array"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("engine feature must be a string"))
            })
            .collect::<Result<Vec<_>>>()?;
        if features != expected.features {
            return refused("engine feature set differs from the armed snapshot");
        }
        for field in [
            "lockdown",
            "frameAttribution",
            "compartments",
            "fullDeputyIntersection",
            "immutableDecisionContext",
        ] {
            if value_at(&document, &["structuralPosture", field])?.as_bool() != Some(true) {
                return refused("required structural posture is not active");
            }
        }
        let claimed = Digest::new(required_str(&document, "armedSnapshotDigest")?)
            .map_err(Error::InvalidModel)?;
        if claimed != expected.armed_snapshot_digest {
            return refused("armed snapshot digest differs from the trusted arming identity");
        }
        let computed = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &document)?;
        if claimed.as_str() != computed {
            return refused("armed snapshot digest is stale or tampered");
        }
        let generations = SnapshotGenerations {
            policy: generation(&document, "policy")?,
            negative: generation(&document, "negative")?,
            dynamic: generation(&document, "dynamic")?,
            handle: generation(&document, "handle")?,
        };
        let entry: ArmedEntry = serde_json::from_value(value_at(&document, &["entry"])?.clone())
            .map_err(|error| invalid(format!("invalid armed entry: {error}")))?;
        entry.validate()?;
        if entry != expected.entry {
            return refused("execution entry differs from the trusted arming identity");
        }
        let project_root_discovery: ArmedProjectRootDiscovery =
            serde_json::from_value(value_at(&document, &["projectRootDiscovery"])?.clone())
                .map_err(|error| {
                    invalid(format!("invalid project-root discovery record: {error}"))
                })?;
        if project_root_discovery != expected.project_root_discovery {
            return refused("project-root discovery differs from the trusted arming identity");
        }
        validate_snapshot_invariants(&document, &project_root_discovery)?;
        validate_expected_protected_artifacts(&document, expected)?;
        let root_bindings: Vec<ArmedRootBinding> =
            serde_json::from_value(value_at(&document, &["rootBindings"])?.clone())
                .map_err(|error| invalid(format!("invalid armed root bindings: {error}")))?;
        let path_canonicalizer_rows: Vec<BoundVolumePathCanonicalizer> = serde_json::from_value(
            value_at(&document, &["pathCanonicalizers"])?.clone(),
        )
        .map_err(|error| invalid(format!("invalid bound-volume canonicalizers: {error}")))?;
        if path_canonicalizer_rows != expected.path_canonicalizers {
            return refused("bound-volume canonicalizers differ from the trusted arming identity");
        }
        let path_canonicalizers =
            bind_path_canonicalizers(path_canonicalizer_rows, &root_bindings)?;
        Ok(Self {
            document: Arc::new(document),
            entry,
            project_root_discovery,
            root_bindings: root_bindings.into(),
            path_canonicalizers,
            protected_artifacts: expected.protected_artifacts.clone().into(),
            armed_snapshot_digest: claimed,
            generations,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.armed_snapshot_digest
    }

    pub fn generations(&self) -> SnapshotGenerations {
        self.generations
    }

    pub fn document(&self) -> &Value {
        &self.document
    }

    pub fn entry(&self) -> &ArmedEntry {
        &self.entry
    }

    pub fn project_root_discovery(&self) -> &ArmedProjectRootDiscovery {
        &self.project_root_discovery
    }

    pub fn engine_target(&self) -> Result<String> {
        value_at(&self.document, &["engine", "target"])?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("engine.target must be a string"))
    }

    pub fn engine_features(&self) -> Result<Vec<String>> {
        value_at(&self.document, &["engine", "features"])?
            .as_array()
            .ok_or_else(|| invalid("engine.features must be an array"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("engine feature must be a string"))
            })
            .collect()
    }

    pub fn root_bindings(&self) -> Result<&[ArmedRootBinding]> {
        Ok(&self.root_bindings)
    }

    pub fn path_canonicalizers(&self) -> &PathAliasCanonicalizers {
        &self.path_canonicalizers
    }

    /// Convert a lexical logical path into its authorization coordinate. The
    /// lexical value remains available to VFS display and SourceId consumers.
    pub fn canonicalize_authorization_path(
        &self,
        principal: &Principal,
        path: &LogicalPath,
    ) -> Result<LogicalPath> {
        self.path_canonicalizers
            .canonicalize_path(path, principal.is_package().then_some(principal))
    }

    /// Exact launcher-authenticated artifact identities backing the snapshot's
    /// mandatory protected-object guards. The Host reopens these paths and
    /// checks both object identity and content digest before runtime creation.
    pub fn protected_artifacts(&self) -> &[ExpectedProtectedArtifact] {
        &self.protected_artifacts
    }

    /// Optional Exact-specific ingress identity authenticated by the armed
    /// snapshot and its protected operation-manifest artifact. Generic Ibex
    /// snapshots omit this binding; an armed Exact ingress may not.
    pub fn exact_embedder_binding(&self) -> Result<Option<ExactEmbedderBinding>> {
        let Some(value) = self.document.get("exactEmbedder") else {
            return Ok(None);
        };
        let binding: ExactEmbedderBinding = serde_json::from_value(value.clone())
            .map_err(|error| invalid(format!("invalid Exact embedder binding: {error}")))?;
        validate_exact_embedder_binding(&binding)?;
        Ok(Some(binding))
    }

    /// Convert an absolute host path into the most-specific authenticated
    /// logical root available to this principal. Package bindings are usable
    /// only by their exact package owner, and a deeper foreign package root
    /// shadows an owned ancestor; absolute bindings are exact rather than
    /// ambient filesystem roots.
    pub fn logical_path_for_host_components(
        &self,
        principal: &Principal,
        host_components: &[PathComponent],
    ) -> Result<LogicalPath> {
        logical_path_for_host_components_in(
            self.root_bindings()?,
            principal,
            host_components,
            &self.path_canonicalizers,
        )
    }

    /// Project one authenticated host path through every constrained
    /// principal's own root-binding view. Bindings are decoded once for the
    /// batch so a deputy stack does not repeatedly parse the armed document.
    pub fn logical_paths_for_host_components(
        &self,
        principals: &[Principal],
        host_components: &[PathComponent],
    ) -> Result<BTreeMap<Principal, LogicalPath>> {
        let bindings = self.root_bindings()?;
        validate_package_binding_host_paths(bindings, &self.path_canonicalizers)?;
        principals
            .iter()
            .map(|principal| {
                Ok((
                    principal.clone(),
                    logical_path_for_host_components_in_validated(
                        bindings,
                        principal,
                        host_components,
                        &self.path_canonicalizers,
                    )?,
                ))
            })
            .collect()
    }

    /// Return the most-specific authenticated root binding used for a host
    /// path. Callers that touch the operating system must revalidate this
    /// binding's object identity before relying on the logical mapping.
    pub fn root_binding_for_host_components(
        &self,
        principal: &Principal,
        host_components: &[PathComponent],
    ) -> Result<ArmedRootBinding> {
        root_binding_for_host_components_in(
            self.root_bindings()?,
            principal,
            host_components,
            &self.path_canonicalizers,
        )
    }

    /// Resolve the owner of the most-specific root binding without trusting a
    /// caller-supplied principal. Package bindings win over their enclosing
    /// project binding; non-package paths are represented by `None` (root).
    pub fn owner_for_host_components(
        &self,
        host_components: &[PathComponent],
    ) -> Result<Option<Principal>> {
        let mut candidates = Vec::new();
        for binding in self.root_bindings()? {
            if host_binding_matches(binding, host_components, &self.path_canonicalizers)? {
                candidates.push(binding);
            }
        }
        candidates.sort_by(|left, right| {
            right
                .host_path
                .components
                .len()
                .cmp(&left.host_path.components.len())
        });
        let binding = candidates.into_iter().next().ok_or_else(|| {
            Error::ArmRefused("host path has no authenticated logical-root binding".into())
        })?;
        Ok(binding.owner.clone())
    }

    /// Reconstruct the exact semantic identity authenticated by this snapshot.
    pub fn semantic_identity(&self) -> Result<SemanticIdentity> {
        Ok(SemanticIdentity {
            profile: required_str(&self.document, "capsVocab")?,
            semantic_core: required_str(&self.document, "semanticCore")?,
            vocab_digest: digest_field(&self.document, "vocabDigest")?,
            registry_digest: digest_field(&self.document, "registryDigest")?,
            policy_digest: digest_field(&self.document, "policyDigest")?,
            armed_snapshot_digest: self.armed_snapshot_digest.clone(),
        })
    }

    /// Decode immutable authority rows for the typed decision engine. This is
    /// deliberately one-way: no legacy capability strings or authored policy
    /// fields are reconstructed after arming.
    pub fn authority_state(&self) -> Result<DecisionAuthorityState> {
        let principal_rows: Vec<SnapshotPrincipalRow> =
            serde_json::from_value(value_at(&self.document, &["principals"])?.clone())
                .map_err(|error| invalid(format!("invalid armed principals: {error}")))?;
        let principals = principal_rows
            .iter()
            .map(|row| row.principal.clone())
            .collect::<Vec<_>>();
        let package_principals = principals
            .iter()
            .filter(|principal| principal.is_package())
            .cloned()
            .collect::<Vec<_>>();
        let mut principal_policies = BTreeMap::new();
        for (principal_index, row) in principal_rows.into_iter().enumerate() {
            let package_owner = row.principal.is_package().then(|| row.principal.clone());
            let static_floor = bind_authorities(
                row.floor,
                principal_index,
                "floor",
                self.digest(),
                package_owner.as_ref(),
                &self.path_canonicalizers,
            )?;
            let denials = bind_authorities(
                row.denials,
                principal_index,
                "denial",
                self.digest(),
                package_owner.as_ref(),
                &self.path_canonicalizers,
            )?;
            let escalation_ceiling = AuthorityCeiling::Bounded(bind_authorities(
                row.escalation_ceiling,
                principal_index,
                "ceiling",
                self.digest(),
                package_owner.as_ref(),
                &self.path_canonicalizers,
            )?);
            if principal_policies
                .insert(
                    row.principal,
                    PrincipalPolicy {
                        denials,
                        static_floor,
                        escalation_ceiling,
                        implicit_package_self: Vec::new(),
                    },
                )
                .is_some()
            {
                return refused("armed snapshot contains a duplicate principal");
            }
        }

        let protected_rows: Vec<SnapshotProtectedObject> =
            serde_json::from_value(value_at(&self.document, &["protectedObjects"])?.clone())
                .map_err(|error| invalid(format!("invalid protected objects: {error}")))?;
        let mut protected_objects = protected_rows
            .into_iter()
            .flat_map(|row| {
                row.denied_actions
                    .into_iter()
                    .map(move |action| ProtectedObjectGuard {
                        action,
                        object: row.object.clone(),
                        verification_generation: None,
                    })
            })
            .collect::<Vec<_>>();
        protected_objects.sort();
        if protected_objects.windows(2).any(|pair| pair[0] == pair[1]) {
            return refused("armed snapshot contains a duplicate protected-object guard");
        }
        let protected_resources = derive_package_write_guards(
            self.root_bindings()?,
            &principals,
            self.digest(),
            &self.path_canonicalizers,
        )?;

        let process_ceiling = match value_at(&self.document, &["processAuthorityCeiling"])?
            .get("kind")
            .and_then(Value::as_str)
        {
            Some("unbounded") => AuthorityCeiling::Unbounded,
            Some("bounded") => {
                let selectors: Vec<AuthoritySelector> = serde_json::from_value(
                    value_at(&self.document, &["processAuthorityCeiling", "authorities"])?.clone(),
                )
                .map_err(|error| invalid(format!("invalid process ceiling: {error}")))?;
                AuthorityCeiling::Bounded(bind_process_ceiling(
                    selectors,
                    self.digest(),
                    &package_principals,
                    &self.path_canonicalizers,
                )?)
            }
            _ => return Err(invalid("processAuthorityCeiling.kind is invalid")),
        };

        Ok(DecisionAuthorityState {
            generations: GenerationSet {
                negative: self.generations.negative,
                dynamic: self.generations.dynamic,
                handle: self.generations.handle,
            },
            process_ceiling: process_ceiling.into(),
            protected_objects: protected_objects.into(),
            protected_resources: protected_resources.into(),
            principal_policies: principal_policies.into(),
            revocations: Vec::new(),
            handles: Vec::new(),
            dynamic_grants: Vec::new(),
        })
    }

    /// Immutable import axes keyed by the same integrity-bound principals used
    /// by effect decisions.
    pub fn import_policies(&self) -> Result<BTreeMap<Principal, PrincipalImportPolicy>> {
        let principal_rows: Vec<SnapshotPrincipalRow> =
            serde_json::from_value(value_at(&self.document, &["principals"])?.clone())
                .map_err(|error| invalid(format!("invalid armed principals: {error}")))?;
        let mut policies = BTreeMap::new();
        for row in principal_rows {
            require_sorted_unique_strings(&row.imports.builtins, "builtin imports")?;
            require_sorted_unique_strings(&row.imports.packages, "package imports")?;
            if policies.insert(row.principal, row.imports).is_some() {
                return refused("armed snapshot contains a duplicate principal import policy");
            }
        }
        Ok(policies)
    }

    /// Serialize authenticated package endowments into the engine's strict
    /// compartment-bootstrap wire format. Ambient process values never
    /// participate; this projection comes only from the immutable armed
    /// document. JSON keeps locator and endowment bytes structural, so names
    /// containing punctuation cannot manufacture another principal row.
    /// @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine
    pub fn compartment_endowments_json(&self) -> Result<String> {
        let principal_rows: Vec<SnapshotPrincipalRow> =
            serde_json::from_value(value_at(&self.document, &["principals"])?.clone())
                .map_err(|error| invalid(format!("invalid armed principals: {error}")))?;
        let mut rows = Vec::new();
        let mut locators = BTreeSet::new();
        for row in principal_rows {
            require_sorted_unique_strings(&row.endowments, "principal endowments")?;
            let Principal::Package { locator, .. } = row.principal else {
                if row.endowments.is_empty() {
                    continue;
                }
                return refused("root principal cannot receive package compartment endowments");
            };
            if !locators.insert(locator.as_str().to_owned()) {
                return refused("armed snapshot contains duplicate compartment endowment locators");
            }
            rows.push(CompartmentEndowmentRow {
                locator: locator.as_str().to_owned(),
                endowments: row.endowments,
            });
        }
        rows.sort_by(|left, right| left.locator.cmp(&right.locator));
        serde_json::to_string(&rows)
            .map_err(|error| invalid(format!("cannot serialize compartment endowments: {error}")))
    }

    /// Arm the neutral decision evaluator directly from the authenticated
    /// snapshot, a validated product definition set, and the caller's checked
    /// target-advertisement result. Snapshot authentication alone does not
    /// prove that the exact engine/feature cell is complete.
    pub fn decision_context(
        &self,
        definitions: DefinitionSet,
        target: TargetArmState,
    ) -> Result<VerifiedDecisionContext> {
        self.decision_context_with_package_objects(definitions, target, Vec::new())
    }

    /// Arm the neutral evaluator with the exact package objects authenticated
    /// by the launcher's integrity walk. These rows are immutable for the Host
    /// lifetime and are appended before the decision context is sealed.
    ///
    /// The snapshot supplies the package principals, roots, and integrity
    /// digests; the host-side walk supplies object/generation evidence that
    /// cannot safely be authored as a portable policy value.
    /// @ref LLP 0023#42-authenticated-package-source-is-immutable
    pub fn decision_context_with_package_objects(
        &self,
        definitions: DefinitionSet,
        target: TargetArmState,
        package_objects: Vec<ProtectedObjectGuard>,
    ) -> Result<VerifiedDecisionContext> {
        let identity = self.semantic_identity()?;
        let mut authority = self.authority_state()?;
        let mut protected_objects = (*authority.protected_objects).clone();
        for guard in &package_objects {
            if guard.action.as_str() != "fs:write" || guard.verification_generation.is_none() {
                return refused(
                    "authenticated package object guard must deny fs:write with a generation",
                );
            }
        }
        protected_objects.extend(package_objects);
        protected_objects.sort();
        if protected_objects.windows(2).any(|pair| pair[0] == pair[1]) {
            return refused("authenticated package object guards are not unique");
        }
        authority.protected_objects = protected_objects.into();
        VerifiedDecisionContext::arm_with_path_canonicalizers(
            ArmInputs {
                expected_identity: identity.clone(),
                loaded_identity: identity,
                target,
                structure_valid: true,
            },
            definitions,
            authority,
            self.path_canonicalizers.clone(),
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotPrincipalRow {
    principal: Principal,
    floor: Vec<AuthoritySelector>,
    denials: Vec<AuthoritySelector>,
    escalation_ceiling: Vec<AuthoritySelector>,
    imports: PrincipalImportPolicy,
    endowments: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompartmentEndowmentRow {
    locator: String,
    endowments: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotProtectedObject {
    role: ProtectedArtifactRole,
    object: ObjectIdentity,
    denied_actions: Vec<ActionId>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotPackageGraph {
    #[allow(dead_code)]
    digest: Digest,
    nodes: Vec<SnapshotGraphNode>,
    import_edges: Vec<SnapshotImportEdge>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotGraphNode {
    principal: Principal,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotImportEdge {
    importer: Principal,
    imported: Principal,
}

fn validate_snapshot_invariants(
    document: &Value,
    project_root_discovery: &ArmedProjectRootDiscovery,
) -> Result<()> {
    validate_protected_object_rows(document)?;

    if let Some(value) = document.get("exactEmbedder") {
        let binding: ExactEmbedderBinding = serde_json::from_value(value.clone())
            .map_err(|error| invalid(format!("invalid Exact embedder binding: {error}")))?;
        validate_exact_embedder_binding(&binding)?;
    }

    let root_identity: Principal =
        serde_json::from_value(value_at(document, &["rootIdentity"])?.clone())
            .map_err(|error| invalid(format!("invalid root identity: {error}")))?;
    if !root_identity.is_root() {
        return refused("rootIdentity is not a root principal");
    }
    let principal_rows: Vec<SnapshotPrincipalRow> =
        serde_json::from_value(value_at(document, &["principals"])?.clone())
            .map_err(|error| invalid(format!("invalid armed principals: {error}")))?;
    let mut authorities = BTreeMap::new();
    for row in &principal_rows {
        require_sorted_unique_strings(&row.imports.builtins, "builtin imports")?;
        require_sorted_unique_strings(&row.imports.packages, "package imports")?;
        require_sorted_unique_strings(&row.endowments, "principal endowments")?;
        if authorities.insert(row.principal.clone(), row).is_some() {
            return refused("armed snapshot contains a duplicate principal authority row");
        }
    }
    if principal_rows
        .iter()
        .filter(|row| row.principal.is_root())
        .count()
        != 1
        || !authorities.contains_key(&root_identity)
    {
        return refused("armed snapshot must contain exactly its rootIdentity authority row");
    }

    let graph: SnapshotPackageGraph =
        serde_json::from_value(value_at(document, &["packageGraph"])?.clone())
            .map_err(|error| invalid(format!("invalid package graph: {error}")))?;
    let mut graph_nodes = BTreeSet::new();
    let mut nodes_by_locator = BTreeMap::new();
    for node in graph.nodes {
        let Principal::Package { locator, .. } = &node.principal else {
            return refused("package graph contains a non-package node");
        };
        if !graph_nodes.insert(node.principal.clone())
            || nodes_by_locator
                .insert(locator.as_str().to_owned(), node.principal)
                .is_some()
        {
            return refused("package graph nodes are not unique by locator and integrity");
        }
    }
    let package_rows = authorities
        .keys()
        .filter(|principal| principal.is_package())
        .cloned()
        .collect::<BTreeSet<_>>();
    if package_rows != graph_nodes {
        return refused("package authority rows must exactly equal package graph nodes");
    }

    let mut graph_edges = BTreeSet::new();
    for edge in graph.import_edges {
        if !authorities.contains_key(&edge.importer)
            || !graph_nodes.contains(&edge.imported)
            || !graph_edges.insert((edge.importer, edge.imported))
        {
            return refused("package graph contains a duplicate or unbound import edge");
        }
    }
    let mut declared_edges = BTreeSet::new();
    for row in &principal_rows {
        for locator in &row.imports.packages {
            let imported = nodes_by_locator.get(locator).ok_or_else(|| {
                Error::ArmRefused(format!(
                    "principal import allowlist names unknown package locator {locator}"
                ))
            })?;
            declared_edges.insert((row.principal.clone(), imported.clone()));
        }
    }
    if declared_edges != graph_edges {
        return refused("principal import allowlists must exactly equal package graph edges");
    }

    let bindings: Vec<ArmedRootBinding> =
        serde_json::from_value(value_at(document, &["rootBindings"])?.clone())
            .map_err(|error| invalid(format!("invalid armed root bindings: {error}")))?;
    validate_root_bindings(&bindings, &graph_nodes)?;
    validate_project_root_discovery(project_root_discovery, &bindings)?;
    Ok(())
}

fn validate_project_root_discovery(
    discovery: &ArmedProjectRootDiscovery,
    bindings: &[ArmedRootBinding],
) -> Result<()> {
    let valid_host_path = |path: &LogicalPath| {
        path.root == LogicalRoot::Absolute
            && path.host_bound == Some(true)
            && !path.components.is_empty()
            && path.is_canonical()
    };
    if !valid_host_path(&discovery.origin)
        || !valid_host_path(&discovery.selected_root)
        || discovery
            .marker_path
            .as_ref()
            .is_some_and(|path| !valid_host_path(path))
    {
        return refused("project-root discovery paths must be non-empty absolute host-bound paths");
    }
    if discovery.marker_set_version != PROJECT_ROOT_MARKER_SET_VERSION {
        return refused("project-root discovery marker-set version is unsupported");
    }

    let project_binding = bindings
        .iter()
        .find(|binding| binding.logical_root == LogicalRoot::Project)
        .expect("validated root bindings have exactly one project binding");
    if discovery.selected_root != project_binding.host_path {
        return refused("project-root discovery selection differs from the project binding");
    }

    let marker_parent_and_name = discovery.marker_path.as_ref().and_then(|path| {
        let (name, parent) = path.components.split_last()?;
        Some((parent, name.bytes()))
    });
    let selected_components = discovery.selected_root.components.as_slice();
    let origin_is_within_selection = discovery.origin.components.starts_with(selected_components);
    let valid = match discovery.marker_kind {
        ArmedProjectRootMarkerKind::ExplicitProject => {
            discovery.marker_path.as_ref() == Some(&discovery.selected_root)
        }
        ArmedProjectRootMarkerKind::OriginFallback => {
            discovery.marker_path.is_none() && discovery.selected_root == discovery.origin
        }
        ArmedProjectRootMarkerKind::PnpmWorkspace => {
            origin_is_within_selection
                && marker_parent_and_name.is_some_and(|(parent, name)| {
                    parent == selected_components && name == b"pnpm-workspace.yaml"
                })
        }
        ArmedProjectRootMarkerKind::PackageWorkspace
        | ArmedProjectRootMarkerKind::PackageManifest => {
            origin_is_within_selection
                && marker_parent_and_name.is_some_and(|(parent, name)| {
                    parent == selected_components && name == b"package.json"
                })
        }
        ArmedProjectRootMarkerKind::Lockfile => {
            origin_is_within_selection
                && marker_parent_and_name.is_some_and(|(parent, name)| {
                    parent == selected_components
                        && matches!(
                            name,
                            b"package-lock.json"
                                | b"pnpm-lock.yaml"
                                | b"yarn.lock"
                                | b"bun.lockb"
                                | b"bun.lock"
                        )
                })
        }
    };
    if !valid {
        return refused("project-root discovery record is internally inconsistent");
    }
    Ok(())
}

fn validate_root_bindings(
    bindings: &[ArmedRootBinding],
    graph_nodes: &BTreeSet<Principal>,
) -> Result<()> {
    if bindings.is_empty() {
        return refused("armed snapshot has no root bindings");
    }
    let mut host_paths = BTreeSet::new();
    let mut logical_keys = BTreeSet::new();
    let mut objects = BTreeSet::new();
    let mut package_binding_counts = BTreeMap::<Principal, usize>::new();
    let mut project_bindings = 0usize;
    for binding in bindings {
        if binding.host_path.root != LogicalRoot::Absolute
            || binding.host_path.host_bound != Some(true)
            || binding.host_path.components.is_empty()
        {
            return refused("root binding must name a non-empty absolute host-bound path");
        }
        let host_key = crate::canonical::to_jcs_bytes(
            &serde_json::to_value(&binding.host_path)
                .map_err(|error| invalid(format!("invalid root binding path: {error}")))?,
        )?;
        if !host_paths.insert(host_key) || !objects.insert(binding.object.clone()) {
            return refused("root bindings contain a duplicate or ambiguous host object");
        }
        let logical_key = crate::canonical::to_jcs_bytes(&serde_json::json!([
            binding.logical_root,
            binding.owner,
            binding.logical_path,
        ]))?;
        if !logical_keys.insert(logical_key) {
            return refused("root bindings contain a duplicate logical mapping");
        }

        match binding.logical_root {
            LogicalRoot::Package => {
                let owner = binding.owner.as_ref().ok_or_else(|| {
                    Error::ArmRefused("package root binding has no exact owner".into())
                })?;
                if !graph_nodes.contains(owner) || binding.logical_path.is_some() {
                    return refused("package root binding owner is outside the package graph");
                }
                *package_binding_counts.entry(owner.clone()).or_default() += 1;
            }
            LogicalRoot::Absolute => {
                if binding.owner.is_some()
                    || binding.logical_path.as_ref().is_none_or(|path| {
                        path.root != LogicalRoot::Absolute || path.host_bound != Some(true)
                    })
                {
                    return refused("absolute root binding lacks its exact logical path");
                }
            }
            LogicalRoot::Project => {
                if binding.owner.is_some() || binding.logical_path.is_some() {
                    return refused("project root binding has invalid owner or logical path");
                }
                project_bindings += 1;
            }
            _ => {
                if binding.owner.is_some() || binding.logical_path.is_some() {
                    return refused("non-package root binding has invalid owner or logical path");
                }
            }
        }
    }
    if project_bindings != 1 {
        return refused("armed snapshot must contain exactly one project root binding");
    }
    if graph_nodes
        .iter()
        .any(|principal| package_binding_counts.get(principal) != Some(&1))
        || package_binding_counts.len() != graph_nodes.len()
    {
        return refused("every package graph node must have exactly one package-root binding");
    }
    Ok(())
}

fn validate_protected_object_rows(document: &Value) -> Result<()> {
    let rows: Vec<SnapshotProtectedObject> =
        serde_json::from_value(value_at(document, &["protectedObjects"])?.clone())
            .map_err(|error| invalid(format!("invalid protected objects: {error}")))?;
    let mut required = vec![
        ProtectedArtifactRole::ArmedPolicy,
        ProtectedArtifactRole::EngineBinary,
        ProtectedArtifactRole::PackageGraph,
        ProtectedArtifactRole::Registry,
    ];
    if document.get("exactEmbedder").is_some() {
        required.push(ProtectedArtifactRole::ExactOperationManifest);
        required.sort();
    }
    if rows.len() != required.len() {
        return refused("armed snapshot protected artifact count does not match its bindings");
    }
    let mut roles = Vec::with_capacity(rows.len());
    let mut objects = Vec::with_capacity(rows.len());
    for row in rows {
        if row.denied_actions.len() != 1 || row.denied_actions[0].as_str() != "fs:write" {
            return refused("every protected artifact must deny exactly fs:write");
        }
        roles.push(row.role);
        objects.push(row.object);
    }
    roles.sort();
    if roles != required {
        return refused("protected artifact roles are missing, duplicate, or mislabeled");
    }
    objects.sort();
    if objects.windows(2).any(|pair| pair[0] == pair[1]) {
        return refused("mandatory protected artifacts must have distinct object identities");
    }
    Ok(())
}

fn validate_expected_protected_artifacts(
    document: &Value,
    expected: &ExpectedArmingIdentity,
) -> Result<()> {
    let mut required = vec![
        ProtectedArtifactRole::ArmedPolicy,
        ProtectedArtifactRole::EngineBinary,
        ProtectedArtifactRole::PackageGraph,
        ProtectedArtifactRole::Registry,
    ];
    let exact_binding = document
        .get("exactEmbedder")
        .map(|value| {
            serde_json::from_value::<ExactEmbedderBinding>(value.clone())
                .map_err(|error| invalid(format!("invalid Exact embedder binding: {error}")))
        })
        .transpose()?;
    if exact_binding.is_some() {
        required.push(ProtectedArtifactRole::ExactOperationManifest);
        required.sort();
    }
    if expected.protected_artifacts.len() != required.len() {
        return refused("arming identity protected artifact count does not match its bindings");
    }
    let mut authenticated = expected.protected_artifacts.clone();
    authenticated.sort_by_key(|artifact| artifact.role);
    if authenticated
        .iter()
        .map(|artifact| artifact.role)
        .collect::<Vec<_>>()
        != required
    {
        return refused("arming identity protected artifact roles are incomplete or duplicated");
    }
    let mut host_paths = BTreeSet::new();
    let mut objects = BTreeSet::new();
    for artifact in &authenticated {
        if artifact.host_path.root != LogicalRoot::Absolute
            || artifact.host_path.host_bound != Some(true)
            || artifact.host_path.components.is_empty()
        {
            return refused("protected artifact path is not a non-empty absolute host binding");
        }
        let path_key = crate::canonical::to_jcs_bytes(
            &serde_json::to_value(&artifact.host_path)
                .map_err(|error| invalid(format!("invalid protected artifact path: {error}")))?,
        )?;
        if !host_paths.insert(path_key) || !objects.insert(artifact.object.clone()) {
            return refused("protected artifact paths and objects must be distinct");
        }
        if artifact.role == ProtectedArtifactRole::EngineBinary
            && artifact.content_digest != expected.engine_binary_digest
        {
            return refused(
                "protected engine content digest differs from the loaded engine digest",
            );
        }
        if artifact.role == ProtectedArtifactRole::ExactOperationManifest
            && exact_binding
                .as_ref()
                .is_none_or(|binding| artifact.content_digest != binding.operation_manifest_digest)
        {
            return refused(
                "protected Exact operation manifest digest differs from its armed binding",
            );
        }
    }

    let rows: Vec<SnapshotProtectedObject> =
        serde_json::from_value(value_at(document, &["protectedObjects"])?.clone())
            .map_err(|error| invalid(format!("invalid protected objects: {error}")))?;
    let by_role = rows
        .into_iter()
        .map(|row| (row.role, row.object))
        .collect::<BTreeMap<_, _>>();
    for artifact in &authenticated {
        if by_role.get(&artifact.role) != Some(&artifact.object) {
            return refused(
                "protected object does not match the independently authenticated artifact role",
            );
        }
    }
    Ok(())
}

fn validate_exact_embedder_binding(binding: &ExactEmbedderBinding) -> Result<()> {
    if binding.schema != "exact/host-operation-endowments/1" {
        return refused("Exact embedder binding schema is unsupported");
    }
    let contexts = [
        (&binding.endowments.app, "app"),
        (&binding.endowments.agent_isolate, "agent isolate"),
        (&binding.endowments.ui_worklet, "UI worklet"),
    ];
    let mut all = BTreeSet::new();
    for (operations, label) in contexts {
        if operations.len() > 4096
            || operations.contains(&0)
            || operations.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return refused(format!(
                "Exact {label} operation endowment is not a bounded sorted unique uint32 set"
            ));
        }
        if operations.iter().any(|operation| !all.insert(*operation)) {
            return refused("Exact operation is endowed to more than one runtime context");
        }
    }
    if binding.endowments.app.is_empty() || binding.endowments.agent_isolate.is_empty() {
        return refused("Exact app and agent-isolate endowments must be non-empty");
    }
    if !binding.endowments.ui_worklet.is_empty() {
        return refused("Exact UI worklet endowment must remain empty");
    }
    Ok(())
}

fn logical_path_for_host_components_in(
    bindings: &[ArmedRootBinding],
    principal: &Principal,
    host_components: &[PathComponent],
    canonicalizers: &PathAliasCanonicalizers,
) -> Result<LogicalPath> {
    let binding =
        root_binding_for_host_components_in(bindings, principal, host_components, canonicalizers)?;
    logical_path_from_binding(&binding, host_components)
}

fn logical_path_for_host_components_in_validated(
    bindings: &[ArmedRootBinding],
    principal: &Principal,
    host_components: &[PathComponent],
    canonicalizers: &PathAliasCanonicalizers,
) -> Result<LogicalPath> {
    let binding = root_binding_for_host_components_in_validated(
        bindings,
        principal,
        host_components,
        canonicalizers,
    )?;
    logical_path_from_binding(binding, host_components)
}

fn logical_path_from_binding(
    binding: &ArmedRootBinding,
    host_components: &[PathComponent],
) -> Result<LogicalPath> {
    if binding.logical_root == LogicalRoot::Absolute {
        return binding.logical_path.clone().ok_or_else(|| {
            Error::ArmRefused("absolute root binding is missing its logical path".into())
        });
    }
    Ok(LogicalPath {
        root: binding.logical_root,
        components: host_components[binding.host_path.components.len()..].to_vec(),
        host_bound: None,
    })
}

fn root_binding_for_host_components_in(
    bindings: &[ArmedRootBinding],
    principal: &Principal,
    host_components: &[PathComponent],
    canonicalizers: &PathAliasCanonicalizers,
) -> Result<ArmedRootBinding> {
    validate_package_binding_host_paths(bindings, canonicalizers)?;
    root_binding_for_host_components_in_validated(
        bindings,
        principal,
        host_components,
        canonicalizers,
    )
    .cloned()
}

fn root_binding_for_host_components_in_validated<'a>(
    bindings: &'a [ArmedRootBinding],
    principal: &Principal,
    host_components: &[PathComponent],
    canonicalizers: &PathAliasCanonicalizers,
) -> Result<&'a ArmedRootBinding> {
    // @ref LLP 0021#decision-staging-and-principal-semantics — package roots
    // are principal-relative mount boundaries: a foreign nested root must not
    // fall through to an owned package ancestor.
    let mut matching_package_bindings = Vec::new();
    for binding in bindings
        .iter()
        .filter(|binding| binding.logical_root == LogicalRoot::Package)
    {
        if host_binding_matches(binding, host_components, canonicalizers)? {
            matching_package_bindings.push(binding);
        }
    }
    let mut candidates = Vec::new();
    for binding in bindings {
        if !host_binding_matches(binding, host_components, canonicalizers)? {
            continue;
        }
        let admitted = match binding.logical_root {
            LogicalRoot::Package => {
                binding.owner.as_ref() == Some(principal)
                    && !matching_package_bindings.iter().any(|foreign| {
                        foreign.owner.as_ref() != Some(principal)
                            && foreign.host_path.components.len()
                                > binding.host_path.components.len()
                    })
            }
            _ => binding.owner.is_none(),
        };
        if admitted {
            candidates.push(binding);
        }
    }
    candidates.sort_by(|left, right| {
        right
            .host_path
            .components
            .len()
            .cmp(&left.host_path.components.len())
    });
    candidates.into_iter().next().ok_or_else(|| {
        Error::ArmRefused("host path has no authenticated logical-root binding".into())
    })
}

fn host_binding_matches(
    binding: &ArmedRootBinding,
    host_components: &[PathComponent],
    canonicalizers: &PathAliasCanonicalizers,
) -> Result<bool> {
    if binding.host_path.root != LogicalRoot::Absolute
        || binding.host_path.host_bound != Some(true)
        || host_components.len() < binding.host_path.components.len()
        || (binding.logical_root == LogicalRoot::Absolute
            && host_components.len() != binding.host_path.components.len())
    {
        return Ok(false);
    }
    let candidate_prefix = LogicalPath {
        root: LogicalRoot::Absolute,
        components: host_components[..binding.host_path.components.len()].to_vec(),
        host_bound: Some(true),
    };
    Ok(canonicalizers.canonicalize_volume_path(
        binding.object.platform,
        &binding.object.volume,
        &candidate_prefix,
    )? == canonicalizers.canonicalize_volume_path(
        binding.object.platform,
        &binding.object.volume,
        &binding.host_path,
    )?)
}

fn validate_package_binding_host_paths(
    bindings: &[ArmedRootBinding],
    canonicalizers: &PathAliasCanonicalizers,
) -> Result<()> {
    for (index, binding) in bindings
        .iter()
        .enumerate()
        .filter(|(_, binding)| binding.logical_root == LogicalRoot::Package)
    {
        for (other_index, other) in bindings.iter().enumerate() {
            if other_index == index
                || binding.object.platform != other.object.platform
                || binding.object.volume != other.object.volume
            {
                continue;
            }
            let binding_path = canonicalizers.canonicalize_volume_path(
                binding.object.platform,
                &binding.object.volume,
                &binding.host_path,
            )?;
            let other_path = canonicalizers.canonicalize_volume_path(
                other.object.platform,
                &other.object.volume,
                &other.host_path,
            )?;
            if binding_path == other_path {
                return refused(
                    "package root binding and another root binding share an authenticated host path",
                );
            }
        }
    }
    Ok(())
}

/// Package source is immutable in the armed profile. Derive every protected
/// package subtree from authenticated root bindings, projected through every
/// authenticated principal's own namespace. This covers nested package
/// layouts without enumerating descendant object identities.
fn derive_package_write_guards(
    bindings: &[ArmedRootBinding],
    principals: &[Principal],
    snapshot_digest: &Digest,
    canonicalizers: &PathAliasCanonicalizers,
) -> Result<Vec<BoundAuthority>> {
    validate_package_binding_host_paths(bindings, canonicalizers)?;
    for principal in principals.iter().filter(|principal| principal.is_package()) {
        if !bindings.iter().any(|binding| {
            binding.logical_root == LogicalRoot::Package
                && binding.owner.as_ref() == Some(principal)
        }) {
            return refused("authenticated package principal has no package root binding");
        }
    }

    let action = ActionId::new("fs:write").map_err(Error::InvalidModel)?;
    let mut guards = BTreeSet::new();

    for binding in bindings
        .iter()
        .filter(|binding| binding.logical_root == LogicalRoot::Package)
    {
        let owner = binding
            .owner
            .as_ref()
            .ok_or_else(|| Error::ArmRefused("package root binding is missing its owner".into()))?;
        if !owner.is_package() || !principals.contains(owner) {
            return refused("package root binding owner has no authenticated principal row");
        }
        let owner_view = logical_path_for_host_components_in_validated(
            bindings,
            owner,
            &binding.host_path.components,
            canonicalizers,
        )?;
        if owner_view.root != LogicalRoot::Package || !owner_view.components.is_empty() {
            return refused("package root binding does not project to its owner's package root");
        }

        for principal in principals {
            let Ok(path) = logical_path_for_host_components_in_validated(
                bindings,
                principal,
                &binding.host_path.components,
                canonicalizers,
            ) else {
                continue;
            };
            let package_root_owner = (path.root == LogicalRoot::Package).then(|| principal.clone());
            let path = canonicalizers.canonicalize_path(&path, package_root_owner.as_ref())?;
            guards.insert((
                AuthoritySelector {
                    action: action.clone(),
                    resource: SelectorResource::PathTree { path },
                },
                package_root_owner,
            ));
        }
    }

    guards
        .into_iter()
        .enumerate()
        .map(|(index, (selector, package_root_owner))| {
            Ok(BoundAuthority {
                source_id: NonEmptyString::new(format!("protected.package-tree.{index:06}"))
                    .map_err(Error::InvalidModel)?,
                selector,
                armed_snapshot_digest: snapshot_digest.clone(),
                package_root_owner,
            })
        })
        .collect()
}

fn bind_authorities(
    selectors: Vec<AuthoritySelector>,
    principal_index: usize,
    channel: &str,
    snapshot_digest: &Digest,
    package_owner: Option<&Principal>,
    canonicalizers: &PathAliasCanonicalizers,
) -> Result<Vec<BoundAuthority>> {
    selectors
        .into_iter()
        .enumerate()
        .map(|(authority_index, mut selector)| {
            let source_id = NonEmptyString::new(format!(
                "principal.{principal_index:06}.{channel}.{authority_index:06}"
            ))
            .map_err(Error::InvalidModel)?;
            let package_root_owner = selector
                .resource
                .contains_package_logical_root()
                .then(|| package_owner.cloned())
                .flatten();
            selector.resource = canonicalizers
                .canonicalize_selector(&selector.resource, package_root_owner.as_ref())?;
            Ok(BoundAuthority {
                source_id,
                selector,
                armed_snapshot_digest: snapshot_digest.clone(),
                package_root_owner,
            })
        })
        .collect()
}

fn bind_process_ceiling(
    selectors: Vec<AuthoritySelector>,
    snapshot_digest: &Digest,
    package_principals: &[Principal],
    canonicalizers: &PathAliasCanonicalizers,
) -> Result<Vec<BoundAuthority>> {
    let mut bound = Vec::new();
    for (selector_index, selector) in selectors.into_iter().enumerate() {
        if selector.resource.contains_package_logical_root() {
            for (owner_index, owner) in package_principals.iter().enumerate() {
                let mut selector = selector.clone();
                selector.resource =
                    canonicalizers.canonicalize_selector(&selector.resource, Some(owner))?;
                bound.push(BoundAuthority {
                    source_id: NonEmptyString::new(format!(
                        "process-ceiling.{selector_index:06}.{owner_index:06}"
                    ))
                    .map_err(Error::InvalidModel)?,
                    selector,
                    armed_snapshot_digest: snapshot_digest.clone(),
                    package_root_owner: Some(owner.clone()),
                });
            }
        } else {
            let mut selector = selector;
            selector.resource = canonicalizers.canonicalize_selector(&selector.resource, None)?;
            bound.push(BoundAuthority {
                source_id: NonEmptyString::new(format!(
                    "process-ceiling.{selector_index:06}.global"
                ))
                .map_err(Error::InvalidModel)?,
                selector,
                armed_snapshot_digest: snapshot_digest.clone(),
                package_root_owner: None,
            });
        }
    }
    Ok(bound)
}

fn bind_path_canonicalizers(
    rows: Vec<BoundVolumePathCanonicalizer>,
    root_bindings: &[ArmedRootBinding],
) -> Result<PathAliasCanonicalizers> {
    PathAliasCanonicalizers::bind(
        rows,
        root_bindings
            .iter()
            .map(|binding| PathCanonicalizerRootBinding {
                logical_root: binding.logical_root,
                owner: binding.owner.clone(),
                logical_path: binding.logical_path.clone(),
                host_path: binding.host_path.clone(),
                platform: binding.object.platform,
                volume: binding.object.volume.clone(),
            }),
    )
}

fn digest_field(value: &Value, field: &str) -> Result<Digest> {
    Digest::new(required_str(value, field)?).map_err(Error::InvalidModel)
}

fn require_sorted_unique_strings(values: &[String], label: &str) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return refused(format!("{label} must be sorted and unique"));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidModel(message.into())
}

fn refused<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::ArmRefused(message.into()))
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value> {
    path.iter().try_fold(value, |current, field| {
        current
            .get(field)
            .ok_or_else(|| invalid(format!("missing {}", path.join("."))))
    })
}

fn required_str(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("{field} must be a string")))
}

fn require_string(value: &Value, field: &str, expected: &str) -> Result<()> {
    if required_str(value, field)? != expected {
        return refused(format!(
            "{field} differs from the expected execution identity"
        ));
    }
    Ok(())
}

fn require_string_at(value: &Value, path: &[&str], expected: &str) -> Result<()> {
    if value_at(value, path)?.as_str() != Some(expected) {
        return refused(format!(
            "{} differs from the expected execution identity",
            path.join(".")
        ));
    }
    Ok(())
}

fn generation(value: &Value, field: &str) -> Result<Generation> {
    let raw = value_at(value, &["generations", field])?
        .as_u64()
        .ok_or_else(|| invalid(format!("generations.{field} must be an unsigned integer")))?;
    SafeUint::new(raw).map_err(Error::InvalidModel)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<u8>, ExpectedArmingIdentity) {
        let mut value: Value = serde_json::from_str(include_str!(
            "../../../capsec/examples/armed-snapshot.canonical.json"
        ))
        .unwrap();
        value["workflow"] = Value::String("production".into());
        value["effectiveMode"] = Value::String("enforce".into());
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &value).unwrap();
        value["armedSnapshotDigest"] = Value::String(digest);
        let digest_at =
            |path: &[&str]| Digest::new(value_at(&value, path).unwrap().as_str().unwrap()).unwrap();
        let protected_artifacts = value["protectedObjects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let role: ProtectedArtifactRole =
                    serde_json::from_value(row["role"].clone()).unwrap();
                let content_digest = match role {
                    ProtectedArtifactRole::EngineBinary => digest_at(&["engine", "binaryDigest"]),
                    ProtectedArtifactRole::ExactOperationManifest => {
                        digest_at(&["exactEmbedder", "operationManifestDigest"])
                    }
                    ProtectedArtifactRole::ArmedPolicy => digest_at(&["policyDigest"]),
                    ProtectedArtifactRole::PackageGraph => digest_at(&["packageGraph", "digest"]),
                    ProtectedArtifactRole::Registry => digest_at(&["registryDigest"]),
                };
                ExpectedProtectedArtifact {
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
            .collect();
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
                .map(|item| item.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            entry: serde_json::from_value(value["entry"].clone()).unwrap(),
            project_root_discovery: serde_json::from_value(value["projectRootDiscovery"].clone())
                .unwrap(),
            path_canonicalizers: serde_json::from_value(value["pathCanonicalizers"].clone())
                .unwrap(),
            protected_artifacts,
        };
        (serde_json::to_vec_pretty(&value).unwrap(), expected)
    }

    fn redigest(value: &mut Value) -> Vec<u8> {
        value["armedSnapshotDigest"] = Value::String(
            compute_checked_contract_digest(DigestKind::ArmedSnapshot, value).unwrap(),
        );
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn arms_exact_execution_identity_and_retains_immutable_document() {
        let (mut bytes, expected) = fixture();
        let armed = ArmedSnapshot::load(&bytes, &expected).unwrap();
        let loaded_digest = armed.digest().clone();
        bytes.fill(b'x');
        assert_eq!(armed.digest(), &loaded_digest);
        assert_eq!(armed.document()["capsVocab"], expected.profile);
        assert_eq!(armed.entry(), &expected.entry);
        assert_eq!(
            armed.project_root_discovery(),
            &expected.project_root_discovery
        );
    }

    #[test]
    fn refuses_entry_route_substitution_and_inconsistent_entry_tuples() {
        let (bytes, mut expected) = fixture();
        expected.entry = ArmedEntry {
            kind: ArmedEntryKind::Eval,
            identity: NonEmptyString::new("ibex:eval").unwrap(),
            mode: ArmedExecutionMode::OneShot,
        };
        let error = ArmedSnapshot::load(&bytes, &expected).unwrap_err();
        assert!(error
            .to_string()
            .contains("execution entry differs from the trusted arming identity"));

        let (bytes, mut expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["entry"] = serde_json::json!({
            "kind": "repl",
            "identity": "ibex:repl",
            "mode": "program"
        });
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &value).unwrap();
        value["armedSnapshotDigest"] = Value::String(digest.clone());
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();
        expected.entry = serde_json::from_value(value["entry"].clone()).unwrap();
        let error =
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap_err();
        assert!(error
            .to_string()
            .contains("armed entry kind, identity, and mode are inconsistent"));

        for identity in [
            "file:///project/../private.js",
            "file:///project/%2Fetc/passwd",
            "file:///project/%2fetc/passwd",
            "file:///project/%2Ehidden.js",
            "file:///project/trailing/",
            "file:///private/app.js",
        ] {
            let entry = ArmedEntry {
                kind: ArmedEntryKind::File,
                identity: NonEmptyString::new(identity).unwrap(),
                mode: ArmedExecutionMode::Program,
            };
            assert!(entry.validate().is_err(), "accepted {identity}");
        }
        for identity in [
            "file:///project/src/app.js",
            "file:///project/a%20b.js",
            "file:///project/%C3%A9.js",
        ] {
            let entry = ArmedEntry {
                kind: ArmedEntryKind::File,
                identity: NonEmptyString::new(identity).unwrap(),
                mode: ArmedExecutionMode::Program,
            };
            entry
                .validate()
                .unwrap_or_else(|_| panic!("refused {identity}"));
        }
    }

    #[test]
    fn refuses_project_root_discovery_substitution_and_binding_mismatch() {
        let (bytes, mut expected) = fixture();
        expected.project_root_discovery.marker_kind = ArmedProjectRootMarkerKind::ExplicitProject;
        let error = ArmedSnapshot::load(&bytes, &expected).unwrap_err();
        assert!(error
            .to_string()
            .contains("project-root discovery differs from the trusted arming identity"));

        let (bytes, mut expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["projectRootDiscovery"]["selectedRoot"]["components"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"encoding": "utf8", "value": "other"}));
        expected.project_root_discovery =
            serde_json::from_value(value["projectRootDiscovery"].clone()).unwrap();
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &value).unwrap();
        value["armedSnapshotDigest"] = Value::String(digest.clone());
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();
        let error =
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap_err();
        assert!(error
            .to_string()
            .contains("selection differs from the project binding"));

        let (bytes, mut expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["projectRootDiscovery"]["markerSetVersion"] =
            Value::String("ibex/project-root-markers/2".into());
        expected.project_root_discovery =
            serde_json::from_value(value["projectRootDiscovery"].clone()).unwrap();
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &value).unwrap();
        value["armedSnapshotDigest"] = Value::String(digest.clone());
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();
        let error =
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap_err();
        assert!(error
            .to_string()
            .contains("marker-set version is unsupported"));

        let (bytes, mut expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["projectRootDiscovery"]["markerKind"] = Value::String("lockfile".into());
        expected.project_root_discovery =
            serde_json::from_value(value["projectRootDiscovery"].clone()).unwrap();
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &value).unwrap();
        value["armedSnapshotDigest"] = Value::String(digest.clone());
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();
        let error =
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap_err();
        assert!(error
            .to_string()
            .contains("project-root discovery record is internally inconsistent"));
    }

    #[test]
    fn compartment_endowment_projection_keeps_delimiters_inside_the_locator() {
        let (bytes, mut expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let locator = "attacker@zz:fetch,Buffer;victim";

        value["principals"][0]["imports"]["packages"][0] = Value::String(locator.to_owned());
        value["principals"][1]["principal"]["locator"] = Value::String(locator.to_owned());
        value["principals"][1]["endowments"] = serde_json::json!(["process"]);
        value["packageGraph"]["nodes"][0]["principal"]["locator"] =
            Value::String(locator.to_owned());
        value["packageGraph"]["importEdges"][0]["imported"]["locator"] =
            Value::String(locator.to_owned());
        value["rootBindings"][0]["owner"]["locator"] = Value::String(locator.to_owned());

        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &value).unwrap();
        value["armedSnapshotDigest"] = Value::String(digest.clone());
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();
        let armed = ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap();

        let projection: Value =
            serde_json::from_str(&armed.compartment_endowments_json().unwrap()).unwrap();
        assert_eq!(
            projection,
            serde_json::json!([{
                "locator": locator,
                "endowments": ["process"],
            }])
        );
    }

    #[test]
    fn maps_host_paths_through_exact_authenticated_root_bindings() {
        let (bytes, expected) = fixture();
        let armed = ArmedSnapshot::load(&bytes, &expected).unwrap();
        let root: Principal = serde_json::from_value(serde_json::json!({
            "kind": "root",
            "identity": "project-root"
        }))
        .unwrap();
        let package: Principal = serde_json::from_value(serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
            "locator": "image-lib@2.4.1"
        }))
        .unwrap();
        let component = |value: &str| PathComponent::utf8(value).unwrap();

        let project = armed
            .logical_path_for_host_components(
                &root,
                &[
                    component("Users"),
                    component("example"),
                    component("project"),
                    component("config.json"),
                ],
            )
            .unwrap();
        assert_eq!(project.root, LogicalRoot::Project);
        assert_eq!(project.components, vec![component("config.json")]);

        let package_path = [
            component("Users"),
            component("example"),
            component("project"),
            component("node_modules"),
            component("image-lib"),
            component("photo.jpg"),
        ];
        let mapped = armed
            .logical_path_for_host_components(&package, &package_path)
            .unwrap();
        assert_eq!(mapped.root, LogicalRoot::Package);
        assert_eq!(mapped.components, vec![component("photo.jpg")]);
        let root_view = armed
            .logical_path_for_host_components(&root, &package_path)
            .unwrap();
        assert_eq!(root_view.root, LogicalRoot::Project);

        assert!(armed
            .logical_path_for_host_components(&root, &[component("etc"), component("passwd")],)
            .is_err());
    }

    #[test]
    fn package_binding_prefix_is_selected_in_its_volume_alias_coordinate() {
        let (bytes, mut expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["rootBindings"][0]["hostPath"]["components"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["value"] = Value::String("Caf\u{e9}-lib".into());
        let bytes = redigest(&mut value);
        expected.armed_snapshot_digest =
            Digest::new(value["armedSnapshotDigest"].as_str().unwrap()).unwrap();
        let armed = ArmedSnapshot::load(&bytes, &expected).unwrap();
        let package: Principal =
            serde_json::from_value(value["principals"][1]["principal"].clone()).unwrap();
        let component = |value: &str| PathComponent::utf8(value).unwrap();
        let mapped = armed
            .logical_path_for_host_components(
                &package,
                &[
                    component("Users"),
                    component("example"),
                    component("project"),
                    component("node_modules"),
                    component("CAFE\u{301}-LIB"),
                    component("photo.jpg"),
                ],
            )
            .unwrap();
        assert_eq!(mapped.root, LogicalRoot::Package);
        assert_eq!(mapped.components, vec![component("photo.jpg")]);
    }

    #[test]
    fn decodes_typed_authority_without_reconstructing_legacy_strings() {
        let (bytes, expected) = fixture();
        let armed = ArmedSnapshot::load(&bytes, &expected).unwrap();
        let identity = armed.semantic_identity().unwrap();
        assert_eq!(identity.armed_snapshot_digest, armed.digest().clone());
        assert_eq!(identity.policy_digest, expected.policy_digest);

        let authority = armed.authority_state().unwrap();
        assert_eq!(authority.principal_policies.len(), 2);
        assert_eq!(authority.protected_objects.len(), 4);
        assert_eq!(authority.generations.negative.get(), 0);
        let package = authority
            .principal_policies
            .iter()
            .find(|(principal, _)| principal.is_package())
            .map(|(_, policy)| policy)
            .unwrap();
        assert_eq!(package.static_floor.len(), 1);
        assert_eq!(package.static_floor[0].selector.action.as_str(), "fs:read");
        assert!(package.static_floor[0].package_root_owner.is_none());
        assert!(matches!(
            &*authority.process_ceiling,
            AuthorityCeiling::Unbounded
        ));
        let imports = armed.import_policies().unwrap();
        let package_imports = imports
            .iter()
            .find(|(principal, _)| principal.is_package())
            .map(|(_, policy)| policy)
            .unwrap();
        assert_eq!(package_imports.builtins, ["node:fs"]);
        assert!(package_imports.packages.is_empty());

        let profile = crate::registry::ValidatedProfile::from_json(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../capsec/registry/capability-definitions.json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../capsec/registry/policy-rules.json"
            )),
        )
        .unwrap();
        let refused = armed
            .decision_context(profile.definitions.clone(), TargetArmState::Incomplete)
            .unwrap_err();
        assert!(matches!(refused, Error::ArmRefused(_)));
        let context = armed
            .decision_context(profile.definitions, TargetArmState::CompleteAdvertised)
            .unwrap();
        assert_eq!(context.identity(), &identity);
    }

    #[test]
    fn authored_denial_and_grant_share_case_and_nfd_occurrence_identity() {
        use crate::cache::{DecisionCacheKey, PositiveAuthorityContext};
        use crate::decision::{
            evaluate_decision_set, DecisionOutcome, DecisionReason, EffectGate,
            TargetCellDisposition, Workflow,
        };
        use crate::model::{
            DecisionContext, DecisionSet, DecisionSetSchema, Effect, EffectCombination, FollowMode,
            ObjectState, OccurrenceResource, StableId, Stage,
        };

        let (bytes, mut expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let authored = serde_json::json!({
            "resource": {
                "kind": "path-exact",
                "path": {
                    "root": "project",
                    "components": [{"encoding": "utf8", "value": "Caf\u{00e9}"}]
                }
            }
        });
        let mut grant = authored.clone();
        grant["cap"] = Value::String("fs:read".into());
        let mut denial = authored;
        denial["cap"] = Value::String("fs:write".into());
        value["principals"][1]["floor"] = serde_json::json!([grant]);
        value["principals"][1]["denials"] = serde_json::json!([denial]);
        let bytes = redigest(&mut value);
        expected.armed_snapshot_digest =
            Digest::new(value["armedSnapshotDigest"].as_str().unwrap()).unwrap();
        let armed = ArmedSnapshot::load(&bytes, &expected).unwrap();
        let profile = crate::registry::ValidatedProfile::from_json(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../capsec/registry/capability-definitions.json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../capsec/registry/policy-rules.json"
            )),
        )
        .unwrap();
        let context = armed
            .decision_context(profile.definitions, TargetArmState::CompleteAdvertised)
            .unwrap();
        let principal: Principal =
            serde_json::from_value(value["principals"][1]["principal"].clone()).unwrap();

        let decide = |action: &str, spelling: &str| {
            let occurrence = OccurrenceResource::PathOccurrence {
                requested: LogicalPath {
                    root: LogicalRoot::Project,
                    components: vec![PathComponent::utf8(spelling).unwrap()],
                    host_bound: None,
                },
                follow_mode: FollowMode::FollowFinal,
                object_state: ObjectState::Unknown,
                parent_object: None,
                final_object: None,
                final_object_generation: None,
                retained_handle: None,
            };
            let set = DecisionSet {
                decision_set_schema: DecisionSetSchema::V1,
                operation_id: NonEmptyString::new(format!("alias-{action}-{spelling}")).unwrap(),
                atomicity_group: StableId::new("alias-canonicalization-test").unwrap(),
                combination: EffectCombination::Conjunction,
                context: DecisionContext {
                    stage: Stage::Requested,
                    actor: principal.clone(),
                    constrained_principals: vec![principal.clone()],
                    presented_handle_ids: vec![],
                },
                effects: vec![Effect {
                    action: ActionId::new(action).unwrap(),
                    effect_owner: principal.clone(),
                    resource: occurrence,
                }],
            };
            let decision = evaluate_decision_set(
                &context,
                &set,
                &[EffectGate {
                    coverage_edge_id: StableId::new("alias-canonicalization-edge").unwrap(),
                    target_cell: TargetCellDisposition::Complete,
                    definition_and_edge_predicates_satisfied: true,
                }],
                Workflow::ProductionEnforce,
                &|_| Some(crate::model::PeerClass::Public),
            )
            .unwrap();
            (set, decision)
        };

        for spelling in ["CAF\u{c9}", "Cafe\u{301}"] {
            let (_, grant) = decide("fs:read", spelling);
            assert_eq!(grant.outcome, DecisionOutcome::Allow);
            assert_eq!(grant.evidence[0].reason, DecisionReason::StaticFloor);

            let (_, denial) = decide("fs:write", spelling);
            assert_eq!(denial.outcome, DecisionOutcome::Deny);
            assert_eq!(denial.evidence[0].reason, DecisionReason::PrincipalDenial);
        }

        // The cache consumes the same post-canonicalization resource bytes as
        // the matcher, even though the two display spellings remain distinct.
        let (composed, _) = decide("fs:read", "CAF\u{c9}");
        let (decomposed, _) = decide("fs:read", "Cafe\u{301}");
        let cache_context = || PositiveAuthorityContext {
            coverage_edge_id: StableId::new("alias-canonicalization-edge").unwrap(),
            handle_ids: vec![],
            dynamic_grant_ids: vec![],
            operation_lease_ids: vec![],
        };
        let composed = DecisionCacheKey::new(
            &context,
            &composed.occurrences()[0],
            &principal,
            cache_context(),
        )
        .unwrap();
        let decomposed = DecisionCacheKey::new(
            &context,
            &decomposed.occurrences()[0],
            &principal,
            cache_context(),
        )
        .unwrap();
        assert_eq!(
            composed.resource_canonical_bytes,
            decomposed.resource_canonical_bytes
        );
    }

    #[test]
    fn canonicalizer_identity_is_trusted_and_changes_snapshot_identity() {
        let (bytes, expected) = fixture();
        let original = ArmedSnapshot::load(&bytes, &expected).unwrap();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["pathCanonicalizers"][0]["identity"] =
            Value::String("apple-apfs-unicode9-nfd-v1".into());
        let changed_bytes = redigest(&mut value);

        let stale = ArmedSnapshot::load(&changed_bytes, &expected).unwrap_err();
        assert!(stale.to_string().contains("armed snapshot digest differs"));

        let mut changed_expected = expected;
        changed_expected.armed_snapshot_digest =
            Digest::new(value["armedSnapshotDigest"].as_str().unwrap()).unwrap();
        changed_expected.path_canonicalizers =
            serde_json::from_value(value["pathCanonicalizers"].clone()).unwrap();
        let changed = ArmedSnapshot::load(&changed_bytes, &changed_expected).unwrap();
        assert_ne!(original.digest(), changed.digest());
        assert_ne!(
            original.path_canonicalizers().rows(),
            changed.path_canonicalizers().rows()
        );
    }

    #[test]
    fn binds_package_root_process_ceiling_for_each_package_principal() {
        let (bytes, mut expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["processAuthorityCeiling"] = serde_json::json!({
            "kind": "bounded",
            "authorities": [{
                "cap": "fs:read",
                "resource": {
                    "kind": "path-tree",
                    "path": {"root": "package", "components": []}
                }
            }]
        });
        let mut second = value["principals"][1].clone();
        let second_principal = serde_json::json!({
            "kind": "package",
            "name": "other-lib",
            "integrity": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "locator": "other-lib@1.0.0"
        });
        second["principal"] = second_principal.clone();
        value["principals"].as_array_mut().unwrap().push(second);
        value["principals"][0]["imports"]["packages"] =
            serde_json::json!(["image-lib@2.4.1", "other-lib@1.0.0"]);
        value["packageGraph"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"principal": second_principal.clone()}));
        let root_identity = value["rootIdentity"].clone();
        value["packageGraph"]["importEdges"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "importer": root_identity,
                "imported": second_principal.clone(),
            }));
        let mut second_binding = value["rootBindings"][0].clone();
        second_binding["owner"] = second_principal;
        second_binding["hostPath"]["components"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["value"] = Value::String("other-lib".into());
        second_binding["object"]["file"] = Value::String("file-201".into());
        value["rootBindings"]
            .as_array_mut()
            .unwrap()
            .push(second_binding);
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &value).unwrap();
        value["armedSnapshotDigest"] = Value::String(digest.clone());
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();
        let snapshot =
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap();
        let authority = snapshot.authority_state().unwrap();
        let AuthorityCeiling::Bounded(rows) = &*authority.process_ceiling else {
            panic!("expected bounded process ceiling");
        };
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row
            .package_root_owner
            .as_ref()
            .is_some_and(Principal::is_package)));
        assert_ne!(rows[0].package_root_owner, rows[1].package_root_owner);
    }

    #[test]
    fn refuses_tamper_stale_identity_target_graph_and_incomplete_cell() {
        let (bytes, expected) = fixture();
        let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
        tampered["runNonce"] = Value::String("changed".into());
        assert!(ArmedSnapshot::load(&serde_json::to_vec(&tampered).unwrap(), &expected).is_err());

        let mut wrong_policy = expected.clone();
        wrong_policy.policy_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert!(ArmedSnapshot::load(&bytes, &wrong_policy).is_err());

        let mut wrong_target = expected.clone();
        wrong_target.target = "wrong-unknown-target".into();
        assert!(ArmedSnapshot::load(&bytes, &wrong_target).is_err());

        let mut wrong_graph = expected.clone();
        wrong_graph.package_graph_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert!(ArmedSnapshot::load(&bytes, &wrong_graph).is_err());
    }

    #[test]
    fn refuses_missing_or_duplicate_protected_artifacts() {
        let (bytes, expected) = fixture();
        let mut missing: Value = serde_json::from_slice(&bytes).unwrap();
        missing["protectedObjects"].as_array_mut().unwrap().pop();
        missing["armedSnapshotDigest"] = Value::String(
            compute_checked_contract_digest(DigestKind::ArmedSnapshot, &missing).unwrap(),
        );
        assert!(ArmedSnapshot::load(&serde_json::to_vec(&missing).unwrap(), &expected).is_err());

        let mut duplicate: Value = serde_json::from_slice(&bytes).unwrap();
        duplicate["protectedObjects"][1]["object"] =
            duplicate["protectedObjects"][0]["object"].clone();
        duplicate["armedSnapshotDigest"] = Value::String(
            compute_checked_contract_digest(DigestKind::ArmedSnapshot, &duplicate).unwrap(),
        );
        assert!(ArmedSnapshot::load(&serde_json::to_vec(&duplicate).unwrap(), &expected).is_err());
    }

    #[test]
    fn authenticates_exact_operation_manifest_and_endowment_projection() {
        let (bytes, mut expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let manifest_digest =
            Digest::new("sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA").unwrap();
        value["exactEmbedder"] = serde_json::json!({
            "schema": "exact/host-operation-endowments/1",
            "operationManifestDigest": manifest_digest,
            "endowments": {
                "app": [7, 11],
                "agentIsolate": [19],
                "uiWorklet": [],
            }
        });
        let object = serde_json::json!({
            "platform": "unix",
            "volume": "fixture-volume",
            "file": "exact-operation-manifest"
        });
        value["protectedObjects"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "role": "exact-operation-manifest",
                "object": object,
                "deniedActions": ["fs:write"]
            }));
        expected
            .protected_artifacts
            .push(ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::ExactOperationManifest,
                host_path: serde_json::from_value(serde_json::json!({
                    "root": "absolute",
                    "components": [
                        {"encoding": "utf8", "value": "fixture"},
                        {"encoding": "utf8", "value": "exact-operation-manifest"}
                    ],
                    "hostBound": true
                }))
                .unwrap(),
                object: serde_json::from_value(object).unwrap(),
                content_digest: manifest_digest.clone(),
            });
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &value).unwrap();
        value["armedSnapshotDigest"] = Value::String(digest.clone());
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();

        let armed = ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap();
        let binding = armed.exact_embedder_binding().unwrap().unwrap();
        assert_eq!(binding.operation_manifest_digest, manifest_digest);
        assert_eq!(binding.endowments.app, [7, 11]);
        assert_eq!(binding.endowments.agent_isolate, [19]);
        assert!(binding.endowments.ui_worklet.is_empty());

        let mut wrong_manifest = expected;
        wrong_manifest
            .protected_artifacts
            .iter_mut()
            .find(|artifact| artifact.role == ProtectedArtifactRole::ExactOperationManifest)
            .unwrap()
            .content_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert!(
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &wrong_manifest)
                .unwrap_err()
                .to_string()
                .contains("manifest digest differs")
        );
    }

    #[test]
    fn refuses_protected_role_object_mismatch_against_launcher_identity() {
        let (bytes, mut expected) = fixture();
        let first = expected.protected_artifacts[0].object.clone();
        expected.protected_artifacts[0].object = expected.protected_artifacts[1].object.clone();
        expected.protected_artifacts[1].object = first;

        assert!(matches!(
            ArmedSnapshot::load(&bytes, &expected),
            Err(Error::ArmRefused(message))
                if message.contains("independently authenticated artifact role")
        ));
    }

    #[test]
    fn refuses_self_consistent_snapshot_mutation_without_trusted_digest_update() {
        let (bytes, expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["runNonce"] = Value::String("attacker-recomputed-snapshot".into());
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &value).unwrap();
        value["armedSnapshotDigest"] = Value::String(digest);

        assert!(matches!(
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected),
            Err(Error::ArmRefused(message))
                if message.contains("trusted arming identity")
        ));
    }

    #[test]
    fn contract_digest_canonicalizes_declared_snapshot_sets() {
        let (bytes, expected) = fixture();
        let original: Value = serde_json::from_slice(&bytes).unwrap();
        let mut permuted = original.clone();
        permuted["principals"].as_array_mut().unwrap().reverse();
        permuted["protectedObjects"]
            .as_array_mut()
            .unwrap()
            .reverse();
        permuted["rootBindings"].as_array_mut().unwrap().reverse();

        assert_eq!(
            compute_checked_contract_digest(DigestKind::ArmedSnapshot, &original).unwrap(),
            compute_checked_contract_digest(DigestKind::ArmedSnapshot, &permuted).unwrap(),
        );
        let permuted_bytes = redigest(&mut permuted);
        assert!(ArmedSnapshot::load(&permuted_bytes, &expected).is_ok());
    }

    #[test]
    fn refuses_graph_authority_and_root_binding_inconsistencies() {
        let (bytes, expected) = fixture();

        let mut missing_edge: Value = serde_json::from_slice(&bytes).unwrap();
        missing_edge["packageGraph"]["importEdges"] = Value::Array(Vec::new());
        assert!(ArmedSnapshot::load(&redigest(&mut missing_edge), &expected).is_err());

        let mut duplicate_authority: Value = serde_json::from_slice(&bytes).unwrap();
        let duplicate = duplicate_authority["principals"][1].clone();
        duplicate_authority["principals"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(ArmedSnapshot::load(&redigest(&mut duplicate_authority), &expected).is_err());

        let mut ambiguous_object: Value = serde_json::from_slice(&bytes).unwrap();
        ambiguous_object["rootBindings"][0]["object"] =
            ambiguous_object["rootBindings"][1]["object"].clone();
        assert!(ArmedSnapshot::load(&redigest(&mut ambiguous_object), &expected).is_err());

        let mut wrong_package_owner: Value = serde_json::from_slice(&bytes).unwrap();
        wrong_package_owner["rootBindings"][0]["owner"] =
            wrong_package_owner["rootIdentity"].clone();
        assert!(ArmedSnapshot::load(&redigest(&mut wrong_package_owner), &expected).is_err());
    }

    #[test]
    fn rejects_duplicate_keys_before_identity_checks() {
        let (_, expected) = fixture();
        let bytes =
            br#"{"snapshotSchema":"ibex/capsec-armed/1","snapshotSchema":"ibex/capsec-armed/1"}"#;
        assert!(matches!(
            ArmedSnapshot::load(bytes, &expected),
            Err(Error::DuplicateKey { .. })
        ));
    }
}
