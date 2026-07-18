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
use crate::registry::DefinitionSet;
use crate::strict_json::parse_strict;
use crate::{Error, Result};

pub const ARMED_SNAPSHOT_SCHEMA: &str = "ibex/capsec-armed/1";
pub const ARMING_ABI: &str = "ibex-capsec-arming-2-root-ceiling-embedded-ranges-bootstrap-seal";

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
    /// Independently authenticated artifact paths, object identities, and
    /// content hashes. The snapshot's role labels are accepted only when they
    /// exactly match this launcher-supplied set.
    pub protected_artifacts: Vec<ExpectedProtectedArtifact>,
    /// Envelope sections authenticated from the already pinned executable.
    /// These have no host path; identity is the mapped object plus byte range,
    /// semantic role, and section digest.
    pub embedded_protected_artifacts: Vec<ExpectedEmbeddedProtectedArtifact>,
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmbeddedByteRange {
    pub offset: SafeUint,
    pub length: SafeUint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedEmbeddedProtectedArtifact {
    pub role: ProtectedArtifactRole,
    pub executable_object: ObjectIdentity,
    pub range: EmbeddedByteRange,
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
    root_bindings: Arc<[ArmedRootBinding]>,
    module_edges: Arc<[SnapshotImportEdge]>,
    protected_artifacts: Arc<[ExpectedProtectedArtifact]>,
    embedded_protected_artifacts: Arc<[ExpectedEmbeddedProtectedArtifact]>,
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
        require_string(&document, "snapshotSchema", ARMED_SNAPSHOT_SCHEMA)?;
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
        validate_snapshot_invariants(&document)?;
        validate_expected_protected_artifacts(&document, expected)?;
        let root_bindings: Vec<ArmedRootBinding> =
            serde_json::from_value(value_at(&document, &["rootBindings"])?.clone())
                .map_err(|error| invalid(format!("invalid armed root bindings: {error}")))?;
        let graph: SnapshotPackageGraph =
            serde_json::from_value(value_at(&document, &["packageGraph"])?.clone())
                .map_err(|error| invalid(format!("invalid package graph: {error}")))?;
        Ok(Self {
            document: Arc::new(document),
            root_bindings: root_bindings.into(),
            module_edges: graph.import_edges.into(),
            protected_artifacts: expected.protected_artifacts.clone().into(),
            embedded_protected_artifacts: expected.embedded_protected_artifacts.clone().into(),
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

    pub fn engine_target(&self) -> Result<String> {
        value_at(&self.document, &["engine", "target"])?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("engine.target must be a string"))
    }

    /// Exact digest-bound module edge lookup. Callers provide the authored
    /// request plus resolution semantics; a bare package allowlist projection
    /// is never sufficient for source acquisition.
    /// @ref LLP 0023#12-package-bindings-are-derived-from-the-graph-and-contained-in-the-project
    pub fn authenticates_module_edge(
        &self,
        importer: &Principal,
        request_specifier: &str,
        imported: &Principal,
        resolution_kind: &str,
        conditions: &[String],
        attributes: &BTreeMap<String, String>,
    ) -> bool {
        self.module_edges.iter().any(|edge| {
            edge.importer == *importer
                && edge.imported == *imported
                && edge
                    .request_specifier
                    .as_ref()
                    .is_some_and(|request| request.as_str() == request_specifier)
                && edge
                    .resolution_kind
                    .is_some_and(|kind| kind.as_str() == resolution_kind)
                && edge.conditions.as_ref().is_some_and(|edge_conditions| {
                    edge_conditions
                        .iter()
                        .map(|condition| condition.as_str().to_owned())
                        .eq(conditions.iter().cloned())
                })
                && edge.attributes.as_ref() == Some(attributes)
        })
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

    /// Exact launcher-authenticated artifact identities backing the snapshot's
    /// mandatory protected-object guards. The Host reopens these paths and
    /// checks both object identity and content digest before runtime creation.
    pub fn protected_artifacts(&self) -> &[ExpectedProtectedArtifact] {
        &self.protected_artifacts
    }

    /// Authenticated sections residing in the pinned mapped executable. The
    /// caller establishes these facts from envelope admission before loading
    /// the snapshot; no pathname materialization is permitted.
    pub fn embedded_protected_artifacts(&self) -> &[ExpectedEmbeddedProtectedArtifact] {
        &self.embedded_protected_artifacts
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
        logical_path_for_host_components_in(self.root_bindings()?, principal, host_components)
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
        validate_package_binding_host_paths(bindings)?;
        principals
            .iter()
            .map(|principal| {
                Ok((
                    principal.clone(),
                    logical_path_for_host_components_in_validated(
                        bindings,
                        principal,
                        host_components,
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
        root_binding_for_host_components_in(self.root_bindings()?, principal, host_components)
    }

    /// Resolve the owner of the most-specific root binding without trusting a
    /// caller-supplied principal. Package bindings win over their enclosing
    /// project binding; non-package paths are represented by `None` (root).
    pub fn owner_for_host_components(
        &self,
        host_components: &[PathComponent],
    ) -> Result<Option<Principal>> {
        let mut candidates = self
            .root_bindings()?
            .iter()
            .filter(|binding| host_binding_matches(binding, host_components))
            .collect::<Vec<_>>();
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
            )?;
            let denials = bind_authorities(
                row.denials,
                principal_index,
                "denial",
                self.digest(),
                package_owner.as_ref(),
            )?;
            let escalation_ceiling = AuthorityCeiling::Bounded(bind_authorities(
                row.escalation_ceiling,
                principal_index,
                "ceiling",
                self.digest(),
                package_owner.as_ref(),
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
                    })
            })
            .collect::<Vec<_>>();
        protected_objects.sort();
        // Multiple authenticated envelope ranges share the mapped executable
        // object; one fs:write guard protects that object for every role.
        protected_objects.dedup();
        let protected_resources =
            derive_package_write_guards(self.root_bindings()?, &principals, self.digest())?;

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
                )?)
            }
            _ => return Err(invalid("processAuthorityCeiling.kind is invalid")),
        };
        let root_ceiling = match value_at(&self.document, &["rootAuthorityCeiling"])?
            .get("kind")
            .and_then(Value::as_str)
        {
            Some("unbounded") => AuthorityCeiling::Unbounded,
            Some("bounded") => {
                let selectors: Vec<AuthoritySelector> = serde_json::from_value(
                    value_at(&self.document, &["rootAuthorityCeiling", "authorities"])?.clone(),
                )
                .map_err(|error| invalid(format!("invalid root authority ceiling: {error}")))?;
                AuthorityCeiling::Bounded(bind_root_ceiling(selectors, self.digest())?)
            }
            _ => return Err(invalid("rootAuthorityCeiling.kind is invalid")),
        };
        let bootstrap_floor: Vec<AuthoritySelector> =
            serde_json::from_value(value_at(&self.document, &["bootstrapAuthorityFloor"])?.clone())
                .map_err(|error| invalid(format!("invalid bootstrap authority floor: {error}")))?;
        let bootstrap_floor = bind_bootstrap_floor(bootstrap_floor, self.digest())?;

        Ok(DecisionAuthorityState {
            generations: GenerationSet {
                negative: self.generations.negative,
                dynamic: self.generations.dynamic,
                handle: self.generations.handle,
            },
            process_ceiling: process_ceiling.into(),
            root_ceiling: root_ceiling.into(),
            bootstrap_floor: bootstrap_floor.into(),
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
    /// snapshot and a validated product definition set.
    pub fn decision_context(&self, definitions: DefinitionSet) -> Result<VerifiedDecisionContext> {
        let identity = self.semantic_identity()?;
        VerifiedDecisionContext::arm(
            ArmInputs {
                expected_identity: identity.clone(),
                loaded_identity: identity,
                target: TargetArmState::CompleteAdvertised,
                structure_valid: true,
            },
            definitions,
            self.authority_state()?,
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
    #[serde(default)]
    embedded_range: Option<EmbeddedByteRange>,
    #[serde(default)]
    content_digest: Option<Digest>,
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotGraphNode {
    principal: Principal,
    #[serde(default)]
    resolving_specifier: Option<NonEmptyString>,
    #[serde(default)]
    root_object: Option<ObjectIdentity>,
    #[serde(default)]
    virtual_aliases: Option<Vec<LogicalPath>>,
    #[serde(default)]
    platform_disposition: Option<SnapshotPlatformDisposition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotImportEdge {
    importer: Principal,
    imported: Principal,
    #[serde(default)]
    request_specifier: Option<NonEmptyString>,
    #[serde(default)]
    resolution_kind: Option<SnapshotResolutionKind>,
    #[serde(default)]
    conditions: Option<Vec<NonEmptyString>>,
    #[serde(default)]
    attributes: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SnapshotPlatformDisposition {
    Required,
    OptionalPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SnapshotResolutionKind {
    EsmStatic,
    DynamicImport,
    CommonJsRequire,
}

impl SnapshotResolutionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::EsmStatic => "esm-static",
            Self::DynamicImport => "dynamic-import",
            Self::CommonJsRequire => "common-js-require",
        }
    }
}

fn validate_snapshot_invariants(document: &Value) -> Result<()> {
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
    let production_graph = document.get("workflow").and_then(Value::as_str) == Some("production");
    let mut graph_nodes = BTreeSet::new();
    let mut nodes_by_locator = BTreeMap::new();
    let mut graph_locations = BTreeMap::new();
    for node in graph.nodes {
        let Principal::Package { locator, .. } = &node.principal else {
            return refused("package graph contains a non-package node");
        };
        if production_graph {
            let resolving_specifier = node.resolving_specifier.as_ref().ok_or_else(|| {
                Error::ArmRefused("production package graph node has no resolving specifier".into())
            })?;
            let root_object = node.root_object.as_ref().ok_or_else(|| {
                Error::ArmRefused(
                    "production package graph node has no canonical root object".into(),
                )
            })?;
            let aliases = node.virtual_aliases.as_ref().ok_or_else(|| {
                Error::ArmRefused("production package graph node has no virtual alias set".into())
            })?;
            if aliases.is_empty()
                || aliases.iter().any(|alias| {
                    !alias.is_canonical()
                        || !matches!(alias.root, LogicalRoot::Project | LogicalRoot::Package)
                })
                || aliases.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return refused(
                    "production package graph virtual aliases must be sorted unique canonical project/package paths",
                );
            }
            if node.platform_disposition.is_none() {
                return refused("production package graph node has no platform disposition");
            }
            graph_locations.insert(
                node.principal.clone(),
                (
                    resolving_specifier.as_str().to_owned(),
                    root_object.clone(),
                    aliases.clone(),
                ),
            );
        }
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
    let mut graph_edge_records = BTreeSet::new();
    for edge in graph.import_edges {
        if production_graph {
            let request = edge.request_specifier.as_ref().ok_or_else(|| {
                Error::ArmRefused("production import edge has no request specifier".into())
            })?;
            let kind = edge.resolution_kind.ok_or_else(|| {
                Error::ArmRefused("production import edge has no resolution kind".into())
            })?;
            let conditions = edge.conditions.as_ref().ok_or_else(|| {
                Error::ArmRefused("production import edge has no condition set".into())
            })?;
            let attributes = edge.attributes.as_ref().ok_or_else(|| {
                Error::ArmRefused("production import edge has no import attributes".into())
            })?;
            let condition_names = conditions
                .iter()
                .map(NonEmptyString::as_str)
                .collect::<Vec<_>>();
            if condition_names.windows(2).any(|pair| pair[0] >= pair[1])
                || condition_names.contains(&"default")
                || !condition_names.contains(&"node")
            {
                return refused(
                    "production import edge conditions must be sorted unique, include node, and exclude default",
                );
            }
            let branch_is_valid = match kind {
                SnapshotResolutionKind::CommonJsRequire => {
                    condition_names.contains(&"require") && !condition_names.contains(&"import")
                }
                SnapshotResolutionKind::EsmStatic | SnapshotResolutionKind::DynamicImport => {
                    condition_names.contains(&"import") && !condition_names.contains(&"require")
                }
            };
            if !branch_is_valid {
                return refused("production import edge conditions disagree with resolution kind");
            }
            if attributes
                .iter()
                .any(|(key, value)| key != "type" || value != "json")
            {
                return refused("production import edge has unsupported import attributes");
            }
            if !edge.imported.is_package() || request.as_str().trim() != request.as_str() {
                return refused("production import edge request or target is invalid");
            }
            let record = crate::canonical::to_jcs_bytes(
                &serde_json::to_value(&edge)
                    .map_err(|error| invalid(format!("invalid import edge: {error}")))?,
            )?;
            if !graph_edge_records.insert(record) {
                return refused("package graph contains a duplicate typed import edge");
            }
        }
        if !authorities.contains_key(&edge.importer) || !graph_nodes.contains(&edge.imported) {
            return refused("package graph contains an unbound import edge");
        }
        graph_edges.insert((edge.importer, edge.imported));
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
    validate_root_bindings(&bindings, &graph_nodes, &graph_locations, production_graph)?;
    Ok(())
}

fn validate_root_bindings(
    bindings: &[ArmedRootBinding],
    graph_nodes: &BTreeSet<Principal>,
    graph_locations: &BTreeMap<Principal, (String, ObjectIdentity, Vec<LogicalPath>)>,
    production_graph: bool,
) -> Result<()> {
    if bindings.is_empty() {
        return refused("armed snapshot has no root bindings");
    }
    let mut host_paths = BTreeSet::new();
    let mut logical_keys = BTreeSet::new();
    let mut objects = BTreeSet::new();
    let mut package_binding_counts = BTreeMap::<Principal, usize>::new();
    let mut package_host_paths = BTreeMap::<Principal, Vec<PathComponent>>::new();
    let mut project_bindings = 0usize;
    let mut project_host_path = None;
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
                package_host_paths.insert(owner.clone(), binding.host_path.components.clone());
                if production_graph {
                    let (_, root_object, aliases) =
                        graph_locations.get(owner).ok_or_else(|| {
                            Error::ArmRefused(
                                "package binding owner has no authenticated graph location".into(),
                            )
                        })?;
                    if &binding.object != root_object {
                        return refused(
                            "package binding object differs from its digest-bound graph location",
                        );
                    }
                    if let Some(logical_path) = binding.logical_path.as_ref() {
                        if !aliases.contains(logical_path) {
                            return refused(
                                "package binding logical path is absent from its graph alias set",
                            );
                        }
                    }
                }
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
                project_host_path = Some(binding.host_path.components.clone());
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
    if production_graph {
        let project = project_host_path
            .as_deref()
            .ok_or_else(|| Error::ArmRefused("production graph has no project binding".into()))?;
        for (principal, package) in package_host_paths {
            let relative = package.strip_prefix(project).ok_or_else(|| {
                Error::ArmRefused(
                    "production package graph root is outside the project binding".into(),
                )
            })?;
            if relative.is_empty() {
                return refused("production package graph root equals the project binding");
            }
            let alias = LogicalPath {
                root: LogicalRoot::Project,
                components: relative.to_vec(),
                host_bound: None,
            };
            let (_, _, aliases) = graph_locations.get(&principal).ok_or_else(|| {
                Error::ArmRefused("production package binding has no graph location".into())
            })?;
            if aliases.as_slice() != [alias] {
                return refused(
                    "production package graph aliases must exactly name the project-relative root",
                );
            }
        }
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
    let mut host_objects = BTreeSet::new();
    let mut embedded_ranges = Vec::new();
    for row in rows {
        if row.denied_actions.len() != 1 || row.denied_actions[0].as_str() != "fs:write" {
            return refused("every protected artifact must deny exactly fs:write");
        }
        roles.push(row.role);
        match (row.embedded_range, row.content_digest) {
            (None, None) => {
                if !host_objects.insert(row.object) {
                    return refused("host protected artifacts must have distinct objects");
                }
            }
            (Some(range), Some(digest)) => {
                if range.length == SafeUint::ZERO
                    || range
                        .offset
                        .get()
                        .checked_add(range.length.get())
                        .and_then(|end| SafeUint::new(end).ok())
                        .is_none()
                {
                    return refused("embedded protected artifact range is invalid");
                }
                embedded_ranges.push((row.object, range, row.role, digest));
            }
            _ => {
                return refused("embedded protected artifact range and digest must appear together")
            }
        }
    }
    roles.sort();
    if roles != required {
        return refused("protected artifact roles are missing, duplicate, or mislabeled");
    }
    embedded_ranges.sort_by(|left, right| {
        (&left.0, left.1.offset, left.1.length, left.2, &left.3).cmp(&(
            &right.0,
            right.1.offset,
            right.1.length,
            right.2,
            &right.3,
        ))
    });
    for pair in embedded_ranges.windows(2) {
        let (left_object, left, _, _) = &pair[0];
        let (right_object, right, _, _) = &pair[1];
        if left_object == right_object && left.offset.get() + left.length.get() > right.offset.get()
        {
            return refused("embedded protected artifact ranges overlap");
        }
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
    if expected.protected_artifacts.len() + expected.embedded_protected_artifacts.len()
        != required.len()
    {
        return refused("arming identity protected artifact count does not match its bindings");
    }
    let mut authenticated_roles = expected
        .protected_artifacts
        .iter()
        .map(|artifact| artifact.role)
        .chain(
            expected
                .embedded_protected_artifacts
                .iter()
                .map(|artifact| artifact.role),
        )
        .collect::<Vec<_>>();
    authenticated_roles.sort();
    if authenticated_roles != required {
        return refused("arming identity protected artifact roles are incomplete or duplicated");
    }
    let mut authenticated = expected.protected_artifacts.clone();
    authenticated.sort_by_key(|artifact| artifact.role);
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

    let mut embedded = expected.embedded_protected_artifacts.clone();
    embedded.sort_by_key(|artifact| artifact.role);
    for artifact in &embedded {
        if artifact.range.length == SafeUint::ZERO
            || artifact
                .range
                .offset
                .get()
                .checked_add(artifact.range.length.get())
                .and_then(|end| SafeUint::new(end).ok())
                .is_none()
        {
            return refused("expected embedded protected artifact range is invalid");
        }
        if artifact.role == ProtectedArtifactRole::EngineBinary
            && artifact.content_digest != expected.engine_binary_digest
        {
            return refused(
                "protected embedded engine digest differs from the loaded engine digest",
            );
        }
        if artifact.role == ProtectedArtifactRole::ExactOperationManifest
            && exact_binding
                .as_ref()
                .is_none_or(|binding| artifact.content_digest != binding.operation_manifest_digest)
        {
            return refused(
                "protected embedded Exact operation manifest digest differs from its armed binding",
            );
        }
    }

    let rows: Vec<SnapshotProtectedObject> =
        serde_json::from_value(value_at(document, &["protectedObjects"])?.clone())
            .map_err(|error| invalid(format!("invalid protected objects: {error}")))?;
    let by_role = rows
        .into_iter()
        .map(|row| (row.role, row))
        .collect::<BTreeMap<_, _>>();
    for artifact in &authenticated {
        let Some(row) = by_role.get(&artifact.role) else {
            return refused("protected host object has no snapshot row");
        };
        if row.object != artifact.object
            || row.embedded_range.is_some()
            || row.content_digest.is_some()
        {
            return refused(
                "protected object does not match the independently authenticated artifact role",
            );
        }
    }
    for artifact in &embedded {
        let Some(row) = by_role.get(&artifact.role) else {
            return refused("protected embedded object has no snapshot row");
        };
        if row.object != artifact.executable_object
            || row.embedded_range.as_ref() != Some(&artifact.range)
            || row.content_digest.as_ref() != Some(&artifact.content_digest)
        {
            return refused(
                "embedded protected object does not match its authenticated range and digest",
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
) -> Result<LogicalPath> {
    let binding = root_binding_for_host_components_in(bindings, principal, host_components)?;
    logical_path_from_binding(&binding, host_components)
}

fn logical_path_for_host_components_in_validated(
    bindings: &[ArmedRootBinding],
    principal: &Principal,
    host_components: &[PathComponent],
) -> Result<LogicalPath> {
    let binding =
        root_binding_for_host_components_in_validated(bindings, principal, host_components)?;
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
) -> Result<ArmedRootBinding> {
    validate_package_binding_host_paths(bindings)?;
    root_binding_for_host_components_in_validated(bindings, principal, host_components).cloned()
}

fn root_binding_for_host_components_in_validated<'a>(
    bindings: &'a [ArmedRootBinding],
    principal: &Principal,
    host_components: &[PathComponent],
) -> Result<&'a ArmedRootBinding> {
    // @ref LLP 0021#decision-staging-and-principal-semantics — package roots
    // are principal-relative mount boundaries: a foreign nested root must not
    // fall through to an owned package ancestor.
    let matching_package_bindings = bindings
        .iter()
        .filter(|binding| {
            binding.logical_root == LogicalRoot::Package
                && host_binding_matches(binding, host_components)
        })
        .collect::<Vec<_>>();
    let mut candidates = bindings
        .iter()
        .filter(|binding| {
            host_binding_matches(binding, host_components)
                && match binding.logical_root {
                    LogicalRoot::Package => {
                        binding.owner.as_ref() == Some(principal)
                            && !matching_package_bindings.iter().any(|foreign| {
                                foreign.owner.as_ref() != Some(principal)
                                    && foreign.host_path.components.len()
                                        > binding.host_path.components.len()
                            })
                    }
                    _ => binding.owner.is_none(),
                }
        })
        .collect::<Vec<_>>();
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

fn host_binding_matches(binding: &ArmedRootBinding, host_components: &[PathComponent]) -> bool {
    binding.host_path.root == LogicalRoot::Absolute
        && binding.host_path.host_bound == Some(true)
        && host_components.starts_with(&binding.host_path.components)
        && (binding.logical_root != LogicalRoot::Absolute
            || host_components.len() == binding.host_path.components.len())
}

fn validate_package_binding_host_paths(bindings: &[ArmedRootBinding]) -> Result<()> {
    for (index, binding) in bindings
        .iter()
        .enumerate()
        .filter(|(_, binding)| binding.logical_root == LogicalRoot::Package)
    {
        if bindings.iter().enumerate().any(|(other_index, other)| {
            other_index != index && other.host_path == binding.host_path
        }) {
            return refused(
                "package root binding and another root binding share an authenticated host path",
            );
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
) -> Result<Vec<BoundAuthority>> {
    validate_package_binding_host_paths(bindings)?;
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
        )?;
        if owner_view.root != LogicalRoot::Package || !owner_view.components.is_empty() {
            return refused("package root binding does not project to its owner's package root");
        }

        for principal in principals {
            let Ok(path) = logical_path_for_host_components_in_validated(
                bindings,
                principal,
                &binding.host_path.components,
            ) else {
                continue;
            };
            let package_root_owner = (path.root == LogicalRoot::Package).then(|| principal.clone());
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
) -> Result<Vec<BoundAuthority>> {
    selectors
        .into_iter()
        .enumerate()
        .map(|(authority_index, selector)| {
            let source_id = NonEmptyString::new(format!(
                "principal.{principal_index:06}.{channel}.{authority_index:06}"
            ))
            .map_err(Error::InvalidModel)?;
            let package_root_owner = selector
                .resource
                .contains_package_logical_root()
                .then(|| package_owner.cloned())
                .flatten();
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
) -> Result<Vec<BoundAuthority>> {
    let mut bound = Vec::new();
    for (selector_index, selector) in selectors.into_iter().enumerate() {
        if selector.resource.contains_package_logical_root() {
            for (owner_index, owner) in package_principals.iter().enumerate() {
                bound.push(BoundAuthority {
                    source_id: NonEmptyString::new(format!(
                        "process-ceiling.{selector_index:06}.{owner_index:06}"
                    ))
                    .map_err(Error::InvalidModel)?,
                    selector: selector.clone(),
                    armed_snapshot_digest: snapshot_digest.clone(),
                    package_root_owner: Some(owner.clone()),
                });
            }
        } else {
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

fn bind_root_ceiling(
    selectors: Vec<AuthoritySelector>,
    snapshot_digest: &Digest,
) -> Result<Vec<BoundAuthority>> {
    selectors
        .into_iter()
        .enumerate()
        .map(|(selector_index, selector)| {
            if selector.resource.contains_package_logical_root() {
                return refused("root authority ceiling cannot contain a package logical root");
            }
            Ok(BoundAuthority {
                source_id: NonEmptyString::new(format!(
                    "root-authority-ceiling.{selector_index:06}"
                ))
                .map_err(Error::InvalidModel)?,
                selector,
                armed_snapshot_digest: snapshot_digest.clone(),
                package_root_owner: None,
            })
        })
        .collect()
}

fn bind_bootstrap_floor(
    selectors: Vec<AuthoritySelector>,
    snapshot_digest: &Digest,
) -> Result<Vec<BoundAuthority>> {
    selectors
        .into_iter()
        .enumerate()
        .map(|(selector_index, selector)| {
            if selector.resource.contains_package_logical_root() {
                return refused("bootstrap authority floor cannot contain a package logical root");
            }
            Ok(BoundAuthority {
                source_id: NonEmptyString::new(format!("bootstrap-floor.{selector_index:06}"))
                    .map_err(Error::InvalidModel)?,
                selector,
                armed_snapshot_digest: snapshot_digest.clone(),
                package_root_owner: None,
            })
        })
        .collect()
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
        let package_principal = value["packageGraph"]["nodes"][0]["principal"].clone();
        let root_principal = value["rootIdentity"].clone();
        let root_object = value["rootBindings"][0]["object"].clone();
        value["packageGraph"]["nodes"][0] = serde_json::json!({
            "principal": package_principal,
            "resolvingSpecifier": "image-lib",
            "rootObject": root_object,
            "virtualAliases": [{
                "root": "project",
                "components": [
                    {"encoding": "utf8", "value": "node_modules"},
                    {"encoding": "utf8", "value": "image-lib"}
                ]
            }],
            "platformDisposition": "required"
        });
        value["packageGraph"]["importEdges"] = serde_json::json!([
            {
                "importer": root_principal,
                "imported": package_principal,
                "requestSpecifier": "image-lib",
                "resolutionKind": "common-js-require",
                "conditions": ["node", "require"],
                "attributes": {}
            },
            {
                "importer": root_principal,
                "imported": package_principal,
                "requestSpecifier": "image-lib",
                "resolutionKind": "dynamic-import",
                "conditions": ["import", "node"],
                "attributes": {}
            },
            {
                "importer": root_principal,
                "imported": package_principal,
                "requestSpecifier": "image-lib",
                "resolutionKind": "esm-static",
                "conditions": ["import", "node"],
                "attributes": {}
            }
        ]);
        value["packageGraph"]["digest"] = Value::String(
            crate::digest::compute_domain_digest(
                "ibex:capsec:package-graph:1",
                &value["packageGraph"],
                &["digest".to_owned()],
            )
            .unwrap(),
        );
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
            protected_artifacts,
            embedded_protected_artifacts: Vec::new(),
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
    }

    #[test]
    fn typed_module_edges_bind_request_kind_conditions_and_principals() {
        let (bytes, expected) = fixture();
        let armed = ArmedSnapshot::load(&bytes, &expected).unwrap();
        let root: Principal =
            serde_json::from_value(armed.document()["rootIdentity"].clone()).unwrap();
        let package: Principal = serde_json::from_value(
            armed.document()["packageGraph"]["nodes"][0]["principal"].clone(),
        )
        .unwrap();
        let attributes = BTreeMap::new();

        assert!(armed.authenticates_module_edge(
            &root,
            "image-lib",
            &package,
            "esm-static",
            &["import".into(), "node".into()],
            &attributes,
        ));
        assert!(!armed.authenticates_module_edge(
            &root,
            "image-lib/private",
            &package,
            "esm-static",
            &["import".into(), "node".into()],
            &attributes,
        ));
        assert!(!armed.authenticates_module_edge(
            &root,
            "image-lib",
            &package,
            "common-js-require",
            &["import".into(), "node".into()],
            &attributes,
        ));
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
        for edge in value["packageGraph"]["importEdges"].as_array_mut().unwrap() {
            edge["imported"]["locator"] = Value::String(locator.to_owned());
        }
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
        let context = armed.decision_context(profile.definitions).unwrap();
        assert_eq!(context.identity(), &identity);
    }

    #[test]
    fn authenticates_embedded_ranges_without_host_paths() {
        let (bytes, mut expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let row = value["protectedObjects"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["role"] == "armed-policy")
            .unwrap();
        row["embeddedRange"] = serde_json::json!({"offset": 4096, "length": 512});
        row["contentDigest"] = Value::String(expected.policy_digest.as_str().to_owned());
        let executable_object: ObjectIdentity =
            serde_json::from_value(row["object"].clone()).unwrap();
        expected
            .protected_artifacts
            .retain(|artifact| artifact.role != ProtectedArtifactRole::ArmedPolicy);
        expected.embedded_protected_artifacts = vec![ExpectedEmbeddedProtectedArtifact {
            role: ProtectedArtifactRole::ArmedPolicy,
            executable_object,
            range: EmbeddedByteRange {
                offset: SafeUint::new(4096).unwrap(),
                length: SafeUint::new(512).unwrap(),
            },
            content_digest: expected.policy_digest.clone(),
        }];
        let bytes = redigest(&mut value);
        expected.armed_snapshot_digest =
            Digest::new(value["armedSnapshotDigest"].as_str().unwrap()).unwrap();
        let armed = ArmedSnapshot::load(&bytes, &expected).unwrap();
        assert_eq!(armed.protected_artifacts().len(), 3);
        assert_eq!(armed.embedded_protected_artifacts().len(), 1);

        let mut wrong = expected;
        wrong.embedded_protected_artifacts[0].range.offset = SafeUint::new(4097).unwrap();
        assert!(matches!(
            ArmedSnapshot::load(&bytes, &wrong),
            Err(Error::ArmRefused(message)) if message.contains("authenticated range and digest")
        ));
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
        let mut second_node = value["packageGraph"]["nodes"][0].clone();
        second_node["principal"] = second_principal.clone();
        second_node["resolvingSpecifier"] = Value::String("other-lib".into());
        second_node["rootObject"]["file"] = Value::String("file-201".into());
        second_node["virtualAliases"][0]["components"][1]["value"] =
            Value::String("other-lib".into());
        value["packageGraph"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(second_node);
        let root_identity = value["rootIdentity"].clone();
        let second_edges = value["packageGraph"]["importEdges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| {
                let mut edge = edge.clone();
                edge["importer"] = root_identity.clone();
                edge["imported"] = second_principal.clone();
                edge["requestSpecifier"] = Value::String("other-lib".into());
                edge
            })
            .collect::<Vec<_>>();
        value["packageGraph"]["importEdges"]
            .as_array_mut()
            .unwrap()
            .extend(second_edges);
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
