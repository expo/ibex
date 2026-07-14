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
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectedArtifactRole {
    ArmedPolicy,
    EngineBinary,
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
        validate_snapshot_invariants(&document)?;
        validate_expected_protected_artifacts(&document, expected)?;
        let root_bindings: Vec<ArmedRootBinding> =
            serde_json::from_value(value_at(&document, &["rootBindings"])?.clone())
                .map_err(|error| invalid(format!("invalid armed root bindings: {error}")))?;
        Ok(Self {
            document: Arc::new(document),
            root_bindings: root_bindings.into(),
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

    /// Exact launcher-authenticated artifact identities backing the snapshot's
    /// mandatory protected-object guards. The Host reopens these paths and
    /// checks both object identity and content digest before runtime creation.
    pub fn protected_artifacts(&self) -> &[ExpectedProtectedArtifact] {
        &self.protected_artifacts
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
        if protected_objects.windows(2).any(|pair| pair[0] == pair[1]) {
            return refused("armed snapshot contains a duplicate protected-object guard");
        }
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

fn validate_snapshot_invariants(document: &Value) -> Result<()> {
    validate_protected_object_rows(document)?;

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
    const REQUIRED: [ProtectedArtifactRole; 4] = [
        ProtectedArtifactRole::ArmedPolicy,
        ProtectedArtifactRole::EngineBinary,
        ProtectedArtifactRole::PackageGraph,
        ProtectedArtifactRole::Registry,
    ];
    if rows.len() != REQUIRED.len() {
        return refused("armed snapshot must protect exactly four mandatory artifacts");
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
    if roles != REQUIRED {
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
    const REQUIRED: [ProtectedArtifactRole; 4] = [
        ProtectedArtifactRole::ArmedPolicy,
        ProtectedArtifactRole::EngineBinary,
        ProtectedArtifactRole::PackageGraph,
        ProtectedArtifactRole::Registry,
    ];
    if expected.protected_artifacts.len() != REQUIRED.len() {
        return refused("arming identity must authenticate exactly four protected artifacts");
    }
    let mut authenticated = expected.protected_artifacts.clone();
    authenticated.sort_by_key(|artifact| artifact.role);
    if authenticated
        .iter()
        .map(|artifact| artifact.role)
        .collect::<Vec<_>>()
        != REQUIRED
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
