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
use crate::digest::{compute_domain_digest, ARMED_SNAPSHOT_DOMAIN};
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
    pub target: String,
    pub engine_binary_digest: Digest,
    pub features: Vec<String>,
    pub package_graph_digest: Digest,
    pub target_complete_and_advertised: bool,
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
        if !expected.target_complete_and_advertised {
            return refused("engine target is not complete and advertised");
        }
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
        let computed = compute_domain_digest(
            ARMED_SNAPSHOT_DOMAIN,
            &document,
            &["armedSnapshotDigest".to_string()],
        )?;
        if claimed.as_str() != computed {
            return refused("armed snapshot digest is stale or tampered");
        }
        let generations = SnapshotGenerations {
            policy: generation(&document, "policy")?,
            negative: generation(&document, "negative")?,
            dynamic: generation(&document, "dynamic")?,
            handle: generation(&document, "handle")?,
        };
        Ok(Self {
            document: Arc::new(document),
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

    pub fn root_bindings(&self) -> Result<Vec<ArmedRootBinding>> {
        serde_json::from_value(value_at(&self.document, &["rootBindings"])?.clone())
            .map_err(|error| invalid(format!("invalid armed root bindings: {error}")))
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
        logical_path_for_host_components_in(&self.root_bindings()?, principal, host_components)
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
        validate_package_binding_host_paths(&bindings)?;
        principals
            .iter()
            .map(|principal| {
                Ok((
                    principal.clone(),
                    logical_path_for_host_components_in_validated(
                        &bindings,
                        principal,
                        host_components,
                    )?,
                ))
            })
            .collect()
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
            derive_package_write_guards(&self.root_bindings()?, &principals, self.digest())?;

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
                AuthorityCeiling::Bounded(bind_authorities(
                    selectors,
                    0,
                    "process-ceiling",
                    self.digest(),
                    None,
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
            process_ceiling,
            protected_objects,
            protected_resources,
            principal_policies,
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
    #[allow(dead_code)]
    endowments: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotProtectedObject {
    #[allow(dead_code)]
    role: String,
    object: ObjectIdentity,
    denied_actions: Vec<ActionId>,
}

fn logical_path_for_host_components_in(
    bindings: &[ArmedRootBinding],
    principal: &Principal,
    host_components: &[PathComponent],
) -> Result<LogicalPath> {
    validate_package_binding_host_paths(bindings)?;
    logical_path_for_host_components_in_validated(bindings, principal, host_components)
}

fn logical_path_for_host_components_in_validated(
    bindings: &[ArmedRootBinding],
    principal: &Principal,
    host_components: &[PathComponent],
) -> Result<LogicalPath> {
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
    let binding = candidates.into_iter().next().ok_or_else(|| {
        Error::ArmRefused("host path has no authenticated logical-root binding".into())
    })?;
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
                // A principal with no authenticated view cannot name this path
                // in a typed decision, so there is no corresponding guard row.
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
        let digest = compute_domain_digest(
            ARMED_SNAPSHOT_DOMAIN,
            &value,
            &["armedSnapshotDigest".to_string()],
        )
        .unwrap();
        value["armedSnapshotDigest"] = Value::String(digest);
        let digest_at =
            |path: &[&str]| Digest::new(value_at(&value, path).unwrap().as_str().unwrap()).unwrap();
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
                .map(|item| item.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            target_complete_and_advertised: true,
        };
        (serde_json::to_vec_pretty(&value).unwrap(), expected)
    }

    fn refresh_armed_digest(value: &mut Value) {
        let digest = compute_domain_digest(
            ARMED_SNAPSHOT_DOMAIN,
            value,
            &["armedSnapshotDigest".to_string()],
        )
        .unwrap();
        value["armedSnapshotDigest"] = Value::String(digest);
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
    fn derives_package_write_guards_for_nested_principal_views() {
        let (bytes, expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let nested_principal = serde_json::json!({
            "kind": "package",
            "name": "codec",
            "integrity": "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
            "locator": "codec@1.0.0"
        });
        let mut nested_row = value["principals"][1].clone();
        nested_row["principal"] = nested_principal.clone();
        value["principals"].as_array_mut().unwrap().push(nested_row);
        value["rootBindings"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "logicalRoot": "package",
                "owner": nested_principal,
                "hostPath": {
                    "root": "absolute",
                    "components": [
                        {"encoding": "utf8", "value": "Users"},
                        {"encoding": "utf8", "value": "example"},
                        {"encoding": "utf8", "value": "project"},
                        {"encoding": "utf8", "value": "node_modules"},
                        {"encoding": "utf8", "value": "image-lib"},
                        {"encoding": "utf8", "value": "node_modules"},
                        {"encoding": "utf8", "value": "codec"}
                    ],
                    "hostBound": true
                },
                "object": {"platform": "apple", "volume": "volume-1", "file": "file-201"}
            }));
        refresh_armed_digest(&mut value);
        let armed = ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap();
        let image_principal: Principal = serde_json::from_value(serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
            "locator": "image-lib@2.4.1"
        }))
        .unwrap();
        let nested_principal: Principal = serde_json::from_value(serde_json::json!({
            "kind": "package",
            "name": "codec",
            "integrity": "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
            "locator": "codec@1.0.0"
        }))
        .unwrap();
        let root_principal: Principal = serde_json::from_value(serde_json::json!({
            "kind": "root",
            "identity": "project-root"
        }))
        .unwrap();
        let components = |values: &[&str]| {
            values
                .iter()
                .map(|value| PathComponent::utf8(*value).unwrap())
                .collect::<Vec<_>>()
        };
        let nested_file = components(&[
            "Users",
            "example",
            "project",
            "node_modules",
            "image-lib",
            "node_modules",
            "codec",
            "index.js",
        ]);
        let image_view = armed
            .logical_path_for_host_components(&image_principal, &nested_file)
            .unwrap();
        assert_eq!(image_view.root, LogicalRoot::Project);
        assert_eq!(
            image_view.components,
            components(&[
                "node_modules",
                "image-lib",
                "node_modules",
                "codec",
                "index.js",
            ])
        );
        let nested_view = armed
            .logical_path_for_host_components(&nested_principal, &nested_file)
            .unwrap();
        assert_eq!(nested_view.root, LogicalRoot::Package);
        assert_eq!(nested_view.components, components(&["index.js"]));
        let root_view = armed
            .logical_path_for_host_components(&root_principal, &nested_file)
            .unwrap();
        assert_eq!(root_view, image_view);

        let guards = armed.authority_state().unwrap().protected_resources;
        assert_eq!(guards.len(), 4);
        assert!(guards
            .windows(2)
            .all(|pair| { pair[0].source_id.as_str() < pair[1].source_id.as_str() }));
        let has_guard = |owner: Option<&Principal>, root, parts: &[&str]| {
            guards.iter().any(|guard| {
                guard.package_root_owner.as_ref() == owner
                    && matches!(
                        &guard.selector.resource,
                        SelectorResource::PathTree { path }
                            if path.root == root && path.components == components(parts)
                    )
            })
        };
        assert!(has_guard(
            Some(&nested_principal),
            LogicalRoot::Package,
            &[]
        ));
        assert!(has_guard(Some(&image_principal), LogicalRoot::Package, &[]));
        assert!(!has_guard(
            Some(&image_principal),
            LogicalRoot::Package,
            &["node_modules", "codec"]
        ));
        assert!(has_guard(
            None,
            LogicalRoot::Project,
            &["node_modules", "image-lib", "node_modules", "codec"]
        ));
    }

    #[test]
    fn refuses_same_name_different_locator_package_host_path_collision() {
        let (bytes, expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        let colliding_principal = serde_json::json!({
            "kind": "package",
            "name": "image-lib",
            "integrity": "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
            "locator": "image-lib@3.0.0"
        });
        let mut colliding_row = value["principals"][1].clone();
        colliding_row["principal"] = colliding_principal.clone();
        value["principals"]
            .as_array_mut()
            .unwrap()
            .push(colliding_row);
        let mut colliding_binding = value["rootBindings"][0].clone();
        colliding_binding["owner"] = colliding_principal;
        value["rootBindings"]
            .as_array_mut()
            .unwrap()
            .push(colliding_binding);
        refresh_armed_digest(&mut value);

        let armed = ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap();
        let error = armed
            .authority_state()
            .err()
            .expect("colliding package host paths must refuse arming");
        assert!(matches!(
            error,
            Error::ArmRefused(message)
                if message.contains("share an authenticated host path")
        ));
    }

    #[test]
    fn refuses_package_principal_without_package_binding() {
        let (bytes, expected) = fixture();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["rootBindings"]
            .as_array_mut()
            .unwrap()
            .retain(|binding| binding["logicalRoot"] != "package");
        refresh_armed_digest(&mut value);

        let armed = ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap();
        let error = armed
            .authority_state()
            .err()
            .expect("a package principal without a package binding must refuse arming");
        assert!(matches!(
            error,
            Error::ArmRefused(message)
                if message.contains("has no package root binding")
        ));
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
        assert_eq!(authority.protected_resources.len(), 2);
        assert!(authority.protected_resources.iter().any(|guard| {
            guard
                .package_root_owner
                .as_ref()
                .is_some_and(Principal::is_package)
                && matches!(
                    &guard.selector.resource,
                    SelectorResource::PathTree { path }
                        if path.root == LogicalRoot::Package && path.components.is_empty()
                )
        }));
        assert!(authority.protected_resources.iter().any(|guard| {
            guard.package_root_owner.is_none()
                && matches!(
                    &guard.selector.resource,
                    SelectorResource::PathTree { path }
                        if path.root == LogicalRoot::Project
                            && path.components == vec![
                                PathComponent::utf8("node_modules").unwrap(),
                                PathComponent::utf8("image-lib").unwrap(),
                            ]
                )
        }));
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
            authority.process_ceiling,
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

        let mut incomplete = expected;
        incomplete.target_complete_and_advertised = false;
        assert!(ArmedSnapshot::load(&bytes, &incomplete).is_err());
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
