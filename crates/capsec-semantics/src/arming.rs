//! Strict immutable armed-snapshot ingestion.
//!
//! The caller supplies facts observed from the execution it is about to start;
//! this module authenticates the serialized snapshot against those facts and
//! returns an immutable value. No authored policy path or environment input is
//! retained. @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine

use std::collections::BTreeMap;
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
    ActionId, AuthoritySelector, Digest, Generation, NonEmptyString, ObjectIdentity, Principal,
    SafeUint,
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
            protected_resources: Vec::new(),
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
