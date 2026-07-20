use std::collections::{BTreeMap, BTreeSet};

use capsec_semantics::cache::GenerationSet;
use capsec_semantics::decision::{
    evaluate_decision_set, ArmInputs, AuthorityCeiling, DecisionAuthorityState, DecisionOutcome,
    DecisionReason, EffectGate, SemanticIdentity, TargetArmState, TargetCellDisposition,
    VerifiedDecisionContext, Workflow,
};
use capsec_semantics::model::{
    DecisionSet, Digest, IpAddress, LogicalPath, LogicalRoot, NonEmptyString, ObjectPlatform,
    PathComponent, PeerClass, Principal, SafeUint, StableId,
};
use capsec_semantics::path_alias::{
    BoundVolumePathCanonicalizer, PathAliasCanonicalizerIdentity, PathAliasCanonicalizers,
    PathCanonicalizerRootBinding,
};
use capsec_semantics::registry::{
    CapabilityDefinitionsDocument, DefinitionSet, PROFILE, SEMANTIC_CORE,
};
use serde_json::json;

const ZERO_DIGEST: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn definitions() -> DefinitionSet {
    let mut document: CapabilityDefinitionsDocument = serde_json::from_slice(include_bytes!(
        "../../../capsec/registry/capability-definitions.json"
    ))
    .unwrap();
    document
        .definitions
        .retain(|definition| definition.id.as_str() == "path:cwd-mutate");
    DefinitionSet::validate(document, &BTreeSet::from(["path.cwd.v1".to_owned()])).unwrap()
}

fn identity() -> SemanticIdentity {
    let digest = Digest::new(ZERO_DIGEST).unwrap();
    SemanticIdentity {
        profile: PROFILE.to_owned(),
        semantic_core: SEMANTIC_CORE.to_owned(),
        vocab_digest: digest.clone(),
        registry_digest: digest.clone(),
        policy_digest: digest.clone(),
        armed_snapshot_digest: digest,
    }
}

fn context() -> VerifiedDecisionContext {
    let identity = identity();
    let volume = NonEmptyString::new("test-volume").unwrap();
    let path_canonicalizers = PathAliasCanonicalizers::bind(
        vec![BoundVolumePathCanonicalizer {
            platform: ObjectPlatform::Unix,
            volume: volume.clone(),
            identity: PathAliasCanonicalizerIdentity::ByteIdentityV1,
        }],
        [PathCanonicalizerRootBinding {
            logical_root: LogicalRoot::Project,
            owner: None,
            logical_path: None,
            host_path: LogicalPath {
                root: LogicalRoot::Absolute,
                components: vec![PathComponent::utf8("project").unwrap()],
                host_bound: Some(true),
            },
            platform: ObjectPlatform::Unix,
            volume,
        }],
    )
    .unwrap();
    VerifiedDecisionContext::arm_with_path_canonicalizers(
        ArmInputs {
            expected_identity: identity.clone(),
            loaded_identity: identity,
            target: TargetArmState::CompleteAdvertised,
            structure_valid: true,
        },
        definitions(),
        DecisionAuthorityState {
            generations: GenerationSet {
                negative: SafeUint::ZERO,
                dynamic: SafeUint::ZERO,
                handle: SafeUint::ZERO,
            },
            process_ceiling: AuthorityCeiling::Unbounded.into(),
            protected_objects: Vec::new().into(),
            protected_resources: Vec::new().into(),
            principal_policies: BTreeMap::new().into(),
            revocations: Vec::new(),
            handles: Vec::new(),
            dynamic_grants: Vec::new(),
        },
        path_canonicalizers,
    )
    .unwrap()
}

fn decision_set(principal: Principal) -> DecisionSet {
    serde_json::from_value(json!({
        "decisionSetSchema": "ibex/capsec-decision-set/1",
        "operationId": "cwd-operation",
        "atomicityGroup": "test.cwd.mutate",
        "combination": "conjunction",
        "context": {
            "stage": "requested",
            "actor": principal,
            "constrainedPrincipals": [principal],
            "presentedHandleIds": []
        },
        "effects": [{
            "cap": "path:cwd-mutate",
            "effectOwner": principal,
            "resource": {
                "kind": "path-occurrence",
                "requested": {
                    "root": "project",
                    "components": [{"encoding": "utf8", "value": "src"}]
                },
                "followMode": "follow-final",
                "objectState": "unknown"
            }
        }]
    }))
    .unwrap()
}

fn gate() -> EffectGate {
    EffectGate {
        coverage_edge_id: StableId::new("test.cwd.edge").unwrap(),
        target_cell: TargetCellDisposition::Complete,
        definition_and_edge_predicates_satisfied: true,
    }
}

fn classifier(_: IpAddress) -> Option<PeerClass> {
    Some(PeerClass::Public)
}

#[test]
fn cwd_mutation_is_core_root_only_before_any_positive_source() {
    let package: Principal = serde_json::from_value(json!({
        "kind": "package",
        "name": "cwd-package",
        "integrity": ZERO_DIGEST,
        "locator": "cwd-package@1.0.0"
    }))
    .unwrap();
    let denied = evaluate_decision_set(
        &context(),
        &decision_set(package.clone()),
        &[gate()],
        Workflow::ProductionEnforce,
        &classifier,
    )
    .unwrap();
    assert_eq!(denied.outcome, DecisionOutcome::Deny);
    assert_eq!(
        denied.evidence[0].reason,
        DecisionReason::DefinitionOrEdgePredicate
    );
    assert_eq!(denied.evidence[0].principal.as_ref(), Some(&package));

    let root: Principal =
        serde_json::from_value(json!({"kind": "root", "identity": "project-root"})).unwrap();
    let allowed = evaluate_decision_set(
        &context(),
        &decision_set(root),
        &[gate()],
        Workflow::ProductionEnforce,
        &classifier,
    )
    .unwrap();
    assert_eq!(allowed.outcome, DecisionOutcome::Allow);
    assert_eq!(allowed.evidence[0].reason, DecisionReason::AmbientRoot);
}
