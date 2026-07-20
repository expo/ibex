use capsec_semantics::digest::{compute_domain_digest, POLICY_DOMAIN};
use capsec_semantics::model::Digest;
use capsec_semantics::policy::{
    CanonicalMountProfile, CanonicalPolicy, CanonicalTargetProfile, ExpectedPolicyIdentity,
};
use capsec_semantics::registry::ValidatedProfile;
use serde_json::Value;

fn definitions() -> capsec_semantics::registry::DefinitionSet {
    ValidatedProfile::from_json(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../capsec/registry/capability-definitions.json"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../capsec/registry/policy-rules.json"
        )),
    )
    .unwrap()
    .definitions
}

fn fixture() -> (Value, ExpectedPolicyIdentity) {
    let value: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../capsec/examples/canonical-policy.canonical.json"
    )))
    .unwrap();
    let expected = ExpectedPolicyIdentity {
        profile: value["capsVocab"].as_str().unwrap().into(),
        semantic_core: value["semanticCore"].as_str().unwrap().into(),
        vocab_digest: Digest::new(value["vocabDigest"].as_str().unwrap()).unwrap(),
        registry_digest: Digest::new(value["registryDigest"].as_str().unwrap()).unwrap(),
    };
    (value, expected)
}

fn recompute(value: &mut Value) {
    value["policyDigest"] = Value::String(
        compute_domain_digest(POLICY_DOMAIN, value, &["policyDigest".to_string()]).unwrap(),
    );
}

fn replace_logical_root(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::Array(values) => {
            for value in values {
                replace_logical_root(value, from, to);
            }
        }
        Value::Object(object) => {
            if object.get("root").and_then(Value::as_str) == Some(from)
                && object.get("components").is_some_and(Value::is_array)
            {
                object.insert("root".into(), Value::String(to.into()));
            }
            for value in object.values_mut() {
                replace_logical_root(value, from, to);
            }
        }
        _ => {}
    }
}

#[test]
fn canonical_policy_loads_as_a_complete_typed_artifact() {
    let (value, expected) = fixture();
    let policy = CanonicalPolicy::load(
        &serde_json::to_vec(&value).unwrap(),
        &expected,
        &definitions(),
    )
    .unwrap();
    assert_eq!(policy.vocab_digest, expected.vocab_digest);
    assert_eq!(policy.registry_digest, expected.registry_digest);
    assert_eq!(policy.principals.len(), 1);
    assert_eq!(policy.computed_candidates.declarations.len(), 1);
    assert_eq!(policy.root_ceiling.len(), 1);
    assert!(matches!(
        policy.target_profile,
        CanonicalTargetProfile::Source { .. }
    ));
    assert!(matches!(
        policy.mount_profile,
        CanonicalMountProfile::ProjectV1
    ));
}

#[test]
fn policy_v2_accepts_a_normalized_compiled_binding_and_rejects_unbound_closures() {
    let (mut compiled, expected) = fixture();
    compiled["targetProfile"] = serde_json::json!({
        "kind": "compiled",
        "profile": "sfe-v1",
        "targetTriple": "aarch64-apple-darwin",
    });
    compiled["mountProfile"] = Value::String("compiled-app-work-v1".into());
    replace_logical_root(&mut compiled["rootCeiling"], "project", "work");
    replace_logical_root(&mut compiled["principals"], "project", "work");
    recompute(&mut compiled);
    let policy = CanonicalPolicy::load(
        &serde_json::to_vec(&compiled).unwrap(),
        &expected,
        &definitions(),
    )
    .unwrap();
    assert!(matches!(
        policy.target_profile,
        CanonicalTargetProfile::Compiled { .. }
    ));
    assert!(matches!(
        policy.mount_profile,
        CanonicalMountProfile::CompiledAppWorkV1
    ));

    let (mut unbound, expected) = fixture();
    unbound["computedCandidates"]["packageClosureOptIns"] = serde_json::json!([]);
    recompute(&mut unbound);
    assert!(CanonicalPolicy::load(
        &serde_json::to_vec(&unbound).unwrap(),
        &expected,
        &definitions(),
    )
    .is_err());
}

#[test]
fn compiled_policy_refuses_project_roots_and_profile_mismatches() {
    let (mut compiled, expected) = fixture();
    compiled["targetProfile"] = serde_json::json!({
        "kind": "compiled",
        "profile": "sfe-v1",
        "targetTriple": "aarch64-apple-darwin",
    });
    compiled["mountProfile"] = Value::String("compiled-app-work-v1".into());
    recompute(&mut compiled);
    let error = CanonicalPolicy::load(
        &serde_json::to_vec(&compiled).unwrap(),
        &expected,
        &definitions(),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("unavailable Project logical root"));

    replace_logical_root(&mut compiled["rootCeiling"], "project", "app");
    replace_logical_root(&mut compiled["principals"], "project", "work");
    compiled["mountProfile"] = Value::String("project-v1".into());
    recompute(&mut compiled);
    let error = CanonicalPolicy::load(
        &serde_json::to_vec(&compiled).unwrap(),
        &expected,
        &definitions(),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("target and mount profiles disagree"));
}

#[test]
fn independently_recomputed_stale_vocabulary_and_registry_are_refused() {
    let (value, expected) = fixture();
    for field in ["vocabDigest", "registryDigest"] {
        let mut stale = value.clone();
        stale[field] = Value::String("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        recompute(&mut stale);
        assert!(CanonicalPolicy::load(
            &serde_json::to_vec(&stale).unwrap(),
            &expected,
            &definitions(),
        )
        .is_err());
    }
}

#[test]
fn production_policy_ingress_rejects_action_constraints_and_unknown_fields() {
    let (mut value, expected) = fixture();
    value["principals"][0]["floor"] = serde_json::json!([{
        "authority": {
            "cap": "env:write",
            "resource": {"kind":"environment-name","target":"broker-base","name":"PATH"}
        },
        "provenance": [{"kind":"direct","source":"constraint-test"}]
    }]);
    recompute(&mut value);
    assert!(CanonicalPolicy::load(
        &serde_json::to_vec(&value).unwrap(),
        &expected,
        &definitions(),
    )
    .is_err());

    let (mut unknown, expected) = fixture();
    unknown["legacyMode"] = Value::String("permissive".into());
    recompute(&mut unknown);
    assert!(CanonicalPolicy::load(
        &serde_json::to_vec(&unknown).unwrap(),
        &expected,
        &definitions(),
    )
    .is_err());
}
