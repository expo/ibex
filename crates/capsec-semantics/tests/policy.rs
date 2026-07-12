use capsec_semantics::digest::{compute_domain_digest, POLICY_DOMAIN};
use capsec_semantics::model::Digest;
use capsec_semantics::policy::{CanonicalPolicy, ExpectedPolicyIdentity};
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
