use capsec_semantics::canonical::{canonicalize, to_jcs, DigestContract};
use capsec_semantics::digest::{compute_contract_digest, compute_domain_digest, DigestKind};
use capsec_semantics::strict_json::parse_strict;
use proptest::prelude::*;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn capsec_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../capsec")
}

fn read_json(relative: &str) -> Value {
    let text = fs::read_to_string(capsec_root().join(relative)).unwrap();
    parse_strict(&text).unwrap()
}

fn contract() -> DigestContract {
    serde_json::from_value(read_json("registry/policy-rules.json")["digestContract"].clone())
        .unwrap()
}

#[test]
fn rejects_duplicate_decoded_keys_before_returning_a_value() {
    let error = parse_strict(r#"{"a":1,"\u0061":2}"#).unwrap_err();
    assert!(error.to_string().contains("duplicate JSON object key"));
}

#[test]
fn rejects_unsafe_integer_spellings() {
    for text in ["9007199254740992", "-9007199254740992", "1e20"] {
        let error = parse_strict(text).unwrap_err();
        assert!(error.to_string().contains("safe range"), "{text}: {error}");
    }
    assert!(parse_strict("9007199254740991").is_ok());
}

#[test]
fn jcs_uses_utf16_key_order_and_ecmascript_numbers() {
    let value = parse_strict(r#"{"\uE000":1,"\uD800\uDC00":2}"#).unwrap();
    assert_eq!(to_jcs(&value).unwrap(), "{\"𐀀\":2,\"\":1}");

    let values = parse_strict("[333333333.33333329,1e-7,1e-6,4.50,-0]").unwrap();
    assert_eq!(
        to_jcs(&values).unwrap(),
        "[333333333.3333333,1e-7,0.000001,4.5,0]"
    );
}

#[test]
fn semantic_sets_are_utf8_sorted_deduplicated_and_idempotent() {
    let contract = contract();
    let left = json!({
        "effects": [
            {"cap":"b", "examples":["𐀀", "\u{e000}"]},
            {"cap":"a"},
            {"cap":"a"}
        ]
    });
    let right = json!({
        "effects": [
            {"cap":"a"},
            {"cap":"b", "examples":["\u{e000}", "𐀀"]}
        ]
    });
    let canonical_left = canonicalize(&left, None, &contract).unwrap();
    let canonical_right = canonicalize(&right, None, &contract).unwrap();
    assert_eq!(canonical_left, canonical_right);
    assert_eq!(
        canonicalize(&canonical_left, None, &contract).unwrap(),
        canonical_left
    );
    assert_eq!(
        canonical_left["effects"][1]["examples"],
        json!(["\u{e000}", "𐀀"])
    );
}

#[test]
fn composite_keyed_sets_follow_the_passed_contract() {
    let contract = contract();
    let value = json!({
        "definitionsSchema":"ibex/capsec-definitions/1",
        "definitions":[{"id":"z"},{"id":"a"}]
    });
    let canonical = canonicalize(&value, Some("ibex/capsec-definitions/1"), &contract).unwrap();
    assert_eq!(canonical["definitions"][0]["id"], "a");
}

#[test]
fn reproduces_all_five_checked_digest_vectors() {
    let contract = contract();
    let vectors = read_json("examples/digest-vectors.canonical.json");
    for vector in vectors["vectors"].as_array().unwrap() {
        let (kind, payload) = match vector["id"].as_str().unwrap() {
            "armed" => (
                DigestKind::ArmedSnapshot,
                read_json("examples/armed-snapshot.canonical.json"),
            ),
            "conformance" => {
                let omit_fields: Vec<String> =
                    serde_json::from_value(vector["omitFields"].clone()).unwrap();
                assert_eq!(
                    compute_domain_digest(
                        vector["domain"].as_str().unwrap(),
                        &vector["payload"],
                        &omit_fields,
                    )
                    .unwrap(),
                    vector["expectedDigest"].as_str().unwrap()
                );
                continue;
            }
            "policy" => (
                DigestKind::Policy,
                read_json("examples/canonical-policy.canonical.json"),
            ),
            "registry" => (
                DigestKind::Registry,
                read_json("examples/registry-digest-bundle.canonical.json"),
            ),
            "vocabulary" => (
                DigestKind::Vocabulary,
                read_json("examples/digest-bundle.canonical.json"),
            ),
            id => panic!("unexpected digest vector {id}"),
        };
        assert_eq!(
            compute_contract_digest(kind, &payload, &contract).unwrap(),
            vector["expectedDigest"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
    }
}

#[test]
fn contract_digest_rejects_cross_domain_payloads() {
    let contract = contract();
    let policy = read_json("examples/canonical-policy.canonical.json");
    assert!(compute_contract_digest(DigestKind::ArmedSnapshot, &policy, &contract).is_err());

    let arbitrary = json!({"purpose":"not a policy"});
    assert!(compute_contract_digest(DigestKind::Policy, &arbitrary, &contract).is_err());
}

#[test]
fn self_digest_field_is_the_only_projected_policy_field() {
    let contract = contract();
    let policy = read_json("examples/canonical-policy.canonical.json");
    let expected = compute_contract_digest(DigestKind::Policy, &policy, &contract).unwrap();

    let mut changed_self = policy.clone();
    changed_self["policyDigest"] = json!("ignored");
    assert_eq!(
        compute_contract_digest(DigestKind::Policy, &changed_self, &contract).unwrap(),
        expected
    );

    let mut changed_other = policy;
    changed_other["purpose"] = json!("tampered");
    assert_ne!(
        compute_contract_digest(DigestKind::Policy, &changed_other, &contract).unwrap(),
        expected
    );
}

#[test]
fn contract_digest_normalizes_semantic_set_permutations() {
    let contract = contract();
    let policy = read_json("examples/canonical-policy.canonical.json");
    let expected = compute_contract_digest(DigestKind::Policy, &policy, &contract).unwrap();
    let mut permuted = policy;
    permuted["principals"][0]["floor"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(
        compute_contract_digest(DigestKind::Policy, &permuted, &contract).unwrap(),
        expected
    );
}

#[test]
fn malformed_duplicate_or_unsorted_contract_sets_fail_closed() {
    let mut duplicate = contract();
    duplicate.set_keys.insert(1, duplicate.set_keys[0].clone());
    assert!(duplicate.validate().is_err());

    let mut unsorted = contract();
    unsorted.set_keys.swap(0, 1);
    assert!(unsorted.validate().is_err());

    let mut duplicate_keyed = contract();
    duplicate_keyed
        .keyed_sets
        .insert(1, duplicate_keyed.keyed_sets[0].clone());
    assert!(duplicate_keyed.validate().is_err());

    let mut changed_domain = contract();
    changed_domain.domains.policy = "ibex:capsec:policy:future".into();
    assert!(changed_domain.validate().is_err());

    let mut changed_projection = contract();
    changed_projection
        .projections
        .policy
        .omit_fields
        .push("purpose".into());
    assert!(changed_projection.validate().is_err());

    let mut changed_members = contract();
    changed_members.projections.vocabulary.members.pop();
    assert!(changed_members.validate().is_err());

    let mut changed_status = contract();
    changed_status.projections.conformance.status = "available".into();
    assert!(changed_status.validate().is_err());
}

#[test]
fn digest_contract_rejects_unknown_nested_fields() {
    let mut value = read_json("registry/policy-rules.json")["digestContract"].clone();
    value["projections"]["policy"]["legacyProjection"] = json!(true);
    assert!(serde_json::from_value::<DigestContract>(value).is_err());
}

proptest! {
    #[test]
    fn generic_set_canonicalization_is_permutation_and_duplicate_invariant(
        values in proptest::collection::vec(any::<i16>(), 0..40)
    ) {
        let contract = contract();
        let mut reversed = values.clone();
        reversed.reverse();
        reversed.extend(values.iter().copied());
        let left = json!({"examples": values});
        let right = json!({"examples": reversed});
        prop_assert_eq!(
            canonicalize(&left, None, &contract).unwrap(),
            canonicalize(&right, None, &contract).unwrap()
        );
    }
}
