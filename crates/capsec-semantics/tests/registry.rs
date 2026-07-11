use std::collections::BTreeSet;

use capsec_semantics::registry::{CapabilityDefinitionsDocument, DefinitionSet, ValidatedProfile};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RulesProfiles {
    normalization_profiles: Vec<NormalizationProfile>,
}

#[derive(Deserialize)]
struct NormalizationProfile {
    id: String,
}

#[test]
fn committed_definition_registry_is_complete_and_valid() {
    let definitions: CapabilityDefinitionsDocument = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../capsec/registry/capability-definitions.json"
    )))
    .expect("committed definitions deserialize");
    let rules: RulesProfiles = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../capsec/registry/policy-rules.json"
    )))
    .expect("committed rules deserialize");
    let profiles = rules
        .normalization_profiles
        .into_iter()
        .map(|profile| profile.id)
        .collect::<BTreeSet<_>>();

    let definitions = DefinitionSet::validate(definitions, &profiles)
        .expect("committed capability definitions satisfy the semantic core");
    assert_eq!(definitions.len(), 38);
    assert!(definitions.contains("fs:read"));
    assert!(definitions.contains("network:fetch"));
    assert!(!definitions.contains("fs:*"));
    assert!(!definitions.contains("network"));
}

#[test]
fn committed_profile_jointly_validates_through_strict_json() {
    let profile = ValidatedProfile::from_json(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../capsec/registry/capability-definitions.json"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../capsec/registry/policy-rules.json"
        )),
    )
    .expect("committed profile satisfies the neutral semantic core");
    assert_eq!(profile.definitions.len(), 38);
    assert_eq!(profile.normalization_profiles.len(), 15);
}

#[test]
fn duplicate_definition_keys_fail_before_deserialization() {
    let duplicate = br#"{
      "definitionsSchema":"ibex/capsec-definitions/1",
      "profile":"ibex/capsec/1",
      "profile":"ibex/capsec/1",
      "semanticCore":"capsec/semantics/1",
      "definitions":[]
    }"#;
    let rules = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../capsec/registry/policy-rules.json"
    ));
    assert!(ValidatedProfile::from_json(duplicate, rules).is_err());
}

#[test]
fn unknown_definition_fields_fail_deserialization() {
    let malformed = r#"{
      "definitionsSchema":"ibex/capsec-definitions/1",
      "profile":"ibex/capsec/1",
      "semanticCore":"capsec/semantics/1",
      "definitions":[],
      "legacyMatcher":true
    }"#;
    assert!(serde_json::from_str::<CapabilityDefinitionsDocument>(malformed).is_err());
}

#[test]
fn unknown_and_present_empty_selector_constraints_fail() {
    let definitions: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../capsec/registry/capability-definitions.json"
    )))
    .unwrap();
    let rules = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../capsec/registry/policy-rules.json"
    ));

    let mut unknown = definitions.clone();
    let row = unknown["definitions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["id"] == "env:read")
        .unwrap();
    row["selectorConstraints"]["environmentTargets"][0] = Value::String("future-target".into());
    assert!(ValidatedProfile::from_json(&serde_json::to_vec(&unknown).unwrap(), rules).is_err());

    let mut empty = definitions;
    let row = empty["definitions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["id"] == "env:read")
        .unwrap();
    row["selectorConstraints"]["stdioStreams"] = Value::Array(vec![]);
    assert!(ValidatedProfile::from_json(&serde_json::to_vec(&empty).unwrap(), rules).is_err());
}
