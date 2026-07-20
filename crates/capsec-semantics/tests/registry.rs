use std::collections::BTreeSet;

use capsec_semantics::model::AuthoritySelector;
use capsec_semantics::registry::{
    CapabilityDefinitionsDocument, DefinitionSet, PrincipalConstraint, ResourceKind,
    ValidatedProfile,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RulesProfiles {
    normalization_profiles: Vec<NormalizationProfile>,
}

#[test]
fn escape_and_shared_process_surfaces_remain_deny_only_with_closed_channels() {
    let definitions: CapabilityDefinitionsDocument = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../capsec/registry/capability-definitions.json"
    )))
    .unwrap();
    let expected = BTreeSet::from([
        "env:process-write",
        "ffi:load",
        "inspector:activate",
        "ipc:channel",
        "process:identity",
        "process:limit",
        "process:priority",
        "process:signal",
        "process:umask",
        "runtime:inspect",
        "storage:persist",
        "storage:read",
        "storage:write",
        "vm:evaluate",
        "wasi:instantiate",
        "worker:create",
    ]);
    let actual = definitions
        .definitions
        .iter()
        .filter(|definition| {
            definition.lifecycle == capsec_semantics::registry::Lifecycle::DenyOnly
        })
        .map(|definition| definition.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    for definition in definitions
        .definitions
        .iter()
        .filter(|definition| expected.contains(definition.id.as_str()))
    {
        assert!(!definition.channels.dynamic);
        assert!(!definition.channels.handle);
        assert!(!definition.channels.synthesis);
    }
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
    assert_eq!(definitions.len(), 41);
    assert!(definitions.contains("fs:read"));
    assert!(definitions.contains("gpu:operation"));
    assert!(definitions.contains("network:fetch"));
    let lifecycle = definitions.get("lifecycle:exit").unwrap();
    assert_eq!(
        lifecycle.principal_constraint,
        Some(PrincipalConstraint::RootOnly)
    );
    assert_eq!(
        lifecycle.resource_kinds,
        vec![ResourceKind::SessionLifecycle]
    );
    assert!(!lifecycle.channels.dynamic);
    assert!(!lifecycle.channels.handle);
    let cwd_mutate = definitions.get("path:cwd-mutate").unwrap();
    assert_eq!(
        cwd_mutate.principal_constraint,
        Some(PrincipalConstraint::RootOnly)
    );
    assert_eq!(cwd_mutate.resource_kinds, vec![ResourceKind::PathExact]);
    let cwd_observe = definitions.get("path:cwd-observe").unwrap();
    assert_eq!(cwd_observe.resource_kinds, vec![ResourceKind::SessionState]);
    assert!(cwd_observe.static_only);
    assert!(!definitions.contains("process:cwd"));
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
    assert_eq!(profile.definitions.len(), 41);
    assert_eq!(profile.normalization_profiles.len(), 18);
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

#[test]
fn action_specific_selector_constraints_are_executable() {
    let definitions = ValidatedProfile::from_json(
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
    .definitions;
    let rejected = [
        serde_json::json!({
            "cap": "env:write",
            "resource": {"kind":"environment-name","target":"broker-base","name":"PATH"}
        }),
        serde_json::json!({
            "cap": "stdio:write",
            "resource": {"kind":"stdio","stream":"stdin","source":{"kind":"terminal","identity":"terminal-1"}}
        }),
        serde_json::json!({
            "cap": "stdio:raw",
            "resource": {"kind":"stdio","stream":"stdin","source":{"kind":"pipe","identity":"pipe-1"}}
        }),
        serde_json::json!({
            "cap": "process:identity",
            "resource": {"kind":"closed-surface","surfaceClass":"process-cwd"}
        }),
        serde_json::json!({
            "cap": "storage:persist",
            "resource": {"kind":"storage-namespace","store":"session","namespace":{"kind":"principal"}}
        }),
    ];
    for value in rejected {
        let selector: AuthoritySelector = serde_json::from_value(value).unwrap();
        assert!(definitions.validate_selector(&selector).is_err());
    }

    for value in [
        serde_json::json!({
            "cap": "env:write",
            "resource": {"kind":"environment-name","target":"principal-overlay","name":"PATH"}
        }),
        serde_json::json!({
            "cap": "stdio:write",
            "resource": {"kind":"stdio","stream":"stdout","source":{"kind":"pipe","identity":"pipe-1"}}
        }),
        serde_json::json!({
            "cap": "process:identity",
            "resource": {"kind":"closed-surface","surfaceClass":"process-identity"}
        }),
        serde_json::json!({
            "cap": "fs:read",
            "resource": {"kind":"path-tree","path":{"root":"project","components":[]}}
        }),
        serde_json::json!({
            "cap": "network:connect",
            "resource": {"kind":"connect-endpoint","transport":"tcp","host":{"kind":"dns-name","name":"example.com"},"port":{"kind":"exact","value":443},"peerClasses":["public"],"route":{"kind":"direct"}}
        }),
    ] {
        let selector: AuthoritySelector = serde_json::from_value(value).unwrap();
        definitions.validate_selector(&selector).unwrap();
    }
}
