//! Cross-language fixture parity for typed resources and matching.
//! @ref LLP 0021#wp2--implement-the-typed-policy-and-decision-core — matcher
//! behavior is frozen by fixtures shared with the JavaScript validator.

use capsec_semantics::containment::{
    compare_authority_containment, selector_matches_occurrence, validate_authority_selector,
    validate_occurrence_stage_facts, AuthorityPolarity, Containment, ContainmentContext,
};
use capsec_semantics::model::{
    AuthoritySelector, DecisionSet, EffectOccurrence, IpAddress, OccurrenceResource, PeerClass,
    Stage,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

fn capsec_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("capsec")
        .join(relative)
}

fn read(relative: &str) -> Vec<u8> {
    fs::read(capsec_file(relative)).expect("read committed CapSec fixture")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContainmentDocument {
    containment_schema: String,
    profile: String,
    vectors: Vec<ContainmentVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContainmentVector {
    id: String,
    parent: AuthoritySelector,
    child: AuthoritySelector,
    context: ContainmentContext,
    expected: Containment,
}

#[test]
fn committed_containment_vectors_match_exactly() {
    let document: ContainmentDocument =
        serde_json::from_slice(&read("examples/authority-containment.canonical.json"))
            .expect("deserialize containment vectors");
    assert_eq!(
        document.containment_schema,
        "ibex/capsec-containment-vectors/1"
    );
    assert_eq!(document.profile, "ibex/capsec/1");
    assert_eq!(document.vectors.len(), 23);
    for vector in document.vectors {
        assert_eq!(
            compare_authority_containment(&vector.parent, &vector.child, &vector.context),
            vector.expected,
            "{}",
            vector.id
        );
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectorExamples {
    example_schema: String,
    selectors: Vec<AuthoritySelector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OccurrenceExamples {
    example_schema: String,
    occurrences: Vec<EffectOccurrence>,
}

#[test]
fn every_committed_selector_and_occurrence_deserializes_and_validates() {
    let selectors: SelectorExamples =
        serde_json::from_slice(&read("examples/authority-selectors.canonical.json"))
            .expect("deserialize selector examples");
    assert_eq!(selectors.example_schema, "ibex/capsec-selector-examples/1");
    assert_eq!(selectors.selectors.len(), 16);
    for selector in &selectors.selectors {
        validate_authority_selector(selector).expect("valid committed selector");
    }

    let occurrences: OccurrenceExamples =
        serde_json::from_slice(&read("examples/effect-occurrences.canonical.json"))
            .expect("deserialize occurrence examples");
    assert_eq!(
        occurrences.example_schema,
        "ibex/capsec-occurrence-examples/1"
    );
    assert_eq!(occurrences.occurrences.len(), 15);
    for occurrence in &occurrences.occurrences {
        validate_occurrence_stage_facts(occurrence).unwrap_or_else(|error| {
            panic!(
                "{} / {}: {error}",
                occurrence.action,
                occurrence.resource.requested_kind_name().unwrap()
            )
        });
    }
}

#[test]
fn mixed_principal_sets_use_jcs_order_not_struct_field_order() {
    let occurrence: EffectOccurrence = serde_json::from_value(json!({
        "cap": "ffi:load",
        "stage": "requested",
        "actor": {"kind":"root", "identity":"root"},
        "effectOwner": {
            "kind":"package", "name":"pkg",
            "integrity":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "locator":"pkg@1.0.0"
        },
        "constrainedPrincipals": [
            {"kind":"root", "identity":"root"},
            {
                "kind":"package", "name":"pkg",
                "integrity":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "locator":"pkg@1.0.0"
            }
        ],
        "resource": {
            "kind":"closed-occurrence",
            "requested":{"kind":"closed-surface", "surfaceClass":"ffi"},
            "surface":"ffi.load"
        }
    }))
    .expect("mixed-principal occurrence deserializes");
    assert!(occurrence.principal_context_is_valid());
}

#[test]
fn committed_conjunctive_effect_set_expands_to_valid_occurrences() {
    let set: DecisionSet = serde_json::from_slice(&read("examples/effect-set.canonical.json"))
        .expect("deserialize effect set");
    assert_eq!(set.effects.len(), 6);
    for occurrence in set.occurrences() {
        validate_occurrence_stage_facts(&occurrence).expect("valid factored occurrence");
    }
}

#[test]
fn malformed_selector_semantics_fail_closed() {
    let missing_absolute_binding: AuthoritySelector = serde_json::from_value(json!({
        "cap": "fs:read",
        "resource": {
            "kind": "path-exact",
            "path": { "root": "absolute", "components": [] }
        }
    }))
    .expect("shape deserializes before semantic validation");
    assert!(validate_authority_selector(&missing_absolute_binding).is_err());

    let cidr_host_bits: AuthoritySelector = serde_json::from_value(json!({
        "cap": "network:connect",
        "resource": {
            "kind": "connect-endpoint",
            "transport": "tcp",
            "host": { "kind": "cidr", "network": "203.0.113.7", "prefix": 24 },
            "port": { "kind": "exact", "value": 443 },
            "peerClasses": ["reserved"],
            "route": { "kind": "direct" }
        }
    }))
    .expect("shape deserializes before semantic validation");
    assert!(validate_authority_selector(&cidr_host_bits).is_err());

    let reversed_range: AuthoritySelector = serde_json::from_value(json!({
        "cap": "network:connect",
        "resource": {
            "kind": "connect-endpoint",
            "transport": "tcp",
            "host": { "kind": "dns-name", "name": "example.com" },
            "port": { "kind": "range", "start": 9000, "end": 8000 },
            "peerClasses": ["public"],
            "route": { "kind": "direct" }
        }
    }))
    .expect("shape deserializes before semantic validation");
    assert!(validate_authority_selector(&reversed_range).is_err());

    let duplicate_set: AuthoritySelector = serde_json::from_value(json!({
        "cap": "network:fetch",
        "resource": {
            "kind": "fetch-endpoint",
            "schemes": ["https", "https"],
            "host": { "kind": "dns-name", "name": "example.com" },
            "port": { "kind": "exact", "value": 443 },
            "peerClasses": ["public"],
            "route": { "kind": "direct" }
        }
    }))
    .expect("shape deserializes before semantic validation");
    assert!(validate_authority_selector(&duplicate_set).is_err());
}

#[test]
fn stage_facts_cannot_arrive_speculatively() {
    let mut occurrences: OccurrenceExamples =
        serde_json::from_slice(&read("examples/effect-occurrences.canonical.json"))
            .expect("deserialize occurrence examples");
    let path = occurrences
        .occurrences
        .iter_mut()
        .find(|occurrence| {
            matches!(
                occurrence.resource,
                OccurrenceResource::PathOccurrence { .. }
            )
        })
        .expect("path occurrence");
    path.stage = Stage::Requested;
    assert!(validate_occurrence_stage_facts(path).is_err());
}

#[test]
fn closed_surfaces_never_become_positive_authority() {
    let selector: AuthoritySelector = serde_json::from_value(json!({
        "cap": "ffi:load",
        "resource": { "kind": "closed-surface", "surfaceClass": "ffi" }
    }))
    .unwrap();
    let occurrence: EffectOccurrence = serde_json::from_value(json!({
        "cap": "ffi:load",
        "stage": "requested",
        "actor": { "kind": "root", "identity": "project-root" },
        "effectOwner": { "kind": "root", "identity": "project-root" },
        "constrainedPrincipals": [
            { "kind": "root", "identity": "project-root" }
        ],
        "resource": {
            "kind": "closed-occurrence",
            "requested": { "kind": "closed-surface", "surfaceClass": "ffi" },
            "surface": "ffi.load"
        }
    }))
    .unwrap();
    let classify = |_: IpAddress| Some(PeerClass::Reserved);
    assert!(!selector_matches_occurrence(
        &selector,
        &occurrence,
        &ContainmentContext::SAME_AUTHORITY_DOMAIN,
        AuthorityPolarity::Positive,
        &classify,
    )
    .unwrap());
    assert!(selector_matches_occurrence(
        &selector,
        &occurrence,
        &ContainmentContext::SAME_AUTHORITY_DOMAIN,
        AuthorityPolarity::Denial,
        &classify,
    )
    .unwrap());
}

#[test]
fn selected_network_peer_must_have_an_allowed_class() {
    let selector: AuthoritySelector = serde_json::from_value(json!({
        "cap": "network:connect",
        "resource": {
            "kind": "connect-endpoint",
            "transport": "tls",
            "host": { "kind": "dns-subtree", "apex": "example.com", "includeApex": true },
            "port": { "kind": "exact", "value": 443 },
            "peerClasses": ["public"],
            "route": { "kind": "direct" }
        }
    }))
    .unwrap();
    let occurrence: EffectOccurrence = serde_json::from_value(json!({
        "cap": "network:connect",
        "stage": "candidate",
        "actor": { "kind": "root", "identity": "project-root" },
        "effectOwner": { "kind": "root", "identity": "project-root" },
        "constrainedPrincipals": [
            { "kind": "root", "identity": "project-root" }
        ],
        "resource": {
            "kind": "network-occurrence",
            "requested": {
                "kind": "connect-endpoint",
                "transport": "tls",
                "host": { "kind": "dns-name", "name": "api.example.com" },
                "port": 443
            },
            "route": { "kind": "direct" },
            "candidates": ["93.184.216.34"],
            "selectedCandidate": "93.184.216.34"
        }
    }))
    .unwrap();
    let public = |_: IpAddress| Some(PeerClass::Public);
    let private = |_: IpAddress| Some(PeerClass::Private);
    assert!(selector_matches_occurrence(
        &selector,
        &occurrence,
        &ContainmentContext::SAME_AUTHORITY_DOMAIN,
        AuthorityPolarity::Positive,
        &public,
    )
    .unwrap());
    assert!(!selector_matches_occurrence(
        &selector,
        &occurrence,
        &ContainmentContext::SAME_AUTHORITY_DOMAIN,
        AuthorityPolarity::Positive,
        &private,
    )
    .unwrap());
}

#[test]
fn wire_roundtrip_preserves_committed_selector_shapes() {
    let raw: Value = serde_json::from_slice(&read("examples/authority-selectors.canonical.json"))
        .expect("read JSON value");
    let typed: SelectorExamples = serde_json::from_value(raw.clone()).unwrap();
    let encoded = serde_json::to_value(&typed.selectors).unwrap();
    assert_eq!(encoded, raw["selectors"]);

    let raw: Value = serde_json::from_slice(&read("examples/effect-occurrences.canonical.json"))
        .expect("read occurrence JSON value");
    let typed: OccurrenceExamples = serde_json::from_value(raw.clone()).unwrap();
    let encoded = serde_json::to_value(&typed.occurrences).unwrap();
    assert_eq!(encoded, raw["occurrences"]);
}
