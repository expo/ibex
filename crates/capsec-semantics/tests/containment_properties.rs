//! Property checks for the typed containment and occurrence matcher.
//! @ref LLP 0021#wp2--implement-the-typed-policy-and-decision-core — matcher
//! behavior requires property coverage in addition to shared golden vectors.

use capsec_semantics::containment::{
    compare_authority_containment, selector_matches_occurrence, AuthorityPolarity, Containment,
    ContainmentContext,
};
use capsec_semantics::model::{AuthoritySelector, EffectOccurrence, IpAddress, PeerClass};
use proptest::prelude::*;
use serde_json::{json, Value};

fn components(values: &[String]) -> Vec<Value> {
    values
        .iter()
        .map(|value| json!({ "encoding": "utf8", "value": value }))
        .collect()
}

fn path_selector(action: &str, kind: &str, parts: &[String]) -> AuthoritySelector {
    serde_json::from_value(json!({
        "cap": action,
        "resource": {
            "kind": kind,
            "path": { "root": "project", "components": components(parts) }
        }
    }))
    .expect("generated selector is valid")
}

fn requested_path_occurrence(parts: &[String]) -> EffectOccurrence {
    serde_json::from_value(json!({
        "cap": "fs:read",
        "stage": "requested",
        "actor": { "kind": "root", "identity": "project-root" },
        "effectOwner": { "kind": "root", "identity": "project-root" },
        "constrainedPrincipals": [
            { "kind": "root", "identity": "project-root" }
        ],
        "resource": {
            "kind": "path-occurrence",
            "requested": { "root": "project", "components": components(parts) },
            "followMode": "follow-final",
            "objectState": "unknown"
        }
    }))
    .expect("generated occurrence is valid")
}

fn component_vec(min: usize, max: usize) -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec("[a-z][a-z0-9]{0,7}", min..=max)
}

proptest! {
    #[test]
    fn identical_typed_authority_is_equal(parts in component_vec(0, 6)) {
        let selector = path_selector("fs:read", "path-tree", &parts);
        prop_assert_eq!(
            compare_authority_containment(
                &selector,
                &selector,
                &ContainmentContext::SAME_AUTHORITY_DOMAIN,
            ),
            Containment::Equal,
        );
    }

    #[test]
    fn path_tree_containment_is_transitive(
        base in component_vec(0, 3),
        middle_tail in component_vec(1, 2),
        leaf_tail in component_vec(1, 2),
    ) {
        let mut middle = base.clone();
        middle.extend(middle_tail);
        let mut leaf = middle.clone();
        leaf.extend(leaf_tail);
        let parent = path_selector("fs:read", "path-tree", &base);
        let child = path_selector("fs:read", "path-tree", &middle);
        let grandchild = path_selector("fs:read", "path-tree", &leaf);
        let context = ContainmentContext::SAME_AUTHORITY_DOMAIN;

        prop_assert_eq!(compare_authority_containment(&parent, &child, &context), Containment::StrictSubset);
        prop_assert_eq!(compare_authority_containment(&child, &grandchild, &context), Containment::StrictSubset);
        prop_assert_eq!(compare_authority_containment(&parent, &grandchild, &context), Containment::StrictSubset);
        prop_assert_eq!(compare_authority_containment(&grandchild, &parent, &context), Containment::Incomparable);
    }

    #[test]
    fn matcher_agrees_with_path_tree_prefix_containment(
        base in component_vec(0, 3),
        tail in component_vec(1, 3),
    ) {
        let mut requested = base.clone();
        requested.extend(tail);
        let selector = path_selector("fs:read", "path-tree", &base);
        let occurrence = requested_path_occurrence(&requested);
        let classify = |_: IpAddress| Some(PeerClass::Reserved);

        prop_assert!(selector_matches_occurrence(
            &selector,
            &occurrence,
            &ContainmentContext::SAME_AUTHORITY_DOMAIN,
            AuthorityPolarity::Positive,
            &classify,
        ).expect("generated matcher input is valid"));

        let unrelated = path_selector("fs:read", "path-tree", &["unrelated".to_owned()]);
        prop_assert!(!selector_matches_occurrence(
            &unrelated,
            &occurrence,
            &ContainmentContext::SAME_AUTHORITY_DOMAIN,
            AuthorityPolarity::Positive,
            &classify,
        ).expect("generated matcher input is valid"));
    }

    #[test]
    fn action_or_snapshot_changes_never_widen_authority(parts in component_vec(0, 6)) {
        let read = path_selector("fs:read", "path-tree", &parts);
        let write = path_selector("fs:write", "path-tree", &parts);
        prop_assert_eq!(
            compare_authority_containment(&read, &write, &ContainmentContext::SAME_AUTHORITY_DOMAIN),
            Containment::Incomparable,
        );
        prop_assert_eq!(
            compare_authority_containment(
                &read,
                &read,
                &ContainmentContext { same_snapshot: false, same_package_root_owner: true },
            ),
            Containment::Incomparable,
        );
    }
}
