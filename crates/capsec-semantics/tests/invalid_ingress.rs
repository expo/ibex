use capsec_semantics::containment::validate_occurrence_stage_facts;
use capsec_semantics::model::{AuthoritySelector, EffectOccurrence};
use capsec_semantics::registry::ValidatedProfile;
use capsec_semantics::strict_json::parse_slice_strict;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    invalid_fixtures: Vec<InvalidFixture>,
}

#[derive(Deserialize)]
struct InvalidFixture {
    path: String,
    validator: String,
}

#[test]
fn every_contract_invalid_fixture_is_rejected_by_rust_production_ingress() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../capsec");
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(root.join("contract-files.json")).unwrap()).unwrap();
    let definitions = ValidatedProfile::from_json(
        &std::fs::read(root.join("registry/capability-definitions.json")).unwrap(),
        &std::fs::read(root.join("registry/policy-rules.json")).unwrap(),
    )
    .unwrap()
    .definitions;

    for fixture in manifest.invalid_fixtures {
        let bytes = std::fs::read(root.join(&fixture.path)).unwrap();
        let strict = parse_slice_strict(&bytes);
        let rejected = match fixture.validator.as_str() {
            "strict-json" => strict.is_err(),
            "selector" => match strict {
                Err(_) => true,
                Ok(value) => match serde_json::from_value::<AuthoritySelector>(value) {
                    Err(_) => true,
                    Ok(selector) => definitions.validate_selector(&selector).is_err(),
                },
            },
            "occurrence" => match strict {
                Err(_) => true,
                Ok(value) => match serde_json::from_value::<EffectOccurrence>(value) {
                    Err(_) => true,
                    Ok(occurrence) => {
                        !occurrence.principal_context_is_valid()
                            || validate_occurrence_stage_facts(&occurrence).is_err()
                            || occurrence
                                .resource
                                .requested_selector_resource()
                                .is_none_or(|requested| {
                                    definitions
                                        .validate_requested_resource(&occurrence.action, &requested)
                                        .is_err()
                                })
                    }
                },
            },
            other => panic!("unknown invalid-fixture validator {other}"),
        };
        assert!(
            rejected,
            "Rust production ingress accepted {}",
            fixture.path
        );
    }
}
