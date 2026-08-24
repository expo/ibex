use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use ibex_runtime::module_loader::artifact::{digest_bytes, source_integrity};
use ibex_runtime::module_loader::composition::{
    check_composition_wire_bounds, composition_step_default,
    compute_alias_import_site_inventory_digest, parse_composition_package_attestations_v1,
    parse_composition_verifier_expectations_v1, parse_prepared_composition_commitment_v1,
    AliasImportSiteV1, CompositionRefusalCode, CompositionRole, PreparedCompositionV1,
    COMPOSITION_ENVIRONMENT_CODES_V1, I_JSON_MAX_SAFE_INTEGER, MAX_COMPOSITION_ALIAS_ROWS_V1,
    MAX_COMPOSITION_ENVELOPE_BYTES_V1, MAX_COMPOSITION_EXTERNAL_REFERENCES_V1,
    MAX_COMPOSITION_NESTING_DEPTH_V1, MAX_COMPOSITION_ROLES_V1, MAX_COMPOSITION_STRING_BYTES_V1,
    MAX_PACKAGE_DECLARED_EDGES_V1, MAX_PACKAGE_RECORDS_V1, PREPARED_ALIAS_TABLE_DOMAIN_V1,
    PREPARED_COMPOSITION_ROOT_DOMAIN_V1, PREPARED_PACKAGE_ROOT_DOMAIN_V1,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/prepared-composition/v1")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn vector<'a>(corpus: &'a Value, name: &str) -> &'a Value {
    corpus["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == name)
        .unwrap_or_else(|| panic!("missing vector {name}"))
}

fn lowercase_sha256(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn assert_manifest_hashes(root: &Path) {
    let manifest = read_json(&root.join("manifest.json"));
    for relative in manifest["files"].as_object().unwrap().keys() {
        let bytes = fs::read(root.join(relative)).unwrap();
        assert_eq!(
            lowercase_sha256(&bytes),
            manifest["files"][relative]["sha256"].as_str().unwrap(),
            "vendored fixture hash drifted for {relative}"
        );
    }
}

fn assert_inline_vectors(corpus: &Value) {
    for vector in corpus["vectors"].as_array().unwrap() {
        if vector["kind"] != "inline" {
            continue;
        }
        let canonical = capsec_semantics::canonical::to_jcs(&vector["value"]).unwrap();
        assert_eq!(canonical, vector["canonicalBytes"].as_str().unwrap());
        assert_eq!(
            canonical.len() as u64,
            vector["canonicalByteLength"].as_u64().unwrap()
        );

        let name = vector["name"].as_str().unwrap();
        let domain = vector["domain"].as_str().unwrap();
        let digest = if name == "alias-import-site-inventory-digest" {
            // This O-3 vector pins the unsorted input bytes separately while
            // its digest contract canonicalizes the deduplicated/sorted rows.
            let rows: Vec<AliasImportSiteV1> =
                serde_json::from_value(vector["value"].clone()).unwrap();
            compute_alias_import_site_inventory_digest(&rows).unwrap()
        } else if domain.starts_with("sha256 (un-domained") {
            source_integrity(canonical.as_bytes()).unwrap()
        } else {
            digest_bytes(domain, canonical.as_bytes()).unwrap()
        };
        assert_eq!(digest.as_str(), vector["digest"].as_str().unwrap());
    }
}

fn assert_typed_ingest(corpus: &Value) {
    let commitment_vector = vector(corpus, "prepared-composition-commitment-record");
    let commitment_bytes = commitment_vector["canonicalBytes"].as_str().unwrap();
    let commitment = parse_prepared_composition_commitment_v1(commitment_bytes).unwrap();
    assert_eq!(
        capsec_semantics::canonical::to_jcs(&serde_json::to_value(&commitment).unwrap()).unwrap(),
        commitment_bytes
    );
    assert!(parse_prepared_composition_commitment_v1(&format!("{commitment_bytes}\n")).is_ok());
    assert!(parse_prepared_composition_commitment_v1(&format!(" {commitment_bytes}")).is_err());

    let expectations_vector = vector(corpus, "composition-verifier-expectations");
    let expectations_bytes = expectations_vector["canonicalBytes"].as_str().unwrap();
    let expectations = parse_composition_verifier_expectations_v1(expectations_bytes).unwrap();
    assert_eq!(
        capsec_semantics::canonical::to_jcs(&serde_json::to_value(&expectations).unwrap()).unwrap(),
        expectations_bytes
    );
    assert_eq!(expectations.expected_target, "exact-dev:mac");
    assert_eq!(expectations.expected_roles, [CompositionRole::App]);
    assert_eq!(expectations.authority_generation, 1);
    assert_eq!(expectations.resolver_generation, 7);
    assert_eq!(expectations.now_unix_ms, 1_755_990_000_000);

    let composition = &vector(corpus, "minimal-app-only-composition-root")["value"];
    let composition_bytes =
        capsec_semantics::canonical::to_jcs_bytes(composition).expect("canonical composition");
    let decoded = PreparedCompositionV1::decode_canonical(&composition_bytes).unwrap();
    assert_eq!(decoded.schema, "exact/prepared-composition/1");
    assert_eq!(decoded.declaration, ["app"]);
    let packages = parse_composition_package_attestations_v1(&composition["packages"]).unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].role, CompositionRole::App);
    assert_eq!(
        packages[0].package_root.as_str(),
        composition["packages"][0]["packageRoot"].as_str().unwrap()
    );
    assert_eq!(packages[0].producer_generation, 7);
    assert_eq!(
        packages[0].producer_generation,
        composition["freshness"]["resolverGeneration"]
            .as_u64()
            .unwrap()
    );

    let alias = vector(corpus, "alias-import-site-inventory-digest");
    let rows: Vec<AliasImportSiteV1> = serde_json::from_value(alias["value"].clone()).unwrap();
    assert_eq!(
        compute_alias_import_site_inventory_digest(&rows)
            .unwrap()
            .as_str(),
        alias["digest"].as_str().unwrap()
    );
}

fn alias_recipe(count: usize) -> Value {
    Value::Array(
        (0..count)
            .map(|index| {
                let source_integrity = source_integrity(format!("alias-{index}").as_bytes())
                    .unwrap()
                    .as_str()
                    .to_owned();
                let import_site_inventory_digest =
                    compute_alias_import_site_inventory_digest(&[AliasImportSiteV1 {
                        importer: format!("/src/m{index}.ts"),
                        specifier: format!("./alias-{index}"),
                    }])
                    .unwrap()
                    .as_str()
                    .to_owned();
                json!({
                    "aliasId": format!("/@fs/repo/js/src/alias-{index}.ts"),
                    "representativeSourceId": format!("ibex-source-id-v1:vec{index}"),
                    "representativeSourceIntegrity": source_integrity,
                    "importSiteInventoryDigest": import_site_inventory_digest,
                })
            })
            .collect(),
    )
}

fn nesting_recipe(depth: usize) -> Value {
    let mut value = json!(0);
    for _ in 0..depth {
        value = json!([value]);
    }
    value
}

fn roles_recipe(count: usize) -> Value {
    let roles = ["app", "agent", "extra"];
    Value::Array(
        (0..count)
            .map(|index| {
                json!({
                    "role": roles[index.min(2)],
                    "packageRoot": digest_bytes(
                        PREPARED_PACKAGE_ROOT_DOMAIN_V1,
                        format!("roles-recipe-{index}").as_bytes(),
                    )
                    .unwrap()
                    .as_str(),
                })
            })
            .collect(),
    )
}

fn assert_recipe_vectors(corpus: &Value) {
    for vector in corpus["vectors"].as_array().unwrap() {
        if vector["kind"] != "recipe" {
            continue;
        }
        let recipe = &vector["recipe"];
        let kind = recipe["kind"].as_str().unwrap();
        let amount = recipe
            .get("count")
            .or_else(|| recipe.get("bytes"))
            .or_else(|| recipe.get("depth"))
            .and_then(Value::as_u64)
            .unwrap() as usize;

        let (value, refusal_bound) = match kind {
            "alias-rows" => (
                alias_recipe(amount),
                (amount > MAX_COMPOSITION_ALIAS_ROWS_V1).then_some("maxAliasRows"),
            ),
            "bounded-string" => {
                let value = json!({ "s": "a".repeat(amount) });
                let violation = check_composition_wire_bounds(&value);
                (
                    value,
                    violation.map(|detail| {
                        assert!(detail.contains("string exceeds"));
                        "maxStringBytes"
                    }),
                )
            }
            "nesting" => {
                let value = nesting_recipe(amount);
                let violation = check_composition_wire_bounds(&value);
                (
                    value,
                    violation.map(|detail| {
                        assert!(detail.contains("nesting depth"));
                        "maxNestingDepth"
                    }),
                )
            }
            "roles" => (
                roles_recipe(amount),
                (amount > MAX_COMPOSITION_ROLES_V1).then_some("maxRoles"),
            ),
            other => panic!("unsupported recipe kind {other}"),
        };

        if let Some(bound) = refusal_bound {
            assert_eq!(vector["expectError"], "envelope-malformed");
            assert_eq!(vector["bound"], bound);
            assert_eq!(
                CompositionRefusalCode::EnvelopeMalformed.as_str(),
                vector["expectError"].as_str().unwrap()
            );
            continue;
        }

        let canonical = capsec_semantics::canonical::to_jcs(&value).unwrap();
        assert_eq!(
            canonical.len() as u64,
            vector["canonicalByteLength"].as_u64().unwrap()
        );
        assert_eq!(
            lowercase_sha256(canonical.as_bytes()),
            vector["canonicalBytesSha256"].as_str().unwrap()
        );
        let domain = match kind {
            "alias-rows" => PREPARED_ALIAS_TABLE_DOMAIN_V1,
            "bounded-string" | "nesting" | "roles" => PREPARED_COMPOSITION_ROOT_DOMAIN_V1,
            _ => unreachable!(),
        };
        assert_eq!(vector["domain"], domain);
        assert_eq!(
            digest_bytes(domain, canonical.as_bytes()).unwrap().as_str(),
            vector["digest"].as_str().unwrap()
        );
    }
}

fn assert_registry_parity(root: &Path) {
    let registry = read_json(&root.join("refusals.generated.json"));
    let rows = registry["admissionRows"].as_array().unwrap();
    assert_eq!(rows.len(), 38);
    for (index, row) in rows.iter().enumerate() {
        let code = CompositionRefusalCode::ALL[index];
        assert_eq!(code.as_str(), row["code"].as_str().unwrap());
        assert_eq!(code.ordinal() as u64, row["ordinal"].as_u64().unwrap());
        assert_eq!(code.step() as u64, row["step"].as_u64().unwrap());
        assert_eq!(code.class().as_str(), row["class"].as_str().unwrap());
        assert_eq!(CompositionRefusalCode::from_code(code.as_str()), Some(code));
    }
    assert_eq!(
        CompositionRefusalCode::from_code("ibex:compiler-fingerprint-mismatch"),
        None
    );
    assert_eq!(
        CompositionRefusalCode::from_code("ibex:engine-binary-digest-mismatch"),
        None
    );

    let defaults = registry["stepDefaults"].as_object().unwrap();
    assert_eq!(defaults.len(), 9);
    for (step, expected) in defaults {
        assert_eq!(
            composition_step_default(step).unwrap().as_str(),
            expected.as_str().unwrap()
        );
    }
    assert_eq!(composition_step_default("9"), None);

    let environment = registry["environmentCodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(environment, COMPOSITION_ENVIRONMENT_CODES_V1);
    let admission_codes = CompositionRefusalCode::ALL
        .iter()
        .map(CompositionRefusalCode::as_str)
        .collect::<BTreeSet<_>>();
    assert!(environment
        .iter()
        .all(|code| !admission_codes.contains(code)));
}

#[test]
fn exact_prepared_composition_vectors_and_registry_match_rust() {
    let root = fixture_root();
    let corpus = read_json(&root.join("vectors/canonical-bytes.json"));
    assert_eq!(corpus["schema"], "exact/prepared-composition-vectors/1");
    assert_eq!(corpus["canonicalization"], "rfc8785-jcs");
    assert_eq!(corpus["vectors"].as_array().unwrap().len(), 21);
    assert_eq!(
        corpus["bounds"],
        json!({
            "maxEnvelopeBytes": MAX_COMPOSITION_ENVELOPE_BYTES_V1,
            "maxRoles": MAX_COMPOSITION_ROLES_V1,
            "maxRecordsPerPackage": MAX_PACKAGE_RECORDS_V1,
            "maxDeclaredEdges": MAX_PACKAGE_DECLARED_EDGES_V1,
            "maxAliasRows": MAX_COMPOSITION_ALIAS_ROWS_V1,
            "maxExternalReferences": MAX_COMPOSITION_EXTERNAL_REFERENCES_V1,
            "maxStringBytes": MAX_COMPOSITION_STRING_BYTES_V1,
            "maxNestingDepth": MAX_COMPOSITION_NESTING_DEPTH_V1,
        })
    );
    assert_eq!(I_JSON_MAX_SAFE_INTEGER, 9_007_199_254_740_991);

    assert_manifest_hashes(&root);
    assert_inline_vectors(&corpus);
    assert_typed_ingest(&corpus);
    assert_recipe_vectors(&corpus);
    assert_registry_parity(&root);
}
