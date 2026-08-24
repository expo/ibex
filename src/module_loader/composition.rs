//! Frozen package-aware composition wire and digest surfaces.
//!
//! This module deliberately contains no admission driver. It parses the two
//! independent channel records, validates envelope-shaped JSON bounds, and
//! exposes the evidence digest used by later LLP 0056 implementation legs.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use capsec_semantics::model::Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::artifact::source_integrity;

pub use super::composition_refusals_generated::{
    composition_step_default, CompositionRefusalClass, CompositionRefusalCode,
    COMPOSITION_ENVIRONMENT_CODES_V1,
};

/// Domain for the canonical prepared-composition envelope.
// @ref LLP 0056#2-terminology--composition-role-is-not-principal — composition domains are lockstep wire literals.
pub const PREPARED_COMPOSITION_ROOT_DOMAIN_V1: &str = "ibex:prepared-composition-root:1";

/// Domain for a canonical prepared-package index.
pub const PREPARED_PACKAGE_ROOT_DOMAIN_V1: &str = "ibex:prepared-package-root:1";

/// Domain for the canonical package-partition preimage.
pub const PREPARED_PARTITION_DOMAIN_V1: &str = "ibex:prepared-partition:1";

/// Domain for the canonical union binding-table preimage.
pub const PREPARED_UNION_TABLE_DOMAIN_V1: &str = "ibex:prepared-union-table:1";

/// Domain for the canonical host-bridged boundary inventory preimage.
pub const PREPARED_BOUNDARY_INVENTORY_DOMAIN_V1: &str = "ibex:prepared-boundary-inventory:1";

/// Domain for the canonical alias-table preimage.
pub const PREPARED_ALIAS_TABLE_DOMAIN_V1: &str = "ibex:prepared-alias-table:1";

/// Domain for the canonical composition entry-plan preimage.
pub const PREPARED_ENTRY_PLAN_DOMAIN_V1: &str = "ibex:prepared-entry-plan:1";

/// Domain for one package's role-scoped semantic graph.
pub const PREPARED_PACKAGE_GRAPH_DOMAIN_V1: &str = "ibex:prepared-package-graph:1";

/// Schema identifier for a host-held prepared-composition commitment.
pub const PREPARED_COMPOSITION_COMMITMENT_SCHEMA_V1: &str =
    "ibex/prepared-composition-commitment/1";

/// Schema identifier for verifier-held composition expectations.
pub const COMPOSITION_VERIFIER_EXPECTATIONS_SCHEMA_V1: &str =
    "ibex/composition-verifier-expectations/1";

/// Channel token for malformed or non-canonical composition records.
pub const IBEX_DEV_COMPOSITION_CORRUPT: &str = "IBEX_DEV_COMPOSITION_CORRUPT";

/// Channel token for unsupported composition record schemas or invariants.
pub const IBEX_DEV_COMPOSITION_SCHEMA: &str = "IBEX_DEV_COMPOSITION_SCHEMA";

/// Channel token for use of the dev composition seam in an armed context.
pub const IBEX_DEV_COMPOSITION_ARMED_CONTEXT: &str = "IBEX_DEV_COMPOSITION_ARMED_CONTEXT";

/// Maximum byte length of the prepared-composition envelope.
pub const MAX_COMPOSITION_ENVELOPE_BYTES_V1: u64 = 64 * 1024 * 1024;

/// Maximum number of declared composition roles.
pub const MAX_COMPOSITION_ROLES_V1: usize = 2;

/// Maximum number of records in one prepared package.
pub const MAX_PACKAGE_RECORDS_V1: usize = 65_536;

/// Maximum number of declared edges in one prepared package.
pub const MAX_PACKAGE_DECLARED_EDGES_V1: usize = 1_048_576;

/// Maximum number of rows in the composition alias table.
pub const MAX_COMPOSITION_ALIAS_ROWS_V1: usize = 1_024;

/// Maximum number of external references in a prepared composition.
pub const MAX_COMPOSITION_EXTERNAL_REFERENCES_V1: usize = 4_096;

/// Maximum UTF-8 byte length of a JSON string value or object key.
pub const MAX_COMPOSITION_STRING_BYTES_V1: usize = 4_096;

/// Maximum recursive JSON depth, with the root at depth zero.
pub const MAX_COMPOSITION_NESTING_DEPTH_V1: usize = 16;

/// Largest integer that is exactly interoperable under I-JSON and RFC 8785.
pub const I_JSON_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// A package-level composition role, never a capability-security `Principal`.
// @ref LLP 0056#2-terminology--composition-role-is-not-principal — role and defining principal are distinct identity axes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompositionRole {
    /// The required application package.
    App,
    /// The optional agent package.
    Agent,
}

impl CompositionRole {
    /// Return the exact lowercase wire spelling for this role.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Agent => "agent",
        }
    }
}

/// Host-held digest-only commitment to canonical composition envelope bytes.
// @ref LLP 0056#32-host-held-commitment-the-33-channel--a-digest-nothing-else — no served-envelope fact is duplicated here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedCompositionCommitmentV1 {
    /// Versioned commitment schema identifier.
    pub schema: String,
    /// Production-shaped workflow marker; posture belongs to the entry type.
    pub workflow: String,
    /// Digest of the canonical prepared-composition envelope.
    pub composition_root_digest: Digest,
}

/// Verifier-held live expectations compared during later composition admission.
// @ref LLP 0056#33-verifier-held-expectations — live facts occupy one independent verifier channel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionVerifierExpectationsV1 {
    /// Versioned expectations schema identifier.
    pub schema: String,
    /// Exact embedder target expected for this startup.
    pub expected_target: String,
    /// Effective package roles expected by the verifier.
    pub expected_roles: Vec<CompositionRole>,
    /// Live session nonce used by later anti-replay checks.
    pub session_nonce: String,
    /// Live authority generation used by later freshness checks.
    pub authority_generation: u64,
    /// Live resolver generation used by later freshness checks.
    pub resolver_generation: u64,
    /// Digest of the verifier's effective policy.
    pub policy_digest: Digest,
    /// Digest of the frozen resolver and transform inventory.
    pub resolver_inventory_digest: Digest,
    /// Verifier-supplied wall-clock instant for deterministic expiry checks.
    pub now_unix_ms: u64,
}

/// One ordered `(role, packageRoot, producerGeneration)` envelope attestation.
///
/// This triple is the one serialized carrier of a package's produce
/// generation. No sidecar or delivery wrapper may carry that fact.
// @ref LLP 0056#48-generation-attestation-envelope-side-decidable-splice — one committed carrier prevents unauthenticated generation drift.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionPackageAttestationV1 {
    /// Package role attested by this row.
    pub role: CompositionRole,
    /// Digest of the role's canonical prepared-package index.
    pub package_root: Digest,
    /// Producer generation committed into the composition envelope.
    pub producer_generation: u64,
}

/// One source import site contributing to committed alias evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AliasImportSiteV1 {
    /// Authenticated importer identity or spelling supplied by the evidence corpus.
    pub importer: String,
    /// Imported alias specifier at that source site.
    pub specifier: String,
}

/// Parse and validate a strict canonical host-held composition commitment.
pub fn parse_prepared_composition_commitment_v1(
    text: &str,
) -> Result<PreparedCompositionCommitmentV1> {
    let value = parse_canonical_channel_value(text, "commitment")?;
    let commitment: PreparedCompositionCommitmentV1 = serde_json::from_value(value)
        .map_err(|error| anyhow!("{IBEX_DEV_COMPOSITION_CORRUPT} commitment shape: {error}"))?;
    if commitment.schema != PREPARED_COMPOSITION_COMMITMENT_SCHEMA_V1 {
        bail!("{IBEX_DEV_COMPOSITION_SCHEMA} unsupported prepared-composition commitment schema");
    }
    if commitment.workflow != "production" {
        bail!(
            "{IBEX_DEV_COMPOSITION_SCHEMA} dev-served commitment must be the production-shaped \
             record (workflow=production); the dev posture lives in the composition entry type"
        );
    }
    Ok(commitment)
}

/// Parse and validate strict canonical verifier-held composition expectations.
pub fn parse_composition_verifier_expectations_v1(
    text: &str,
) -> Result<CompositionVerifierExpectationsV1> {
    let value = parse_canonical_channel_value(text, "expectations")?;
    let expectations: CompositionVerifierExpectationsV1 = serde_json::from_value(value)
        .map_err(|error| anyhow!("{IBEX_DEV_COMPOSITION_CORRUPT} expectations shape: {error}"))?;
    if expectations.schema != COMPOSITION_VERIFIER_EXPECTATIONS_SCHEMA_V1 {
        bail!("{IBEX_DEV_COMPOSITION_SCHEMA} unsupported composition verifier expectations schema");
    }
    if !matches!(
        expectations.expected_roles.as_slice(),
        [CompositionRole::App] | [CompositionRole::App, CompositionRole::Agent]
    ) {
        bail!(
            "{IBEX_DEV_COMPOSITION_SCHEMA} expectedRoles must be exactly [\"app\"] or [\"app\",\"agent\"]"
        );
    }
    for (field, value) in [
        ("authorityGeneration", expectations.authority_generation),
        ("resolverGeneration", expectations.resolver_generation),
        ("nowUnixMs", expectations.now_unix_ms),
    ] {
        if value > I_JSON_MAX_SAFE_INTEGER {
            bail!(
                "{IBEX_DEV_COMPOSITION_CORRUPT} expectations {field} exceeds the I-JSON safe integer maximum"
            );
        }
    }
    Ok(expectations)
}

/// Parse the envelope's ordered package-attestation array without admitting it.
///
/// Generation equality against composition freshness is intentionally deferred
/// to leg 2; this function only validates typed row shape and local ordering.
pub fn parse_composition_package_attestations_v1(
    value: &Value,
) -> Result<Vec<CompositionPackageAttestationV1>> {
    let rows = value
        .as_array()
        .ok_or_else(|| anyhow!("composition packages must be an array"))?;
    if rows.is_empty() || rows.len() > MAX_COMPOSITION_ROLES_V1 {
        bail!("composition packages must contain between 1 and {MAX_COMPOSITION_ROLES_V1} rows");
    }

    let mut parsed = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let attestation: CompositionPackageAttestationV1 = serde_json::from_value(row.clone())
            .map_err(|error| {
                anyhow!("composition package attestation row {index} has invalid shape: {error}")
            })?;
        if attestation.producer_generation > I_JSON_MAX_SAFE_INTEGER {
            bail!(
                "composition package attestation row {index} producerGeneration exceeds the I-JSON safe integer maximum"
            );
        }
        if parsed
            .last()
            .is_some_and(|previous: &CompositionPackageAttestationV1| {
                previous.role >= attestation.role
            })
        {
            bail!("composition package roles must be unique and ordered app before agent");
        }
        parsed.push(attestation);
    }
    Ok(parsed)
}

/// Return the first prepared-composition JSON wire-bound violation, if any.
// @ref LLP 0056#31-served-bytes-artifact-storage-untrusted-until-admitted — envelope and package JSON share these scalar wire bounds.
pub fn check_composition_wire_bounds(value: &Value) -> Option<String> {
    check_composition_wire_bounds_at(value, "$", 0)
}

fn check_composition_wire_bounds_at(value: &Value, path: &str, depth: usize) -> Option<String> {
    if depth > MAX_COMPOSITION_NESTING_DEPTH_V1 {
        return Some(format!(
            "nesting depth exceeds {MAX_COMPOSITION_NESTING_DEPTH_V1} at {path}"
        ));
    }
    match value {
        Value::Null | Value::Bool(_) => None,
        Value::Number(number) => {
            let safe = number
                .as_i64()
                .is_some_and(|value| value.unsigned_abs() <= I_JSON_MAX_SAFE_INTEGER)
                || number
                    .as_u64()
                    .is_some_and(|value| value <= I_JSON_MAX_SAFE_INTEGER);
            (!safe).then(|| {
                format!("number is not a safe integer (I-JSON/RFC 8785 integer rule) at {path}")
            })
        }
        Value::String(text) => (text.len() > MAX_COMPOSITION_STRING_BYTES_V1).then(|| {
            format!("string exceeds {MAX_COMPOSITION_STRING_BYTES_V1} UTF-8 bytes at {path}")
        }),
        Value::Array(values) => values.iter().enumerate().find_map(|(index, entry)| {
            check_composition_wire_bounds_at(entry, &format!("{path}[{index}]"), depth + 1)
        }),
        Value::Object(entries) => {
            for (key, entry) in entries {
                if key.len() > MAX_COMPOSITION_STRING_BYTES_V1 {
                    return Some(format!(
                        "object key exceeds {MAX_COMPOSITION_STRING_BYTES_V1} UTF-8 bytes at {path}"
                    ));
                }
                if let Some(violation) =
                    check_composition_wire_bounds_at(entry, &format!("{path}.{key}"), depth + 1)
                {
                    return Some(violation);
                }
            }
            None
        }
    }
}

/// Compute the un-domained digest of deduplicated, sorted alias import sites.
///
/// This mirrors the Exact-side O-3 algorithm authority
/// (`computeAliasImportSiteInventoryDigest`) operation-for-operation, because
/// producer and verifier must reach identical bytes: rows are deduplicated by
/// the SPACE-JOINED `"importer specifier"` key with last-write-wins Map
/// semantics, then sorted by `(importer, specifier)` under UTF-16 code-unit
/// order (JavaScript string `<`). The joined-key collision class (importer
/// `"a b"` + specifier `"c"` collides with importer `"a"` + specifier
/// `"b c"`) is authority-inherited and reproduced deliberately — a one-sided
/// "fix" here would diverge from committed evidence; changing the algorithm
/// is an O-1 package amendment on the Exact side first.
// @ref LLP 0056#47-the-committed-alias-table-verification-inputs — alias evidence is source inventory, not a commitment domain.
pub fn compute_alias_import_site_inventory_digest(rows: &[AliasImportSiteV1]) -> Result<Digest> {
    let mut unique: BTreeMap<String, &AliasImportSiteV1> = BTreeMap::new();
    for row in rows {
        // Last wins, exactly like `new Map(rows.map(row => [key, row]))`.
        unique.insert(format!("{} {}", row.importer, row.specifier), row);
    }
    let mut sorted = unique.into_values().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        compare_utf16(&left.importer, &right.importer)
            .then_with(|| compare_utf16(&left.specifier, &right.specifier))
    });
    let value = serde_json::to_value(sorted)?;
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)?;
    source_integrity(&canonical)
}

/// Compare two strings in UTF-16 code-unit order (JavaScript string `<`).
fn compare_utf16(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn parse_canonical_channel_value(text: &str, record: &str) -> Result<Value> {
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|error| anyhow!("{IBEX_DEV_COMPOSITION_CORRUPT} {record}: {error}"))?;
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&value).map_err(|error| {
        anyhow!("{IBEX_DEV_COMPOSITION_CORRUPT} {record} canonicalization: {error}")
    })?;
    if canonical != text.trim_end_matches('\n').as_bytes() {
        bail!("{IBEX_DEV_COMPOSITION_CORRUPT} {record} is not canonical JCS");
    }
    if let Some(violation) = check_composition_wire_bounds(&value) {
        bail!("{IBEX_DEV_COMPOSITION_CORRUPT} {record}: {violation}");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_digest(label: &str) -> String {
        source_integrity(label.as_bytes())
            .unwrap()
            .as_str()
            .to_owned()
    }

    fn commitment_value() -> Value {
        json!({
            "schema": PREPARED_COMPOSITION_COMMITMENT_SCHEMA_V1,
            "workflow": "production",
            "compositionRootDigest": valid_digest("composition-root"),
        })
    }

    fn expectations_value() -> Value {
        json!({
            "schema": COMPOSITION_VERIFIER_EXPECTATIONS_SCHEMA_V1,
            "expectedTarget": "exact-dev:mac",
            "expectedRoles": ["app"],
            "sessionNonce": "session",
            "authorityGeneration": 1,
            "resolverGeneration": 7,
            "policyDigest": valid_digest("policy"),
            "resolverInventoryDigest": valid_digest("resolver"),
            "nowUnixMs": 1_755_990_000_000_u64,
        })
    }

    fn canonical(value: &Value) -> String {
        capsec_semantics::canonical::to_jcs(value).unwrap()
    }

    #[test]
    fn strict_commitment_ingest_rejects_noncanonical_and_invalid_records() {
        let valid = commitment_value();
        assert!(parse_prepared_composition_commitment_v1(&canonical(&valid)).is_ok());

        let mut unknown = valid.clone();
        unknown["unknown"] = json!(true);
        let error = parse_prepared_composition_commitment_v1(&canonical(&unknown)).unwrap_err();
        assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_CORRUPT));

        let mut wrong_schema = valid.clone();
        wrong_schema["schema"] = json!("ibex/prepared-composition-commitment/2");
        let error =
            parse_prepared_composition_commitment_v1(&canonical(&wrong_schema)).unwrap_err();
        assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_SCHEMA));

        let mut wrong_workflow = valid.clone();
        wrong_workflow["workflow"] = json!("development");
        let error =
            parse_prepared_composition_commitment_v1(&canonical(&wrong_workflow)).unwrap_err();
        assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_SCHEMA));

        let pretty = serde_json::to_string_pretty(&valid).unwrap();
        let error = parse_prepared_composition_commitment_v1(&pretty).unwrap_err();
        assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_CORRUPT));

        let duplicate = format!(
            "{{\"compositionRootDigest\":{},\"schema\":{},\"schema\":{},\"workflow\":\"production\"}}",
            serde_json::to_string(&valid["compositionRootDigest"]).unwrap(),
            serde_json::to_string(PREPARED_COMPOSITION_COMMITMENT_SCHEMA_V1).unwrap(),
            serde_json::to_string(PREPARED_COMPOSITION_COMMITMENT_SCHEMA_V1).unwrap(),
        );
        let error = parse_prepared_composition_commitment_v1(&duplicate).unwrap_err();
        assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_CORRUPT));
    }

    #[test]
    fn strict_expectations_ingest_rejects_shape_number_and_role_violations() {
        let valid = expectations_value();
        assert!(parse_composition_verifier_expectations_v1(&canonical(&valid)).is_ok());

        let mut unknown = valid.clone();
        unknown["unknown"] = json!(true);
        let error = parse_composition_verifier_expectations_v1(&canonical(&unknown)).unwrap_err();
        assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_CORRUPT));

        let mut wrong_schema = valid.clone();
        wrong_schema["schema"] = json!("ibex/composition-verifier-expectations/2");
        let error =
            parse_composition_verifier_expectations_v1(&canonical(&wrong_schema)).unwrap_err();
        assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_SCHEMA));

        let pretty = serde_json::to_string_pretty(&valid).unwrap();
        let error = parse_composition_verifier_expectations_v1(&pretty).unwrap_err();
        assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_CORRUPT));

        let duplicate = canonical(&valid).replacen(
            "\"authorityGeneration\":1,",
            "\"authorityGeneration\":1,\"authorityGeneration\":1,",
            1,
        );
        let error = parse_composition_verifier_expectations_v1(&duplicate).unwrap_err();
        assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_CORRUPT));

        for bad_number in [json!(1.5), json!(-1)] {
            let mut value = valid.clone();
            value["authorityGeneration"] = bad_number;
            let error = parse_composition_verifier_expectations_v1(&canonical(&value)).unwrap_err();
            assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_CORRUPT));
        }
        let mut unsafe_integer = valid.clone();
        unsafe_integer["authorityGeneration"] = json!(I_JSON_MAX_SAFE_INTEGER + 1);
        let unsafe_text = serde_json::to_string(&unsafe_integer).unwrap();
        let error = parse_composition_verifier_expectations_v1(&unsafe_text).unwrap_err();
        assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_CORRUPT));

        let mut maximum_integer = valid.clone();
        maximum_integer["authorityGeneration"] = json!(I_JSON_MAX_SAFE_INTEGER);
        assert!(parse_composition_verifier_expectations_v1(&canonical(&maximum_integer)).is_ok());

        for roles in [
            json!([]),
            json!(["agent"]),
            json!(["app", "app"]),
            json!(["agent", "app"]),
        ] {
            let mut value = valid.clone();
            value["expectedRoles"] = roles;
            let error = parse_composition_verifier_expectations_v1(&canonical(&value)).unwrap_err();
            assert!(error.to_string().starts_with(IBEX_DEV_COMPOSITION_SCHEMA));
        }
    }

    #[test]
    fn wire_bounds_match_exact_depth_string_and_integer_edges() {
        let mut depth_16 = json!(0);
        for _ in 0..MAX_COMPOSITION_NESTING_DEPTH_V1 {
            depth_16 = json!([depth_16]);
        }
        assert_eq!(check_composition_wire_bounds(&depth_16), None);
        assert!(check_composition_wire_bounds(&json!([depth_16]))
            .unwrap()
            .contains("nesting depth"));

        assert_eq!(
            check_composition_wire_bounds(&json!("a".repeat(MAX_COMPOSITION_STRING_BYTES_V1))),
            None
        );
        assert!(check_composition_wire_bounds(&json!(
            "a".repeat(MAX_COMPOSITION_STRING_BYTES_V1 + 1)
        ))
        .unwrap()
        .contains("string exceeds"));

        let long_key = "k".repeat(MAX_COMPOSITION_STRING_BYTES_V1 + 1);
        let object = Value::Object([(long_key, Value::Null)].into_iter().collect());
        assert!(check_composition_wire_bounds(&object)
            .unwrap()
            .contains("object key exceeds"));

        assert_eq!(
            check_composition_wire_bounds(&json!(I_JSON_MAX_SAFE_INTEGER)),
            None
        );
        assert!(check_composition_wire_bounds(&json!(I_JSON_MAX_SAFE_INTEGER + 1)).is_some());
    }

    #[test]
    fn package_attestation_parse_is_shape_only_and_ordered() {
        let app = json!({
            "role": "app",
            "packageRoot": valid_digest("app"),
            "producerGeneration": 7,
        });
        let agent = json!({
            "role": "agent",
            "packageRoot": valid_digest("agent"),
            "producerGeneration": 7,
        });
        assert_eq!(
            parse_composition_package_attestations_v1(&json!([app.clone(), agent.clone()]))
                .unwrap()
                .len(),
            2
        );
        assert!(parse_composition_package_attestations_v1(&json!([])).is_err());
        assert!(parse_composition_package_attestations_v1(&json!([agent, app])).is_err());
    }

    #[test]
    fn alias_inventory_deduplicates_first_and_sorts() {
        let rows = vec![
            AliasImportSiteV1 {
                importer: "/src/b.ts".into(),
                specifier: "./alias".into(),
            },
            AliasImportSiteV1 {
                importer: "/src/a.ts".into(),
                specifier: "./alias".into(),
            },
            AliasImportSiteV1 {
                importer: "/src/b.ts".into(),
                specifier: "./alias".into(),
            },
        ];
        let expected = source_integrity(
            br#"[{"importer":"/src/a.ts","specifier":"./alias"},{"importer":"/src/b.ts","specifier":"./alias"}]"#,
        )
        .unwrap();
        assert_eq!(
            compute_alias_import_site_inventory_digest(&rows).unwrap(),
            expected
        );
    }

    #[test]
    fn alias_inventory_mirrors_the_authority_joined_key_last_wins_dedupe() {
        // "a b" + "c" and "a" + "b c" share the joined key "a b c"; the
        // authority's Map keeps the LAST row only. Reproduced deliberately.
        let rows = vec![
            AliasImportSiteV1 {
                importer: "a b".into(),
                specifier: "c".into(),
            },
            AliasImportSiteV1 {
                importer: "a".into(),
                specifier: "b c".into(),
            },
        ];
        let expected = source_integrity(br#"[{"importer":"a","specifier":"b c"}]"#).unwrap();
        assert_eq!(
            compute_alias_import_site_inventory_digest(&rows).unwrap(),
            expected
        );
    }

    #[test]
    fn alias_inventory_sorts_by_utf16_code_units_like_javascript() {
        // U+10000 encodes as the surrogate pair D800 DC00, which sorts BEFORE
        // U+E000 under UTF-16 code-unit order (JavaScript `<`) even though it
        // is the larger code point (Rust `str` order would reverse them).
        let astral = "\u{10000}";
        let private_use = "\u{e000}";
        let rows = vec![
            AliasImportSiteV1 {
                importer: private_use.into(),
                specifier: "s".into(),
            },
            AliasImportSiteV1 {
                importer: astral.into(),
                specifier: "s".into(),
            },
        ];
        let expected_value = serde_json::json!([
            { "importer": astral, "specifier": "s" },
            { "importer": private_use, "specifier": "s" },
        ]);
        let expected =
            source_integrity(&capsec_semantics::canonical::to_jcs_bytes(&expected_value).unwrap())
                .unwrap();
        assert_eq!(
            compute_alias_import_site_inventory_digest(&rows).unwrap(),
            expected
        );
    }
}
