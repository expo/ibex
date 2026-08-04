//! Production admission for portable-engine CapSec target advertisements.
//!
//! This module deliberately keeps the three authorities separate: checked
//! publication bytes select one v2 target row, the build-authenticated A/P/C
//! marker opens that row, and fresh process-local reconstruction proves the
//! engine that is actually mapped. None of the mapped identity is serialized
//! into the publication.
//!
//! @ref LLP 0035#promotion-lineage-and-admission — only the checked C form may
//! open production; A and later descendants remain closed.
//! @ref LLP 0035#runtime-identity-split — portable equality and an independent
//! mapped-instance proof are both required at Host startup.
//! @ref LLP 0035#reports-and-advertisements — v2 advertisements publish the
//! portable identity and detached mapped-evidence references, never locality.

use crate::engine::portable_identity::{
    MappedEngineInstanceIdentity, PortableEngineArtifactIdentity, RawSha256Digest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use capsec_semantics::decision::TargetCellDisposition;
use capsec_semantics::model::Digest;
use capsec_semantics::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const ADVERTISEMENT_SCHEMA_V1: &str = "ibex/capsec-target-advertisements/1";
const ADVERTISEMENT_SCHEMA_V2: &str = "ibex/capsec-target-advertisements/2";
const CAPSEC_PROFILE: &str = "ibex/capsec/1";
const PROMOTION_ADMISSION_SCHEMA: &str = "ibex/portable-engine-checked-promotion-admission/1";
const PROMOTION_ADMISSION_DOMAIN: &str = "ibex.portable-engine-checked-promotion-admission.v1";
const REPORT_SCHEMA_V2: &str = "ibex/capsec-conformance/2";
const REPORT_DOMAIN_V2: &str = "ibex:capsec:conformance:2";
const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;
const CHECKED_IMPLEMENTATION_MANIFEST_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/capsec/generated/implementation-manifest.json"
));

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdvertisementTarget {
    triple: String,
    features: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MappedEvidenceReference {
    evidence_digest: Digest,
    raw_content_digest: Digest,
    attempt_digest: Digest,
    attempt_raw_content_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TargetAdvertisement {
    target: AdvertisementTarget,
    conformance_digest: Digest,
    report_raw_content_digest: Digest,
    source_revision: String,
    source_tree_digest: Digest,
    engine: PortableEngineArtifactIdentity,
    mapped_engine_execution_evidence: Vec<MappedEvidenceReference>,
    vocabulary_digest: Digest,
    registry_digest: Digest,
    implementation_manifest_digest: Digest,
    fixture_catalog_digest: Digest,
    recipe_catalog_digest: Digest,
    recipe_catalog_raw_content_digest: Digest,
    public_surface_execution_digest: Digest,
    public_surface_execution_raw_content_digest: Digest,
    output_disposition_evidence_raw_content_digest: Digest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetAdvertisementCatalog {
    target_advertisement_schema: String,
    profile: String,
    target_cells_raw_content_digest: Digest,
    advertisements: Vec<TargetAdvertisement>,
}

#[derive(Clone, Debug)]
pub(super) struct SelectedTargetAdvertisement {
    advertisement: TargetAdvertisement,
    target_cells_raw_content_digest: Digest,
}

impl std::ops::Deref for SelectedTargetAdvertisement {
    type Target = TargetAdvertisement;

    fn deref(&self) -> &Self::Target {
        &self.advertisement
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckedPromotionAdmission {
    schema: String,
    authorized: bool,
    current_revision: String,
    source_revision: String,
    promotion_topic_revision: Option<String>,
    source_tree_object_id: Option<String>,
    target_triple: String,
    portable_artifact_id: Digest,
    admission_digest: Option<Digest>,
    verification_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConformanceRunnerBinding {
    source_revision: String,
    source_tree_digest: Digest,
    artifact_id: Digest,
    build_consumption_digest: Digest,
    post_link_set_digest: Digest,
    verification_digest: Digest,
    test_executable_digest: RawSha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportBindings {
    source_revision: String,
    source_tree_digest: Digest,
    conformance_runner: ConformanceRunnerBinding,
    engine: PortableEngineArtifactIdentity,
    target: AdvertisementTarget,
    vocabulary_digest: Digest,
    registry_digest: Digest,
    implementation_manifest_digest: Digest,
    fixture_catalog_digest: Digest,
    recipe_catalog_digest: Digest,
    recipe_catalog_raw_content_digest: Digest,
    public_surface_execution_digest: Digest,
    public_surface_execution_raw_content_digest: Digest,
    target_cells_raw_content_digest: Digest,
    output_disposition_evidence_raw_content_digest: Digest,
    mapped_engine_execution_evidence: Vec<MappedEvidenceReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportSummary {
    cells: u64,
    conformant_cells: u64,
    incomplete_cells: u64,
    required_fixtures: u64,
    passed_fixtures: u64,
    missing_fixtures: u64,
    failed_fixtures: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportExecution {
    fixture_id: String,
    outcome: String,
    executor: String,
    artifact_digest: Digest,
    raw_content_digest: Digest,
    binding_digest: Digest,
    mapped_engine_execution_evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportCell {
    edge_id: String,
    implementation_branch_ids: Vec<String>,
    enforcement_branch_ids: Vec<String>,
    status: String,
    required_fixtures: Vec<String>,
    passed_fixtures: Vec<String>,
    missing_fixtures: Vec<String>,
    failed_fixtures: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PortableConformanceReport {
    conformance_schema: String,
    profile: String,
    status: String,
    bindings: ReportBindings,
    summary: ReportSummary,
    executions: Vec<ReportExecution>,
    cells: Vec<ReportCell>,
    conformance_digest: Digest,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidModel(message.into())
}

fn refused(message: impl Into<String>) -> Error {
    Error::ArmRefused(message.into())
}

fn exact_object_keys(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{label} is not an object")))?;
    if object.len() != expected.len() || expected.iter().any(|field| !object.contains_key(*field)) {
        return Err(invalid(format!("{label} does not have its exact fields")));
    }
    Ok(())
}

fn valid_sha1_object_id(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_capsec_stable_id(value: &str) -> bool {
    let mut expect_segment_start = true;
    for byte in value.bytes() {
        if matches!(byte, b'.' | b'_' | b'/' | b'-') {
            if expect_segment_start {
                return false;
            }
            expect_segment_start = true;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            expect_segment_start = false;
        } else {
            return false;
        }
    }
    !expect_segment_start
}

fn valid_portable_target_triple(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    matches!(
        parts.as_slice(),
        ["aarch64" | "x86_64", "apple", "darwin"]
            | ["aarch64" | "x86_64", "unknown", "linux", "gnu" | "musl"]
            | ["aarch64" | "x86_64", "pc", "windows", "msvc"]
    )
}

fn validate_target(target: &AdvertisementTarget, label: &str) -> Result<()> {
    if !valid_portable_target_triple(&target.triple) {
        return Err(invalid(format!(
            "{label}.triple is unsupported or malformed"
        )));
    }
    for feature in &target.features {
        if !valid_capsec_stable_id(feature) {
            return Err(invalid(format!(
                "{label}.features contains an invalid stable ID"
            )));
        }
    }
    if target
        .features
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(invalid(format!(
            "{label}.features is not canonically sorted and unique"
        )));
    }
    Ok(())
}

fn validate_canonical_ids(values: &[String], label: &str) -> Result<()> {
    if values.iter().any(|value| !valid_capsec_stable_id(value)) {
        return Err(invalid(format!("{label} contains an invalid stable ID")));
    }
    if values
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(invalid(format!(
            "{label} is not canonically sorted and unique"
        )));
    }
    Ok(())
}

fn validate_evidence_references(references: &[MappedEvidenceReference]) -> Result<()> {
    if references.is_empty() {
        return Err(invalid(
            "target advertisement has no mapped-engine execution evidence",
        ));
    }
    if references.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid(
            "mapped-engine evidence references are not canonically sorted and unique",
        ));
    }
    let unique_column = |values: Vec<&Digest>| values.into_iter().collect::<BTreeSet<_>>().len();
    let expected = references.len();
    if unique_column(
        references
            .iter()
            .map(|reference| &reference.evidence_digest)
            .collect(),
    ) != expected
        || unique_column(
            references
                .iter()
                .map(|reference| &reference.raw_content_digest)
                .collect(),
        ) != expected
        || unique_column(
            references
                .iter()
                .map(|reference| &reference.attempt_digest)
                .collect(),
        ) != expected
        || unique_column(
            references
                .iter()
                .map(|reference| &reference.attempt_raw_content_digest)
                .collect(),
        ) != expected
    {
        return Err(invalid(
            "mapped-engine evidence references repeat one identity column",
        ));
    }
    Ok(())
}

fn validate_conformance_runner_binding(
    binding: &ConformanceRunnerBinding,
    source_revision: &str,
    source_tree_digest: &Digest,
    engine: &PortableEngineArtifactIdentity,
) -> Result<()> {
    if !valid_sha1_object_id(&binding.source_revision)
        || binding.source_revision != source_revision
        || &binding.source_tree_digest != source_tree_digest
        || binding.artifact_id != engine.artifact_id
    {
        return Err(refused(
            "promoted report conformance runner differs from its source or portable engine binding",
        ));
    }
    for digest in [
        &binding.build_consumption_digest,
        &binding.post_link_set_digest,
        &binding.verification_digest,
    ] {
        if digest.as_str().len() != "sha256-".len() + 43 {
            return Err(invalid(
                "promoted report conformance runner has a malformed stage digest",
            ));
        }
    }
    if binding.test_executable_digest.as_str().len() != "sha256-".len() + 64 {
        return Err(invalid(
            "promoted report conformance runner has a malformed executable digest",
        ));
    }
    Ok(())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_once(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut index = 0;
    while index < bytes.len() {
        if index + 2 < bytes.len() && bytes[index] == b'%' {
            if let (Some(high), Some(low)) =
                (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
            {
                decoded.push((high << 4) | low);
                changed = true;
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    changed.then(|| String::from_utf8(decoded).ok()).flatten()
}

fn boundary_before(bytes: &[u8], index: usize) -> bool {
    index == 0
        || bytes[index - 1].is_ascii_whitespace()
        || matches!(bytes[index - 1], b'"' | b'\'' | b'(' | b'=')
}

fn looks_host_local(value: &str) -> bool {
    let mut variants = vec![value.trim().to_owned()];
    for _ in 0..3 {
        let Some(decoded) = percent_decode_once(variants.last().expect("one variant")) else {
            break;
        };
        if variants.contains(&decoded) {
            break;
        }
        variants.push(decoded);
    }
    variants.into_iter().any(|variant| {
        let lower = variant.to_ascii_lowercase();
        let bytes = lower.as_bytes();
        (0..bytes.len()).any(|index| {
            if !boundary_before(bytes, index) {
                return false;
            }
            let rest = &bytes[index..];
            rest.starts_with(b"file://")
                || (rest.starts_with(b"/") && !rest.starts_with(b"//"))
                || (rest.len() >= 3
                    && rest[0].is_ascii_alphabetic()
                    && rest[1] == b':'
                    && matches!(rest[2], b'/' | b'\\'))
                || (rest.starts_with(b"\\\\") && rest.get(2).is_some_and(|byte| *byte != b'\\'))
                || [b"dev:".as_slice(), b"file:", b"ino:", b"inode:", b"volume:"]
                    .iter()
                    .any(|prefix| rest.starts_with(prefix))
                || (rest.starts_with(b"0x")
                    && rest[2..]
                        .iter()
                        .take_while(|byte| byte.is_ascii_hexdigit())
                        .count()
                        > 0
                    && {
                        let end = 2 + rest[2..]
                            .iter()
                            .take_while(|byte| byte.is_ascii_hexdigit())
                            .count();
                        end == rest.len()
                            || rest.get(end).is_some_and(|byte| {
                                byte.is_ascii_whitespace()
                                    || matches!(*byte, b'"' | b'\'' | b')' | b',' | b';')
                            })
                    })
        })
    })
}

fn reject_published_locality(value: &Value, path: &str) -> Result<()> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "after",
        "before",
        "binarydigest",
        "canonicallocalruntimepath",
        "engineartifactpath",
        "enginebinarydigest",
        "localobject",
        "mappedengine",
        "mappedobject",
        "mappingproof",
        "object",
        "observationdigest",
        "processarchitecture",
        "regionend",
        "regionstart",
        "targetarchitecture",
    ];
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_published_locality(value, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                if FORBIDDEN_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
                    return Err(invalid(format!(
                        "{path}.{key} is a mapped/local engine field"
                    )));
                }
                reject_published_locality(value, &format!("{path}.{key}"))?;
            }
        }
        Value::String(text) if looks_host_local(text) => {
            return Err(invalid(format!(
                "{path} contains a host-local path, URI, address, or object identity"
            )))
        }
        _ => {}
    }
    Ok(())
}

fn raw_content_digest(bytes: &[u8]) -> String {
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

fn validate_advertisement(advertisement: &TargetAdvertisement, index: usize) -> Result<()> {
    let label = format!("target advertisements[{index}]");
    validate_target(&advertisement.target, &format!("{label}.target"))?;
    if !valid_sha1_object_id(&advertisement.source_revision) {
        return Err(invalid(format!("{label}.sourceRevision is malformed")));
    }
    advertisement
        .engine
        .validate()
        .map_err(|error| invalid(format!("{label}.engine is invalid: {error}")))?;
    if advertisement.engine.target.triple != advertisement.target.triple {
        return Err(invalid(format!(
            "{label}.engine target differs from its CapSec target"
        )));
    }
    validate_evidence_references(&advertisement.mapped_engine_execution_evidence)
}

/// Select one exact v2 row. Legacy v1 is recognized only as an explicitly
/// closed compatibility state. The target-cell digest is joined later to the
/// exact promoted report because source A intentionally retains only its
/// all-unsupported diagnostic catalog.
pub(super) fn select_v2_advertisement(
    advertisements_text: &str,
    target: &str,
    features: &[String],
) -> Result<SelectedTargetAdvertisement> {
    let value = capsec_semantics::strict_json::parse_strict(advertisements_text)
        .map_err(|error| invalid(format!("invalid checked target advertisements: {error}")))?;
    let schema = value
        .get("targetAdvertisementSchema")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("checked target advertisements have no schema"))?;
    if schema == ADVERTISEMENT_SCHEMA_V1 {
        return Err(refused(
            "legacy v1 target advertisements are diagnostic-only and remain closed; ordinary `ibex run` cannot arm until the standard promotion pipeline ships a generated v2 advertisement for this target; `--project-root` selects the mounted project but does not mint advertisements; use `ibex capsec audit <file>` only for unarmed diagnostics",
        ));
    }
    if schema != ADVERTISEMENT_SCHEMA_V2 {
        return Err(invalid(format!(
            "unsupported target advertisement schema {schema:?}"
        )));
    }
    reject_published_locality(&value, "targetAdvertisements")?;
    let catalog: TargetAdvertisementCatalog = serde_json::from_value(value).map_err(|error| {
        invalid(format!(
            "invalid checked v2 target advertisement model: {error}"
        ))
    })?;
    if catalog.target_advertisement_schema != ADVERTISEMENT_SCHEMA_V2
        || catalog.profile != CAPSEC_PROFILE
    {
        return Err(invalid(
            "checked v2 target advertisements have the wrong schema or profile",
        ));
    }
    for (index, advertisement) in catalog.advertisements.iter().enumerate() {
        validate_advertisement(advertisement, index)?;
        if catalog.advertisements[..index].contains(advertisement) {
            return Err(invalid("checked target advertisements repeat a row"));
        }
    }
    let matching = catalog
        .advertisements
        .into_iter()
        .filter(|advertisement| {
            advertisement.target.triple == target && advertisement.target.features == features
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(refused(format!(
            "engine target {target} with its exact features has no unique verified advertisement"
        )));
    }
    Ok(SelectedTargetAdvertisement {
        advertisement: matching.into_iter().next().expect("one checked match"),
        target_cells_raw_content_digest: catalog.target_cells_raw_content_digest,
    })
}

fn parse_checked_promotion_admission(text: &str) -> Result<(Value, CheckedPromotionAdmission)> {
    if text == "null\n" {
        return Err(refused(
            "portable-engine promotion admission is absent from this build",
        ));
    }
    let canonical = text
        .strip_suffix('\n')
        .ok_or_else(|| invalid("checked promotion admission must end in exactly one line feed"))?;
    if canonical.ends_with('\n') {
        return Err(invalid(
            "checked promotion admission has more than one trailing line feed",
        ));
    }
    let value = capsec_semantics::strict_json::parse_strict(canonical)
        .map_err(|error| invalid(format!("invalid checked promotion admission: {error}")))?;
    let expected_canonical = capsec_semantics::canonical::to_jcs(&value).map_err(|error| {
        invalid(format!(
            "checked promotion admission is not I-JSON: {error}"
        ))
    })?;
    if expected_canonical != canonical {
        return Err(invalid(
            "checked promotion admission bytes are not exact RFC 8785 JCS",
        ));
    }
    exact_object_keys(
        &value,
        &[
            "schema",
            "authorized",
            "currentRevision",
            "sourceRevision",
            "promotionTopicRevision",
            "sourceTreeObjectId",
            "targetTriple",
            "portableArtifactId",
            "admissionDigest",
            "verificationDigest",
        ],
        "checked promotion admission",
    )?;
    let admission = serde_json::from_value(value.clone()).map_err(|error| {
        invalid(format!(
            "invalid checked promotion admission model: {error}"
        ))
    })?;
    Ok((value, admission))
}

/// Require the exact build-authenticated A/P/C admission and join all selectors
/// that are independently present in the v2 publication.
pub(super) fn require_checked_promotion(
    advertisement: &SelectedTargetAdvertisement,
    admission_text: &str,
) -> Result<()> {
    let (value, admission) = parse_checked_promotion_admission(admission_text)?;
    if admission.schema != PROMOTION_ADMISSION_SCHEMA {
        return Err(invalid("checked promotion admission has the wrong schema"));
    }
    if !valid_sha1_object_id(&admission.current_revision)
        || !valid_sha1_object_id(&admission.source_revision)
    {
        return Err(invalid(
            "checked promotion admission carries a malformed revision",
        ));
    }
    let expected_digest = capsec_semantics::digest::compute_domain_digest(
        PROMOTION_ADMISSION_DOMAIN,
        &value,
        &["verificationDigest".to_owned()],
    )
    .map_err(|error| {
        invalid(format!(
            "cannot verify checked promotion admission: {error}"
        ))
    })?;
    if admission.verification_digest.as_str() != expected_digest {
        return Err(refused(
            "checked promotion admission verification digest does not bind its exact fields",
        ));
    }
    if !admission.authorized {
        if admission.current_revision != admission.source_revision
            || admission.promotion_topic_revision.is_some()
            || admission.source_tree_object_id.is_some()
            || admission.admission_digest.is_some()
        {
            return Err(invalid(
                "diagnostic promotion admission carries unauthorized lineage authority",
            ));
        }
        return Err(refused(
            "diagnostic portable-engine admission does not authorize production",
        ));
    }
    let topic = admission
        .promotion_topic_revision
        .as_deref()
        .ok_or_else(|| invalid("authorized promotion admission has no promotion topic revision"))?;
    let source_tree = admission
        .source_tree_object_id
        .as_deref()
        .ok_or_else(|| invalid("authorized promotion admission has no source tree object"))?;
    if !valid_sha1_object_id(topic)
        || !valid_sha1_object_id(source_tree)
        || admission.admission_digest.is_none()
        || admission.current_revision == admission.source_revision
        || admission.current_revision == topic
        || admission.source_revision == topic
    {
        return Err(invalid(
            "authorized promotion admission A/P/C lineage is malformed",
        ));
    }
    if admission.source_revision != advertisement.source_revision {
        return Err(refused(
            "promotion admission source revision differs from the advertisement",
        ));
    }
    if admission.target_triple != advertisement.target.triple {
        return Err(refused(
            "promotion admission target differs from the advertisement",
        ));
    }
    if admission.portable_artifact_id != advertisement.engine.artifact_id {
        return Err(refused(
            "promotion admission artifact differs from the advertisement",
        ));
    }
    Ok(())
}

fn validate_report_cell(cell: &ReportCell, index: usize) -> Result<()> {
    let label = format!("promoted report cells[{index}]");
    if !valid_capsec_stable_id(&cell.edge_id) || cell.status != "conformant" {
        return Err(invalid(format!(
            "{label} has a malformed edge or non-conformant status"
        )));
    }
    for (values, field) in [
        (&cell.implementation_branch_ids, "implementationBranchIds"),
        (&cell.enforcement_branch_ids, "enforcementBranchIds"),
        (&cell.required_fixtures, "requiredFixtures"),
        (&cell.passed_fixtures, "passedFixtures"),
        (&cell.missing_fixtures, "missingFixtures"),
        (&cell.failed_fixtures, "failedFixtures"),
    ] {
        validate_canonical_ids(values, &format!("{label}.{field}"))?;
    }
    if cell.required_fixtures != cell.passed_fixtures
        || !cell.missing_fixtures.is_empty()
        || !cell.failed_fixtures.is_empty()
    {
        return Err(refused(format!(
            "{label} does not carry complete passing fixture evidence"
        )));
    }
    let implementation_prefix = format!("{}.", cell.edge_id);
    if cell.implementation_branch_ids.iter().any(|branch| {
        !branch.starts_with(&implementation_prefix)
            || crate::capsec_registry_generated::CAPSEC_IMPLEMENTATION_BRANCH_IDS
                .binary_search(&branch.as_str())
                .is_err()
    }) || cell.enforcement_branch_ids.iter().any(|branch| {
        crate::capsec_registry_generated::CAPSEC_ENFORCEMENT_BRANCH_IDS
            .binary_search(&branch.as_str())
            .is_err()
    }) {
        return Err(refused(format!(
            "{label} names a branch outside the checked inventory"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct CheckedCoverageSemantics {
    classification: String,
    effect_mode: Option<String>,
    surface_observed_key: String,
    action_ids: Vec<String>,
    logical_branch_action_ids: Vec<(String, Vec<String>)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckedTargetCellAuthority {
    implementation_branch_ids: Vec<String>,
    enforcement_branch_ids: Vec<String>,
    required_fixtures: Vec<String>,
}

#[derive(Clone, Debug)]
struct CheckedReportAuthority {
    implementation_manifest_digest: Digest,
    fixture_catalog_digest: Digest,
    cells: BTreeMap<String, CheckedTargetCellAuthority>,
}

#[derive(Clone, Debug)]
struct CheckedImplementationRow {
    edge_id: String,
    branch_id: String,
    enforcement_branch_id: String,
    terminal_observed_key: String,
    fixture_obligations: Vec<String>,
}

fn required_string<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| invalid(format!("{label}.{field} is missing or malformed")))
}

fn required_canonical_ids(value: &Value, field: &str, label: &str) -> Result<Vec<String>> {
    let values = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("{label}.{field} is missing or malformed")))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(format!("{label}.{field} contains a non-string ID")))
        })
        .collect::<Result<Vec<_>>>()?;
    validate_canonical_ids(&values, &format!("{label}.{field}"))?;
    Ok(values)
}

fn canonical_value_digest(value: &Value, label: &str) -> Result<Digest> {
    let canonical = capsec_semantics::canonical::to_jcs(value)
        .map_err(|error| invalid(format!("cannot canonicalize {label}: {error}")))?;
    Digest::new(&raw_content_digest(canonical.as_bytes()))
        .map_err(|error| invalid(format!("cannot digest {label}: {error}")))
}

fn effect_action_ids(value: Option<&Value>, label: &str) -> Result<Vec<String>> {
    let Some(effects) = value else {
        return Ok(Vec::new());
    };
    let effects = effects
        .as_array()
        .ok_or_else(|| invalid(format!("{label} is not an array")))?;
    let mut action_ids = effects
        .iter()
        .map(|effect| required_string(effect, "cap", label).map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    action_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    action_ids.dedup();
    Ok(action_ids)
}

fn checked_coverage_semantics() -> Result<BTreeMap<String, CheckedCoverageSemantics>> {
    let coverage = capsec_semantics::strict_json::parse_strict(
        crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGES_JSON,
    )
    .map_err(|error| invalid(format!("invalid checked coverage edges: {error}")))?;
    if coverage.get("coverageSchema").and_then(Value::as_str) != Some("ibex/capsec-coverage/1")
        || coverage.get("profile").and_then(Value::as_str) != Some(CAPSEC_PROFILE)
    {
        return Err(invalid(
            "checked coverage edges have the wrong schema or profile",
        ));
    }
    let rows = coverage
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("checked coverage edges have no rows"))?;
    let mut semantics = BTreeMap::new();
    for row in rows {
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("checked coverage edge has no ID"))?;
        let classification = row
            .get("classification")
            .and_then(Value::as_str)
            .filter(|value| matches!(*value, "effects" | "closed" | "non-capability"))
            .ok_or_else(|| invalid(format!("checked coverage edge {id} has no closed class")))?;
        let effect_mode = row
            .get("effectMode")
            .map(|value| {
                value
                    .as_str()
                    .filter(|mode| {
                        matches!(
                            *mode,
                            "conjunctive" | "conditional" | "conditional-unrefined"
                        )
                    })
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        invalid(format!(
                            "checked coverage edge {id} has an invalid effect mode"
                        ))
                    })
            })
            .transpose()?;
        let surface = row
            .get("surface")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid(format!("checked coverage edge {id} has no surface")))?;
        let surface_kind = surface
            .get("kind")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid(format!("checked coverage edge {id} has no surface kind")))?;
        let surface_name = surface
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid(format!("checked coverage edge {id} has no surface name")))?;
        let action_ids =
            effect_action_ids(row.get("effects"), &format!("checked edge {id}.effects"))?;
        let logical_branch_action_ids = row
            .get("logicalBranches")
            .map(|value| {
                value
                    .as_array()
                    .ok_or_else(|| {
                        invalid(format!(
                            "checked coverage edge {id}.logicalBranches is not an array"
                        ))
                    })?
                    .iter()
                    .map(|branch| {
                        let branch_id = required_string(
                            branch,
                            "id",
                            &format!("checked coverage edge {id}.logicalBranches"),
                        )?
                        .to_owned();
                        if !valid_capsec_stable_id(&branch_id) {
                            return Err(invalid(format!(
                                "checked coverage edge {id} has an invalid logical branch ID"
                            )));
                        }
                        let actions = effect_action_ids(
                            branch.get("effects"),
                            &format!(
                                "checked coverage edge {id}.logicalBranches[{branch_id}].effects"
                            ),
                        )?;
                        Ok((branch_id, actions))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        if logical_branch_action_ids
            .windows(2)
            .any(|pair| pair[0].0.as_bytes() >= pair[1].0.as_bytes())
        {
            return Err(invalid(format!(
                "checked coverage edge {id} logical branches are not canonically ordered"
            )));
        }
        if semantics
            .insert(
                id.to_owned(),
                CheckedCoverageSemantics {
                    classification: classification.to_owned(),
                    effect_mode,
                    surface_observed_key: format!("{surface_kind}:{surface_name}"),
                    action_ids,
                    logical_branch_action_ids,
                },
            )
            .is_some()
        {
            return Err(invalid(format!("checked coverage edge {id} is duplicated")));
        }
    }
    if semantics.len() != crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS.len()
        || crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS
            .iter()
            .any(|edge| !semantics.contains_key(*edge))
    {
        return Err(invalid(
            "checked coverage rows differ from the generated exact edge inventory",
        ));
    }
    Ok(semantics)
}

fn checked_target_implementation_branches(
    target: &AdvertisementTarget,
    coverage: &BTreeMap<String, CheckedCoverageSemantics>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let cells = capsec_semantics::strict_json::parse_strict(
        crate::capsec_registry_generated::CAPSEC_TARGET_CELLS_JSON,
    )
    .map_err(|error| invalid(format!("invalid checked target cells: {error}")))?;
    if cells.get("targetCellSchema").and_then(Value::as_str) != Some("ibex/capsec-target-cells/1")
        || cells.get("profile").and_then(Value::as_str) != Some(CAPSEC_PROFILE)
    {
        return Err(invalid(
            "checked target cells have the wrong schema or profile",
        ));
    }
    let rows = cells
        .get("cells")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("checked target cells have no rows"))?;
    let mut selected = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        let row_target: AdvertisementTarget = serde_json::from_value(
            row.get("target")
                .cloned()
                .ok_or_else(|| invalid(format!("checked target cell {index} has no target")))?,
        )
        .map_err(|error| {
            invalid(format!(
                "checked target cell {index} target is invalid: {error}"
            ))
        })?;
        validate_target(
            &row_target,
            &format!("checked target cells[{index}].target"),
        )?;
        if row_target != *target {
            continue;
        }
        let edge_id = required_string(row, "edgeId", &format!("checked target cells[{index}]"))?;
        if !valid_capsec_stable_id(edge_id) || !coverage.contains_key(edge_id) {
            return Err(invalid(format!(
                "checked target cell {index} names an unknown edge"
            )));
        }
        let branch_ids = required_canonical_ids(
            row,
            "implementationBranchIds",
            &format!("checked target cells[{index}]"),
        )?;
        let prefix = format!("{edge_id}.");
        if branch_ids.iter().any(|branch| {
            !branch.starts_with(&prefix)
                || crate::capsec_registry_generated::CAPSEC_IMPLEMENTATION_BRANCH_IDS
                    .binary_search(&branch.as_str())
                    .is_err()
        }) {
            return Err(invalid(format!(
                "checked target cell {edge_id} has an implementation branch outside the checked inventory"
            )));
        }
        if selected.insert(edge_id.to_owned(), branch_ids).is_some() {
            return Err(invalid(format!(
                "checked target cells repeat exact target edge {edge_id}"
            )));
        }
    }
    if selected.len() != coverage.len() || coverage.keys().any(|edge| !selected.contains_key(edge))
    {
        return Err(invalid(
            "checked target cells do not contain the complete exact-target coverage inventory",
        ));
    }
    Ok(selected)
}

fn target_absence_fixture(edge_id: &str, target: &AdvertisementTarget) -> Result<String> {
    let target_key = serde_json::to_string(&serde_json::json!([target.triple, target.features]))
        .map_err(|error| invalid(format!("cannot serialize target absence key: {error}")))?;
    let hash = Sha256::digest(target_key.as_bytes());
    let mut hexadecimal = String::with_capacity(hash.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in hash {
        hexadecimal.push(HEX[usize::from(byte >> 4)] as char);
        hexadecimal.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(format!(
        "{edge_id}.target.{}.{hexadecimal}.absent",
        target.triple
    ))
}

fn checked_implementation_rows(
    value: &Value,
) -> Result<BTreeMap<String, CheckedImplementationRow>> {
    if value
        .get("implementationManifestSchema")
        .and_then(Value::as_str)
        != Some("ibex/capsec-implementation/1")
        || value.get("profile").and_then(Value::as_str) != Some(CAPSEC_PROFILE)
        || value.get("status").and_then(Value::as_str) != Some("inventory-only-until-conformance")
    {
        return Err(invalid(
            "checked implementation manifest has the wrong schema, profile, or status",
        ));
    }
    let surfaces = value
        .get("surfaces")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("checked implementation manifest has no surfaces"))?;
    let mut rows = BTreeMap::new();
    for (index, surface) in surfaces.iter().enumerate() {
        let label = format!("checked implementation surfaces[{index}]");
        let edge_id = required_string(surface, "edgeId", &label)?.to_owned();
        let branch_id = required_string(surface, "branchId", &label)?.to_owned();
        let enforcement_branch_id =
            required_string(surface, "enforcementBranchId", &label)?.to_owned();
        if !valid_capsec_stable_id(&edge_id)
            || !valid_capsec_stable_id(&branch_id)
            || !valid_capsec_stable_id(&enforcement_branch_id)
            || !branch_id.starts_with(&format!("{edge_id}."))
            || crate::capsec_registry_generated::CAPSEC_IMPLEMENTATION_BRANCH_IDS
                .binary_search(&branch_id.as_str())
                .is_err()
            || crate::capsec_registry_generated::CAPSEC_ENFORCEMENT_BRANCH_IDS
                .binary_search(&enforcement_branch_id.as_str())
                .is_err()
        {
            return Err(invalid(format!(
                "{label} names a branch outside the checked inventory"
            )));
        }
        let observed_key = required_string(surface, "observedKey", &label)?.to_owned();
        let terminal_observed_key = surface
            .get("enforcementRoute")
            .and_then(|route| route.get("terminalObservedKey"))
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .unwrap_or(&observed_key)
            .to_owned();
        let fixture_obligations = required_canonical_ids(surface, "fixtureObligations", &label)?;
        if fixture_obligations.is_empty() {
            return Err(invalid(format!("{label} has no fixture obligations")));
        }
        let row = CheckedImplementationRow {
            edge_id,
            branch_id: branch_id.clone(),
            enforcement_branch_id,
            terminal_observed_key,
            fixture_obligations,
        };
        if rows.insert(branch_id.clone(), row).is_some() {
            return Err(invalid(format!(
                "checked implementation manifest repeats branch {branch_id}"
            )));
        }
    }
    if rows.len() != crate::capsec_registry_generated::CAPSEC_IMPLEMENTATION_BRANCH_IDS.len()
        || crate::capsec_registry_generated::CAPSEC_IMPLEMENTATION_BRANCH_IDS
            .iter()
            .any(|branch| !rows.contains_key(*branch))
    {
        return Err(invalid(
            "checked implementation manifest differs from the generated exact branch inventory",
        ));
    }
    Ok(rows)
}

/// Rebuild the report-facing branch, enforcement, and fixture authority from
/// checked source artifacts. A promotion report can prove these obligations;
/// it cannot choose a smaller set or mutually rebind its own digest fields.
///
/// @ref LLP 0035#phase-2--split-runtime-and-publication-identity — candidate
/// cells are independently source-derived, and supplied report cells are only
/// exact-byte evidence for that complete authority.
fn checked_report_authority(target: &AdvertisementTarget) -> Result<CheckedReportAuthority> {
    let coverage = checked_coverage_semantics()?;
    let target_branches = checked_target_implementation_branches(target, &coverage)?;
    let implementation = capsec_semantics::strict_json::parse_strict(
        CHECKED_IMPLEMENTATION_MANIFEST_JSON,
    )
    .map_err(|error| invalid(format!("invalid checked implementation manifest: {error}")))?;
    let implementation_manifest_digest =
        canonical_value_digest(&implementation, "checked implementation manifest")?;
    let candidates = implementation
        .get("candidateTargets")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("checked implementation manifest has no candidate targets"))?;
    let matching_targets = candidates
        .iter()
        .map(|candidate| {
            serde_json::from_value::<AdvertisementTarget>(candidate.clone()).map_err(|error| {
                invalid(format!(
                    "checked implementation manifest has an invalid candidate target: {error}"
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|candidate| candidate == target)
        .count();
    if matching_targets != 1 {
        return Err(invalid(
            "checked implementation manifest does not name one exact candidate target",
        ));
    }
    let implementation_rows = checked_implementation_rows(&implementation)?;
    let mut cells = BTreeMap::new();
    let mut fixture_catalog = Vec::with_capacity(coverage.len());
    for edge_id in crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS {
        let semantics = coverage
            .get(*edge_id)
            .ok_or_else(|| invalid(format!("checked edge {edge_id} has no semantics")))?;
        let implementation_branch_ids = target_branches
            .get(*edge_id)
            .ok_or_else(|| invalid(format!("checked target has no branch row for {edge_id}")))?
            .clone();
        let selected_rows = implementation_branch_ids
            .iter()
            .map(|branch| {
                implementation_rows.get(branch).ok_or_else(|| {
                    invalid(format!("checked target selects unknown branch {branch}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if selected_rows.iter().any(|row| row.edge_id != *edge_id) {
            return Err(invalid(format!(
                "checked target branch selection crosses edge {edge_id}"
            )));
        }
        let enforcement_branch_ids = selected_rows
            .iter()
            .map(|row| row.enforcement_branch_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let required_fixtures = if selected_rows.is_empty() {
            vec![target_absence_fixture(edge_id, target)?]
        } else {
            selected_rows
                .iter()
                .flat_map(|row| row.fixture_obligations.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        };
        let fixture_bindings = required_fixtures
            .iter()
            .map(|fixture_id| {
                let matching_rows = selected_rows
                    .iter()
                    .copied()
                    .filter(|row| row.fixture_obligations.binary_search(fixture_id).is_ok())
                    .collect::<Vec<_>>();
                if !selected_rows.is_empty() && matching_rows.is_empty() {
                    return Err(invalid(format!(
                        "checked fixture {fixture_id} has no selected implementation branch"
                    )));
                }
                let fixture_implementation_ids = matching_rows
                    .iter()
                    .map(|row| row.branch_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let fixture_enforcement_ids = matching_rows
                    .iter()
                    .map(|row| row.enforcement_branch_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let terminal_observed_keys = if matching_rows.is_empty() {
                    vec![semantics.surface_observed_key.clone()]
                } else {
                    matching_rows
                        .iter()
                        .map(|row| row.terminal_observed_key.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                };
                let action_ids = semantics
                    .logical_branch_action_ids
                    .iter()
                    .find_map(|(logical_branch_id, actions)| {
                        matching_rows
                            .iter()
                            .any(|row| {
                                fixture_id.starts_with(&format!(
                                    "{}.logical.{logical_branch_id}.",
                                    row.enforcement_branch_id
                                ))
                            })
                            .then(|| actions.clone())
                    })
                    .unwrap_or_else(|| semantics.action_ids.clone());
                Ok(serde_json::json!({
                    "fixtureId": fixture_id,
                    "implementationBranchIds": fixture_implementation_ids,
                    "enforcementBranchIds": fixture_enforcement_ids,
                    "terminalObservedKeys": terminal_observed_keys,
                    "classifications": [semantics.classification],
                    "actionIds": action_ids,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        fixture_catalog.push(serde_json::json!({
            "edgeId": edge_id,
            "implementationBranchIds": implementation_branch_ids,
            "enforcementBranchIds": enforcement_branch_ids,
            "requiredFixtures": required_fixtures,
            "fixtureBindings": fixture_bindings,
        }));
        cells.insert(
            (*edge_id).to_owned(),
            CheckedTargetCellAuthority {
                implementation_branch_ids,
                enforcement_branch_ids,
                required_fixtures,
            },
        );
    }
    let fixture_catalog_digest =
        canonical_value_digest(&Value::Array(fixture_catalog), "checked fixture catalog")?;
    Ok(CheckedReportAuthority {
        implementation_manifest_digest,
        fixture_catalog_digest,
        cells,
    })
}

/// Validate the exact embedded report selected by build.rs and derive Host's
/// complete/closed map from its complete conformant cell membership plus the
/// checked source classification. No source-A `unsupported` row is borrowed.
pub(super) fn authenticated_report_target_cells(
    advertisement: &SelectedTargetAdvertisement,
    report_text: &str,
) -> Result<BTreeMap<String, TargetCellDisposition>> {
    let authority = checked_report_authority(&advertisement.target)?;
    authenticated_report_target_cells_with_authority(advertisement, report_text, &authority)
}

fn authenticated_report_target_cells_with_authority(
    advertisement: &SelectedTargetAdvertisement,
    report_text: &str,
    authority: &CheckedReportAuthority,
) -> Result<BTreeMap<String, TargetCellDisposition>> {
    if report_text == "null\n" {
        return Err(refused(
            "promoted portable conformance report is absent from this build",
        ));
    }
    let value = capsec_semantics::strict_json::parse_strict(report_text)
        .map_err(|error| invalid(format!("invalid embedded promoted report: {error}")))?;
    reject_published_locality(&value, "promotedReport")?;
    let report: PortableConformanceReport = serde_json::from_value(value.clone())
        .map_err(|error| invalid(format!("invalid embedded promoted report model: {error}")))?;
    if report.conformance_schema != REPORT_SCHEMA_V2
        || report.profile != CAPSEC_PROFILE
        || report.status != "conformant"
    {
        return Err(refused(
            "embedded promoted report is not one conformant v2 report",
        ));
    }
    let expected_digest = capsec_semantics::digest::compute_domain_digest(
        REPORT_DOMAIN_V2,
        &value,
        &["conformanceDigest".to_owned()],
    )
    .map_err(|error| invalid(format!("cannot verify promoted report digest: {error}")))?;
    if report.conformance_digest.as_str() != expected_digest
        || report.conformance_digest != advertisement.conformance_digest
        || advertisement.report_raw_content_digest.as_str()
            != raw_content_digest(report_text.as_bytes())
    {
        return Err(refused(
            "advertisement does not bind the exact promoted report bytes and digest",
        ));
    }
    let bindings = &report.bindings;
    validate_conformance_runner_binding(
        &bindings.conformance_runner,
        &bindings.source_revision,
        &bindings.source_tree_digest,
        &bindings.engine,
    )?;
    if bindings.target != advertisement.target
        || bindings.source_revision != advertisement.source_revision
        || bindings.source_tree_digest != advertisement.source_tree_digest
        || bindings.engine != advertisement.engine
        || bindings.mapped_engine_execution_evidence
            != advertisement.mapped_engine_execution_evidence
        || bindings.vocabulary_digest != advertisement.vocabulary_digest
        || bindings.registry_digest != advertisement.registry_digest
        || bindings.implementation_manifest_digest != advertisement.implementation_manifest_digest
        || bindings.fixture_catalog_digest != advertisement.fixture_catalog_digest
        || bindings.recipe_catalog_digest != advertisement.recipe_catalog_digest
        || bindings.recipe_catalog_raw_content_digest
            != advertisement.recipe_catalog_raw_content_digest
        || bindings.public_surface_execution_digest != advertisement.public_surface_execution_digest
        || bindings.public_surface_execution_raw_content_digest
            != advertisement.public_surface_execution_raw_content_digest
        || bindings.output_disposition_evidence_raw_content_digest
            != advertisement.output_disposition_evidence_raw_content_digest
        || bindings.target_cells_raw_content_digest != advertisement.target_cells_raw_content_digest
    {
        return Err(refused(
            "promoted report bindings differ from the target advertisement",
        ));
    }
    if bindings.implementation_manifest_digest != authority.implementation_manifest_digest
        || bindings.fixture_catalog_digest != authority.fixture_catalog_digest
    {
        return Err(refused(
            "promoted report does not bind the checked source-derived implementation and fixture authority",
        ));
    }
    validate_target(&bindings.target, "promotedReport.bindings.target")?;
    validate_evidence_references(&bindings.mapped_engine_execution_evidence)?;

    for count in [
        report.summary.cells,
        report.summary.conformant_cells,
        report.summary.incomplete_cells,
        report.summary.required_fixtures,
        report.summary.passed_fixtures,
        report.summary.missing_fixtures,
        report.summary.failed_fixtures,
    ] {
        if count > MAX_IJSON_INTEGER {
            return Err(invalid(
                "promoted report summary exceeds the I-JSON safe range",
            ));
        }
    }
    if report
        .executions
        .windows(2)
        .any(|pair| pair[0].fixture_id.as_bytes() >= pair[1].fixture_id.as_bytes())
    {
        return Err(invalid(
            "promoted report executions are not canonically ordered and unique",
        ));
    }
    let mapped_digests = bindings
        .mapped_engine_execution_evidence
        .iter()
        .map(|reference| &reference.evidence_digest)
        .collect::<BTreeSet<_>>();
    for execution in &report.executions {
        if !valid_capsec_stable_id(&execution.fixture_id)
            || !valid_capsec_stable_id(&execution.executor)
            || execution.outcome != "passed"
            || !mapped_digests.contains(&execution.mapped_engine_execution_evidence_digest)
        {
            return Err(refused(
                "promoted report contains a malformed, failed, or unbound execution",
            ));
        }
        let _ = (
            &execution.artifact_digest,
            &execution.raw_content_digest,
            &execution.binding_digest,
        );
    }

    let coverage_semantics = checked_coverage_semantics()?;
    if report.cells.len() != coverage_semantics.len()
        || authority.cells.len() != coverage_semantics.len()
        || report
            .cells
            .windows(2)
            .any(|pair| pair[0].edge_id >= pair[1].edge_id)
    {
        return Err(refused(
            "promoted report cell membership is not the exact ordered coverage inventory",
        ));
    }
    let mut required_fixtures = BTreeSet::new();
    let mut passed_fixtures = BTreeSet::new();
    let mut result = BTreeMap::new();
    for (index, (cell, expected_edge)) in report
        .cells
        .iter()
        .zip(crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS)
        .enumerate()
    {
        validate_report_cell(cell, index)?;
        if cell.edge_id != *expected_edge {
            return Err(refused(format!(
                "promoted report cell {} does not equal checked edge {expected_edge}",
                cell.edge_id
            )));
        }
        required_fixtures.extend(cell.required_fixtures.iter().cloned());
        passed_fixtures.extend(cell.passed_fixtures.iter().cloned());
        let semantics = coverage_semantics
            .get(*expected_edge)
            .ok_or_else(|| invalid(format!("checked edge {expected_edge} has no semantics")))?;
        let expected_authority = authority.cells.get(*expected_edge).ok_or_else(|| {
            invalid(format!(
                "checked edge {expected_edge} has no source-derived report authority"
            ))
        })?;
        if cell.implementation_branch_ids != expected_authority.implementation_branch_ids
            || cell.enforcement_branch_ids != expected_authority.enforcement_branch_ids
            || cell.required_fixtures != expected_authority.required_fixtures
        {
            return Err(refused(format!(
                "promoted report cell {expected_edge} does not equal its complete checked source-derived branch and fixture authority"
            )));
        }
        let disposition = if cell.implementation_branch_ids.is_empty() {
            TargetCellDisposition::Closed
        } else if semantics.effect_mode.as_deref() == Some("conditional-unrefined") {
            return Err(refused(format!(
                "checked edge {expected_edge} still has an unrefined conditional effect"
            )));
        } else {
            match semantics.classification.as_str() {
                "effects" | "non-capability" => TargetCellDisposition::Complete,
                "closed" => TargetCellDisposition::Closed,
                _ => {
                    return Err(invalid(format!(
                        "checked edge {expected_edge} has no derivable target disposition"
                    )))
                }
            }
        };
        result.insert((*expected_edge).to_owned(), disposition);
    }
    let execution_fixtures = report
        .executions
        .iter()
        .map(|execution| execution.fixture_id.clone())
        .collect::<BTreeSet<_>>();
    if required_fixtures.is_empty()
        || required_fixtures != passed_fixtures
        || passed_fixtures != execution_fixtures
        || report.summary.cells != report.cells.len() as u64
        || report.summary.conformant_cells != report.cells.len() as u64
        || report.summary.incomplete_cells != 0
        || report.summary.required_fixtures != required_fixtures.len() as u64
        || report.summary.passed_fixtures != passed_fixtures.len() as u64
        || report.summary.missing_fixtures != 0
        || report.summary.failed_fixtures != 0
    {
        return Err(refused(
            "promoted report summary or fixture membership is incomplete",
        ));
    }
    Ok(result)
}

/// Reconstruct and validate both runtime identity layers without ever copying
/// mapped/local fields into an advertisement or comparing CapSec features with
/// portable package-layout features.
pub(super) fn authenticate_local_engine(
    advertisement: &SelectedTargetAdvertisement,
    portable: &PortableEngineArtifactIdentity,
    mapped: &MappedEngineInstanceIdentity,
) -> Result<()> {
    portable.validate().map_err(|error| {
        refused(format!(
            "loaded portable engine identity is invalid: {error}"
        ))
    })?;
    mapped
        .validate()
        .map_err(|error| refused(format!("loaded mapped engine identity is invalid: {error}")))?;
    if advertisement.engine != *portable {
        return Err(refused(
            "target advertisement does not identify the exact loaded portable engine artifact",
        ));
    }
    if mapped.portable != *portable {
        return Err(refused(
            "loaded mapped engine instance does not rejoin the portable identity",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TOPIC_P: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const MERGE_C: &str = "cccccccccccccccccccccccccccccccccccccccc";
    const DESCENDANT_D: &str = "dddddddddddddddddddddddddddddddddddddddd";
    const SOURCE_TREE: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    struct Fixture {
        advertisements: Value,
        report: String,
        authority: CheckedReportAuthority,
        admission: Value,
        portable: PortableEngineArtifactIdentity,
        mapped: MappedEngineInstanceIdentity,
        target: String,
        features: Vec<String>,
    }

    fn digest(label: &str) -> String {
        capsec_semantics::digest::compute_domain_digest(
            "ibex.test.host-portable-admission.v1",
            &serde_json::json!({"label": label}),
            &[],
        )
        .unwrap()
    }

    fn checked_marker(mut value: Value) -> String {
        value["verificationDigest"] = Value::String(digest("placeholder"));
        let verification = capsec_semantics::digest::compute_domain_digest(
            PROMOTION_ADMISSION_DOMAIN,
            &value,
            &["verificationDigest".to_owned()],
        )
        .unwrap();
        value["verificationDigest"] = Value::String(verification);
        format!("{}\n", capsec_semantics::canonical::to_jcs(&value).unwrap())
    }

    fn fixture_identities() -> (PortableEngineArtifactIdentity, MappedEngineInstanceIdentity) {
        let vectors: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/vectors/portable-engine-provenance-v1.valid.json"
        )))
        .unwrap();
        let portable =
            serde_json::from_value(vectors["documents"]["portableIdentity"].clone()).unwrap();
        let mapped =
            serde_json::from_value(vectors["documents"]["mappedInstance"].clone()).unwrap();
        (portable, mapped)
    }

    fn report_for(advertisement: &Value, target_cells_digest: &str) -> String {
        let evidence_digest =
            advertisement["mappedEngineExecutionEvidence"][0]["evidenceDigest"].clone();
        let cells = crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS
            .iter()
            .enumerate()
            .map(|(index, edge)| {
                let prefix = format!("{edge}.");
                let implementation =
                    crate::capsec_registry_generated::CAPSEC_IMPLEMENTATION_BRANCH_IDS
                        .iter()
                        .filter(|branch| branch.starts_with(&prefix))
                        .copied()
                        .collect::<Vec<_>>();
                let enforcement = crate::capsec_registry_generated::CAPSEC_ENFORCEMENT_BRANCH_IDS
                    .iter()
                    .filter(|branch| branch.starts_with(&prefix))
                    .copied()
                    .collect::<Vec<_>>();
                let fixtures = if index == 0 {
                    serde_json::json!(["fixture.host-admission.a", "fixture.host-admission.b"])
                } else {
                    serde_json::json!([])
                };
                serde_json::json!({
                    "edgeId": edge,
                    "implementationBranchIds": implementation,
                    "enforcementBranchIds": enforcement,
                    "status": "conformant",
                    "requiredFixtures": fixtures,
                    "passedFixtures": fixtures,
                    "missingFixtures": [],
                    "failedFixtures": [],
                })
            })
            .collect::<Vec<_>>();
        let mut report = serde_json::json!({
            "conformanceSchema": REPORT_SCHEMA_V2,
            "profile": CAPSEC_PROFILE,
            "status": "conformant",
            "bindings": {
                "sourceRevision": advertisement["sourceRevision"],
                "sourceTreeDigest": advertisement["sourceTreeDigest"],
                "conformanceRunner": {
                    "sourceRevision": advertisement["sourceRevision"],
                    "sourceTreeDigest": advertisement["sourceTreeDigest"],
                    "artifactId": advertisement["engine"]["artifactId"],
                    "buildConsumptionDigest": digest("runner-build-consumption"),
                    "postLinkSetDigest": digest("runner-post-link-set"),
                    "verificationDigest": digest("runner-verification"),
                    "testExecutableDigest": format!("sha256-{}", "e".repeat(64)),
                },
                "engine": advertisement["engine"],
                "target": advertisement["target"],
                "vocabularyDigest": advertisement["vocabularyDigest"],
                "registryDigest": advertisement["registryDigest"],
                "implementationManifestDigest": advertisement["implementationManifestDigest"],
                "fixtureCatalogDigest": advertisement["fixtureCatalogDigest"],
                "recipeCatalogDigest": advertisement["recipeCatalogDigest"],
                "recipeCatalogRawContentDigest": advertisement["recipeCatalogRawContentDigest"],
                "publicSurfaceExecutionDigest": advertisement["publicSurfaceExecutionDigest"],
                "publicSurfaceExecutionRawContentDigest": advertisement["publicSurfaceExecutionRawContentDigest"],
                "targetCellsRawContentDigest": target_cells_digest,
                "outputDispositionEvidenceRawContentDigest": advertisement["outputDispositionEvidenceRawContentDigest"],
                "mappedEngineExecutionEvidence": advertisement["mappedEngineExecutionEvidence"],
            },
            "summary": {
                "cells": cells.len(),
                "conformantCells": cells.len(),
                "incompleteCells": 0,
                "requiredFixtures": 2,
                "passedFixtures": 2,
                "missingFixtures": 0,
                "failedFixtures": 0,
            },
            "executions": [
                {
                    "fixtureId": "fixture.host-admission.a",
                    "outcome": "passed",
                    "executor": "ibex-test",
                    "artifactDigest": digest("execution-artifact-a"),
                    "rawContentDigest": digest("execution-raw-a"),
                    "bindingDigest": digest("execution-binding-a"),
                    "mappedEngineExecutionEvidenceDigest": evidence_digest,
                },
                {
                    "fixtureId": "fixture.host-admission.b",
                    "outcome": "passed",
                    "executor": "ibex-test",
                    "artifactDigest": digest("execution-artifact-b"),
                    "rawContentDigest": digest("execution-raw-b"),
                    "bindingDigest": digest("execution-binding-b"),
                    "mappedEngineExecutionEvidenceDigest": evidence_digest,
                }
            ],
            "cells": cells,
            "conformanceDigest": digest("placeholder-report"),
        });
        report["conformanceDigest"] = Value::String(
            capsec_semantics::digest::compute_domain_digest(
                REPORT_DOMAIN_V2,
                &report,
                &["conformanceDigest".to_owned()],
            )
            .unwrap(),
        );
        format!("{}\n", serde_json::to_string_pretty(&report).unwrap())
    }

    fn test_authority(advertisement: &Value, report_text: &str) -> CheckedReportAuthority {
        let report: PortableConformanceReport = serde_json::from_str(report_text).unwrap();
        let cells = report
            .cells
            .into_iter()
            .map(|cell| {
                (
                    cell.edge_id,
                    CheckedTargetCellAuthority {
                        implementation_branch_ids: cell.implementation_branch_ids,
                        enforcement_branch_ids: cell.enforcement_branch_ids,
                        required_fixtures: cell.required_fixtures,
                    },
                )
            })
            .collect();
        CheckedReportAuthority {
            implementation_manifest_digest: serde_json::from_value(
                advertisement["implementationManifestDigest"].clone(),
            )
            .unwrap(),
            fixture_catalog_digest: serde_json::from_value(
                advertisement["fixtureCatalogDigest"].clone(),
            )
            .unwrap(),
            cells,
        }
    }

    fn fixture() -> Fixture {
        let (portable, mapped) = fixture_identities();
        portable.validate().unwrap();
        mapped.validate().unwrap();
        let cells = b"{\"checked\":true}\n".to_vec();
        let target = portable.target.triple.clone();
        let features = vec![
            "hermes-frame-attribution".to_owned(),
            "native-compartments".to_owned(),
            "native-lockdown".to_owned(),
        ];
        let evidence = serde_json::json!([{
            "evidenceDigest": digest("evidence"),
            "rawContentDigest": digest("evidence-raw"),
            "attemptDigest": digest("attempt"),
            "attemptRawContentDigest": digest("attempt-raw"),
        }]);
        let mut advertisement = serde_json::json!({
            "target": {"triple": target, "features": features},
            "conformanceDigest": digest("conformance"),
            "reportRawContentDigest": digest("report-raw"),
            "sourceRevision": SOURCE_A,
            "sourceTreeDigest": digest("source-tree"),
            "engine": portable,
            "mappedEngineExecutionEvidence": evidence,
            "vocabularyDigest": digest("vocabulary"),
            "registryDigest": digest("registry"),
            "implementationManifestDigest": digest("implementation"),
            "fixtureCatalogDigest": digest("fixtures"),
            "recipeCatalogDigest": digest("recipes"),
            "recipeCatalogRawContentDigest": digest("recipes-raw"),
            "publicSurfaceExecutionDigest": digest("public-execution"),
            "publicSurfaceExecutionRawContentDigest": digest("public-execution-raw"),
            "outputDispositionEvidenceRawContentDigest": digest("output-disposition-raw"),
        });
        let target_cells_digest = raw_content_digest(&cells);
        let report = report_for(&advertisement, &target_cells_digest);
        let authority = test_authority(&advertisement, &report);
        let report_value: Value = serde_json::from_str(&report).unwrap();
        advertisement["conformanceDigest"] = report_value["conformanceDigest"].clone();
        advertisement["reportRawContentDigest"] =
            Value::String(raw_content_digest(report.as_bytes()));
        let advertisements = serde_json::json!({
            "targetAdvertisementSchema": ADVERTISEMENT_SCHEMA_V2,
            "profile": CAPSEC_PROFILE,
            "targetCellsRawContentDigest": target_cells_digest,
            "advertisements": [advertisement],
        });
        let admission = serde_json::json!({
            "schema": PROMOTION_ADMISSION_SCHEMA,
            "authorized": true,
            "currentRevision": MERGE_C,
            "sourceRevision": SOURCE_A,
            "promotionTopicRevision": TOPIC_P,
            "sourceTreeObjectId": SOURCE_TREE,
            "targetTriple": target,
            "portableArtifactId": portable.artifact_id,
            "admissionDigest": digest("lineage-admission"),
            "verificationDigest": digest("placeholder"),
        });
        Fixture {
            advertisements,
            report,
            authority,
            admission,
            portable,
            mapped,
            target,
            features,
        }
    }

    fn select(fixture: &Fixture) -> Result<SelectedTargetAdvertisement> {
        select_v2_advertisement(
            &serde_json::to_string(&fixture.advertisements).unwrap(),
            &fixture.target,
            &fixture.features,
        )
    }

    fn authenticate_fixture_report(
        fixture: &Fixture,
        advertisement: &SelectedTargetAdvertisement,
        report_text: &str,
    ) -> Result<BTreeMap<String, TargetCellDisposition>> {
        authenticated_report_target_cells_with_authority(
            advertisement,
            report_text,
            &fixture.authority,
        )
    }

    fn rebind_report(
        advertisement: &SelectedTargetAdvertisement,
        mut report: Value,
    ) -> (SelectedTargetAdvertisement, String) {
        report["conformanceDigest"] = Value::String(
            capsec_semantics::digest::compute_domain_digest(
                REPORT_DOMAIN_V2,
                &report,
                &["conformanceDigest".to_owned()],
            )
            .unwrap(),
        );
        let report_text = format!("{}\n", serde_json::to_string_pretty(&report).unwrap());
        let mut rebound = advertisement.clone();
        rebound.advertisement.conformance_digest =
            serde_json::from_value(report["conformanceDigest"].clone()).unwrap();
        rebound.advertisement.report_raw_content_digest =
            Digest::new(&raw_content_digest(report_text.as_bytes())).unwrap();
        (rebound, report_text)
    }

    #[test]
    fn tracked_source_a_legacy_advertisement_stays_closed() {
        let fixture = fixture();
        let error = select_v2_advertisement(
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/capsec/generated/target-advertisements.json"
            )),
            &fixture.target,
            &fixture.features,
        )
        .unwrap_err();
        assert!(error.to_string().contains("legacy v1"), "{error}");
    }

    #[test]
    fn source_a_diagnostic_admission_stays_closed() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        let mut admission = fixture.admission.clone();
        admission["authorized"] = Value::Bool(false);
        admission["currentRevision"] = Value::String(SOURCE_A.into());
        admission["promotionTopicRevision"] = Value::Null;
        admission["sourceTreeObjectId"] = Value::Null;
        admission["admissionDigest"] = Value::Null;
        let error =
            require_checked_promotion(&advertisement, &checked_marker(admission)).unwrap_err();
        assert!(error.to_string().contains("does not authorize"), "{error}");
    }

    #[test]
    fn exact_merge_c_admission_and_both_local_identities_are_accepted() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        require_checked_promotion(&advertisement, &checked_marker(fixture.admission.clone()))
            .unwrap();
        let target_cells =
            authenticate_fixture_report(&fixture, &advertisement, &fixture.report).unwrap();
        assert_eq!(
            target_cells.len(),
            crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS.len()
        );
        authenticate_local_engine(&advertisement, &fixture.portable, &fixture.mapped).unwrap();
    }

    #[test]
    fn later_descendant_d_diagnostic_state_cannot_inherit_c_authority() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        let mut admission = fixture.admission.clone();
        admission["authorized"] = Value::Bool(false);
        admission["currentRevision"] = Value::String(DESCENDANT_D.into());
        admission["sourceRevision"] = Value::String(DESCENDANT_D.into());
        admission["promotionTopicRevision"] = Value::Null;
        admission["sourceTreeObjectId"] = Value::Null;
        admission["admissionDigest"] = Value::Null;
        assert!(require_checked_promotion(&advertisement, &checked_marker(admission)).is_err());
    }

    #[test]
    fn missing_or_mutated_checked_admission_is_refused() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        assert!(require_checked_promotion(&advertisement, "null\n").is_err());

        let mut marker = checked_marker(fixture.admission.clone());
        let at = marker.find(MERGE_C).unwrap();
        marker.replace_range(at..at + MERGE_C.len(), DESCENDANT_D);
        let error = require_checked_promotion(&advertisement, &marker).unwrap_err();
        assert!(error.to_string().contains("verification digest"), "{error}");
    }

    #[test]
    fn missing_mutated_or_incomplete_promoted_report_is_refused() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        assert!(authenticate_fixture_report(&fixture, &advertisement, "null\n").is_err());

        let mut mutated = fixture.report.clone();
        let at = mutated.find(SOURCE_A).unwrap();
        mutated.replace_range(at..at + SOURCE_A.len(), DESCENDANT_D);
        assert!(authenticate_fixture_report(&fixture, &advertisement, &mutated).is_err());

        let mut report: Value = serde_json::from_str(&fixture.report).unwrap();
        report["cells"].as_array_mut().unwrap().pop();
        let count = report["cells"].as_array().unwrap().len() as u64;
        report["summary"]["cells"] = Value::from(count);
        report["summary"]["conformantCells"] = Value::from(count);
        report["conformanceDigest"] = Value::String(
            capsec_semantics::digest::compute_domain_digest(
                REPORT_DOMAIN_V2,
                &report,
                &["conformanceDigest".to_owned()],
            )
            .unwrap(),
        );
        let report_text = format!("{}\n", serde_json::to_string_pretty(&report).unwrap());
        let mut rebound = advertisement.clone();
        rebound.advertisement.conformance_digest =
            Digest::new(report["conformanceDigest"].as_str().unwrap()).unwrap();
        rebound.advertisement.report_raw_content_digest =
            Digest::new(raw_content_digest(report_text.as_bytes())).unwrap();
        let error = authenticate_fixture_report(&fixture, &rebound, &report_text).unwrap_err();
        assert!(error.to_string().contains("cell membership"), "{error}");
    }

    #[test]
    fn report_cannot_omit_a_source_branch_to_reclassify_an_effect_as_closed() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        let semantics = checked_coverage_semantics().unwrap();
        let mut report: Value = serde_json::from_str(&fixture.report).unwrap();
        let victim = report["cells"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|cell| {
                !cell["implementationBranchIds"]
                    .as_array()
                    .unwrap()
                    .is_empty()
                    && matches!(
                        semantics
                            .get(cell["edgeId"].as_str().unwrap())
                            .unwrap()
                            .classification
                            .as_str(),
                        "effects" | "non-capability"
                    )
            })
            .unwrap();
        victim["implementationBranchIds"] = Value::Array(Vec::new());
        let (rebound, report_text) = rebind_report(&advertisement, report);
        let error = authenticate_fixture_report(&fixture, &rebound, &report_text).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("source-derived branch and fixture authority"),
            "{error}"
        );
    }

    #[test]
    fn report_cannot_omit_enforcement_or_fixture_authority() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();

        let mut missing_enforcement: Value = serde_json::from_str(&fixture.report).unwrap();
        let victim = missing_enforcement["cells"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|cell| !cell["enforcementBranchIds"].as_array().unwrap().is_empty())
            .unwrap();
        victim["enforcementBranchIds"].as_array_mut().unwrap().pop();
        let (rebound, report_text) = rebind_report(&advertisement, missing_enforcement);
        let error = authenticate_fixture_report(&fixture, &rebound, &report_text).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("source-derived branch and fixture authority"),
            "{error}"
        );

        let mut missing_fixture: Value = serde_json::from_str(&fixture.report).unwrap();
        missing_fixture["cells"][0]["requiredFixtures"]
            .as_array_mut()
            .unwrap()
            .pop();
        missing_fixture["cells"][0]["passedFixtures"]
            .as_array_mut()
            .unwrap()
            .pop();
        missing_fixture["executions"].as_array_mut().unwrap().pop();
        missing_fixture["summary"]["requiredFixtures"] = Value::from(1);
        missing_fixture["summary"]["passedFixtures"] = Value::from(1);
        let (rebound, report_text) = rebind_report(&advertisement, missing_fixture);
        let error = authenticate_fixture_report(&fixture, &rebound, &report_text).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("source-derived branch and fixture authority"),
            "{error}"
        );
    }

    #[test]
    fn report_and_advertisement_cannot_mutually_rebind_checked_source_authority() {
        let fixture = fixture();
        for field in ["implementationManifestDigest", "fixtureCatalogDigest"] {
            let mut advertisement = select(&fixture).unwrap();
            let substituted = Digest::new(&digest(&format!("substituted-{field}"))).unwrap();
            match field {
                "implementationManifestDigest" => {
                    advertisement.advertisement.implementation_manifest_digest =
                        substituted.clone();
                }
                "fixtureCatalogDigest" => {
                    advertisement.advertisement.fixture_catalog_digest = substituted.clone();
                }
                _ => unreachable!(),
            }
            let mut report: Value = serde_json::from_str(&fixture.report).unwrap();
            report["bindings"][field] = Value::String(substituted.as_str().to_owned());
            let (rebound, report_text) = rebind_report(&advertisement, report);
            let error = authenticate_fixture_report(&fixture, &rebound, &report_text).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("checked source-derived implementation and fixture authority"),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn report_conformance_runner_must_be_complete_locality_free_and_rejoin_source() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();

        let mut substituted: Value = serde_json::from_str(&fixture.report).unwrap();
        substituted["bindings"]["conformanceRunner"]["sourceRevision"] =
            Value::String(DESCENDANT_D.into());
        let (rebound, report_text) = rebind_report(&advertisement, substituted);
        let error = authenticate_fixture_report(&fixture, &rebound, &report_text).unwrap_err();
        assert!(
            error.to_string().contains("conformance runner differs"),
            "{error}"
        );

        let mut path_bearing: Value = serde_json::from_str(&fixture.report).unwrap();
        path_bearing["bindings"]["conformanceRunner"]["testExecutablePath"] =
            Value::String("/runner/target/debug/deps/ibex".into());
        let (rebound, report_text) = rebind_report(&advertisement, path_bearing);
        let error = authenticate_fixture_report(&fixture, &rebound, &report_text).unwrap_err();
        assert!(error.to_string().contains("host-local path"), "{error}");

        let mut omitted: Value = serde_json::from_str(&fixture.report).unwrap();
        omitted["bindings"]
            .as_object_mut()
            .unwrap()
            .remove("conformanceRunner");
        let (rebound, report_text) = rebind_report(&advertisement, omitted);
        let error = authenticate_fixture_report(&fixture, &rebound, &report_text).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid embedded promoted report model"),
            "{error}"
        );
    }

    #[test]
    fn checked_report_authority_covers_the_complete_source_target() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        let authority = checked_report_authority(&advertisement.target).unwrap();
        assert_eq!(
            authority.cells.len(),
            crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS.len()
        );
        assert!(authority
            .cells
            .values()
            .all(|cell| !cell.required_fixtures.is_empty()));
        assert!(authority.cells.values().any(|cell| {
            cell.implementation_branch_ids.len() > 1
                && cell.enforcement_branch_ids.len() > 1
                && cell.required_fixtures.len() > 1
        }));
    }

    #[test]
    fn promotion_source_target_and_artifact_joins_are_exact() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        for (field, replacement, expected) in [
            ("sourceRevision", DESCENDANT_D.to_owned(), "source revision"),
            (
                "targetTriple",
                "x86_64-apple-darwin".to_owned(),
                "target differs",
            ),
            (
                "portableArtifactId",
                digest("other-artifact"),
                "artifact differs",
            ),
        ] {
            let mut admission = fixture.admission.clone();
            admission[field] = Value::String(replacement);
            let error =
                require_checked_promotion(&advertisement, &checked_marker(admission)).unwrap_err();
            assert!(error.to_string().contains(expected), "{field}: {error}");
        }
    }

    #[test]
    fn advertised_engine_substitution_is_refused() {
        let mut fixture = fixture();
        fixture.advertisements["advertisements"][0]["engine"]["profile"]["id"] =
            Value::String("substituted-profile".into());
        let advertisement = select(&fixture).unwrap();
        require_checked_promotion(&advertisement, &checked_marker(fixture.admission.clone()))
            .unwrap();
        let error = authenticate_local_engine(&advertisement, &fixture.portable, &fixture.mapped)
            .unwrap_err();
        assert!(
            error.to_string().contains("exact loaded portable"),
            "{error}"
        );
    }

    #[test]
    fn mapped_identity_must_independently_rejoin_the_local_portable_identity() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        let mut mapped_value = serde_json::to_value(&fixture.mapped).unwrap();
        mapped_value["portable"]["profile"]["id"] = Value::String("other-profile".into());
        mapped_value["observationDigest"] = Value::String(
            capsec_semantics::digest::compute_domain_digest(
                "ibex.mapped-engine-instance-identity.v1",
                &mapped_value,
                &["observationDigest".to_owned()],
            )
            .unwrap(),
        );
        let mapped: MappedEngineInstanceIdentity = serde_json::from_value(mapped_value).unwrap();
        mapped.validate().unwrap();
        let error =
            authenticate_local_engine(&advertisement, &fixture.portable, &mapped).unwrap_err();
        assert!(error.to_string().contains("does not rejoin"), "{error}");
    }

    #[test]
    fn v2_publication_with_mapped_locality_is_refused() {
        let mut mapped_field = fixture();
        mapped_field.advertisements["advertisements"][0]["canonicalLocalRuntimePath"] =
            Value::String("/private/tmp/libhermes.dylib".into());
        let error = select(&mapped_field).unwrap_err();
        assert!(
            error.to_string().contains("mapped/local engine field"),
            "{error}"
        );

        let mut address_string = fixture();
        address_string.advertisements["advertisements"][0]["engine"]["profile"]["id"] =
            Value::String("0x1234".into());
        let error = select(&address_string).unwrap_err();
        assert!(error.to_string().contains("host-local"), "{error}");
    }

    #[test]
    fn duplicate_v2_json_keys_are_refused_before_selection() {
        let fixture = fixture();
        let text = serde_json::to_string(&fixture.advertisements).unwrap();
        let text = text.replacen(
            &format!("\"targetAdvertisementSchema\":\"{ADVERTISEMENT_SCHEMA_V2}\""),
            &format!(
                "\"targetAdvertisementSchema\":\"{ADVERTISEMENT_SCHEMA_V2}\",\"targetAdvertisementSchema\":\"{ADVERTISEMENT_SCHEMA_V2}\""
            ),
            1,
        );
        let error = select_v2_advertisement(&text, &fixture.target, &fixture.features).unwrap_err();
        assert!(
            error.to_string().contains("duplicate JSON object key"),
            "{error}"
        );
    }
}
