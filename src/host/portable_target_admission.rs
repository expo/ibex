//! Production admission for portable-engine CapSec target advertisements.
//!
//! This module deliberately keeps the three authorities separate: checked
//! publication bytes select one v3 target row, the build-authenticated A/P/C
//! marker opens that row, and fresh process-local reconstruction proves the
//! engine that is actually mapped. None of the mapped identity is serialized
//! into the publication.
//!
//! @ref LLP 0035#promotion-lineage-and-admission — only the checked C form may
//! open production; A and later descendants remain closed.
//! @ref LLP 0035#runtime-identity-split — portable equality and an independent
//! mapped-instance proof are both required at Host startup.
//! @ref LLP 0035#reports-and-advertisements — advertisements publish the
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
const ADVERTISEMENT_SCHEMA_V3: &str = "ibex/capsec-target-advertisements/3";
const CAPSEC_PROFILE: &str = "ibex/capsec/1";
const PROMOTION_ADMISSION_SCHEMA: &str = "ibex/portable-engine-checked-promotion-admission/2";
const PROMOTION_ADMISSION_DOMAIN: &str = "ibex.portable-engine-checked-promotion-admission.v2";
const REPORT_SCHEMA_V3: &str = "ibex/capsec-conformance/3";
const REPORT_DOMAIN_V3: &str = "ibex:capsec:conformance:3";
const SCOPE_SCHEMA_V1: &str = "ibex/capsec-scope/1";
const SCOPE_DOMAIN_V1: &str = "ibex:capsec:scope:1";
const SCOPE_GENESIS: &str = "genesis";
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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeIntensionalDefinition {
    capability_families: Vec<String>,
    surface_kinds: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeClosureEdge {
    from_edge_id: String,
    to_edge_id: String,
    dependency_kind: ScopeDependencyKind,
    implementation_branch_id: String,
    terminal_observed_key: String,
    proof_paths: Vec<String>,
    source_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
enum ScopeDependencyKind {
    #[serde(rename = "source-derived-route")]
    SourceDerivedRoute,
    #[serde(rename = "argument-selected-branch-alternative")]
    ArgumentSelectedBranchAlternative,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScopeClosureEdgeIdentity {
    from_edge_id: String,
    to_edge_id: String,
}

impl ScopeClosureEdge {
    fn identity(&self) -> ScopeClosureEdgeIdentity {
        ScopeClosureEdgeIdentity {
            from_edge_id: self.from_edge_id.clone(),
            to_edge_id: self.to_edge_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum ScopePredecessor {
    #[serde(rename = "genesis")]
    Genesis,
    #[serde(rename = "scope")]
    Scope {
        #[serde(rename = "scopeDigest")]
        scope_digest: Digest,
    },
}

impl ScopePredecessor {
    fn digest(&self) -> &str {
        match self {
            Self::Genesis => SCOPE_GENESIS,
            Self::Scope { scope_digest } => scope_digest.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CapsecScopeArtifact {
    scope_schema: String,
    profile: String,
    target: AdvertisementTarget,
    intensional_definition: ScopeIntensionalDefinition,
    expanded_cell_ids: Vec<String>,
    closure_edges: Vec<ScopeClosureEdge>,
    predecessor: ScopePredecessor,
    scope_expansion_diff_digest: Digest,
    scope_cell_mapping_digest: Digest,
    scope_digest: Digest,
}

/// Host-only cell posture retained in the admitted scoped aggregate.
///
/// @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — uncertified is
/// a host admission fact and projects to the unchanged typed `Incomplete`
/// disposition only at Host's single projection funnel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostCellDisposition {
    Certified(TargetCellDisposition),
    Uncertified,
}

/// The inseparable output of scoped report admission.
///
/// Its fields and constructor stay private to this module. `Host` can consume
/// the value and use these read-only projections, but cannot mint or splice a
/// scope identity, expansion, and disposition map itself.
/// @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — Option B makes
/// this aggregate the sole runtime authority for scope introspection and gate
/// projection; the armed snapshot carries no scope identity.
#[derive(Debug)]
pub(super) struct AdmittedScopedTargetCells {
    scope_digest: Digest,
    predecessor_scope_digest: String,
    expanded_cells: BTreeSet<String>,
    dispositions: BTreeMap<String, HostCellDisposition>,
    uncertified_remainder: usize,
}

impl AdmittedScopedTargetCells {
    fn new(
        scope_digest: Digest,
        predecessor_scope_digest: String,
        expanded_cells: BTreeSet<String>,
        dispositions: BTreeMap<String, HostCellDisposition>,
    ) -> Result<Self> {
        let inventory = crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS;
        let exhaustive = dispositions.len() == inventory.len()
            && inventory
                .iter()
                .all(|edge| dispositions.contains_key(*edge));
        let expansion_is_exact = !expanded_cells.is_empty()
            && expanded_cells
                .iter()
                .all(|edge| inventory.binary_search(&edge.as_str()).is_ok());
        let predecessor_is_valid = predecessor_scope_digest == SCOPE_GENESIS
            || Digest::new(&predecessor_scope_digest).is_ok();
        let partition_matches = dispositions.iter().all(|(edge, disposition)| {
            matches!(
                (expanded_cells.contains(edge), disposition),
                (
                    true,
                    HostCellDisposition::Certified(
                        TargetCellDisposition::Complete | TargetCellDisposition::Closed
                    )
                ) | (false, HostCellDisposition::Uncertified)
            )
        });
        if !exhaustive || !expansion_is_exact || !predecessor_is_valid || !partition_matches {
            return Err(refused(
                "admitted scoped target cells do not exhaustively match their carried expansion",
            ));
        }
        let uncertified_remainder = dispositions
            .values()
            .filter(|disposition| matches!(disposition, HostCellDisposition::Uncertified))
            .count();
        Ok(Self {
            scope_digest,
            predecessor_scope_digest,
            expanded_cells,
            dispositions,
            uncertified_remainder,
        })
    }

    pub(super) fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub(super) fn disposition(&self, edge: &str) -> Option<HostCellDisposition> {
        self.dispositions.get(edge).copied()
    }

    pub(super) fn uncertified_remainder(&self) -> usize {
        self.uncertified_remainder
    }

    pub(super) fn uncertified_edge_ids(&self) -> impl Iterator<Item = &str> {
        self.dispositions.iter().filter_map(|(edge, disposition)| {
            matches!(disposition, HostCellDisposition::Uncertified).then_some(edge.as_str())
        })
    }

    pub(super) fn is_coherent(&self) -> bool {
        // This is a deliberately redundant Host-boundary re-derivation of
        // `new`'s postcondition, not an independent admission source. With the
        // current private fields and no mutators it cannot fail for a safely
        // constructed value; keeping that strength explicit avoids crediting
        // the guard as a second validator.
        let inventory = crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS;
        (self.predecessor_scope_digest == SCOPE_GENESIS
            || Digest::new(&self.predecessor_scope_digest).is_ok())
            && !self.expanded_cells.is_empty()
            && self.dispositions.len() == inventory.len()
            && inventory
                .iter()
                .all(|edge| self.dispositions.contains_key(*edge))
            && self
                .expanded_cells
                .iter()
                .all(|edge| inventory.binary_search(&edge.as_str()).is_ok())
            && self.uncertified_remainder
                == self
                    .dispositions
                    .values()
                    .filter(|disposition| matches!(disposition, HostCellDisposition::Uncertified))
                    .count()
            && self.dispositions.iter().all(|(edge, disposition)| {
                matches!(
                    (self.expanded_cells.contains(edge), disposition),
                    (
                        true,
                        HostCellDisposition::Certified(
                            TargetCellDisposition::Complete | TargetCellDisposition::Closed
                        )
                    ) | (false, HostCellDisposition::Uncertified)
                )
            })
    }
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
    scope_digest: Digest,
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
    target: AdvertisementTarget,
    portable_artifact_id: Digest,
    admission_digest: Option<Digest>,
    admitted_scope_digest: Option<Digest>,
    predecessor_scope_digest: Option<String>,
    verification_digest: Digest,
}

#[derive(Clone, Debug)]
pub(super) struct CheckedPromotionScopeAnchor {
    admitted_scope_digest: Digest,
    predecessor_scope_digest: String,
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
    scope_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportSummary {
    cells: u64,
    conformant_cells: u64,
    incomplete_cells: u64,
    uncertified_cells: u64,
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
    if target.features.is_empty() {
        return Err(invalid(format!(
            "{label}.features is not a non-empty canonical tuple component"
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

/// Select one exact v3 row. Legacy v1 is recognized only as an explicitly
/// closed compatibility state. The target-cell digest is joined later to the
/// exact promoted report because source A intentionally retains only its
/// all-unsupported diagnostic catalog.
pub(super) fn select_v3_advertisement(
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
            "legacy v1 target advertisements are diagnostic-only and remain closed; ordinary `ibex run` cannot arm until the standard promotion pipeline ships a generated v3 advertisement for this target; `--project-root` selects the mounted project but does not mint advertisements; use `ibex capsec audit <file>` only for unarmed diagnostics",
        ));
    }
    if schema != ADVERTISEMENT_SCHEMA_V3 {
        return Err(invalid(format!(
            "unsupported target advertisement schema {schema:?}"
        )));
    }
    reject_published_locality(&value, "targetAdvertisements")?;
    let catalog: TargetAdvertisementCatalog = serde_json::from_value(value).map_err(|error| {
        invalid(format!(
            "invalid checked v3 target advertisement model: {error}"
        ))
    })?;
    if catalog.target_advertisement_schema != ADVERTISEMENT_SCHEMA_V3
        || catalog.profile != CAPSEC_PROFILE
    {
        return Err(invalid(
            "checked v3 target advertisements have the wrong schema or profile",
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
            "target",
            "portableArtifactId",
            "admissionDigest",
            "admittedScopeDigest",
            "predecessorScopeDigest",
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
/// that are independently present in the v3 publication.
pub(super) fn require_checked_promotion(
    advertisement: &SelectedTargetAdvertisement,
    admission_text: &str,
) -> Result<CheckedPromotionScopeAnchor> {
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
    validate_target(&admission.target, "checked promotion admission.target")?;
    if !admission.authorized {
        if admission.current_revision != admission.source_revision
            || admission.promotion_topic_revision.is_some()
            || admission.source_tree_object_id.is_some()
            || admission.admission_digest.is_some()
            || admission.admitted_scope_digest.is_some()
            || admission.predecessor_scope_digest.is_some()
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
        || admission.admitted_scope_digest.is_none()
        || admission.predecessor_scope_digest.is_none()
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
    if admission.target != advertisement.target {
        return Err(refused(
            "promotion admission target differs from the advertisement",
        ));
    }
    if admission.portable_artifact_id != advertisement.engine.artifact_id {
        return Err(refused(
            "promotion admission artifact differs from the advertisement",
        ));
    }
    let admitted_scope_digest = admission
        .admitted_scope_digest
        .expect("authorized admission checked above");
    let predecessor_scope_digest = admission
        .predecessor_scope_digest
        .expect("authorized admission checked above");
    if predecessor_scope_digest != SCOPE_GENESIS && Digest::new(&predecessor_scope_digest).is_err()
    {
        return Err(invalid(
            "checked promotion admission predecessor scope identity is malformed",
        ));
    }
    if admitted_scope_digest != advertisement.scope_digest {
        return Err(refused(
            "promotion admission scope differs from the advertisement",
        ));
    }
    Ok(CheckedPromotionScopeAnchor {
        admitted_scope_digest,
        predecessor_scope_digest,
    })
}

fn validate_report_cell(cell: &ReportCell, index: usize) -> Result<()> {
    let label = format!("promoted report cells[{index}]");
    if !valid_capsec_stable_id(&cell.edge_id) {
        return Err(invalid(format!("{label} has a malformed edge")));
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
    surface_kind: String,
    surface_observed_key: String,
    action_ids: Vec<String>,
    logical_branch_action_ids: Vec<(String, Vec<String>)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckedTargetCellAuthority {
    implementation_branch_ids: Vec<String>,
    enforcement_branch_ids: Vec<String>,
    required_fixtures: Vec<String>,
    fixture_action_families: BTreeMap<String, BTreeSet<String>>,
    surface_kind: String,
    closure_dependencies: BTreeSet<String>,
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
    observed_key: String,
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
                    surface_kind: surface_kind.to_owned(),
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
            observed_key,
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
    let mut observed_edges = BTreeMap::<String, BTreeSet<String>>::new();
    for (edge_id, branch_ids) in &target_branches {
        for branch_id in branch_ids {
            let row = implementation_rows.get(branch_id).ok_or_else(|| {
                invalid(format!("checked target selects unknown branch {branch_id}"))
            })?;
            observed_edges
                .entry(row.observed_key.clone())
                .or_default()
                .insert(edge_id.clone());
        }
    }
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
        let fixture_binding_rows = required_fixtures
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
                let action_families = action_ids
                    .iter()
                    .filter_map(|action| {
                        action.split_once(':').map(|(family, _)| family.to_owned())
                    })
                    .collect::<BTreeSet<_>>();
                Ok((
                    serde_json::json!({
                        "fixtureId": fixture_id,
                        "implementationBranchIds": fixture_implementation_ids,
                        "enforcementBranchIds": fixture_enforcement_ids,
                        "terminalObservedKeys": terminal_observed_keys,
                        "classifications": [semantics.classification],
                        "actionIds": action_ids,
                    }),
                    fixture_id.clone(),
                    action_families,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let fixture_bindings = fixture_binding_rows
            .iter()
            .map(|(binding, _, _)| binding.clone())
            .collect::<Vec<_>>();
        let fixture_action_families = fixture_binding_rows
            .into_iter()
            .map(|(_, fixture_id, families)| (fixture_id, families))
            .collect::<BTreeMap<_, _>>();
        let closure_dependencies = selected_rows
            .iter()
            .flat_map(|row| {
                observed_edges
                    .get(&row.terminal_observed_key)
                    .into_iter()
                    .flatten()
            })
            .cloned()
            .collect::<BTreeSet<_>>();
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
                fixture_action_families,
                surface_kind: semantics.surface_kind.clone(),
                closure_dependencies,
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

fn parse_scope_artifact(scope_text: &str) -> Result<(Value, CapsecScopeArtifact)> {
    if scope_text == "null" || scope_text == "null\n" {
        return Err(refused(
            "promoted CapSec scope artifact is absent from this build",
        ));
    }
    let value = capsec_semantics::strict_json::parse_strict(scope_text)
        .map_err(|error| invalid(format!("invalid promoted scope artifact: {error}")))?;
    let expected = capsec_semantics::canonical::to_jcs(&value)
        .map_err(|error| invalid(format!("promoted scope artifact is not I-JSON: {error}")))?;
    if expected != scope_text {
        return Err(invalid(
            "promoted scope artifact bytes are not exact RFC 8785 JCS",
        ));
    }
    let scope = serde_json::from_value(value.clone())
        .map_err(|error| invalid(format!("invalid promoted scope artifact model: {error}")))?;
    Ok((value, scope))
}

fn validate_scope_selector(selector: &ScopeIntensionalDefinition) -> Result<()> {
    let validate = |values: &[String], label: &str| -> Result<()> {
        if values.is_empty()
            || values
                .iter()
                .any(|value| value.is_empty() || !valid_capsec_stable_id(value))
            || values
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(invalid(format!(
                "promoted scope {label} is not a non-empty canonical selector set"
            )));
        }
        Ok(())
    };
    validate(&selector.capability_families, "capabilityFamilies")?;
    validate(&selector.surface_kinds, "surfaceKinds")
}

fn derive_scope_expansion(
    authority: &CheckedReportAuthority,
    selector: &ScopeIntensionalDefinition,
) -> Result<(BTreeSet<String>, BTreeSet<ScopeClosureEdgeIdentity>)> {
    validate_scope_selector(selector)?;
    let families = selector
        .capability_families
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let surface_kinds = selector
        .surface_kinds
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut expanded = authority
        .cells
        .iter()
        .filter(|(_, cell)| {
            surface_kinds.contains(cell.surface_kind.as_str())
                && cell
                    .fixture_action_families
                    .values()
                    .any(|fixture_families| {
                        !fixture_families.is_empty()
                            && fixture_families
                                .iter()
                                .all(|family| families.contains(family.as_str()))
                    })
        })
        .map(|(edge, _)| edge.clone())
        .collect::<BTreeSet<_>>();
    if expanded.is_empty() {
        return Err(refused(
            "promoted scope selector expands to no checked target cells",
        ));
    }

    let mut pending = expanded.iter().cloned().collect::<Vec<_>>();
    let mut closure = BTreeSet::new();
    while let Some(from_edge_id) = pending.pop() {
        let cell = authority.cells.get(&from_edge_id).ok_or_else(|| {
            invalid(format!(
                "derived scope edge {from_edge_id} has no checked report authority"
            ))
        })?;
        for to_edge_id in &cell.closure_dependencies {
            closure.insert(ScopeClosureEdgeIdentity {
                from_edge_id: from_edge_id.clone(),
                to_edge_id: to_edge_id.clone(),
            });
            if expanded.insert(to_edge_id.clone()) {
                pending.push(to_edge_id.clone());
            }
        }
    }
    Ok((expanded, closure))
}

fn admit_scope_artifact(
    advertisement: &SelectedTargetAdvertisement,
    scope_text: &str,
    authority: &CheckedReportAuthority,
    anchor: &CheckedPromotionScopeAnchor,
) -> Result<(CapsecScopeArtifact, BTreeSet<String>)> {
    let (value, scope) = parse_scope_artifact(scope_text)?;
    if scope.scope_schema != SCOPE_SCHEMA_V1 || scope.profile != CAPSEC_PROFILE {
        return Err(invalid(
            "promoted scope artifact has the wrong schema or profile",
        ));
    }
    validate_target(&scope.target, "promotedScope.target")?;
    if scope.target != advertisement.target {
        return Err(refused(
            "promoted scope target differs from the advertisement",
        ));
    }
    let recomputed = capsec_semantics::digest::compute_domain_digest(
        SCOPE_DOMAIN_V1,
        &value,
        &["scopeDigest".to_owned()],
    )
    .map_err(|error| invalid(format!("cannot recompute promoted scope digest: {error}")))?;
    if scope.scope_digest.as_str() != recomputed
        || scope.scope_digest != advertisement.scope_digest
        || scope.scope_digest != anchor.admitted_scope_digest
    {
        return Err(refused(
            "promoted scope digest does not rejoin its advertisement and lineage anchor",
        ));
    }
    if scope.predecessor.digest() != anchor.predecessor_scope_digest {
        return Err(refused(
            "promoted scope predecessor differs from the lineage-resolved anchor",
        ));
    }
    let closure_order = scope
        .closure_edges
        .iter()
        .map(|edge| {
            serde_json::to_value(edge)
                .map_err(|error| invalid(format!("cannot project promoted scope closure: {error}")))
                .and_then(|edge| {
                    capsec_semantics::canonical::to_jcs(&edge).map_err(|error| {
                        invalid(format!("promoted scope closure is not I-JSON: {error}"))
                    })
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let expanded_cell_ids = scope.expanded_cell_ids.iter().collect::<BTreeSet<_>>();
    if scope
        .expanded_cell_ids
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        || scope
            .expanded_cell_ids
            .iter()
            .any(|edge| !valid_capsec_stable_id(edge) || !authority.cells.contains_key(edge))
        || scope.closure_edges.is_empty()
        || closure_order.windows(2).any(|pair| pair[0] >= pair[1])
        || scope.closure_edges.iter().any(|edge| {
            !valid_capsec_stable_id(&edge.from_edge_id)
                || !valid_capsec_stable_id(&edge.to_edge_id)
                || !valid_capsec_stable_id(&edge.implementation_branch_id)
                || edge.terminal_observed_key.is_empty()
                || edge.proof_paths.is_empty()
                || edge.source_refs.is_empty()
                || edge
                    .proof_paths
                    .windows(2)
                    .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
                || edge
                    .source_refs
                    .windows(2)
                    .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
                || !expanded_cell_ids.contains(&edge.from_edge_id)
                || !expanded_cell_ids.contains(&edge.to_edge_id)
        })
    {
        return Err(invalid(
            "promoted scope expansion or closure is not canonical over the checked inventory",
        ));
    }
    let (expanded, closure) = derive_scope_expansion(authority, &scope.intensional_definition)?;
    if scope
        .expanded_cell_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expanded
        || scope
            .closure_edges
            .iter()
            .map(ScopeClosureEdge::identity)
            .collect::<BTreeSet<_>>()
            != closure
    {
        return Err(refused(
            "promoted scope expansion or closure differs from source-derived recomputation",
        ));
    }
    Ok((scope, expanded))
}

/// Validate the exact embedded report selected by build.rs and derive Host's
/// complete/closed map from its complete conformant cell membership plus the
/// checked source classification. No source-A `unsupported` row is borrowed.
pub(super) fn authenticated_report_target_cells(
    advertisement: &SelectedTargetAdvertisement,
    report_text: &str,
    scope_text: &str,
    anchor: &CheckedPromotionScopeAnchor,
) -> Result<AdmittedScopedTargetCells> {
    let authority = checked_report_authority(&advertisement.target)?;
    authenticated_report_target_cells_with_authority(
        advertisement,
        report_text,
        scope_text,
        anchor,
        &authority,
    )
}

fn authenticated_report_target_cells_with_authority(
    advertisement: &SelectedTargetAdvertisement,
    report_text: &str,
    scope_text: &str,
    anchor: &CheckedPromotionScopeAnchor,
    authority: &CheckedReportAuthority,
) -> Result<AdmittedScopedTargetCells> {
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
    let (scope, expanded_cells) =
        admit_scope_artifact(advertisement, scope_text, authority, anchor)?;
    if report.conformance_schema != REPORT_SCHEMA_V3
        || report.profile != CAPSEC_PROFILE
        || report.status != "conformant"
    {
        return Err(refused(
            "embedded promoted report is not one conformant v3 report",
        ));
    }
    let expected_digest = capsec_semantics::digest::compute_domain_digest(
        REPORT_DOMAIN_V3,
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
        || bindings.scope_digest != advertisement.scope_digest
        || bindings.scope_digest != scope.scope_digest
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
        report.summary.uncertified_cells,
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
        let certified_disposition = if cell.implementation_branch_ids.is_empty() {
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
        if expanded_cells.contains(*expected_edge) {
            if cell.status != "conformant"
                || cell.required_fixtures != cell.passed_fixtures
                || !cell.missing_fixtures.is_empty()
                || !cell.failed_fixtures.is_empty()
            {
                return Err(refused(format!(
                    "in-scope promoted report cell {expected_edge} does not carry complete passing fixture evidence"
                )));
            }
            required_fixtures.extend(cell.required_fixtures.iter().cloned());
            passed_fixtures.extend(cell.passed_fixtures.iter().cloned());
            result.insert(
                (*expected_edge).to_owned(),
                HostCellDisposition::Certified(certified_disposition),
            );
        } else {
            if cell.status != "uncertified"
                || !cell.passed_fixtures.is_empty()
                || !cell.missing_fixtures.is_empty()
                || !cell.failed_fixtures.is_empty()
            {
                return Err(refused(format!(
                    "out-of-scope promoted report cell {expected_edge} does not carry the zero-contribution uncertified disposition"
                )));
            }
            result.insert(
                (*expected_edge).to_owned(),
                HostCellDisposition::Uncertified,
            );
        }
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
        || report.summary.conformant_cells != expanded_cells.len() as u64
        || report.summary.incomplete_cells != 0
        || report.summary.uncertified_cells != (report.cells.len() - expanded_cells.len()) as u64
        || report.summary.required_fixtures != required_fixtures.len() as u64
        || report.summary.passed_fixtures != passed_fixtures.len() as u64
        || report.summary.missing_fixtures != 0
        || report.summary.failed_fixtures != 0
    {
        return Err(refused(
            "promoted report summary or fixture membership is incomplete",
        ));
    }
    AdmittedScopedTargetCells::new(
        scope.scope_digest,
        scope.predecessor.digest().to_owned(),
        expanded_cells,
        result,
    )
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
        scope: String,
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

    #[test]
    fn generated_scope_vector_deserializes_through_the_production_parser() {
        let vector = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/vectors/capsec-scope-v1.valid.json"
        ));
        let (_, scope) = parse_scope_artifact(vector).unwrap();
        assert_eq!(scope.scope_schema, SCOPE_SCHEMA_V1);
        assert_eq!(scope.predecessor, ScopePredecessor::Genesis);
        assert!(!scope.expanded_cell_ids.is_empty());
        assert!(!scope.closure_edges.is_empty());
        assert!(scope.closure_edges.iter().all(|edge| {
            edge.dependency_kind == ScopeDependencyKind::SourceDerivedRoute
                && !edge.implementation_branch_id.is_empty()
                && !edge.terminal_observed_key.is_empty()
                && !edge.proof_paths.is_empty()
                && !edge.source_refs.is_empty()
        }));
    }

    fn test_authority(advertisement: &Value) -> CheckedReportAuthority {
        let cells = crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS
            .iter()
            .enumerate()
            .map(|(index, edge)| {
                let prefix = format!("{edge}.");
                let implementation_branch_ids =
                    crate::capsec_registry_generated::CAPSEC_IMPLEMENTATION_BRANCH_IDS
                        .iter()
                        .filter(|branch| branch.starts_with(&prefix))
                        .map(|branch| (*branch).to_owned())
                        .collect::<Vec<_>>();
                let enforcement_branch_ids =
                    crate::capsec_registry_generated::CAPSEC_ENFORCEMENT_BRANCH_IDS
                        .iter()
                        .filter(|branch| branch.starts_with(&prefix))
                        .map(|branch| (*branch).to_owned())
                        .collect::<Vec<_>>();
                let required_fixtures = match index {
                    0 => vec![
                        "fixture.host-admission.a".to_owned(),
                        "fixture.host-admission.b".to_owned(),
                    ],
                    1 => vec!["fixture.host-admission.out-of-scope".to_owned()],
                    _ => Vec::new(),
                };
                let fixture_action_families = required_fixtures
                    .iter()
                    .map(|fixture| {
                        let families = if index == 0 {
                            BTreeSet::from(["scope.family".to_owned()])
                        } else {
                            BTreeSet::from(["outside.family".to_owned()])
                        };
                        (fixture.clone(), families)
                    })
                    .collect();
                (
                    (*edge).to_owned(),
                    CheckedTargetCellAuthority {
                        implementation_branch_ids,
                        enforcement_branch_ids,
                        required_fixtures,
                        fixture_action_families,
                        surface_kind: if index == 0 {
                            "native.test".to_owned()
                        } else {
                            "other.test".to_owned()
                        },
                        closure_dependencies: if index == 0 {
                            BTreeSet::from([(*edge).to_owned()])
                        } else {
                            BTreeSet::new()
                        },
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

    fn scope_for(advertisement: &Value, authority: &CheckedReportAuthority) -> (Value, String) {
        let selector = ScopeIntensionalDefinition {
            capability_families: vec!["scope.family".to_owned()],
            surface_kinds: vec!["native.test".to_owned()],
        };
        let (expanded, closure) = derive_scope_expansion(authority, &selector).unwrap();
        let closure = closure
            .into_iter()
            .map(|edge| ScopeClosureEdge {
                implementation_branch_id: authority.cells[&edge.from_edge_id]
                    .implementation_branch_ids[0]
                    .clone(),
                terminal_observed_key: "native-op:scope-fixture".to_owned(),
                proof_paths: vec!["native-op:scope-fixture".to_owned()],
                source_refs: vec!["src/host/portable_target_admission.rs#scope-fixture".to_owned()],
                dependency_kind: ScopeDependencyKind::SourceDerivedRoute,
                from_edge_id: edge.from_edge_id,
                to_edge_id: edge.to_edge_id,
            })
            .collect::<Vec<_>>();
        let mut scope = serde_json::json!({
            "scopeSchema": SCOPE_SCHEMA_V1,
            "profile": CAPSEC_PROFILE,
            "target": advertisement["target"],
            "intensionalDefinition": selector,
            "expandedCellIds": expanded,
            "closureEdges": closure,
            "predecessor": {"kind": "genesis"},
            "scopeExpansionDiffDigest": digest("expansion-diff"),
            "scopeCellMappingDigest": digest("cell-mapping"),
            "scopeDigest": digest("placeholder-scope"),
        });
        scope["scopeDigest"] = Value::String(
            capsec_semantics::digest::compute_domain_digest(
                SCOPE_DOMAIN_V1,
                &scope,
                &["scopeDigest".to_owned()],
            )
            .unwrap(),
        );
        let text = capsec_semantics::canonical::to_jcs(&scope).unwrap();
        (scope, text)
    }

    fn report_for(
        advertisement: &Value,
        target_cells_digest: &str,
        authority: &CheckedReportAuthority,
        expanded: &BTreeSet<String>,
    ) -> String {
        let evidence_digest =
            advertisement["mappedEngineExecutionEvidence"][0]["evidenceDigest"].clone();
        let cells = authority
            .cells
            .iter()
            .map(|(edge, cell)| {
                let in_scope = expanded.contains(edge);
                serde_json::json!({
                    "edgeId": edge,
                    "implementationBranchIds": cell.implementation_branch_ids,
                    "enforcementBranchIds": cell.enforcement_branch_ids,
                    "status": if in_scope { "conformant" } else { "uncertified" },
                    "requiredFixtures": cell.required_fixtures,
                    "passedFixtures": if in_scope { cell.required_fixtures.clone() } else { Vec::new() },
                    "missingFixtures": [],
                    "failedFixtures": [],
                })
            })
            .collect::<Vec<_>>();
        let mut report = serde_json::json!({
            "conformanceSchema": REPORT_SCHEMA_V3,
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
                "scopeDigest": advertisement["scopeDigest"],
            },
            "summary": {
                "cells": cells.len(),
                "conformantCells": expanded.len(),
                "incompleteCells": 0,
                "uncertifiedCells": cells.len() - expanded.len(),
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
                REPORT_DOMAIN_V3,
                &report,
                &["conformanceDigest".to_owned()],
            )
            .unwrap(),
        );
        format!("{}\n", serde_json::to_string_pretty(&report).unwrap())
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
            "scopeDigest": digest("placeholder-scope"),
        });
        let target_cells_digest = raw_content_digest(&cells);
        let authority = test_authority(&advertisement);
        let (scope_value, scope) = scope_for(&advertisement, &authority);
        advertisement["scopeDigest"] = scope_value["scopeDigest"].clone();
        let expanded = scope_value["expandedCellIds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge.as_str().unwrap().to_owned())
            .collect();
        let report = report_for(&advertisement, &target_cells_digest, &authority, &expanded);
        let report_value: Value = serde_json::from_str(&report).unwrap();
        advertisement["conformanceDigest"] = report_value["conformanceDigest"].clone();
        advertisement["reportRawContentDigest"] =
            Value::String(raw_content_digest(report.as_bytes()));
        let advertisements = serde_json::json!({
            "targetAdvertisementSchema": ADVERTISEMENT_SCHEMA_V3,
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
            "target": {"triple": target, "features": features},
            "portableArtifactId": portable.artifact_id,
            "admissionDigest": digest("lineage-admission"),
            "admittedScopeDigest": scope_value["scopeDigest"],
            "predecessorScopeDigest": SCOPE_GENESIS,
            "verificationDigest": digest("placeholder"),
        });
        Fixture {
            advertisements,
            report,
            scope,
            authority,
            admission,
            portable,
            mapped,
            target,
            features,
        }
    }

    fn select(fixture: &Fixture) -> Result<SelectedTargetAdvertisement> {
        select_v3_advertisement(
            &serde_json::to_string(&fixture.advertisements).unwrap(),
            &fixture.target,
            &fixture.features,
        )
    }

    fn authenticate_fixture_report(
        fixture: &Fixture,
        advertisement: &SelectedTargetAdvertisement,
        report_text: &str,
    ) -> Result<AdmittedScopedTargetCells> {
        let anchor =
            require_checked_promotion(advertisement, &checked_marker(fixture.admission.clone()))?;
        authenticated_report_target_cells_with_authority(
            advertisement,
            report_text,
            &fixture.scope,
            &anchor,
            &fixture.authority,
        )
    }

    fn rebind_report(
        advertisement: &SelectedTargetAdvertisement,
        mut report: Value,
    ) -> (SelectedTargetAdvertisement, String) {
        report["conformanceDigest"] = Value::String(
            capsec_semantics::digest::compute_domain_digest(
                REPORT_DOMAIN_V3,
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

    fn scoped_host(fixture: &Fixture) -> super::super::Host {
        let advertisement = select(fixture).unwrap();
        let admitted =
            authenticate_fixture_report(fixture, &advertisement, &fixture.report).unwrap();
        let snapshot = super::super::tests::example_armed_snapshot_with(|_| {});
        super::super::Host::new_armed_with_target_cells(
            super::super::HostConfig::default(),
            std::sync::Arc::new(snapshot),
            super::super::HostTargetCells::Scoped(admitted),
            super::super::AuthenticatedPackageSourceState::default(),
        )
        .unwrap()
    }

    fn decision_set() -> capsec_semantics::model::DecisionSet {
        serde_json::from_value(serde_json::json!({
            "decisionSetSchema": "ibex/capsec-decision-set/1",
            "operationId": "scope-ingress-test",
            "atomicityGroup": "scope.ingress.test",
            "combination": "conjunction",
            "context": {
                "stage": "commit",
                "actor": {"kind": "root", "identity": "project-root"},
                "constrainedPrincipals": [
                    {"kind": "root", "identity": "project-root"}
                ]
            },
            "effects": [{
                "cap": "env:read",
                "effectOwner": {"kind": "root", "identity": "project-root"},
                "resource": {
                    "kind": "environment-occurrence",
                    "requested": {
                        "kind": "environment-name",
                        "target": "principal-overlay",
                        "name": "SCOPE_TEST"
                    },
                    "valueOrigin": "principal-overlay"
                }
            }]
        }))
        .unwrap()
    }

    fn gate(
        edge: &str,
        target_cell: TargetCellDisposition,
    ) -> capsec_semantics::decision::EffectGate {
        capsec_semantics::decision::EffectGate {
            coverage_edge_id: capsec_semantics::model::StableId::new(edge).unwrap(),
            target_cell,
            definition_and_edge_predicates_satisfied: true,
        }
    }

    #[test]
    fn admitted_aggregate_is_atomic_exhaustive_and_partitioned() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<HostCellDisposition>();

        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        let admitted =
            authenticate_fixture_report(&fixture, &advertisement, &fixture.report).unwrap();
        assert!(admitted.is_coherent());

        let mut missing = admitted.dispositions.clone();
        missing.remove(crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS[0]);
        assert!(AdmittedScopedTargetCells::new(
            admitted.scope_digest.clone(),
            admitted.predecessor_scope_digest.clone(),
            admitted.expanded_cells.clone(),
            missing,
        )
        .is_err());

        let in_scope = admitted.expanded_cells.iter().next().unwrap();
        let mut inverted = admitted.dispositions.clone();
        inverted.insert(in_scope.clone(), HostCellDisposition::Uncertified);
        assert!(AdmittedScopedTargetCells::new(
            admitted.scope_digest.clone(),
            admitted.predecessor_scope_digest.clone(),
            admitted.expanded_cells.clone(),
            inverted,
        )
        .is_err());

        let mut expanded_with_unknown = admitted.expanded_cells.clone();
        expanded_with_unknown.insert("surface.native.unknown".to_owned());
        assert!(AdmittedScopedTargetCells::new(
            admitted.scope_digest,
            admitted.predecessor_scope_digest,
            expanded_with_unknown,
            admitted.dispositions,
        )
        .is_err());
    }

    #[test]
    fn scope_is_canonical_source_rederived_and_single_per_tuple() {
        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        let anchor =
            require_checked_promotion(&advertisement, &checked_marker(fixture.admission.clone()))
                .unwrap();

        let pretty = format!(
            "{}\n",
            serde_json::to_string_pretty(
                &serde_json::from_str::<Value>(fixture.scope.trim_end()).unwrap()
            )
            .unwrap()
        );
        let error =
            admit_scope_artifact(&advertisement, &pretty, &fixture.authority, &anchor).unwrap_err();
        assert!(error.to_string().contains("RFC 8785 JCS"), "{error}");

        let mut scope: Value = serde_json::from_str(fixture.scope.trim_end()).unwrap();
        let mut expanded = scope["expandedCellIds"].as_array().unwrap().clone();
        expanded.push(Value::String(
            crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS[1].to_owned(),
        ));
        expanded.sort_by(|left, right| {
            left.as_str()
                .unwrap()
                .as_bytes()
                .cmp(right.as_str().unwrap().as_bytes())
        });
        scope["expandedCellIds"] = Value::Array(expanded);
        scope["scopeDigest"] = Value::String(
            capsec_semantics::digest::compute_domain_digest(
                SCOPE_DOMAIN_V1,
                &scope,
                &["scopeDigest".to_owned()],
            )
            .unwrap(),
        );
        let scope_text = capsec_semantics::canonical::to_jcs(&scope).unwrap();
        let scope_digest: Digest = serde_json::from_value(scope["scopeDigest"].clone()).unwrap();
        let mut rebound = advertisement.clone();
        rebound.advertisement.scope_digest = scope_digest.clone();
        let rebound_anchor = CheckedPromotionScopeAnchor {
            admitted_scope_digest: scope_digest,
            predecessor_scope_digest: SCOPE_GENESIS.to_owned(),
        };
        let error =
            admit_scope_artifact(&rebound, &scope_text, &fixture.authority, &rebound_anchor)
                .unwrap_err();
        assert!(
            error.to_string().contains("source-derived recomputation"),
            "{error}"
        );

        let mut duplicate = fixture.advertisements.clone();
        let row = duplicate["advertisements"][0].clone();
        duplicate["advertisements"]
            .as_array_mut()
            .unwrap()
            .push(row);
        assert!(select_v3_advertisement(
            &serde_json::to_string(&duplicate).unwrap(),
            &fixture.target,
            &fixture.features,
        )
        .is_err());
    }

    #[test]
    fn out_of_scope_rows_keep_honest_required_fixtures_without_authoritative_credit() {
        let fixture = fixture();
        let report: Value = serde_json::from_str(&fixture.report).unwrap();
        let out = report["cells"]
            .as_array()
            .unwrap()
            .iter()
            .find(|cell| cell["requiredFixtures"].as_array().unwrap().len() == 1)
            .unwrap();
        assert_eq!(out["status"], "uncertified");
        assert_eq!(
            out["requiredFixtures"],
            serde_json::json!(["fixture.host-admission.out-of-scope"])
        );
        assert_eq!(out["passedFixtures"], serde_json::json!([]));
        assert!(report["executions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| { row["fixtureId"] != "fixture.host-admission.out-of-scope" }));

        let advertisement = select(&fixture).unwrap();
        authenticate_fixture_report(&fixture, &advertisement, &fixture.report).unwrap();
    }

    #[test]
    fn scoped_projection_and_introspection_share_one_aggregate() {
        let fixture = fixture();
        let host = scoped_host(&fixture);
        let introspection = host.capsec_scope_introspection().unwrap();
        let introspection_json = serde_json::to_value(&introspection).unwrap();
        assert_eq!(
            introspection_json
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["schema", "scopeDigest", "uncertifiedRemainder"])
        );
        assert_eq!(
            introspection_json["uncertifiedRemainder"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["count", "edgeIds"])
        );
        let scope: CapsecScopeArtifact = serde_json::from_str(fixture.scope.trim_end()).unwrap();
        let advertisement = select(&fixture).unwrap();
        let admitted =
            authenticate_fixture_report(&fixture, &advertisement, &fixture.report).unwrap();
        assert_eq!(introspection.scope_digest, scope.scope_digest);
        assert_eq!(
            introspection.uncertified_remainder.count,
            crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS.len()
                - scope.expanded_cell_ids.len()
        );
        let remainder = introspection
            .uncertified_remainder
            .edge_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for edge in crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS {
            let expected = match admitted.disposition(edge) {
                Some(HostCellDisposition::Certified(disposition)) => disposition,
                Some(HostCellDisposition::Uncertified) | None => {
                    assert!(remainder.contains(edge));
                    TargetCellDisposition::Incomplete
                }
            };
            assert_eq!(host.target_cell(edge), expected, "{edge}");
        }

        let complete_snapshot = super::super::tests::example_armed_snapshot_with(|_| {});
        let complete = unsafe {
            super::super::Host::new_armed_for_test(
                super::super::HostConfig::default(),
                std::sync::Arc::new(complete_snapshot),
            )
            .unwrap()
        };
        assert!(complete.capsec_scope_introspection().is_none());
        assert!(super::super::Host::new(super::super::HostConfig::default())
            .capsec_scope_introspection()
            .is_none());
    }

    #[test]
    fn non_advertisement_constructors_remain_scope_incapable() {
        // This source scrape is only a formatting-sensitive smoke check. The
        // actual construction boundary is this private module plus private
        // `AdmittedScopedTargetCells::new`; this fixture cannot prove that a
        // future constructor helper stays scope-incapable.
        fn constructor_body<'a>(source: &'a str, name: &str) -> &'a str {
            let marker = format!("fn {name}(");
            let start = source
                .find(&marker)
                .unwrap_or_else(|| panic!("missing Host constructor {name}"));
            let tail = &source[start..];
            let end = [
                "\n    }\n\n    ///",
                "\n    }\n\n    fn ",
                "\n    }\n\n    #[",
                "\n    }\n\n    pub ",
            ]
            .into_iter()
            .filter_map(|boundary| tail.find(boundary))
            .min()
            .unwrap_or_else(|| panic!("cannot bound Host constructor {name}"));
            &tail[..end]
        }

        let source = include_str!("mod.rs");
        for (name, complete_spelling) in [
            (
                "new_armed_unadvertised_dev",
                "HostTargetCells::Complete(target_cells)",
            ),
            (
                "new_armed_insecure",
                "HostTargetCells::Complete(target_cells)",
            ),
            (
                "new_armed_for_capsec_simulator_performance_observer",
                "HostTargetCells::Complete(target_cells)",
            ),
            (
                "new_armed_for_test",
                "HostTargetCells::Complete(complete_test_target_cells())",
            ),
            (
                "new_armed_for_test_with_package_sources",
                "HostTargetCells::Complete(complete_test_target_cells())",
            ),
            (
                "new_armed_for_native_module_runner_conformance",
                "HostTargetCells::Complete(cells)",
            ),
        ] {
            let body = constructor_body(source, name);
            assert!(body.contains(complete_spelling), "{name}");
            assert!(!body.contains("HostTargetCells::Scoped"), "{name}");
            assert!(!body.contains("capsec_scope_introspection"), "{name}");
        }

        let production = constructor_body(source, "new_armed");
        assert!(production.contains("HostTargetCells::Scoped(target_cells)"));
        assert!(!production.contains("HostTargetCells::Complete"));
    }

    #[test]
    fn scoped_refusal_funnel_covers_all_three_evaluator_bodies_once() {
        use capsec_semantics::decision::{DecisionOutcome, DecisionReason};

        let fixture = fixture();
        let host = scoped_host(&fixture);
        let set = decision_set();
        let edge = crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS[1];

        let decision = host
            .evaluate_typed_decision(&set, &[gate(edge, TargetCellDisposition::Complete)])
            .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::RefuseArming);
        let result = host
            .evaluate_typed_decision_with_evidence(
                &set,
                &[gate(edge, TargetCellDisposition::Complete)],
            )
            .unwrap();
        assert_eq!(result.decision.outcome, DecisionOutcome::RefuseArming);
        let projections =
            capsec_semantics::decision::PrincipalPathProjections::new(vec![BTreeMap::new()]);
        let result = host
            .evaluate_typed_path_decision_with_evidence(
                &set,
                &[gate(edge, TargetCellDisposition::Incomplete)],
                &projections,
            )
            .unwrap();
        assert_eq!(result.decision.outcome, DecisionOutcome::RefuseArming);

        let in_scope = serde_json::from_str::<CapsecScopeArtifact>(fixture.scope.trim_end())
            .unwrap()
            .expanded_cell_ids[0]
            .clone();
        let defect = host
            .evaluate_typed_decision_inner(
                &set,
                &[gate(&in_scope, TargetCellDisposition::Incomplete)],
                None,
            )
            .unwrap();
        assert_eq!(defect.outcome, DecisionOutcome::RefuseArming);

        let refusals = host.capsec_scoped_refusals();
        assert_eq!(refusals.len(), 4);
        assert!(refusals[..3].iter().all(|refusal| {
            refusal.coverage_edge_id == edge
                && refusal.decision_reason == DecisionReason::TargetCellIncomplete
                && refusal.host_disposition
                    == super::super::CapsecScopedRefusalHostDisposition::Uncertified
        }));
        assert_eq!(
            refusals[3].host_disposition,
            super::super::CapsecScopedRefusalHostDisposition::IncompleteDefect
        );
        assert_eq!(refusals[3].coverage_edge_id, in_scope);
        assert_eq!(refusals[3].presented_target_cell, None);
        assert_eq!(
            refusals[0].presented_target_cell,
            Some(TargetCellDisposition::Complete)
        );
        assert_eq!(
            refusals[1].presented_target_cell,
            Some(TargetCellDisposition::Complete)
        );
        assert_eq!(refusals[2].presented_target_cell, None);
        let envelope = serde_json::to_value(&refusals[0]).unwrap();
        let keys = envelope
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "coverageEdgeId",
                "decisionReason",
                "hostDisposition",
                "presentedTargetCell",
                "scopeDigest",
            ])
        );
        assert_ne!(envelope["hostDisposition"], "extension-declared");
    }

    #[test]
    fn all_four_public_ingresses_discard_and_recompute_scoped_cells() {
        use capsec_semantics::decision::{DecisionOutcome, DecisionReason};

        let fixture = fixture();
        let host = scoped_host(&fixture);
        let set = decision_set();
        let out = crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS[1];
        let incoming = gate(out, TargetCellDisposition::Complete);
        let set_json = serde_json::to_vec(&set).unwrap();
        let gates_json = serde_json::to_vec(&vec![incoming.clone()]).unwrap();

        let decisions = [
            host.evaluate_typed_decision(&set, &[incoming.clone()])
                .unwrap(),
            host.evaluate_typed_decision_with_evidence(&set, &[incoming.clone()])
                .unwrap()
                .decision,
            host.evaluate_typed_decision_json(&set_json, &gates_json)
                .unwrap(),
            host.evaluate_typed_decision_json_with_evidence(&set_json, &gates_json)
                .unwrap()
                .decision,
        ];
        assert!(decisions.iter().all(|decision| {
            decision.outcome == DecisionOutcome::RefuseArming
                && decision.evidence[0].reason == DecisionReason::TargetCellIncomplete
        }));
        assert_eq!(host.capsec_scoped_refusals().len(), 4);
        assert!(host.capsec_scoped_refusals().iter().all(|refusal| {
            refusal.presented_target_cell == Some(TargetCellDisposition::Complete)
        }));

        let in_scope = serde_json::from_str::<CapsecScopeArtifact>(fixture.scope.trim_end())
            .unwrap()
            .expanded_cell_ids[0]
            .clone();
        let recomputed = host
            .evaluate_typed_decision(&set, &[gate(&in_scope, TargetCellDisposition::Incomplete)])
            .unwrap();
        assert_ne!(
            recomputed.evidence.first().map(|evidence| evidence.reason),
            Some(DecisionReason::TargetCellIncomplete)
        );

        let absent = "extension.absent.scope-edge";
        let refused = host
            .evaluate_typed_decision(&set, &[gate(absent, TargetCellDisposition::Complete)])
            .unwrap();
        assert_eq!(refused.outcome, DecisionOutcome::RefuseArming);
        assert_eq!(
            host.capsec_scoped_refusals()
                .last()
                .unwrap()
                .host_disposition,
            super::super::CapsecScopedRefusalHostDisposition::AbsentEdge
        );

        let complete_snapshot = super::super::tests::example_armed_snapshot_with(|_| {});
        let complete = unsafe {
            super::super::Host::new_armed_for_test(
                super::super::HostConfig::default(),
                std::sync::Arc::new(complete_snapshot),
            )
            .unwrap()
        };
        let unchanged = complete
            .evaluate_typed_decision(&set, &[gate(absent, TargetCellDisposition::Complete)])
            .unwrap();
        assert_ne!(unchanged.outcome, DecisionOutcome::RefuseArming);
        assert!(complete.capsec_scoped_refusals().is_empty());
    }

    #[test]
    fn c_abi_discards_presented_complete_for_an_uncertified_cell() {
        use std::ffi::CStr;

        let fixture = fixture();
        let host = scoped_host(&fixture);
        let set = serde_json::to_vec(&decision_set()).unwrap();
        let out = crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS[1];
        let gates = serde_json::to_vec(&vec![gate(out, TargetCellDisposition::Complete)]).unwrap();
        super::super::abi::install_host(host.clone());
        let result = unsafe {
            super::super::abi::ex_host_evaluate_typed_decision(
                set.as_ptr(),
                set.len(),
                gates.as_ptr(),
                gates.len(),
            )
        };
        assert!(!result.is_null());
        let payload = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
        let value: Value = serde_json::from_str(payload).unwrap();
        super::super::abi::ex_host_free_string(result);
        assert_eq!(value["decision"]["outcome"], "refuse-arming");
        assert_eq!(
            value["decision"]["evidence"][0]["reason"],
            "target-cell-incomplete"
        );
        let refusal = host.capsec_scoped_refusals().last().unwrap().clone();
        assert_eq!(
            refusal.host_disposition,
            super::super::CapsecScopedRefusalHostDisposition::Uncertified
        );
        assert_eq!(
            refusal.presented_target_cell,
            Some(TargetCellDisposition::Complete)
        );
    }

    #[test]
    fn runtime_extension_resolver_separates_collisions_from_extension_declared() {
        use capsec_semantics::decision::{DecisionOutcome, DecisionReason};

        let fixture = fixture();
        let advertisement = select(&fixture).unwrap();
        let admitted =
            authenticate_fixture_report(&fixture, &advertisement, &fixture.report).unwrap();
        let complete_runtime = super::super::tests::example_runtime_extension_armed_host();
        let snapshot = complete_runtime.armed_snapshot().unwrap().clone();
        let host = super::super::Host::new_armed_with_target_cells(
            super::super::HostConfig::default(),
            snapshot,
            super::super::HostTargetCells::Scoped(admitted),
            super::super::AuthenticatedPackageSourceState::default(),
        )
        .unwrap();

        let out = crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS[1];
        let resolved = host
            .resolve_runtime_extension_gate(capsec_semantics::model::StableId::new(out).unwrap());
        assert_eq!(resolved.target_cell, TargetCellDisposition::Incomplete);
        let refused = host
            .evaluate_typed_decision_inner(&decision_set(), &[resolved], None)
            .unwrap();
        assert_eq!(refused.outcome, DecisionOutcome::RefuseArming);
        assert_eq!(
            refused.evidence[0].reason,
            DecisionReason::TargetCellIncomplete
        );
        assert!(host.capsec_scope_diagnostics().is_empty());

        let root = host.typed_principal_for_module("0").unwrap();
        host.authorize_runtime_extension_operation(
            11,
            17,
            "ibex.conformance",
            "complete",
            "fixture.complete",
            "runtime-extension.invoke.authenticated-v1",
            "requested",
            "fixture.operation.decision",
            &["runtime-extension"],
            r#"{"input":"hello"}"#,
            root.clone(),
            vec![root],
            vec![],
        )
        .unwrap();
        assert_eq!(host.capsec_scoped_refusals().len(), 1);
        let diagnostics = host.capsec_scope_diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].diagnostic_kind,
            super::super::CapsecScopeDiagnosticKind::ExtensionDeclared
        );
        assert_eq!(
            diagnostics[0].coverage_edge_id,
            "runtime-extension.invoke.authenticated-v1"
        );
        let diagnostic = serde_json::to_value(&diagnostics[0]).unwrap();
        assert_eq!(
            diagnostic
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["coverageEdgeId", "diagnosticKind", "schema", "scopeDigest",])
        );
    }

    #[test]
    fn scoped_host_keeps_scope_out_of_the_frozen_armed_snapshot() {
        let fixture = fixture();
        let host = scoped_host(&fixture);
        let document = host.armed_snapshot().unwrap().document();
        assert_eq!(
            document.get("snapshotSchema").and_then(Value::as_str),
            Some("ibex/capsec-armed/1")
        );
        assert!(document.get("scopeDigest").is_none());
        assert!(host.capsec_scope_introspection().is_some());
    }

    #[test]
    fn inline_legacy_advertisement_stays_closed() {
        let fixture = fixture();
        let legacy = serde_json::json!({
            "targetAdvertisementSchema": ADVERTISEMENT_SCHEMA_V1,
            "profile": CAPSEC_PROFILE,
            "targetCellsRawContentDigest": digest("legacy-target-cells"),
            "advertisements": [],
        });
        let error = select_v3_advertisement(
            &serde_json::to_string(&legacy).unwrap(),
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
        admission["admittedScopeDigest"] = Value::Null;
        admission["predecessorScopeDigest"] = Value::Null;
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
            target_cells.dispositions.len(),
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
        admission["admittedScopeDigest"] = Value::Null;
        admission["predecessorScopeDigest"] = Value::Null;
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
                REPORT_DOMAIN_V3,
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
        let mut admission = fixture.admission.clone();
        admission["target"]["triple"] = Value::String("x86_64-apple-darwin".to_owned());
        let error =
            require_checked_promotion(&advertisement, &checked_marker(admission)).unwrap_err();
        assert!(error.to_string().contains("target differs"), "{error}");
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
    fn v3_publication_with_mapped_locality_is_refused() {
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
    fn duplicate_v3_json_keys_are_refused_before_selection() {
        let fixture = fixture();
        let text = serde_json::to_string(&fixture.advertisements).unwrap();
        let text = text.replacen(
            &format!("\"targetAdvertisementSchema\":\"{ADVERTISEMENT_SCHEMA_V3}\""),
            &format!(
                "\"targetAdvertisementSchema\":\"{ADVERTISEMENT_SCHEMA_V3}\",\"targetAdvertisementSchema\":\"{ADVERTISEMENT_SCHEMA_V3}\""
            ),
            1,
        );
        let error = select_v3_advertisement(&text, &fixture.target, &fixture.features).unwrap_err();
        assert!(
            error.to_string().contains("duplicate JSON object key"),
            "{error}"
        );
    }
}
