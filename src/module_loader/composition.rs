//! Package-aware composition wire, admission, and report surfaces.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use capsec_semantics::model::{Digest, NonEmptyString};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::artifact::{source_integrity, ModuleArtifactV1};
use super::identity::{ResolutionKind, SourceId};

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

/// Landed O-1 schema identifier for the composition envelope.
pub const PREPARED_COMPOSITION_SCHEMA_V1: &str = "exact/prepared-composition/1";

/// Provisional LLP 0056 schema identifier for one ibex-side prepared package.
pub const PREPARED_PACKAGE_SCHEMA_V1: &str = "ibex/prepared-package/1";

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

/// Maximum number of rows in the composition union binding table.
pub const MAX_COMPOSITION_UNION_ROWS_V1: usize = 1_048_576;

/// Maximum byte length of one prepared-package index.
pub const MAX_PACKAGE_INDEX_BYTES_V1: u64 = 64 * 1024 * 1024;

/// Maximum byte length of one prepared carrier manifest.
pub const MAX_PACKAGE_MANIFEST_BYTES_V1: u64 = 16 * 1024 * 1024;

/// Maximum byte length of one prepared carrier payload.
pub const MAX_PACKAGE_CARRIER_BYTES_V1: u64 = 512 * 1024 * 1024;

/// Maximum byte length of one computed-candidate table.
pub const MAX_PACKAGE_CANDIDATE_TABLE_BYTES_V1: u64 = 64 * 1024 * 1024;

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

/// The landed Exact O-1 prepared-composition envelope.
///
/// Field names and requiredness follow
/// `authorities/prepared-composition-v1.schema.json` exactly. Semantic
/// predicates intentionally remain for admission steps 2–7; this type owns
/// only strict shape plus the step-1 envelope-surface bounds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedCompositionV1 {
    pub schema: String,
    /// Kept as strings so the step-2 unknown/duplicate-role predicates remain
    /// reachable rather than being collapsed into step-1 shape failure.
    pub declaration: Vec<String>,
    pub packages: Vec<CompositionPackageAttestationV1>,
    pub partition: CompositionPartitionV1,
    pub union_binding_table: CompositionUnionBindingTableV1,
    pub host_bridged_inventories: Vec<CompositionHostBridgedInventoryV1>,
    pub alias_table: CompositionAliasTableV1,
    pub agent_boundary: CompositionAgentBoundaryV1,
    pub boot_core_dynamic_follow_list: Vec<CompositionDynamicFollowV1>,
    pub entry_plan: CompositionEntryPlanV1,
    pub freshness: CompositionFreshnessV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionPartitionV1 {
    pub digest: Digest,
    pub roles: CompositionPartitionRolesV1,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionPartitionRolesV1 {
    #[serde(default)]
    pub app: Option<u64>,
    #[serde(default)]
    pub agent: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionUnionBindingTableV1 {
    pub digest: Digest,
    pub rows: Vec<CompositionUnionBindingRowV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionUnionBindingRowV1 {
    pub from_role: CompositionRole,
    pub from_source_id: String,
    pub specifier: String,
    pub to_role: CompositionRole,
    pub to_source_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum HostBridgedReasonV1 {
    #[serde(rename = "target is not a bundle module")]
    TargetIsNotBundleModule,
    #[serde(rename = "target excluded by lowering fallback")]
    TargetExcludedByLoweringFallback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostBridgedInventoryRowV1 {
    pub module: String,
    pub specifier: String,
    pub reason: HostBridgedReasonV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionHostBridgedInventoryV1 {
    pub role: CompositionRole,
    pub digest: Digest,
    pub rows: Vec<HostBridgedInventoryRowV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionAliasTableV1 {
    pub digest: Digest,
    pub rows: Vec<CompositionAliasRowV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionAliasRowV1 {
    pub alias_id: String,
    pub representative_source_id: String,
    pub representative_source_integrity: Digest,
    pub import_site_inventory_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionAgentBoundaryV1 {
    pub entry_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionDynamicFollowV1 {
    pub importer: String,
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionEntryPlanV1 {
    pub digest: Digest,
    pub entries: Vec<CompositionEntryDescriptorV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionEntryDescriptorV1 {
    pub role: CompositionRole,
    pub root: String,
    /// Retained as a string so step 7 owns the unknown-action predicate.
    pub action: String,
    #[serde(default)]
    pub export: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionFreshnessV1 {
    pub session_nonce: String,
    pub authority_generation: u64,
    pub resolver_generation: u64,
    pub expires_at_ms: u64,
    pub policy_digest: Digest,
    pub target: String,
    pub encoding: String,
    pub agent_packing: String,
    pub producer: CompositionProducerV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionProducerV1 {
    pub id: NonEmptyString,
    pub binary_digest: Digest,
}

/// Provisional ibex-side package index from LLP 0056 §4.3.
///
/// O-1 has not landed the carrier-bearing package schema yet. These names,
/// meanings, and invariants are normative from LLP 0056; its byte encoding
/// remains provisional until that authority row lands.
// @ref LLP 0056#43-the-package-index--ibexprepared-package1 — package bytes exclude entry and generation facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedPackageV1 {
    pub schema: String,
    pub role: CompositionRole,
    pub producer_id: NonEmptyString,
    pub producer_binary_digest: Digest,
    pub package_graph_digest: Digest,
    pub records: Vec<PreparedPackageRecordV1>,
    pub carriers: Vec<PreparedPackageCarrierIndexV1>,
    pub candidate_tables: Vec<PreparedPackageCandidateTableIndexV1>,
    pub host_bridged_inventory: Vec<HostBridgedInventoryRowV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedPackageRecordV1 {
    pub source_id: SourceId,
    pub bindings: Vec<PreparedPackageBindingV1>,
    pub artifact: ModuleArtifactV1,
    pub carrier_index: usize,
    pub entry_id: NonEmptyString,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedPackageBindingV1 {
    pub specifier: String,
    pub resolution_kind: ResolutionKind,
    pub target: PreparedPackageBindingTargetV1,
}

// @ref LLP 0056#45-binding-rows--a-tagged-target — external ownership is explicit and never inferred.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PreparedPackageBindingTargetV1 {
    Local {
        source_id: SourceId,
    },
    External {
        role: CompositionRole,
        source_id: SourceId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedPackageCarrierIndexV1 {
    pub manifest_file: String,
    pub bytes_file: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedPackageCandidateTableIndexV1 {
    pub file: String,
    pub digest: Digest,
}

/// Per-package verification state carried by composition receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompositionPackageVerificationStatusV1 {
    NotChecked,
    Verified,
    Refused,
}

/// Package row shared by every §8 report variant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionReportPackageV1 {
    pub role: CompositionRole,
    pub package_root_prefix: String,
    pub record_count: u64,
    pub carrier_count: u64,
    pub hbc_carrier_count: u64,
    pub javascript_carrier_count: u64,
    pub verification_status: CompositionPackageVerificationStatusV1,
}

/// Fields present on every composition startup report.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionReportCommonV1 {
    pub schema: &'static str,
    pub composition_schema_version: u32,
    pub authority: &'static str,
    pub posture: &'static str,
    pub non_production: bool,
    pub fingerprint_posture: &'static str,
    pub attribution: &'static str,
    pub declared_roles: Option<Vec<String>>,
    pub composition_root_prefix: Option<String>,
    pub entry_plan: Option<CompositionEntryPlanV1>,
    pub engine_binding_digest_prefix: Option<String>,
    pub packages: Vec<CompositionReportPackageV1>,
    pub commitment_parse_us: u64,
    pub admission_us: u64,
    pub graph_link_us: u64,
    pub agent_evaluate_us: u64,
    pub agent_invoke_us: u64,
    pub app_evaluate_us: u64,
    pub agent_evaluated_record_count: u64,
    pub app_evaluated_record_count: u64,
    pub shared_evaluated_record_count: u64,
}

/// Total §8 report. Slice 2 serializes `channel-error` and `refused`; the
/// admitted variants are defined now for the slice-3 handoff.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "admissionStatus", rename_all = "kebab-case")]
pub enum DevUnarmedCompositionStartupReportV1 {
    ChannelError {
        #[serde(flatten)]
        common: CompositionReportCommonV1,
        channel_token: String,
        detail: String,
    },
    Refused {
        #[serde(flatten)]
        common: CompositionReportCommonV1,
        failure_stage: u32,
        #[serde(serialize_with = "serialize_composition_refusal_code")]
        reason_code: CompositionRefusalCode,
        #[serde(skip_serializing_if = "Option::is_none")]
        package_role: Option<CompositionRole>,
        detail: String,
    },
    Admitted {
        #[serde(flatten)]
        common: CompositionReportCommonV1,
        agent_invoke_returned_thenable: bool,
    },
    AdmittedStartupError {
        #[serde(flatten)]
        common: CompositionReportCommonV1,
        startup_phase: CompositionStartupPhaseV1,
        error_detail: String,
        agent_invoke_returned_thenable: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompositionStartupPhaseV1 {
    AgentEvaluate,
    AgentInvoke,
    AppEvaluate,
}

fn serialize_composition_refusal_code<S>(
    code: &CompositionRefusalCode,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(code.as_str())
}

#[cfg(feature = "dev-committed-embedder")]
#[derive(Clone, Debug)]
// driver-wiring pending the LLP 0056 §10 amendment
// (issues/20260824-llp0056-s10-grant-authority-defect.md): consumed by the
// blocked step-6/slice-3 driver, constructed by nothing yet.
#[allow(dead_code)]
struct CompositionAuthorizedEdgeV1 {
    origin: SourceId,
    target: SourceId,
    specifier: String,
    resolution_kind: ResolutionKind,
}

/// Step-6 capability proving the union plan passed structural closure and the
/// defining-principal policy. Slice 3 consumes this without a fresh policy
/// decision.
#[cfg(feature = "dev-committed-embedder")]
#[derive(Debug)]
// driver-wiring pending the §10 amendment: fields are read by the blocked
// slice-3 linker consumption; nothing constructs this yet.
#[allow(dead_code)]
pub struct AuthorizedCompositionPlanV1 {
    packages: BTreeMap<CompositionRole, super::runner_pipeline::AdmittedCompositionPackageV1>,
    authorized_edges: Vec<CompositionAuthorizedEdgeV1>,
    roots: Vec<SourceId>,
    main_root: SourceId,
}

/// Successful steps-0–7 handoff to the link/evaluate slice.
#[cfg(feature = "dev-committed-embedder")]
#[derive(Debug)]
pub struct AdmittedCompositionV1 {
    pub authorized: AuthorizedCompositionPlanV1,
    pub envelope: PreparedCompositionV1,
    pub commitment: PreparedCompositionCommitmentV1,
    pub expectations: CompositionVerifierExpectationsV1,
    pub report: DevUnarmedCompositionStartupReportV1,
}

/// Admission driver result is total: channel failure, registry refusal, or a
/// typed step-7 capability. No prose-only error escapes this boundary.
#[cfg(feature = "dev-committed-embedder")]
#[derive(Debug)]
pub enum CompositionAdmissionOutcomeV1 {
    ChannelError(DevUnarmedCompositionStartupReportV1),
    Refused(DevUnarmedCompositionStartupReportV1),
    Admitted(Box<AdmittedCompositionV1>),
}

impl PreparedCompositionV1 {
    /// Strict JSON -> byte-exact JCS -> envelope bounds -> closed serde shape.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_COMPOSITION_ENVELOPE_BYTES_V1 {
            bail!("composition envelope exceeds {MAX_COMPOSITION_ENVELOPE_BYTES_V1} bytes");
        }
        let value = parse_canonical_served_value(bytes, "composition envelope")?;
        enforce_envelope_surface_bounds(&value)?;
        let envelope: Self = serde_json::from_value(value)
            .context("prepared-composition envelope has an invalid shape")?;
        if envelope.schema != PREPARED_COMPOSITION_SCHEMA_V1 {
            bail!("unsupported prepared-composition envelope schema");
        }
        Ok(envelope)
    }
}

impl PreparedPackageV1 {
    /// Strict canonical package decode with the §3.1 package-surface bounds.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_PACKAGE_INDEX_BYTES_V1 {
            bail!("prepared-package index exceeds {MAX_PACKAGE_INDEX_BYTES_V1} bytes");
        }
        let value = parse_canonical_served_value(bytes, "prepared-package index")?;
        if let Some(violation) = check_composition_wire_bounds(&value) {
            bail!("prepared-package index: {violation}");
        }
        let package: Self =
            serde_json::from_value(value).context("prepared-package index has an invalid shape")?;
        if package.records.len() > MAX_PACKAGE_RECORDS_V1 {
            bail!("prepared-package records exceed {MAX_PACKAGE_RECORDS_V1}");
        }
        let declared_edges = package.records.iter().try_fold(0usize, |count, record| {
            count
                .checked_add(record.bindings.len())
                .ok_or_else(|| anyhow!("prepared-package declared-edge count overflow"))
        })?;
        if declared_edges > MAX_PACKAGE_DECLARED_EDGES_V1 {
            bail!("prepared-package declared edges exceed {MAX_PACKAGE_DECLARED_EDGES_V1}");
        }
        let external_references = package
            .records
            .iter()
            .flat_map(|record| &record.bindings)
            .filter(|binding| {
                matches!(
                    &binding.target,
                    PreparedPackageBindingTargetV1::External { .. }
                )
            })
            .count();
        if external_references > MAX_COMPOSITION_EXTERNAL_REFERENCES_V1 {
            bail!(
                "prepared-package external references exceed {MAX_COMPOSITION_EXTERNAL_REFERENCES_V1}"
            );
        }
        Ok(package)
    }
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

fn parse_canonical_served_value(bytes: &[u8], record: &str) -> Result<Value> {
    let text = std::str::from_utf8(bytes).with_context(|| format!("{record} is not UTF-8"))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|error| anyhow!("{record} is not strict JSON: {error}"))?;
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
        .with_context(|| format!("cannot canonicalize {record}"))?;
    if canonical != bytes {
        bail!("{record} is not byte-exact canonical JCS");
    }
    Ok(value)
}

fn array_len_at(value: &Value, path: &[&str]) -> Option<usize> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_array().map(Vec::len)
}

fn enforce_envelope_surface_bounds(value: &Value) -> Result<()> {
    if let Some(violation) = check_composition_wire_bounds(value) {
        bail!("composition envelope: {violation}");
    }
    for (path, bound, label) in [
        (
            &["declaration"][..],
            MAX_COMPOSITION_ROLES_V1,
            "declared roles",
        ),
        (
            &["packages"][..],
            MAX_COMPOSITION_ROLES_V1,
            "package attestations",
        ),
        (
            &["hostBridgedInventories"][..],
            MAX_COMPOSITION_ROLES_V1,
            "host-bridged inventories",
        ),
        (
            &["aliasTable", "rows"][..],
            MAX_COMPOSITION_ALIAS_ROWS_V1,
            "alias rows",
        ),
        (
            &["unionBindingTable", "rows"][..],
            MAX_COMPOSITION_UNION_ROWS_V1,
            "union-table rows",
        ),
        (
            &["entryPlan", "entries"][..],
            MAX_COMPOSITION_ROLES_V1,
            "entry-plan rows",
        ),
    ] {
        if array_len_at(value, path).is_some_and(|len| len > bound) {
            bail!("composition envelope {label} exceed {bound}");
        }
    }

    let external_references = value
        .get("unionBindingTable")
        .and_then(|table| table.get("rows"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|row| row.get("fromRole") != row.get("toRole"))
        .count();
    if external_references > MAX_COMPOSITION_EXTERNAL_REFERENCES_V1 {
        bail!(
            "composition envelope external references exceed {MAX_COMPOSITION_EXTERNAL_REFERENCES_V1}"
        );
    }

    for role in ["app", "agent"] {
        if value
            .get("partition")
            .and_then(|partition| partition.get("roles"))
            .and_then(|roles| roles.get(role))
            .and_then(Value::as_u64)
            .is_some_and(|count| count > MAX_PACKAGE_RECORDS_V1 as u64)
        {
            bail!("composition envelope {role} record count exceeds {MAX_PACKAGE_RECORDS_V1}");
        }
    }
    Ok(())
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

    #[test]
    fn package_index_is_generation_and_entry_free_and_canonical() {
        let package = json!({
            "schema": PREPARED_PACKAGE_SCHEMA_V1,
            "role": "app",
            "producerId": "fixture-producer",
            "producerBinaryDigest": valid_digest("producer"),
            "packageGraphDigest": valid_digest("package-graph"),
            "records": [],
            "carriers": [],
            "candidateTables": [],
            "hostBridgedInventory": [],
        });
        let bytes = capsec_semantics::canonical::to_jcs_bytes(&package).unwrap();
        assert!(PreparedPackageV1::decode_canonical(&bytes).is_ok());

        for forbidden in ["entry", "generation"] {
            let mut invalid = package.clone();
            invalid[forbidden] = json!(1);
            let bytes = capsec_semantics::canonical::to_jcs_bytes(&invalid).unwrap();
            assert!(PreparedPackageV1::decode_canonical(&bytes).is_err());
        }

        let pretty = serde_json::to_vec_pretty(&package).unwrap();
        assert!(PreparedPackageV1::decode_canonical(&pretty).is_err());
    }
}
