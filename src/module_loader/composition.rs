//! Package-aware composition wire, admission, and report surfaces.

use std::collections::BTreeMap;
#[cfg(feature = "dev-committed-embedder")]
use std::collections::BTreeSet;
#[cfg(feature = "dev-committed-embedder")]
use std::path::Path;
#[cfg(feature = "dev-committed-embedder")]
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
#[cfg(feature = "dev-committed-embedder")]
use capsec_semantics::arming::SnapshotGenerations;
use capsec_semantics::model::{Digest, NonEmptyString};
#[cfg(feature = "dev-committed-embedder")]
use capsec_semantics::model::{Generation, Principal, Stage};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "dev-committed-embedder")]
use super::artifact::DynamicEdgeV1;
use super::artifact::{digest_bytes, source_integrity, ModuleArtifactV1};
#[cfg(feature = "dev-committed-embedder")]
use super::carrier::PreparedCarrierEngineBindingV2;
#[cfg(feature = "dev-committed-embedder")]
use super::graph::{
    ComputedCandidateBinding, ComputedCandidateSiteMap, DynamicImportBindingKey, GraphEdgeKey,
    SynchronousGraphPlan,
};
use super::identity::{ResolutionKind, SourceId};
#[cfg(all(feature = "dev-committed-embedder", test))]
use super::runner_pipeline::parse_dev_composition_channel_records_unchecked_v1;
#[cfg(feature = "dev-committed-embedder")]
use super::runner_pipeline::{
    admit_composition_package_v1, parse_dev_composition_channel_records_v1,
    read_bounded_prepared_file, AdmittedCompositionPackageV1, CommittedHbcEngineExpectationV1,
};
#[cfg(feature = "dev-committed-embedder")]
use super::security::{
    AuthorizedGraphOperation, GraphAuthorityContext, GraphImportPolicy, ModuleGraphAuthorizer,
};

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

    #[cfg(feature = "dev-committed-embedder")]
    fn order(self) -> u8 {
        match self {
            Self::App => 0,
            Self::Agent => 1,
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
    pub embedded_eager_source_bytes: u64,
    pub embedded_eager_source_chars: u64,
    pub verification_status: CompositionPackageVerificationStatusV1,
}

/// One phase bracket captured from the Apple host-monotonic authority.
///
/// These are observed boundaries, not durations projected onto another
/// timestamp. The startup evidence assembler may therefore use them as DAG
/// events without inventing ordering that the runtime did not observe.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionHostMonotonicBoundaryV1 {
    pub start_host_monotonic_ms: f64,
    pub end_host_monotonic_ms: f64,
}

/// Complete measured admission/link/evaluation bracket for one composition.
///
/// This value is absent when the platform cannot expose Apple's
/// `mach_absolute_time` clock or when all three phase boundaries were not
/// observed. The microsecond duration counters in the surrounding report stay
/// useful diagnostics, but absence here must never turn them into ledger
/// timestamps.
// @ref LLP 0056#8-the-report--tagged-shapes-one-per-outcome — phaseBoundaries is the report's nullable observed-clock authority; duration counters stay diagnostic.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionHostMonotonicPhaseBoundariesV1 {
    pub schema_version: &'static str,
    pub clock_domain: &'static str,
    pub clock_source: &'static str,
    pub timing_basis: &'static str,
    pub admission: CompositionHostMonotonicBoundaryV1,
    pub link: CompositionHostMonotonicBoundaryV1,
    pub evaluation: CompositionHostMonotonicBoundaryV1,
}

#[cfg(feature = "dev-committed-embedder")]
impl CompositionHostMonotonicPhaseBoundariesV1 {
    pub(crate) fn measured(
        admission: (f64, f64),
        link: (f64, f64),
        evaluation: (f64, f64),
    ) -> Option<Self> {
        let ordered = admission.0.is_finite()
            && admission.1.is_finite()
            && link.0.is_finite()
            && link.1.is_finite()
            && evaluation.0.is_finite()
            && evaluation.1.is_finite()
            && admission.0 >= 0.0
            && admission.1 >= admission.0
            && link.0 >= admission.1
            && link.1 >= link.0
            && evaluation.0 >= link.1
            && evaluation.1 >= evaluation.0;
        ordered.then_some(Self {
            schema_version: "ibex/prepared-phase-boundaries/1",
            clock_domain: "host-monotonic",
            clock_source: "mach-absolute-time",
            timing_basis: "observed-boundary",
            admission: CompositionHostMonotonicBoundaryV1 {
                start_host_monotonic_ms: admission.0,
                end_host_monotonic_ms: admission.1,
            },
            link: CompositionHostMonotonicBoundaryV1 {
                start_host_monotonic_ms: link.0,
                end_host_monotonic_ms: link.1,
            },
            evaluation: CompositionHostMonotonicBoundaryV1 {
                start_host_monotonic_ms: evaluation.0,
                end_host_monotonic_ms: evaluation.1,
            },
        })
    }
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
    /// Digest of the resolver/transform/compiler inventory that was both
    /// committed as the envelope producer identity and independently
    /// supplied through verifier-held expectations.
    pub compiler_identity_binding_digest_prefix: Option<String>,
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
    pub phase_boundaries: Option<CompositionHostMonotonicPhaseBoundariesV1>,
}

/// Total §8 report. Slice 2 serializes `channel-error` and `refused`; the
/// admitted variants are defined now for the slice-3 handoff.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(
    tag = "admissionStatus",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
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

#[cfg(feature = "dev-committed-embedder")]
impl DevUnarmedCompositionStartupReportV1 {
    pub(crate) fn admission_status(&self) -> &'static str {
        match self {
            Self::ChannelError { .. } => "channel-error",
            Self::Refused { .. } => "refused",
            Self::Admitted { .. } => "admitted",
            Self::AdmittedStartupError { .. } => "admitted-startup-error",
        }
    }

    fn common_mut(&mut self) -> &mut CompositionReportCommonV1 {
        match self {
            Self::ChannelError { common, .. }
            | Self::Refused { common, .. }
            | Self::Admitted { common, .. }
            | Self::AdmittedStartupError { common, .. } => common,
        }
    }

    pub(crate) fn set_graph_link_duration(&mut self, duration: Duration) {
        self.common_mut().graph_link_us = i_json_duration_us(duration);
    }

    pub(crate) fn set_phase_boundaries(
        &mut self,
        phase_boundaries: Option<CompositionHostMonotonicPhaseBoundariesV1>,
    ) {
        self.common_mut().phase_boundaries = phase_boundaries;
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn set_execution_observations(
        &mut self,
        agent_evaluate: Duration,
        agent_invoke: Duration,
        app_evaluate: Duration,
        agent_evaluated_record_count: usize,
        app_evaluated_record_count: usize,
        shared_evaluated_record_count: usize,
        agent_invoke_returned_thenable: bool,
    ) {
        let common = self.common_mut();
        common.agent_evaluate_us = i_json_duration_us(agent_evaluate);
        common.agent_invoke_us = i_json_duration_us(agent_invoke);
        common.app_evaluate_us = i_json_duration_us(app_evaluate);
        common.agent_evaluated_record_count = u64::try_from(agent_evaluated_record_count)
            .unwrap_or(I_JSON_MAX_SAFE_INTEGER)
            .min(I_JSON_MAX_SAFE_INTEGER);
        common.app_evaluated_record_count = u64::try_from(app_evaluated_record_count)
            .unwrap_or(I_JSON_MAX_SAFE_INTEGER)
            .min(I_JSON_MAX_SAFE_INTEGER);
        common.shared_evaluated_record_count = u64::try_from(shared_evaluated_record_count)
            .unwrap_or(I_JSON_MAX_SAFE_INTEGER)
            .min(I_JSON_MAX_SAFE_INTEGER);
        match self {
            Self::Admitted {
                agent_invoke_returned_thenable: returned,
                ..
            }
            | Self::AdmittedStartupError {
                agent_invoke_returned_thenable: returned,
                ..
            } => *returned = agent_invoke_returned_thenable,
            Self::ChannelError { .. } | Self::Refused { .. } => {}
        }
    }

    pub(crate) fn into_link_refusal(self, detail: String) -> Self {
        match self {
            Self::Admitted { common, .. } => Self::Refused {
                common,
                failure_stage: 8,
                reason_code: CompositionRefusalCode::LinkFailure,
                package_role: None,
                detail,
            },
            report => report,
        }
    }

    pub(crate) fn into_startup_error(
        self,
        startup_phase: CompositionStartupPhaseV1,
        error_detail: String,
    ) -> Self {
        match self {
            Self::Admitted {
                common,
                agent_invoke_returned_thenable,
            } => Self::AdmittedStartupError {
                common,
                startup_phase,
                error_detail,
                agent_invoke_returned_thenable,
            },
            report => report,
        }
    }
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompositionAuthorizedEdgeV1 {
    pub(crate) origin: SourceId,
    pub(crate) target: SourceId,
    pub(crate) specifier: String,
    pub(crate) resolution_kind: ResolutionKind,
}

/// Step-6 capability proving the union plan passed structural closure and the
/// defining-principal policy. Slice 3 consumes this without a fresh policy
/// decision.
#[cfg(feature = "dev-committed-embedder")]
#[derive(Debug)]
pub struct AuthorizedCompositionPlanV1 {
    pub(crate) packages:
        BTreeMap<CompositionRole, super::runner_pipeline::AdmittedCompositionPackageV1>,
    pub(crate) authorized_edges: Vec<CompositionAuthorizedEdgeV1>,
    pub(crate) authorization_receipts: Vec<AuthorizedGraphOperation>,
    pub(crate) allowed_dynamic_bindings: BTreeMap<SourceId, BTreeSet<DynamicImportBindingKey>>,
    pub(crate) authority_contexts: BTreeMap<SourceId, GraphAuthorityContext>,
    pub(crate) roots: Vec<SourceId>,
    pub(crate) main_root: SourceId,
}

#[cfg(feature = "dev-committed-embedder")]
impl AuthorizedCompositionPlanV1 {
    pub(crate) fn execution_plan(
        &self,
        aliases: &[CompositionAliasRowV1],
    ) -> Result<SynchronousGraphPlan<'_>> {
        let ownership = self
            .packages
            .iter()
            .flat_map(|(role, package)| {
                package
                    .records
                    .keys()
                    .cloned()
                    .map(|source_id| (source_id, *role))
            })
            .collect::<BTreeMap<_, _>>();
        build_union_plan_v1(&self.packages, &ownership, aliases)
    }

    pub(crate) fn root_plan(&self) -> Result<super::graph::CompositionRootPlan> {
        super::graph::CompositionRootPlan::new(self.roots.clone(), &self.main_root)
    }

    pub(crate) fn admitted_records(&self) -> BTreeSet<SourceId> {
        self.packages
            .values()
            .flat_map(|package| package.records.keys().cloned())
            .collect()
    }

    pub(crate) fn graph_generation(&self) -> Result<u64> {
        let mut generations = self
            .packages
            .values()
            .map(|package| package.producer_generation);
        let generation = generations
            .next()
            .ok_or_else(|| anyhow!("authorized composition contains no package"))?;
        if generation == 0 || generations.any(|candidate| candidate != generation) {
            bail!("authorized composition does not retain one nonzero generation");
        }
        Ok(generation)
    }
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

#[cfg(feature = "dev-committed-embedder")]
const COMPOSITION_REPORT_SCHEMA_V1: &str = "ibex/dev-unarmed-composition-startup-report/1";
#[cfg(feature = "dev-committed-embedder")]
const DEV_UNARMED_COMPOSITION_AUTHORITY_V1: &str = "dev-unarmed-dev-served (non-production)";
#[cfg(feature = "dev-committed-embedder")]
const DEV_UNARMED_FINGERPRINT_POSTURE_V1: &str =
    "artifact-vouched external producer (currency check pending LLP 0043 registry)";
#[cfg(feature = "dev-committed-embedder")]
const DEV_UNARMED_ATTRIBUTION_V1: &str = "collapsed-to-root (dev-unarmed; no compartment registry)";

#[cfg(feature = "dev-committed-embedder")]
enum CompositionEngineProbeV1 {
    Runtime,
    #[cfg(test)]
    Fixed(Option<CommittedHbcEngineExpectationV1>),
}

#[cfg(feature = "dev-committed-embedder")]
enum CompositionChannelProbeV1 {
    Checked,
    #[cfg(test)]
    Unchecked,
}

#[cfg(feature = "dev-committed-embedder")]
fn i_json_duration_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros())
        .unwrap_or(I_JSON_MAX_SAFE_INTEGER)
        .min(I_JSON_MAX_SAFE_INTEGER)
}

/// Read the same host-monotonic authority used by Exact's Swift boot ledger.
///
/// `mach_absolute_time` is intentionally used directly instead of Rust's
/// opaque `Instant`: the numeric endpoints cross the FFI/report boundary and
/// must be comparable byte-for-byte with host-produced session timestamps.
#[cfg(all(feature = "dev-committed-embedder", target_vendor = "apple"))]
#[allow(deprecated)] // libc exposes the exact Darwin clock ABI required here.
pub(crate) fn composition_host_monotonic_now_ms_v1() -> Option<f64> {
    static TIMEBASE: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();
    let &(numer, denom) = TIMEBASE
        .get_or_init(|| {
            let mut info = libc::mach_timebase_info_data_t { numer: 0, denom: 0 };
            // SAFETY: `info` is a valid writable timebase structure for the
            // duration of this call. Darwin returns zero on success.
            let status = unsafe { libc::mach_timebase_info(&mut info) };
            (status == 0 && info.denom != 0).then_some((info.numer, info.denom))
        })
        .as_ref()?;
    // SAFETY: `mach_absolute_time` has no arguments and returns the current
    // process-independent uptime tick count.
    let ticks = unsafe { libc::mach_absolute_time() };
    let milliseconds = (ticks as f64) * (numer as f64) / (denom as f64) / 1_000_000.0;
    (milliseconds.is_finite() && milliseconds >= 0.0).then_some(milliseconds)
}

#[cfg(all(feature = "dev-committed-embedder", not(target_vendor = "apple")))]
pub(crate) fn composition_host_monotonic_now_ms_v1() -> Option<f64> {
    None
}

#[cfg(feature = "dev-committed-embedder")]
fn digest_prefix(digest: &Digest) -> String {
    digest.as_str().chars().take(24).collect()
}

#[cfg(feature = "dev-committed-embedder")]
fn runtime_hbc_engine_expectation_v1() -> Option<CommittedHbcEngineExpectationV1> {
    let (Ok(digest), Ok(bytecode_version)) = (
        crate::engine::loaded_engine_binary_digest(),
        crate::engine::loaded_engine_bytecode_version(),
    ) else {
        return None;
    };
    let binary_digest = Digest::new(digest).ok()?;
    Some(CommittedHbcEngineExpectationV1 {
        engine_binding: PreparedCarrierEngineBindingV2::LoadedFile { binary_digest },
        bytecode_version,
    })
}

#[cfg(feature = "dev-committed-embedder")]
fn engine_binding_digest_prefix_v1(
    engine: Option<&CommittedHbcEngineExpectationV1>,
) -> Option<String> {
    match engine.map(|engine| &engine.engine_binding) {
        Some(PreparedCarrierEngineBindingV2::LoadedFile { binary_digest }) => {
            Some(digest_prefix(binary_digest))
        }
        Some(PreparedCarrierEngineBindingV2::StaticCompatibility { .. }) | None => None,
    }
}

#[cfg(feature = "dev-committed-embedder")]
fn channel_token_from_error_v1(detail: &str) -> String {
    [
        IBEX_DEV_COMPOSITION_ARMED_CONTEXT,
        IBEX_DEV_COMPOSITION_SCHEMA,
        IBEX_DEV_COMPOSITION_CORRUPT,
    ]
    .into_iter()
    .find(|token| detail.contains(token))
    .unwrap_or(IBEX_DEV_COMPOSITION_CORRUPT)
    .to_owned()
}

#[cfg(feature = "dev-committed-embedder")]
fn report_common_v1(
    envelope: Option<&PreparedCompositionV1>,
    composition_root: Option<&Digest>,
    admitted_packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
    statuses: &BTreeMap<CompositionRole, CompositionPackageVerificationStatusV1>,
    engine_binding_digest_prefix: Option<String>,
    commitment_parse_us: u64,
    admission_us: u64,
) -> CompositionReportCommonV1 {
    let packages = envelope.map_or_else(Vec::new, |envelope| {
        envelope
            .packages
            .iter()
            .map(|attestation| {
                let admitted = admitted_packages.get(&attestation.role);
                if let Some(package) = admitted {
                    debug_assert_eq!(package.role, attestation.role);
                    debug_assert_eq!(package.package_root, attestation.package_root);
                }
                CompositionReportPackageV1 {
                    role: attestation.role,
                    package_root_prefix: admitted.map_or_else(
                        || digest_prefix(&attestation.package_root),
                        |package| digest_prefix(&package.package_root),
                    ),
                    record_count: admitted
                        .map(|package| package.records.len() as u64)
                        .unwrap_or(0),
                    carrier_count: admitted
                        .map(|package| package.carrier_count as u64)
                        .unwrap_or(0),
                    hbc_carrier_count: admitted
                        .map(|package| package.hbc_carrier_count as u64)
                        .unwrap_or(0),
                    javascript_carrier_count: admitted
                        .map(|package| package.javascript_carrier_count as u64)
                        .unwrap_or(0),
                    embedded_eager_source_bytes: admitted
                        .map(|package| package.embedded_eager_source_bytes as u64)
                        .unwrap_or(0),
                    embedded_eager_source_chars: admitted
                        .map(|package| package.embedded_eager_source_chars as u64)
                        .unwrap_or(0),
                    verification_status: statuses
                        .get(&attestation.role)
                        .copied()
                        .unwrap_or(CompositionPackageVerificationStatusV1::NotChecked),
                }
            })
            .collect()
    });
    CompositionReportCommonV1 {
        schema: COMPOSITION_REPORT_SCHEMA_V1,
        composition_schema_version: 1,
        authority: DEV_UNARMED_COMPOSITION_AUTHORITY_V1,
        posture: "dev-unarmed",
        non_production: true,
        fingerprint_posture: DEV_UNARMED_FINGERPRINT_POSTURE_V1,
        attribution: DEV_UNARMED_ATTRIBUTION_V1,
        declared_roles: envelope.map(|envelope| envelope.declaration.clone()),
        composition_root_prefix: composition_root.map(digest_prefix),
        entry_plan: envelope.map(|envelope| envelope.entry_plan.clone()),
        engine_binding_digest_prefix,
        compiler_identity_binding_digest_prefix: envelope
            .map(|envelope| digest_prefix(&envelope.freshness.producer.binary_digest)),
        packages,
        commitment_parse_us,
        admission_us,
        graph_link_us: 0,
        agent_evaluate_us: 0,
        agent_invoke_us: 0,
        app_evaluate_us: 0,
        agent_evaluated_record_count: 0,
        app_evaluated_record_count: 0,
        shared_evaluated_record_count: 0,
        phase_boundaries: None,
    }
}

#[cfg(feature = "dev-committed-embedder")]
pub(crate) fn composition_embedder_channel_error_report_v1(
    detail: impl Into<String>,
) -> DevUnarmedCompositionStartupReportV1 {
    let detail = detail.into();
    let channel_token = channel_token_from_error_v1(&detail);
    DevUnarmedCompositionStartupReportV1::ChannelError {
        common: report_common_v1(None, None, &BTreeMap::new(), &BTreeMap::new(), None, 0, 0),
        channel_token,
        detail,
    }
}

#[cfg(feature = "dev-committed-embedder")]
#[allow(clippy::too_many_arguments)]
fn refused_outcome_v1(
    envelope: Option<&PreparedCompositionV1>,
    composition_root: Option<&Digest>,
    admitted_packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
    statuses: &BTreeMap<CompositionRole, CompositionPackageVerificationStatusV1>,
    engine_binding_digest_prefix: Option<String>,
    commitment_parse_us: u64,
    admission_started: Instant,
    code: CompositionRefusalCode,
    package_role: Option<CompositionRole>,
    detail: impl Into<String>,
) -> CompositionAdmissionOutcomeV1 {
    let report = DevUnarmedCompositionStartupReportV1::Refused {
        common: report_common_v1(
            envelope,
            composition_root,
            admitted_packages,
            statuses,
            engine_binding_digest_prefix,
            commitment_parse_us,
            i_json_duration_us(admission_started.elapsed()),
        ),
        failure_stage: u32::from(code.step()),
        reason_code: code,
        package_role,
        detail: detail.into(),
    };
    CompositionAdmissionOutcomeV1::Refused(report)
}

#[cfg(feature = "dev-committed-embedder")]
fn digest_canonical_value_v1<T: Serialize>(domain: &str, value: &T) -> Result<Digest> {
    let value = serde_json::to_value(value)?;
    let bytes = capsec_semantics::canonical::to_jcs_bytes(&value)?;
    digest_bytes(domain, &bytes)
}

#[cfg(feature = "dev-committed-embedder")]
fn served_package_roles_v1(composition_dir: &Path) -> Result<Vec<String>> {
    let packages_dir = composition_dir.join("packages");
    let entries = match std::fs::read_dir(&packages_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(anyhow!(
                "cannot enumerate composition packages {}: {error}",
                packages_dir.display()
            ))
        }
    };
    let mut roles = Vec::new();
    for entry in entries {
        let entry = entry.context("cannot enumerate a composition package entry")?;
        roles.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("composition package name is not UTF-8"))?,
        );
    }
    roles.sort();
    Ok(roles)
}

#[cfg(feature = "dev-committed-embedder")]
fn declaration_roles_v1(declaration: &[String]) -> Option<Vec<CompositionRole>> {
    declaration
        .iter()
        .map(|role| match role.as_str() {
            "app" => Some(CompositionRole::App),
            "agent" => Some(CompositionRole::Agent),
            _ => None,
        })
        .collect()
}

#[cfg(feature = "dev-committed-embedder")]
fn legal_declaration_v1(declaration: &[String]) -> bool {
    matches!(declaration, [app] if app == "app")
        || matches!(declaration, [app, agent] if app == "app" && agent == "agent")
}

#[cfg(feature = "dev-committed-embedder")]
fn source_id_wire_v1(source_id: &SourceId) -> Result<String> {
    source_id
        .encode()
        .context("cannot encode admitted SourceId")
}

#[cfg(feature = "dev-committed-embedder")]
fn normalize_vite_dev_specifier_v1(specifier: &str) -> String {
    // Exact authority: `collectAliasImportSites` in
    // `packages/exact-devtools/src/prepared-composition-schema.ts` calls
    // `normalizeViteDevSpecifier` from `prepared-graph-producer.ts`. Keep
    // these operations in lockstep: split at the first `?`, strip exactly
    // `/@fs`, discard `v=*`, `t=*`, and bare `import`, preserve every other
    // query in original order, then omit `?` only when no parameters remain.
    let (mut path, query) = specifier
        .split_once('?')
        .map_or((specifier, ""), |(path, query)| (path, query));
    if path.starts_with("/@fs/") {
        path = &path["/@fs".len()..];
    }
    let kept = query
        .split('&')
        .filter(|parameter| {
            !parameter.is_empty()
                && !parameter.starts_with("v=")
                && !parameter.starts_with("t=")
                && *parameter != "import"
        })
        .collect::<Vec<_>>();
    if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    }
}

#[cfg(feature = "dev-committed-embedder")]
fn alias_matches_specifier_v1(alias_id: &str, specifier: &str) -> bool {
    specifier == alias_id
        || normalize_vite_dev_specifier_v1(specifier) == normalize_vite_dev_specifier_v1(alias_id)
}

#[cfg(feature = "dev-committed-embedder")]
fn alias_import_sites_v1(
    alias_id: &str,
    packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
) -> Result<Vec<AliasImportSiteV1>> {
    let mut rows = Vec::new();
    for package in packages.values() {
        for (source_id, record) in &package.records {
            let importer = source_id_wire_v1(source_id)?;
            for binding in &record.bindings {
                if alias_matches_specifier_v1(alias_id, &binding.specifier) {
                    rows.push(AliasImportSiteV1 {
                        importer: importer.clone(),
                        specifier: binding.specifier.clone(),
                    });
                }
            }
        }
        for row in &package.host_bridged_inventory {
            if alias_matches_specifier_v1(alias_id, &row.specifier) {
                rows.push(AliasImportSiteV1 {
                    importer: row.module.clone(),
                    specifier: row.specifier.clone(),
                });
            }
        }
    }
    Ok(rows)
}

#[cfg(feature = "dev-committed-embedder")]
fn validate_alias_table_v1(
    envelope: &PreparedCompositionV1,
    packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
) -> Result<(), String> {
    let owned = packages
        .values()
        .flat_map(|package| package.records.keys())
        .map(|source_id| source_id_wire_v1(source_id).map(|wire| (wire, source_id)))
        .collect::<Result<BTreeMap<_, _>>>()
        .map_err(|error| format!("{error:#}"))?;
    let mut rows = envelope.alias_table.rows.clone();
    rows.sort_by(|left, right| compare_utf16(&left.alias_id, &right.alias_id));
    if rows != envelope.alias_table.rows {
        return Err("alias table rows are not sorted by aliasId".into());
    }
    let digest = digest_canonical_value_v1(PREPARED_ALIAS_TABLE_DOMAIN_V1, &rows)
        .map_err(|error| format!("cannot recompute alias-table digest: {error:#}"))?;
    if digest != envelope.alias_table.digest {
        return Err("alias-table digest differs from its committed rows".into());
    }
    let mut aliases = BTreeSet::new();
    for row in &rows {
        if !aliases.insert(row.alias_id.clone()) {
            return Err("alias table repeats an aliasId".into());
        }
        if owned.contains_key(&row.alias_id) {
            return Err("aliasId collides with an owned SourceId".into());
        }
        let representative = owned
            .get(&row.representative_source_id)
            .ok_or_else(|| "alias representative is absent from the composition".to_owned())?;
        let record = packages
            .values()
            .find_map(|package| package.records.get(*representative))
            .expect("owned representative has an admitted record");
        if record.artifact.semantics.source_integrity != row.representative_source_integrity {
            return Err("alias representative source integrity disagrees".into());
        }
        // Amendment A2: the O-3 preimage consumes committed import-site rows
        // only. `resolverInventoryDigest` is intentionally absent here.
        let sites = alias_import_sites_v1(&row.alias_id, packages)
            .map_err(|error| format!("cannot collect alias import sites: {error:#}"))?;
        let observed = compute_alias_import_site_inventory_digest(&sites)
            .map_err(|error| format!("cannot recompute alias import sites: {error:#}"))?;
        if observed != row.import_site_inventory_digest {
            return Err("alias import-site evidence disagrees".into());
        }
    }
    Ok(())
}

#[cfg(feature = "dev-committed-embedder")]
fn ownership_map_v1(
    packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
) -> BTreeMap<SourceId, CompositionRole> {
    packages
        .iter()
        .flat_map(|(role, package)| {
            package
                .records
                .keys()
                .cloned()
                .map(|source_id| (source_id, *role))
        })
        .collect()
}

#[cfg(feature = "dev-committed-embedder")]
fn resolve_alias_target_v1(
    target: &SourceId,
    ownership: &BTreeMap<SourceId, CompositionRole>,
    alias_rows: &[CompositionAliasRowV1],
) -> Result<SourceId> {
    if ownership.contains_key(target) {
        return Ok(target.clone());
    }
    let wire = source_id_wire_v1(target)?;
    let Some(alias) = alias_rows.iter().find(|row| row.alias_id == wire) else {
        return Ok(target.clone());
    };
    SourceId::decode(&alias.representative_source_id)
        .context("alias representative is not a canonical SourceId")
}

#[cfg(feature = "dev-committed-embedder")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PartitionRowV1<'a> {
    source_id: &'a str,
    role: CompositionRole,
}

#[cfg(feature = "dev-committed-embedder")]
fn recompute_partition_v1(
    declaration: &[CompositionRole],
    packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
) -> Result<CompositionPartitionV1> {
    let mut encoded = Vec::new();
    for (role, package) in packages {
        for source_id in package.records.keys() {
            encoded.push((source_id_wire_v1(source_id)?, *role));
        }
    }
    encoded
        .sort_by(|left, right| compare_utf16(&left.0, &right.0).then_with(|| left.1.cmp(&right.1)));
    encoded.dedup();
    let rows = encoded
        .iter()
        .map(|(source_id, role)| PartitionRowV1 {
            source_id,
            role: *role,
        })
        .collect::<Vec<_>>();
    let digest = digest_canonical_value_v1(PREPARED_PARTITION_DOMAIN_V1, &rows)?;
    let roles = CompositionPartitionRolesV1 {
        app: declaration.contains(&CompositionRole::App).then(|| {
            packages
                .get(&CompositionRole::App)
                .map_or(0, |package| package.records.len() as u64)
        }),
        agent: declaration.contains(&CompositionRole::Agent).then(|| {
            packages
                .get(&CompositionRole::Agent)
                .map_or(0, |package| package.records.len() as u64)
        }),
    };
    Ok(CompositionPartitionV1 { digest, roles })
}

#[cfg(feature = "dev-committed-embedder")]
fn recompute_union_rows_v1(
    packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
    ownership: &BTreeMap<SourceId, CompositionRole>,
    aliases: &[CompositionAliasRowV1],
) -> Result<Vec<CompositionUnionBindingRowV1>> {
    let mut rows = Vec::new();
    for (from_role, package) in packages {
        for (origin, record) in &package.records {
            for binding in &record.bindings {
                let PreparedPackageBindingTargetV1::External { role, source_id } = &binding.target
                else {
                    continue;
                };
                let target = resolve_alias_target_v1(source_id, ownership, aliases)?;
                rows.push(CompositionUnionBindingRowV1 {
                    from_role: *from_role,
                    from_source_id: source_id_wire_v1(origin)?,
                    specifier: binding.specifier.clone(),
                    to_role: *role,
                    to_source_id: source_id_wire_v1(&target)?,
                });
            }
        }
    }
    rows.sort_by(|left, right| {
        left.from_role
            .cmp(&right.from_role)
            .then_with(|| compare_utf16(&left.from_source_id, &right.from_source_id))
            .then_with(|| compare_utf16(&left.specifier, &right.specifier))
    });
    Ok(rows)
}

#[cfg(feature = "dev-committed-embedder")]
fn literal_dynamic_specifiers_v1(
    record: &super::runner_pipeline::AdmittedCompositionPackageRecordV1,
) -> BTreeSet<String> {
    record
        .artifact
        .semantics
        .dynamic_edges
        .iter()
        .filter_map(|edge| match edge {
            DynamicEdgeV1::Literal { specifier, .. } => Some(specifier.as_str().to_owned()),
            DynamicEdgeV1::Computed { .. } => None,
        })
        .collect()
}

#[cfg(feature = "dev-committed-embedder")]
fn recompute_boundary_rows_v1(
    package: &AdmittedCompositionPackageV1,
) -> Result<Vec<HostBridgedInventoryRowV1>> {
    let mut rows = Vec::new();
    for (source_id, record) in &package.records {
        let bound_dynamic = record
            .bindings
            .iter()
            .filter(|binding| binding.resolution_kind == ResolutionKind::DynamicImport)
            .map(|binding| binding.specifier.as_str())
            .collect::<BTreeSet<_>>();
        for specifier in literal_dynamic_specifiers_v1(record) {
            if !bound_dynamic.contains(specifier.as_str()) {
                rows.push(HostBridgedInventoryRowV1 {
                    module: source_id_wire_v1(source_id)?,
                    specifier,
                    reason: HostBridgedReasonV1::TargetIsNotBundleModule,
                });
            }
        }
    }
    rows.sort_by(|left, right| {
        compare_utf16(&left.module, &right.module)
            .then_with(|| compare_utf16(&left.specifier, &right.specifier))
    });
    Ok(rows)
}

#[cfg(feature = "dev-committed-embedder")]
fn computed_candidate_site_map_v1(
    packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
) -> Result<ComputedCandidateSiteMap> {
    let mut rows = ComputedCandidateSiteMap::new();
    let admitted = packages
        .values()
        .flat_map(|package| package.records.keys().cloned())
        .collect::<BTreeSet<_>>();
    for record in packages
        .values()
        .flat_map(|package| package.records.values())
    {
        for table in &record.candidate_tables {
            for candidate in &table.candidates {
                // A candidate table authenticates a finite host-resolution
                // universe; it does not force every named target into this
                // admitted union. Out-of-union targets remain host-bridged
                // and therefore have no native plan row or step-7 closure.
                if !admitted.contains(&candidate.target.0) {
                    continue;
                }
                let key = (table.site, candidate.specifier.as_str().to_owned());
                let binding = ComputedCandidateBinding {
                    target: candidate.target.0.clone(),
                    attributes: candidate.attributes.clone(),
                };
                if let Some(previous) = rows
                    .entry(table.requester.0.clone())
                    .or_default()
                    .insert(key, binding.clone())
                {
                    if previous != binding {
                        bail!("computed-candidate site and spelling disagree across sidecars");
                    }
                }
            }
        }
    }
    Ok(rows)
}

#[cfg(feature = "dev-committed-embedder")]
fn build_union_plan_v1<'a>(
    packages: &'a BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
    ownership: &BTreeMap<SourceId, CompositionRole>,
    aliases: &[CompositionAliasRowV1],
) -> Result<SynchronousGraphPlan<'a>> {
    let mut records = Vec::new();
    let mut host_bridged_dynamic_edges = BTreeMap::<SourceId, BTreeSet<String>>::new();
    for package in packages.values() {
        for row in &package.host_bridged_inventory {
            let source_id = SourceId::decode(&row.module)
                .context("host-bridged inventory module is not a SourceId")?;
            host_bridged_dynamic_edges
                .entry(source_id)
                .or_default()
                .insert(row.specifier.clone());
        }
        for record in package.records.values() {
            let mut bindings = BTreeMap::new();
            for binding in &record.bindings {
                let target = match &binding.target {
                    PreparedPackageBindingTargetV1::Local { source_id }
                    | PreparedPackageBindingTargetV1::External { source_id, .. } => {
                        resolve_alias_target_v1(source_id, ownership, aliases)?
                    }
                };
                bindings.insert(
                    GraphEdgeKey::new(binding.specifier.clone(), binding.resolution_kind),
                    target,
                );
            }
            records.push((record.verified(), bindings));
        }
    }
    let candidates = computed_candidate_site_map_v1(packages)?;
    SynchronousGraphPlan::new_typed_with_host_bridged_dynamic_edges(
        records,
        candidates,
        host_bridged_dynamic_edges,
    )
    .map_err(anyhow::Error::from)
}

#[cfg(feature = "dev-committed-embedder")]
fn effective_record_principal_v1(
    package: &AdmittedCompositionPackageV1,
    source_id: &SourceId,
) -> Result<Principal> {
    if let Some(principal) = source_id.defining_principal() {
        return Ok(principal.clone());
    }
    package
        .principals
        .iter()
        .find(|principal| principal.is_root())
        .cloned()
        .ok_or_else(|| anyhow!("admitted package has no root principal for builtin attribution"))
}

#[cfg(feature = "dev-committed-embedder")]
fn authorize_composition_edges_v1(
    packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
    ownership: &BTreeMap<SourceId, CompositionRole>,
    aliases: &[CompositionAliasRowV1],
) -> std::result::Result<Vec<CompositionAuthorizedEdgeV1>, String> {
    let mut authorized = Vec::new();
    for (origin_role, package) in packages {
        for (origin, record) in &package.records {
            for binding in &record.bindings {
                let (declared_target, external) = match &binding.target {
                    PreparedPackageBindingTargetV1::Local { source_id } => (source_id, false),
                    PreparedPackageBindingTargetV1::External { source_id, .. } => (source_id, true),
                };
                let target = resolve_alias_target_v1(declared_target, ownership, aliases)
                    .map_err(|error| format!("cannot resolve authorized edge: {error:#}"))?;
                let target_role = ownership
                    .get(&target)
                    .ok_or_else(|| "authorized edge target is absent".to_owned())?;
                let target_package = packages
                    .get(target_role)
                    .expect("ownership only names admitted packages");
                if external {
                    let importer = effective_record_principal_v1(package, origin)
                        .map_err(|error| format!("{error:#}"))?;
                    let imported = effective_record_principal_v1(target_package, &target)
                        .map_err(|error| format!("{error:#}"))?;
                    // @ref LLP 0056#10-security-posture-v1--authorized-linker-defining-principals — A2 denies every external edge crossing defining principals; equal principals bypass policy.
                    if importer != imported {
                        return Err(format!(
                            "external {} edge from {} package crosses defining principals",
                            binding.specifier,
                            origin_role.as_str()
                        ));
                    }
                }
                // Internal package edges retain the landed dev-lane effective
                // policy: this v1 driver invents no new internal denial.
                authorized.push(CompositionAuthorizedEdgeV1 {
                    origin: origin.clone(),
                    target,
                    specifier: binding.specifier.clone(),
                    resolution_kind: binding.resolution_kind,
                });
            }
        }
    }
    Ok(authorized)
}

#[cfg(feature = "dev-committed-embedder")]
struct DevUnarmedCompositionGraphPolicyV1 {
    digest: Digest,
    generations: SnapshotGenerations,
}

#[cfg(feature = "dev-committed-embedder")]
impl GraphImportPolicy for DevUnarmedCompositionGraphPolicyV1 {
    fn snapshot_digest(&self) -> &Digest {
        &self.digest
    }

    fn snapshot_generations(&self) -> SnapshotGenerations {
        self.generations
    }

    fn authenticates_module_edge(
        &self,
        _importer: &Principal,
        _request_specifier: &str,
        _imported: &Principal,
        _resolution_kind: &str,
        _conditions: &[String],
        _attributes: &BTreeMap<String, String>,
    ) -> bool {
        // Cross-package, cross-principal edges have already been denied by
        // `authorize_composition_edges_v1`. The remaining crossing calls are
        // internal package edges, whose v1 policy is the landed dev-lane
        // allow behavior from LLP 0056 §10.
        true
    }
}

#[cfg(feature = "dev-committed-embedder")]
fn composition_authority_contexts_v1(
    packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
    graph_generation: u64,
) -> Result<BTreeMap<SourceId, GraphAuthorityContext>> {
    let mut contexts = BTreeMap::new();
    for package in packages.values() {
        for source_id in package.records.keys() {
            let principal = effective_record_principal_v1(package, source_id)?;
            contexts.insert(
                source_id.clone(),
                GraphAuthorityContext::new(
                    source_id.clone(),
                    principal.clone(),
                    principal.clone(),
                    principal.clone(),
                    vec![principal],
                    Stage::Requested,
                    graph_generation,
                )?,
            );
        }
    }
    Ok(contexts)
}

#[cfg(feature = "dev-committed-embedder")]
type NativeCompositionAuthorizationV1 = (
    Vec<AuthorizedGraphOperation>,
    BTreeMap<SourceId, BTreeSet<DynamicImportBindingKey>>,
    BTreeMap<SourceId, GraphAuthorityContext>,
);

#[cfg(feature = "dev-committed-embedder")]
fn authorize_native_composition_plan_v1(
    plan: &SynchronousGraphPlan<'_>,
    packages: &BTreeMap<CompositionRole, AdmittedCompositionPackageV1>,
    policy_digest: &Digest,
    authority_generation: u64,
    graph_generation: u64,
) -> Result<NativeCompositionAuthorizationV1> {
    let generation = Generation::new(authority_generation).map_err(anyhow::Error::msg)?;
    let policy = DevUnarmedCompositionGraphPolicyV1 {
        digest: policy_digest.clone(),
        generations: SnapshotGenerations {
            policy: generation,
            negative: generation,
            dynamic: generation,
            handle: generation,
        },
    };
    let authorizer = ModuleGraphAuthorizer::new(&policy);
    let contexts = composition_authority_contexts_v1(packages, graph_generation)?;
    let ownership = ownership_map_v1(packages);
    let mut receipts = BTreeMap::new();
    let mut allowed_dynamic_bindings =
        BTreeMap::<SourceId, BTreeSet<DynamicImportBindingKey>>::new();

    // Step 6 authorizes the complete admitted union. Step 8 later selects the
    // entry-plan closure without asking policy again. Every admitted record
    // carries its own CapSec context, so the union of per-root reachable
    // sweeps is exactly one pass over the admitted records — the sweep-per-
    // root shape re-walked the closure from all ~N records and measured
    // ~6-9 s at 625 records on the first live composition boots; the
    // one-pass form produces the identical merged receipt/binding set.
    for receipt in plan.authorize_admitted_record_operations(&authorizer, &contexts)? {
        receipts
            .entry(receipt.decision().operation_id.as_str().to_owned())
            .or_insert(receipt);
    }
    {
        let dynamic = plan.authorize_admitted_dynamic_candidates(
            &authorizer,
            &contexts,
            |requester, binding| {
                // @ref LLP 0056#75-the-retained-composition-session-aliases-and-dynamic-imports — only declared literal within-package targets enter the native table; computed and cross-package requests remain host-bridged.
                binding.site.is_none()
                    && matches!(
                        (ownership.get(requester), ownership.get(&binding.target)),
                        (Some(requester_owner), Some(target_owner))
                            if requester_owner == target_owner
                    )
            },
        )?;
        for receipt in dynamic.receipts {
            receipts
                .entry(receipt.decision().operation_id.as_str().to_owned())
                .or_insert(receipt);
        }
        for (source_id, bindings) in dynamic.allowed_bindings {
            allowed_dynamic_bindings
                .entry(source_id)
                .or_default()
                .extend(bindings);
        }
    }
    Ok((
        receipts.into_values().collect(),
        allowed_dynamic_bindings,
        contexts,
    ))
}

#[cfg(feature = "dev-committed-embedder")]
fn entry_plan_digest_v1(entries: &[CompositionEntryDescriptorV1]) -> Result<Digest> {
    digest_canonical_value_v1(PREPARED_ENTRY_PLAN_DOMAIN_V1, &entries)
}

/// Admit a prepared package composition through LLP 0056 step 7.
///
/// This dev-only driver is total: step-0 channel failures and step-1–7
/// refusals are returned as serialized-report values, while success carries
/// the typed step-6 authorization capability into the slice-3 linker.
// @ref LLP 0056#5-the-nine-steps--the-ibex-half — predicates run in registry order and cross-package step 3 selects the lowest `(step, ordinal, roleOrder)` tuple.
#[cfg(feature = "dev-committed-embedder")]
pub fn admit_prepared_composition_v1(
    composition_dir: &Path,
    commitment_text: &str,
    expectations_text: &str,
    project_root: &Path,
) -> CompositionAdmissionOutcomeV1 {
    admit_prepared_composition_with_probes_v1(
        composition_dir,
        commitment_text,
        expectations_text,
        project_root,
        CompositionChannelProbeV1::Checked,
        CompositionEngineProbeV1::Runtime,
    )
}

#[cfg(feature = "dev-committed-embedder")]
fn admit_prepared_composition_with_probes_v1(
    composition_dir: &Path,
    commitment_text: &str,
    expectations_text: &str,
    project_root: &Path,
    channel_probe: CompositionChannelProbeV1,
    engine_probe: CompositionEngineProbeV1,
) -> CompositionAdmissionOutcomeV1 {
    let channel_started = Instant::now();
    let parsed = match channel_probe {
        CompositionChannelProbeV1::Checked => {
            parse_dev_composition_channel_records_v1(commitment_text, expectations_text)
        }
        #[cfg(test)]
        CompositionChannelProbeV1::Unchecked => {
            parse_dev_composition_channel_records_unchecked_v1(commitment_text, expectations_text)
        }
    };
    let commitment_parse_us = i_json_duration_us(channel_started.elapsed());
    let (commitment, expectations) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            let detail = format!("{error:#}");
            let report = DevUnarmedCompositionStartupReportV1::ChannelError {
                common: report_common_v1(
                    None,
                    None,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    None,
                    commitment_parse_us,
                    0,
                ),
                channel_token: channel_token_from_error_v1(&detail),
                detail,
            };
            return CompositionAdmissionOutcomeV1::ChannelError(report);
        }
    };
    let hbc_engine = match engine_probe {
        CompositionEngineProbeV1::Runtime => runtime_hbc_engine_expectation_v1(),
        #[cfg(test)]
        CompositionEngineProbeV1::Fixed(engine) => engine,
    };
    let engine_binding_digest_prefix = engine_binding_digest_prefix_v1(hbc_engine.as_ref());
    let admission_started = Instant::now();
    let mut statuses = BTreeMap::new();
    let mut admitted_packages = BTreeMap::new();

    // Step 1: the envelope is the only served object decoded before its
    // independently held composition-root commitment is checked.
    let envelope_bytes = match read_bounded_prepared_file(
        &composition_dir.join("composition.json"),
        MAX_COMPOSITION_ENVELOPE_BYTES_V1,
        "composition envelope",
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return refused_outcome_v1(
                None,
                None,
                &admitted_packages,
                &statuses,
                engine_binding_digest_prefix,
                commitment_parse_us,
                admission_started,
                CompositionRefusalCode::EnvelopeMalformed,
                None,
                format!("{error:#}"),
            )
        }
    };
    let envelope = match PreparedCompositionV1::decode_canonical(&envelope_bytes) {
        Ok(envelope) => envelope,
        Err(error) => {
            return refused_outcome_v1(
                None,
                None,
                &admitted_packages,
                &statuses,
                engine_binding_digest_prefix,
                commitment_parse_us,
                admission_started,
                CompositionRefusalCode::EnvelopeMalformed,
                None,
                format!("{error:#}"),
            )
        }
    };
    let observed_composition_root =
        match digest_bytes(PREPARED_COMPOSITION_ROOT_DOMAIN_V1, &envelope_bytes) {
            Ok(digest) => digest,
            Err(error) => {
                return refused_outcome_v1(
                    Some(&envelope),
                    None,
                    &admitted_packages,
                    &statuses,
                    engine_binding_digest_prefix,
                    commitment_parse_us,
                    admission_started,
                    CompositionRefusalCode::CompositionCommitmentMismatch,
                    None,
                    format!("cannot digest composition envelope: {error:#}"),
                )
            }
        };

    macro_rules! refuse {
        ($code:expr, $role:expr, $detail:expr) => {
            return refused_outcome_v1(
                Some(&envelope),
                Some(&observed_composition_root),
                &admitted_packages,
                &statuses,
                engine_binding_digest_prefix.clone(),
                commitment_parse_us,
                admission_started,
                $code,
                $role,
                $detail,
            )
        };
    }

    // Step 2a: authenticate the envelope and then check only its internal
    // parity facts. Invalid declarations remain reachable at #6/#7/#10.
    if observed_composition_root != commitment.composition_root_digest {
        refuse!(
            CompositionRefusalCode::CompositionCommitmentMismatch,
            None,
            "composition envelope digest differs from the host-held commitment"
        );
    }
    if legal_declaration_v1(&envelope.declaration)
        && (envelope.entry_plan.entries.len() != envelope.declaration.len()
            || envelope.packages.len() != envelope.declaration.len()
            || envelope
                .packages
                .iter()
                .zip(&envelope.declaration)
                .any(|(package, role)| package.role.as_str() != role))
    {
        refuse!(
            CompositionRefusalCode::CompositionCommitmentMismatch,
            None,
            "composition envelope declaration parity is internally inconsistent"
        );
    }

    // Step 2b, registry ordinals #3–#10.
    if envelope.freshness.session_nonce != expectations.session_nonce
        || expectations.now_unix_ms > envelope.freshness.expires_at_ms
        || envelope.freshness.authority_generation != expectations.authority_generation
        || envelope.freshness.resolver_generation != expectations.resolver_generation
    {
        refuse!(
            CompositionRefusalCode::CompositionReplayed,
            None,
            "composition freshness differs from verifier-held live state"
        );
    }
    if envelope.freshness.policy_digest != expectations.policy_digest {
        refuse!(
            CompositionRefusalCode::CompositionPolicyStale,
            None,
            "composition policy digest differs from verifier-held policy"
        );
    }
    if envelope.freshness.producer.binary_digest != expectations.resolver_inventory_digest {
        refuse!(
            CompositionRefusalCode::CompositionReplayed,
            None,
            "composition resolver/compiler inventory differs from verifier-held live state"
        );
    }
    if envelope.freshness.target != expectations.expected_target
        || !matches!(
            envelope.freshness.encoding.as_str(),
            "javascript-factory-table" | "hermes-bytecode"
        )
        || envelope.freshness.agent_packing != "boot-core-v1"
    {
        refuse!(
            CompositionRefusalCode::IbexTargetProfileMismatch,
            None,
            "composition target, encoding, or agent-packing profile is incompatible"
        );
    }
    if envelope
        .declaration
        .iter()
        .any(|role| !matches!(role.as_str(), "app" | "agent"))
    {
        refuse!(
            CompositionRefusalCode::CompositionUnknownRole,
            None,
            "composition declaration contains an unknown role"
        );
    }
    let declaration_unique = envelope.declaration.iter().collect::<BTreeSet<_>>();
    let package_roles = envelope
        .packages
        .iter()
        .map(|package| package.role)
        .collect::<Vec<_>>();
    if declaration_unique.len() != envelope.declaration.len()
        || package_roles.iter().collect::<BTreeSet<_>>().len() != package_roles.len()
    {
        refuse!(
            CompositionRefusalCode::CompositionDuplicateRole,
            None,
            "composition repeats a role"
        );
    }
    let served_roles = match served_package_roles_v1(composition_dir) {
        Ok(roles) => roles,
        Err(error) => {
            refuse!(
                CompositionRefusalCode::CompositionMismatch,
                None,
                format!("cannot establish served package roles: {error:#}")
            );
        }
    };
    if served_roles
        .iter()
        .any(|role| !envelope.declaration.contains(role))
    {
        refuse!(
            CompositionRefusalCode::CompositionPackageExtra,
            None,
            "served composition contains an undeclared package"
        );
    }
    if envelope
        .declaration
        .iter()
        .any(|role| !served_roles.contains(role))
    {
        refuse!(
            CompositionRefusalCode::CompositionPackageMissing,
            None,
            "declared composition package is not served"
        );
    }
    let expected_role_names = expectations
        .expected_roles
        .iter()
        .map(|role| role.as_str().to_owned())
        .collect::<Vec<_>>();
    if !legal_declaration_v1(&envelope.declaration) || envelope.declaration != expected_role_names {
        refuse!(
            CompositionRefusalCode::CompositionMismatch,
            None,
            "composition declaration differs from verifier-held effective roles"
        );
    }
    let declaration = declaration_roles_v1(&envelope.declaration)
        .expect("closed legal declaration maps to typed roles");

    // Step 3 package predicates are completed for every package, then the
    // lowest `(ordinal, roleOrder)` failure wins. This prevents a later app
    // failure from suppressing an earlier agent predicate.
    let mut package_results = Vec::new();
    for role in &declaration {
        let attestation = envelope
            .packages
            .iter()
            .find(|package| package.role == *role)
            .expect("step 2 established one attestation per declared role");
        package_results.push((
            *role,
            admit_composition_package_v1(
                &composition_dir.join("packages").join(role.as_str()),
                *role,
                &attestation.package_root,
                attestation.producer_generation,
                project_root,
                hbc_engine.as_ref(),
            ),
        ));
    }
    let winning_failure = package_results
        .iter()
        .filter_map(|(_, result)| result.as_ref().err())
        .min_by_key(|failure| (failure.code.ordinal(), failure.role.order()))
        .map(|failure| (failure.code, failure.role, failure.detail.clone()));
    if let Some((failure_code, failure_role, failure_detail)) = winning_failure {
        for (role, result) in package_results {
            let status = if role == failure_role {
                CompositionPackageVerificationStatusV1::Refused
            } else if result.is_ok() {
                CompositionPackageVerificationStatusV1::Verified
            } else {
                CompositionPackageVerificationStatusV1::NotChecked
            };
            statuses.insert(role, status);
            if let Ok(package) = result {
                admitted_packages.insert(role, package);
            }
        }
        refuse!(failure_code, Some(failure_role), failure_detail);
    }
    for (role, result) in package_results {
        admitted_packages.insert(
            role,
            result.expect("failure-free package sweep admitted every package"),
        );
    }
    // Both packages completed the per-package sweep before composition-wide
    // #22/#23. Start from verified and downgrade only an attributable role.
    for role in &declaration {
        statuses.insert(*role, CompositionPackageVerificationStatusV1::Verified);
    }
    let splice_role = declaration.iter().copied().find(|role| {
        let attestation = envelope
            .packages
            .iter()
            .find(|attestation| attestation.role == *role)
            .expect("step 2 established one attestation per declared role");
        let package = admitted_packages
            .get(role)
            .expect("declared package was admitted");
        attestation.producer_generation != envelope.freshness.resolver_generation
            || package.producer_id != envelope.freshness.producer.id
            || package.producer_binary_digest != envelope.freshness.producer.binary_digest
    });
    if let Some(role) = splice_role {
        statuses.insert(role, CompositionPackageVerificationStatusV1::Refused);
        refuse!(
            CompositionRefusalCode::GenerationSplice,
            Some(role),
            "package generation or producer identity differs from the composition envelope"
        );
    }
    if let Err(detail) = validate_alias_table_v1(&envelope, &admitted_packages) {
        refuse!(CompositionRefusalCode::AliasConflict, None, detail);
    }

    // Step 4: recomputation deliberately deduplicates `(SourceId, role)` so
    // the lower #24 predicate remains independently reachable from #25/#26.
    let recomputed_partition = match recompute_partition_v1(&declaration, &admitted_packages) {
        Ok(partition) => partition,
        Err(error) => {
            refuse!(
                CompositionRefusalCode::PartitionMismatch,
                None,
                format!("cannot recompute composition partition: {error:#}")
            );
        }
    };
    if recomputed_partition != envelope.partition {
        refuse!(
            CompositionRefusalCode::PartitionMismatch,
            None,
            "recomputed composition partition differs from the envelope"
        );
    }
    if let Some((role, _)) = declaration.iter().find_map(|role| {
        admitted_packages
            .get(role)
            .filter(|package| package.duplicate_source_id)
            .map(|package| (*role, package))
    }) {
        statuses.insert(role, CompositionPackageVerificationStatusV1::Refused);
        refuse!(
            CompositionRefusalCode::IbexDuplicateSourceId,
            Some(role),
            "prepared package repeats a SourceId"
        );
    }
    if declaration.contains(&CompositionRole::Agent) {
        let app = admitted_packages
            .get(&CompositionRole::App)
            .expect("legal declaration requires app");
        let agent = admitted_packages
            .get(&CompositionRole::Agent)
            .expect("declared agent package was admitted");
        if agent
            .records
            .keys()
            .any(|source_id| app.records.contains_key(source_id))
        {
            refuse!(
                CompositionRefusalCode::PackageOverlap,
                None,
                "one SourceId is owned by both composition packages"
            );
        }
    }

    let ownership = ownership_map_v1(&admitted_packages);
    // Step 5 #27 is an ordinal-outer sweep: any app edge resolving to an
    // agent-owned record wins over every other no-third-state miss.
    if let Some(app) = admitted_packages.get(&CompositionRole::App) {
        for record in app.records.values() {
            for binding in &record.bindings {
                let source_id = match &binding.target {
                    PreparedPackageBindingTargetV1::Local { source_id }
                    | PreparedPackageBindingTargetV1::External { source_id, .. } => source_id,
                };
                let target =
                    resolve_alias_target_v1(source_id, &ownership, &envelope.alias_table.rows)
                        .unwrap_or_else(|_| source_id.clone());
                if ownership.get(&target) == Some(&CompositionRole::Agent) {
                    statuses.insert(
                        CompositionRole::App,
                        CompositionPackageVerificationStatusV1::Refused,
                    );
                    refuse!(
                        CompositionRefusalCode::AppReferencesAgent,
                        Some(CompositionRole::App),
                        "application package declares an edge to an agent-owned record"
                    );
                }
            }
        }
    }
    for role in &declaration {
        let package = admitted_packages
            .get(role)
            .expect("declared package was admitted");
        for record in package.records.values() {
            for binding in &record.bindings {
                let valid = match &binding.target {
                    PreparedPackageBindingTargetV1::Local { source_id } => {
                        resolve_alias_target_v1(source_id, &ownership, &envelope.alias_table.rows)
                            .ok()
                            .and_then(|target| ownership.get(&target).copied())
                            == Some(*role)
                    }
                    PreparedPackageBindingTargetV1::External {
                        role: target_role, ..
                    } => *role == CompositionRole::Agent && *target_role == CompositionRole::App,
                };
                if !valid {
                    statuses.insert(*role, CompositionPackageVerificationStatusV1::Refused);
                    refuse!(
                        CompositionRefusalCode::LocalAgreementDisagreement,
                        Some(*role),
                        "package binding is neither local ownership nor a legal agent-to-app external reference"
                    );
                }
            }
        }
    }

    // Step 6 #29–#34.
    let union_rows =
        match recompute_union_rows_v1(&admitted_packages, &ownership, &envelope.alias_table.rows) {
            Ok(rows) => rows,
            Err(error) => {
                refuse!(
                    CompositionRefusalCode::UnionTableMismatch,
                    None,
                    format!("cannot recompute union binding table: {error:#}")
                );
            }
        };
    let union_digest = match digest_canonical_value_v1(PREPARED_UNION_TABLE_DOMAIN_V1, &union_rows)
    {
        Ok(digest) => digest,
        Err(error) => {
            refuse!(
                CompositionRefusalCode::UnionTableMismatch,
                None,
                format!("cannot digest union binding table: {error:#}")
            );
        }
    };
    if envelope.union_binding_table.rows != union_rows
        || envelope.union_binding_table.digest != union_digest
    {
        refuse!(
            CompositionRefusalCode::UnionTableMismatch,
            None,
            "recomputed union binding table differs from the envelope"
        );
    }
    let mut expected_inventories = Vec::new();
    for role in &declaration {
        let package = admitted_packages
            .get(role)
            .expect("declared package was admitted");
        let rows = match recompute_boundary_rows_v1(package) {
            Ok(rows) => rows,
            Err(error) => {
                refuse!(
                    CompositionRefusalCode::BoundaryInventoryMismatch,
                    None,
                    format!("cannot recompute boundary inventory: {error:#}")
                );
            }
        };
        if rows != package.host_bridged_inventory {
            refuse!(
                CompositionRefusalCode::BoundaryInventoryMismatch,
                None,
                format!(
                    "{} package boundary inventory violates locality",
                    role.as_str()
                )
            );
        }
        let preimage = serde_json::json!({ "role": role, "rows": rows });
        let digest =
            match digest_canonical_value_v1(PREPARED_BOUNDARY_INVENTORY_DOMAIN_V1, &preimage) {
                Ok(digest) => digest,
                Err(error) => {
                    refuse!(
                        CompositionRefusalCode::BoundaryInventoryMismatch,
                        None,
                        format!("cannot digest boundary inventory: {error:#}")
                    );
                }
            };
        expected_inventories.push(CompositionHostBridgedInventoryV1 {
            role: *role,
            digest,
            rows: package.host_bridged_inventory.clone(),
        });
    }
    if expected_inventories != envelope.host_bridged_inventories {
        refuse!(
            CompositionRefusalCode::BoundaryInventoryMismatch,
            None,
            "composition boundary inventories differ from admitted package facts"
        );
    }
    for package in admitted_packages.values() {
        for record in package.records.values() {
            for binding in &record.bindings {
                let PreparedPackageBindingTargetV1::External { role, source_id } = &binding.target
                else {
                    continue;
                };
                let target =
                    resolve_alias_target_v1(source_id, &ownership, &envelope.alias_table.rows)
                        .unwrap_or_else(|_| source_id.clone());
                let Some(owner) = ownership.get(&target) else {
                    refuse!(
                        CompositionRefusalCode::ExternalTargetAbsent,
                        None,
                        "external reference target is absent from the composition"
                    );
                };
                if owner != role {
                    refuse!(
                        CompositionRefusalCode::ExternalOwnerMismatch,
                        None,
                        "external reference target is owned by a different package"
                    );
                }
            }
        }
    }
    let union_plan =
        match build_union_plan_v1(&admitted_packages, &ownership, &envelope.alias_table.rows) {
            Ok(plan) => plan,
            Err(error) => {
                refuse!(
                    CompositionRefusalCode::UnionTableMismatch,
                    None,
                    format!("cannot construct union graph plan: {error:#}")
                );
            }
        };
    for source_id in ownership.keys() {
        if let Err(error) = union_plan.import_bindings(source_id) {
            refuse!(
                CompositionRefusalCode::ExportDisagreement,
                None,
                format!("resolved import namespace disagrees: {error}")
            );
        }
    }
    let authorized_edges = match authorize_composition_edges_v1(
        &admitted_packages,
        &ownership,
        &envelope.alias_table.rows,
    ) {
        Ok(edges) => edges,
        Err(detail) => {
            refuse!(CompositionRefusalCode::CrossPrincipalDenied, None, detail);
        }
    };
    let graph_generation = admitted_packages
        .values()
        .next()
        .expect("every legal composition contains the app package")
        .producer_generation;
    let (authorization_receipts, allowed_dynamic_bindings, authority_contexts) =
        match authorize_native_composition_plan_v1(
            &union_plan,
            &admitted_packages,
            &envelope.freshness.policy_digest,
            envelope.freshness.authority_generation,
            graph_generation,
        ) {
            Ok(authorized) => authorized,
            Err(error) => {
                refuse!(
                    CompositionRefusalCode::UnionTableMismatch,
                    None,
                    format!("cannot retain authorized union plan: {error:#}")
                );
            }
        };

    // Step 7 #35–#37. Digest/order/action recomputation precedes descriptor
    // structure, followed by resolved namespace presence and linkage order.
    let observed_entry_digest = match entry_plan_digest_v1(&envelope.entry_plan.entries) {
        Ok(digest) => digest,
        Err(error) => {
            refuse!(
                CompositionRefusalCode::EntryPlanMismatch,
                None,
                format!("cannot recompute entry-plan digest: {error:#}")
            );
        }
    };
    if observed_entry_digest != envelope.entry_plan.digest {
        refuse!(
            CompositionRefusalCode::EntryPlanMismatch,
            None,
            "entry-plan digest differs from its committed descriptors"
        );
    }
    let expected_order = if declaration.contains(&CompositionRole::Agent) {
        vec![CompositionRole::Agent, CompositionRole::App]
    } else {
        vec![CompositionRole::App]
    };
    if envelope.entry_plan.entries.len() != expected_order.len()
        || envelope
            .entry_plan
            .entries
            .iter()
            .zip(&expected_order)
            .any(|(entry, role)| entry.role != *role)
    {
        refuse!(
            CompositionRefusalCode::EntryPlanMismatch,
            None,
            "entry-plan order or cardinality differs from the declaration"
        );
    }
    for entry in &envelope.entry_plan.entries {
        if !matches!(entry.action.as_str(), "evaluate" | "evaluate-then-invoke") {
            refuse!(
                CompositionRefusalCode::EntryDescriptorInvalid,
                None,
                "entry descriptor carries an unknown action"
            );
        }
        match entry.role {
            CompositionRole::App if entry.action != "evaluate" || entry.export.is_some() => {
                refuse!(
                    CompositionRefusalCode::EntryPlanMismatch,
                    None,
                    "app entry descriptor differs from the expected evaluate action"
                );
            }
            CompositionRole::Agent
                if entry.action == "evaluate-then-invoke"
                    && entry.export.as_deref().is_none_or(str::is_empty) =>
            {
                refuse!(
                    CompositionRefusalCode::EntryDescriptorInvalid,
                    None,
                    "agent invoke descriptor has no named export"
                );
            }
            CompositionRole::Agent
                if entry.action != "evaluate-then-invoke"
                    || entry.export.as_deref() != Some("installExactNativeAgentBootstrap") =>
            {
                refuse!(
                    CompositionRefusalCode::EntryPlanMismatch,
                    None,
                    "agent descriptor differs from the expected invoke plan"
                );
            }
            CompositionRole::App | CompositionRole::Agent => {}
        }
    }
    let mut roots = Vec::with_capacity(envelope.entry_plan.entries.len());
    let mut roots_by_role = BTreeMap::new();
    for entry in &envelope.entry_plan.entries {
        let root = match SourceId::decode(&entry.root) {
            Ok(root) => root,
            Err(error) => {
                refuse!(
                    CompositionRefusalCode::EntryDescriptorInvalid,
                    None,
                    format!("entry descriptor root is malformed: {error:#}")
                );
            }
        };
        if ownership.get(&root) != Some(&entry.role) {
            refuse!(
                CompositionRefusalCode::EntryDescriptorInvalid,
                None,
                "entry descriptor root is not owned by its role"
            );
        }
        roots_by_role.insert(entry.role, root.clone());
        roots.push(root);
    }
    if let Some(agent_root) = roots_by_role.get(&CompositionRole::Agent) {
        let namespace = match union_plan.namespace(agent_root) {
            Ok(namespace) => namespace,
            Err(error) => {
                refuse!(
                    CompositionRefusalCode::EntryDescriptorInvalid,
                    None,
                    format!("agent root namespace cannot be resolved: {error}")
                );
            }
        };
        if !namespace.contains_key("installExactNativeAgentBootstrap") {
            refuse!(
                CompositionRefusalCode::EntryDescriptorInvalid,
                None,
                "agent root lacks installExactNativeAgentBootstrap in its resolved namespace"
            );
        }
        let app_root = roots_by_role
            .get(&CompositionRole::App)
            .expect("every legal declaration contains app");
        match union_plan.evaluation_order(agent_root) {
            Ok(closure) if closure.contains(app_root) => {
                refuse!(
                    CompositionRefusalCode::EntryPlanMismatch,
                    None,
                    "app root occurs in the agent evaluation closure"
                );
            }
            Ok(_) => {}
            Err(error) => {
                refuse!(
                    CompositionRefusalCode::CompositionRootUnlinked,
                    None,
                    format!("agent root has no evaluation order: {error}")
                );
            }
        }
    }
    if let Err(error) = union_plan.linkage_order_for_roots(&roots, &allowed_dynamic_bindings) {
        refuse!(
            CompositionRefusalCode::CompositionRootUnlinked,
            None,
            format!("composition roots have no linkage order: {error}")
        );
    }
    if let Err(error) = union_plan.synchronous_evaluation_order_for_roots(&roots) {
        refuse!(
            CompositionRefusalCode::CompositionRootUnlinked,
            None,
            format!("composition roots have no synchronous evaluation order: {error}")
        );
    }
    let main_root = roots_by_role
        .get(&CompositionRole::App)
        .expect("every legal declaration contains app")
        .clone();
    drop(union_plan);

    let report = DevUnarmedCompositionStartupReportV1::Admitted {
        common: report_common_v1(
            Some(&envelope),
            Some(&observed_composition_root),
            &admitted_packages,
            &statuses,
            engine_binding_digest_prefix,
            commitment_parse_us,
            i_json_duration_us(admission_started.elapsed()),
        ),
        agent_invoke_returned_thenable: false,
    };
    let authorized = AuthorizedCompositionPlanV1 {
        packages: admitted_packages,
        authorized_edges,
        authorization_receipts,
        allowed_dynamic_bindings,
        authority_contexts,
        roots,
        main_root,
    };
    CompositionAdmissionOutcomeV1::Admitted(Box::new(AdmittedCompositionV1 {
        authorized,
        envelope,
        commitment,
        expectations,
        report,
    }))
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

/// Recompute the provisional LLP 0056 §4.2 package-graph digest.
///
/// PROVISIONAL pending the O-1 preimage row: the preimage is one JCS array
/// `[records, bindings]`. `records` is sorted lexicographically by each
/// `SourceId`'s own canonical JCS bytes and contains two-element arrays
/// `[sourceId, semanticDigest]`. `bindings` follows that same source order and
/// preserves each record's declared binding order; each row is `[sourceId,
/// specifier, resolutionKind, target]`, where `target` is `["local",
/// sourceId]` or `["external", sourceId]`. The external target intentionally
/// contributes only its target `SourceId`: package role and external-reference
/// legality are separate committed/index predicates. The resulting JCS bytes
/// are digested under
/// `ibex:prepared-package-graph:1`.
// @ref LLP 0056#42-the-package-graph-digest — carriers and artifacts bind a recomputed role-scoped semantic graph facet.
pub(crate) fn compute_package_graph_digest_v1(
    records: &[PreparedPackageRecordV1],
) -> Result<Digest> {
    let mut ordered = records
        .iter()
        .map(|record| {
            Ok((
                capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(
                    &record.source_id,
                )?)?,
                record,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    ordered.sort_by(|left, right| left.0.cmp(&right.0));

    let record_rows = ordered
        .iter()
        .map(|(_, record)| {
            serde_json::json!([&record.source_id, &record.artifact.semantic_digest,])
        })
        .collect::<Vec<_>>();
    let binding_rows = ordered
        .iter()
        .flat_map(|(_, record)| {
            record.bindings.iter().map(|binding| {
                let target = match &binding.target {
                    PreparedPackageBindingTargetV1::Local { source_id } => {
                        serde_json::json!(["local", source_id])
                    }
                    PreparedPackageBindingTargetV1::External { source_id, .. } => {
                        serde_json::json!(["external", source_id])
                    }
                };
                serde_json::json!([
                    &record.source_id,
                    &binding.specifier,
                    binding.resolution_kind,
                    target,
                ])
            })
        })
        .collect::<Vec<_>>();
    let preimage = serde_json::json!([record_rows, binding_rows]);
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&preimage)?;
    digest_bytes(PREPARED_PACKAGE_GRAPH_DOMAIN_V1, &canonical)
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
    if canonical != text.as_bytes() {
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
    use capsec_semantics::model::{PathComponent, Principal};
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
            "resolverInventoryDigest": valid_digest("composition-fixture-producer"),
            "nowUnixMs": 1_755_990_000_000_u64,
        })
    }

    fn canonical(value: &Value) -> String {
        capsec_semantics::canonical::to_jcs(value).unwrap()
    }

    #[test]
    fn strict_commitment_ingest_rejects_noncanonical_and_invalid_records() {
        let valid = commitment_value();
        let valid_text = canonical(&valid);
        assert!(parse_prepared_composition_commitment_v1(&valid_text).is_ok());
        assert!(parse_prepared_composition_commitment_v1(&format!("{valid_text}\n")).is_err());

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
        let valid_text = canonical(&valid);
        assert!(parse_composition_verifier_expectations_v1(&valid_text).is_ok());
        assert!(parse_composition_verifier_expectations_v1(&format!("{valid_text}\n")).is_err());

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

    #[cfg(feature = "dev-committed-embedder")]
    #[test]
    fn vite_alias_normalization_matches_the_exact_authority() {
        assert_eq!(
            normalize_vite_dev_specifier_v1(
                "/@fs/repo/src/bootstrap.ts?v=abc&t=123&import&raw&worker"
            ),
            "/repo/src/bootstrap.ts?raw&worker"
        );
        assert_eq!(
            normalize_vite_dev_specifier_v1("/@fs/repo/src/bootstrap.ts?import&t=1&v=2"),
            "/repo/src/bootstrap.ts"
        );
        assert!(alias_matches_specifier_v1(
            "/repo/src/bootstrap.ts?raw&worker",
            "/@fs/repo/src/bootstrap.ts?v=abc&t=123&import&raw&worker"
        ));
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

    #[test]
    fn provisional_package_graph_digest_matches_independent_two_record_jcs_vector() {
        let owner = Principal::Root {
            identity: NonEmptyString::new("package-graph-vector").unwrap(),
        };
        let source_id = |name: &str| {
            SourceId::file(owner.clone(), vec![PathComponent::utf8(name).unwrap()]).unwrap()
        };
        let source_a = source_id("a.mjs");
        let source_z = source_id("z.mjs");
        let external = source_id("external.mjs");
        let producer = source_integrity(b"package-graph-vector-producer").unwrap();
        let artifact_a = crate::module_loader::producer_spike::produce_module_artifact_v1(
            source_a.clone(),
            "a.mjs",
            std::path::Path::new("a.mjs"),
            "import './z.mjs'; export const a = 1;",
            producer.clone(),
        )
        .unwrap();
        let artifact_z = crate::module_loader::producer_spike::produce_module_artifact_v1(
            source_z.clone(),
            "z.mjs",
            std::path::Path::new("z.mjs"),
            "export const z = 1;",
            producer,
        )
        .unwrap();
        let records = vec![
            PreparedPackageRecordV1 {
                source_id: source_z.clone(),
                bindings: vec![PreparedPackageBindingV1 {
                    specifier: "external-app".into(),
                    resolution_kind: ResolutionKind::DynamicImport,
                    target: PreparedPackageBindingTargetV1::External {
                        role: CompositionRole::App,
                        source_id: external.clone(),
                    },
                }],
                artifact: artifact_z.clone(),
                carrier_index: 1,
                entry_id: NonEmptyString::new("z").unwrap(),
            },
            PreparedPackageRecordV1 {
                source_id: source_a.clone(),
                bindings: vec![PreparedPackageBindingV1 {
                    specifier: "./z.mjs".into(),
                    resolution_kind: ResolutionKind::EsmStatic,
                    target: PreparedPackageBindingTargetV1::Local {
                        source_id: source_z.clone(),
                    },
                }],
                artifact: artifact_a.clone(),
                carrier_index: 0,
                entry_id: NonEmptyString::new("a").unwrap(),
            },
        ];

        // Independent inline spelling of the provisional `[records,
        // bindings]` JCS preimage. In particular, records are source-sorted
        // despite the input order and the external target contributes no role.
        let expected_preimage = json!([
            [
                [&source_a, &artifact_a.semantic_digest],
                [&source_z, &artifact_z.semantic_digest],
            ],
            [
                [&source_a, "./z.mjs", "esm-static", ["local", &source_z]],
                [
                    &source_z,
                    "external-app",
                    "dynamic-import",
                    ["external", &external]
                ],
            ],
        ]);
        let expected_bytes = capsec_semantics::canonical::to_jcs_bytes(&expected_preimage).unwrap();
        let expected = digest_bytes(PREPARED_PACKAGE_GRAPH_DOMAIN_V1, &expected_bytes).unwrap();
        assert_eq!(compute_package_graph_digest_v1(&records).unwrap(), expected);
        assert_eq!(
            expected.as_str(),
            "sha256-wWGoLP4Rw5F93Mq9GDNMlf2wkzB9FLsbA84YvBIa9gQ"
        );
    }
}

#[cfg(all(test, feature = "dev-committed-embedder"))]
mod driver_tests;
