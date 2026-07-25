//! Construction-private, source-derived WebGPU CapSec authority sessions.
//!
//! The caller-attribution digest is retained as provenance only. Positive
//! authority is decided here from the armed snapshot and the checked WebGPU
//! operation registry. The opaque session identity and callback table never
//! enter JavaScript or the public target-advertisement plane.
//! @ref LLP 0002#the-optional-exact-gpu-service-registration-seam

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::c_void;
use std::sync::{Arc, Mutex, OnceLock};

use base64::Engine as _;
use capsec_semantics::decision::{DecisionOutcome, EffectGate, TargetCellDisposition};
use capsec_semantics::model::{
    canonicalize_principal_set, ActionId, AuthoritySelector, DecisionContext, DecisionSet,
    DecisionSetSchema, Digest, Effect, EffectCombination, EffectOccurrence, NonEmptyString,
    OccurrenceResource, Principal, SelectorResource, StableId, Stage,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::Host;

const GPU_SERVICE_ABI_V2: u32 = 0x0002_0000;
const GPU_TOPOLOGY_ISOLATED_PER_LOGICAL_V2: u32 = 1;
const MAX_GPU_AUTHORITY_SESSIONS: usize = 1024;
const MAX_GPU_PRESENTED_HANDLES: usize = 256;
const EXPERIMENTAL_WEBGPU_PRE1A_OPERATION_COUNT: usize = 63;
const EXPERIMENTAL_WEBGPU_PRE1A_POSITIVE_SELECTOR_COUNT: usize = 23;
const EXPERIMENTAL_WEBGPU_PRE1A_PRIVATE_TARGET_CELL_COUNT: usize = 65;
const EXPERIMENTAL_WEBGPU_PRE1A_REGISTRY_RAW_SHA256: &str =
    "47407c27d39b39350a9997009a63264146b10a147a6b06df7b0f740c60b24f2e";

pub(crate) const GPU_AUTHORITY_ALLOWED: i32 = 1;
pub(crate) const GPU_AUTHORITY_DENIED: i32 = 0;
pub(crate) const GPU_AUTHORITY_INVALID: i32 = -1;
pub(crate) const GPU_AUTHORITY_STALE: i32 = -2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GpuRuntimeIdentityV2 {
    pub runtime_address: u64,
    pub runtime_nonce: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GpuRealmIdentityV2 {
    pub runtime: GpuRuntimeIdentityV2,
    pub realm_id: u64,
    pub realm_generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GpuAccountIdentityV2 {
    pub account_id: u64,
    pub account_generation: u64,
    pub authority_digest: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GpuDeviceIdentityV2 {
    pub logical_device_id: u64,
    pub logical_device_generation: u64,
    pub provider_generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GpuObjectRefV2 {
    pub kind: u32,
    pub flags: u32,
    pub object_id: u64,
    pub object_generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExactGpuAuthoritySessionFactsV2 {
    pub struct_size: u32,
    pub abi_version: u32,
    pub operation_id: u32,
    pub topology_id: u32,
    pub authority_session_id: u64,
    pub realm: GpuRealmIdentityV2,
    pub account: GpuAccountIdentityV2,
    pub ingress_device: GpuDeviceIdentityV2,
    pub provider_generation: u64,
    pub operation_instance_id: u64,
    pub promise_id: u64,
    pub captured_scope_id: u64,
    pub adapter_ordinal: u64,
    pub device_ingress_ordinal: u64,
    pub queue_ingress_ordinal: u64,
    pub authority_context_digest: [u8; 32],
    pub receiver: GpuObjectRefV2,
    pub target: GpuObjectRefV2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExactGpuAuthorityPresentedHandleV2 {
    pub struct_size: u32,
    pub abi_version: u32,
    pub account: GpuAccountIdentityV2,
    pub device: GpuDeviceIdentityV2,
    pub object: GpuObjectRefV2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExactGpuAuthorityDecisionRequestV2 {
    pub struct_size: u32,
    pub abi_version: u32,
    pub stage: u32,
    pub flags: u32,
    pub facts: ExactGpuAuthoritySessionFactsV2,
    pub presented_handles: *const ExactGpuAuthorityPresentedHandleV2,
    pub presented_handle_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExactGpuAuthorityRetireV2 {
    pub struct_size: u32,
    pub abi_version: u32,
    pub flags: u32,
    pub reserved: u32,
    pub facts: ExactGpuAuthoritySessionFactsV2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExactGpuAuthorityDecisionBatchV2 {
    pub struct_size: u32,
    pub abi_version: u32,
    pub phase: u32,
    pub flags: u32,
    pub decisions: *const ExactGpuAuthorityDecisionRequestV2,
    pub decision_count: usize,
}

pub type ExactGpuAuthorityAllowedContinuationV2 =
    unsafe extern "C" fn(continuation_context: *mut c_void) -> i32;

#[repr(C)]
pub struct ExactGpuAuthoritySessionApiV2 {
    pub struct_size: u32,
    pub abi_version: u32,
    pub authority_context: *mut c_void,
    pub evaluate: Option<
        unsafe extern "C" fn(
            authority_context: *mut c_void,
            decision: *const ExactGpuAuthorityDecisionRequestV2,
        ) -> i32,
    >,
    pub retire: Option<
        unsafe extern "C" fn(
            authority_context: *mut c_void,
            retire: *const ExactGpuAuthorityRetireV2,
        ) -> i32,
    >,
    pub evaluate_batch_and_then: Option<
        unsafe extern "C" fn(
            authority_context: *mut c_void,
            batch: *const ExactGpuAuthorityDecisionBatchV2,
            continuation_context: *mut c_void,
            continuation: Option<ExactGpuAuthorityAllowedContinuationV2>,
        ) -> i32,
    >,
}

// The table contains immutable function pointers and an intentionally null
// context; publishing its process-lifetime address is thread-safe.
unsafe impl Sync for ExactGpuAuthoritySessionApiV2 {}

static GPU_AUTHORITY_API_V2: ExactGpuAuthoritySessionApiV2 = ExactGpuAuthoritySessionApiV2 {
    struct_size: std::mem::size_of::<ExactGpuAuthoritySessionApiV2>() as u32,
    abi_version: GPU_SERVICE_ABI_V2,
    authority_context: std::ptr::null_mut(),
    evaluate: Some(evaluate_gpu_authority_session_v2),
    retire: Some(retire_gpu_authority_session_v2),
    evaluate_batch_and_then: Some(evaluate_gpu_authority_batch_and_then_v2),
};

pub(crate) fn authority_session_api_v2() -> &'static ExactGpuAuthoritySessionApiV2 {
    &GPU_AUTHORITY_API_V2
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GpuAuthorityCarrierFacts {
    pub operation_id: u32,
    pub topology_id: u32,
    pub realm: GpuRealmIdentityV2,
    pub account: GpuAccountIdentityV2,
    pub ingress_device: GpuDeviceIdentityV2,
    pub provider_generation: u64,
    pub operation_instance_id: u64,
    pub promise_id: u64,
    pub captured_scope_id: u64,
    pub adapter_ordinal: u64,
    pub device_ingress_ordinal: u64,
    pub queue_ingress_ordinal: u64,
    pub authority_context_digest: [u8; 32],
    pub receiver: GpuObjectRefV2,
    pub target: GpuObjectRefV2,
}

impl GpuAuthorityCarrierFacts {
    fn matches_ffi(&self, facts: &ExactGpuAuthoritySessionFactsV2) -> bool {
        facts.struct_size == std::mem::size_of::<ExactGpuAuthoritySessionFactsV2>() as u32
            && facts.abi_version == GPU_SERVICE_ABI_V2
            && facts.operation_id == self.operation_id
            && facts.topology_id == self.topology_id
            && facts.realm == self.realm
            && facts.account == self.account
            && facts.ingress_device == self.ingress_device
            && facts.provider_generation == self.provider_generation
            && facts.operation_instance_id == self.operation_instance_id
            && facts.promise_id == self.promise_id
            && facts.captured_scope_id == self.captured_scope_id
            && facts.adapter_ordinal == self.adapter_ordinal
            && facts.device_ingress_ordinal == self.device_ingress_ordinal
            && facts.queue_ingress_ordinal == self.queue_ingress_ordinal
            && facts.authority_context_digest == self.authority_context_digest
            && facts.receiver == self.receiver
            && facts.target == self.target
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationAuthorityKind {
    TypedPositive,
    StructuralAuthorityReducing,
    StructuralControlPlane,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeOperation {
    operation_name: String,
    wire_id: u32,
    edge_id: String,
    private_target_cell_id: String,
    authority_kind: OperationAuthorityKind,
    receiver_kind: u32,
    target_kind: u32,
    promise_required: bool,
}

#[derive(Clone, Debug)]
struct RuntimeRegistry {
    provider: ProviderIdentity,
    operations: BTreeMap<u32, RuntimeOperation>,
    presentation_authority: RuntimePresentationAuthority,
    operation_count: usize,
    positive_operation_names: Vec<String>,
    private_target_cells: BTreeMap<String, TargetCellDisposition>,
    raw_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
struct RuntimePresentationAuthority {
    capture_operation_id: u32,
    branches: BTreeMap<String, RuntimeOperation>,
}

/// The complete private authority projection admitted only by Exact's named
/// experimental product constructor. The public target-cell and advertisement
/// registries remain separate and unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExperimentalWebGpuPre1AArming {
    pub operation_count: usize,
    pub positive_selectors: Vec<AuthoritySelector>,
    pub private_target_cells: BTreeMap<String, TargetCellDisposition>,
}

#[derive(Clone, Debug)]
struct ProviderIdentity {
    profile_id: String,
    profile_digest: [u8; 32],
    webgpu_c_vocabulary_digest: [u8; 32],
    operation_set_digest: [u8; 32],
    semantic_program_digest: [u8; 32],
    runtime_routing_digest: [u8; 32],
    sorted_operation_ids: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryDocument {
    webgpu_operation_registry_schema: String,
    profile: String,
    webgpu_profile_id: String,
    webgpu_scope_id: String,
    status: String,
    source: RegistrySource,
    provider_identity: RegistryProviderIdentity,
    public_boundary: RegistryPublicBoundary,
    bridge_edges: BTreeMap<String, String>,
    operation_count: usize,
    operations: Vec<RegistryOperation>,
    presentation_authority: RegistryPresentationAuthority,
    private_target_cell_count: usize,
    private_target_cells: Vec<RegistryPrivateCell>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistrySource {
    production_plan_path: String,
    production_plan_raw_content_sha256: String,
    wrapper_authority_path: String,
    wrapper_authority_raw_content_sha256: String,
    authenticated_digests: RegistryAuthenticatedDigests,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryAuthenticatedDigests {
    operation_set: String,
    semantic_program_set: String,
    runtime_routing: String,
    webgpu_c_vocabulary: String,
    projection: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryProviderIdentity {
    abi_version: u32,
    topology_id: u32,
    profile_id: String,
    profile_digest: String,
    webgpu_c_vocabulary_digest: String,
    operation_set_digest: String,
    semantic_program_digest: String,
    runtime_routing_digest: String,
    sorted_operation_ids: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryPublicBoundary {
    navigator_gpu: String,
    embedded_executable_web_gpu_codecs: String,
    native_factory: String,
    wp1_target_advertisements: String,
    platform_support_claim: String,
    positive_grant_issuer: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryAuthoritySession {
    decision_kind: String,
    #[serde(default)]
    action: Option<String>,
    stages: Vec<String>,
    target_cell_disposition: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryOperation {
    operation_id: String,
    wire_id: u32,
    edge_id: String,
    edge_classification: String,
    dispatch_class: String,
    logical_execution_kind: String,
    provider_submission: String,
    receiver_handle_kind: Option<String>,
    wrapper_allocated_target_handle_kind: Option<String>,
    operation_instance_identity: String,
    promise_identity: String,
    private_target_cell_id: String,
    authority_session: Option<RegistryAuthoritySession>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryPresentationAuthority {
    schema: String,
    capture_operation_id: String,
    branches: Vec<RegistryPresentationBranch>,
    phase_programs: Vec<RegistryPresentationPhaseProgram>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryPresentationBranch {
    id: String,
    operation_id: String,
    edge_id: String,
    private_target_cell_id: String,
    action: String,
    stages: Vec<String>,
    target_cell_disposition: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryPresentationPhaseProgram {
    phase: String,
    decisions: Vec<RegistryPresentationPhaseDecision>,
    continuation_after: Option<RegistryPresentationPhaseKey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryPresentationPhaseDecision {
    branch: String,
    stage: String,
    invocation: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryPresentationPhaseKey {
    branch: String,
    stage: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryPrivateCell {
    id: String,
    edge_id: String,
    target: RegistryPrivateTarget,
    support_disposition: String,
    capsec_disposition: String,
    implementation_branch_ids: Vec<String>,
    provider_bridge_edge_id: Option<String>,
    positive_authority: String,
    authority_session: Option<RegistryAuthoritySession>,
    public_install_disposition: String,
    platform_support_claim: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryPrivateTarget {
    kind: String,
    id: String,
}

fn parse_hex_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        output[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(output)
}

fn digest_bytes(value: &Digest) -> Option<[u8; 32]> {
    let encoded = value.as_str().strip_prefix("sha256-")?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    decoded.try_into().ok()
}

fn object_kind(name: &str) -> Option<u32> {
    Some(match name {
        "GPU" => 1,
        "GPUAdapter" => 2,
        "GPUDevice" => 3,
        "GPUQueue" => 4,
        "GPUBuffer" => 5,
        "GPUTexture" => 6,
        "GPUTextureView" => 7,
        "GPUSampler" => 8,
        "GPUBindGroupLayout" => 9,
        "GPUBindGroup" => 10,
        "GPUPipelineLayout" => 11,
        "GPUShaderModule" => 12,
        "GPUComputePipeline" => 13,
        "GPURenderPipeline" => 14,
        "GPUCommandEncoder" => 15,
        "GPUComputePassEncoder" => 16,
        "GPURenderPassEncoder" => 17,
        "GPURenderBundleEncoder" => 18,
        "GPURenderBundle" => 19,
        "GPUCommandBuffer" => 20,
        "GPUQuerySet" => 21,
        "GPUCanvasContext" => 22,
        _ => return None,
    })
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn non_session_operation_matches_registry_semantics(
    operation: &RegistryOperation,
    cell: &RegistryPrivateCell,
) -> bool {
    if operation.provider_submission != "none"
        || cell.authority_session.is_some()
        || cell.provider_bridge_edge_id.is_some()
    {
        return false;
    }
    match operation.dispatch_class.as_str() {
        "wrapper-local" | "wrapper-property-read" => {
            operation.logical_execution_kind == "wrapper-local"
                && operation.edge_classification == "non-capability"
                && operation.operation_instance_identity == "not-carried-wrapper-only"
                && operation.promise_identity == "not-carried-wrapper-only"
                && cell.capsec_disposition == "non-capability"
                && cell.positive_authority == "not-applicable-wrapper-local"
        }
        "wrapper-recording" => {
            operation.logical_execution_kind == "wrapper-recording"
                && operation.edge_classification == "non-capability"
                && operation.operation_instance_identity
                    == "wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record"
                && operation.promise_identity == "zero-non-applicable-sealed-local-timeline-record"
                && cell.capsec_disposition == "non-capability"
                && cell.positive_authority == "not-applicable-wrapper-recording"
        }
        "wrapper-local-deferred-service" => {
            operation.logical_execution_kind == "wrapper-local-deferred-service"
                && operation.edge_classification == "closed"
                && operation.operation_instance_identity
                    == "wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record"
                && operation.promise_identity == "zero-non-applicable-sealed-local-timeline-record"
                && cell.capsec_disposition == "closed"
                && cell.positive_authority == "absent-closed-deferred-service-edge"
        }
        _ => false,
    }
}

fn presentation_phase_programs_match(programs: &[RegistryPresentationPhaseProgram]) -> bool {
    let phase = |index: usize,
                 name: &str,
                 decisions: &[(&str, &str, &str)],
                 continuation_after: Option<(&str, &str)>| {
        let Some(program) = programs.get(index) else {
            return false;
        };
        program.phase == name
            && program.decisions.len() == decisions.len()
            && program
                .decisions
                .iter()
                .zip(decisions)
                .all(|(actual, expected)| {
                    actual.branch == expected.0
                        && actual.stage == expected.1
                        && actual.invocation == expected.2
                })
            && program
                .continuation_after
                .as_ref()
                .map(|key| (key.branch.as_str(), key.stage.as_str()))
                == continuation_after
    };
    programs.len() == 5
        && phase(
            0,
            "entry",
            &[("acquire", "requested", "capture-and-retain")],
            None,
        )
        && phase(
            1,
            "entry-recheck",
            &[("acquire", "requested", "transient-current-call")],
            None,
        )
        && phase(
            2,
            "acquire-admission",
            &[
                ("acquire", "commit", "evaluate"),
                ("present", "requested", "evaluate"),
            ],
            None,
        )
        && phase(
            3,
            "candidate-commit",
            &[
                ("acquire", "repeat", "evaluate-and-then-batch"),
                ("present", "commit", "evaluate-and-then-batch"),
            ],
            Some(("present", "commit")),
        )
        && phase(
            4,
            "handoff-repeat",
            &[("present", "repeat", "evaluate-and-then-batch")],
            Some(("present", "repeat")),
        )
}

fn load_runtime_registry_from_json(source: &str) -> Option<RuntimeRegistry> {
    let raw_sha256: [u8; 32] = Sha256::digest(source.as_bytes()).into();
    let value = capsec_semantics::strict_json::parse_strict(source).ok()?;
    let document: RegistryDocument = serde_json::from_value(value).ok()?;
    if document.webgpu_operation_registry_schema != "ibex/webgpu-private-capsec-operations/2"
        || document.profile != "ibex/capsec/1"
        || document.webgpu_profile_id != document.provider_identity.profile_id
        || document.webgpu_scope_id.is_empty()
        || document.status != "construction-private-source-derived-no-public-install"
        || document.source.production_plan_path
            != "packages/ibex-runtime-js/src/webgpu/production-plan.generated.ts"
        || document.source.wrapper_authority_path
            != "tests/fixtures/webgpu-test-wrapper-authority-v1.json"
        || parse_hex_digest(&document.source.production_plan_raw_content_sha256).is_none()
        || parse_hex_digest(&document.source.wrapper_authority_raw_content_sha256).is_none()
        || parse_hex_digest(&document.source.authenticated_digests.projection).is_none()
        || document.provider_identity.abi_version != GPU_SERVICE_ABI_V2
        || document.provider_identity.topology_id != GPU_TOPOLOGY_ISOLATED_PER_LOGICAL_V2
        || document.public_boundary.navigator_gpu != "absent"
        || document.public_boundary.embedded_executable_web_gpu_codecs != "absent"
        || document.public_boundary.native_factory != "unsupported-null"
        || document.public_boundary.wp1_target_advertisements != "empty"
        || document.public_boundary.platform_support_claim != "none"
        || document.public_boundary.positive_grant_issuer != "absent"
        || document.operation_count == 0
        || document.operation_count > 4096
        || document.operation_count != document.operations.len()
        || document.private_target_cell_count != document.operation_count + 2
        || document.private_target_cell_count != document.private_target_cells.len()
        || document.presentation_authority.schema != "ibex/webgpu-presentation-authority/1"
        || document.presentation_authority.capture_operation_id
            != "GPUCanvasContext.getCurrentTexture"
        || document.presentation_authority.branches.len() != 2
        || !presentation_phase_programs_match(&document.presentation_authority.phase_programs)
        || !is_sorted_unique(&document.provider_identity.sorted_operation_ids)
        || document.provider_identity.sorted_operation_ids.contains(&0)
        || document.bridge_edges.is_empty()
        || document.bridge_edges.values().any(|edge| {
            !crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS.contains(&edge.as_str())
        })
    {
        return None;
    }

    let provider = ProviderIdentity {
        profile_id: document.provider_identity.profile_id,
        profile_digest: parse_hex_digest(&document.provider_identity.profile_digest)?,
        webgpu_c_vocabulary_digest: parse_hex_digest(
            &document.provider_identity.webgpu_c_vocabulary_digest,
        )?,
        operation_set_digest: parse_hex_digest(&document.provider_identity.operation_set_digest)?,
        semantic_program_digest: parse_hex_digest(
            &document.provider_identity.semantic_program_digest,
        )?,
        runtime_routing_digest: parse_hex_digest(
            &document.provider_identity.runtime_routing_digest,
        )?,
        sorted_operation_ids: document.provider_identity.sorted_operation_ids,
    };
    if parse_hex_digest(&document.source.authenticated_digests.webgpu_c_vocabulary)?
        != provider.webgpu_c_vocabulary_digest
        || parse_hex_digest(&document.source.authenticated_digests.operation_set)?
            != provider.operation_set_digest
        || parse_hex_digest(&document.source.authenticated_digests.semantic_program_set)?
            != provider.semantic_program_digest
        || parse_hex_digest(&document.source.authenticated_digests.runtime_routing)?
            != provider.runtime_routing_digest
    {
        return None;
    }

    let cells = document
        .private_target_cells
        .into_iter()
        .map(|cell| (cell.edge_id.clone(), cell))
        .collect::<BTreeMap<_, _>>();
    let unique_cell_ids = cells
        .values()
        .map(|cell| cell.id.as_str())
        .collect::<BTreeSet<_>>();
    let submit_bridge_edge = document.bridge_edges.get("submit")?.clone();
    if cells.len() != document.private_target_cell_count
        || unique_cell_ids.len() != document.private_target_cell_count
    {
        return None;
    }
    let operation_count = document.operation_count;
    let mut operations = BTreeMap::new();
    let mut operation_edges = BTreeSet::new();
    let mut all_wire_ids = Vec::new();
    let mut ordered_names = Vec::new();
    let mut positive_operation_names = Vec::new();
    let mut capture_operation_wire_id = None;
    for operation in document.operations {
        if operation.operation_id == document.presentation_authority.capture_operation_id {
            capture_operation_wire_id = Some(operation.wire_id);
        }
        ordered_names.push(operation.operation_id.clone());
        all_wire_ids.push(operation.wire_id);
        if operation.wire_id == 0
            || !operation_edges.insert(operation.edge_id.clone())
            || !crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS
                .contains(&operation.edge_id.as_str())
        {
            return None;
        }
        let receiver_kind = match operation.receiver_handle_kind.as_deref() {
            Some(name) => object_kind(name)?,
            None => 1,
        };
        let target_kind = match operation.wrapper_allocated_target_handle_kind.as_deref() {
            Some(name) => object_kind(name)?,
            None => 0,
        };
        let Some(session) = operation.authority_session.clone() else {
            let cell = cells.get(&operation.edge_id)?;
            if cell.id != operation.private_target_cell_id
                || cell.public_install_disposition != "absent"
                || cell.platform_support_claim != "none"
                || cell.support_disposition != "supported-construction-private-only"
                || cell.target.kind != "construction-private-runtime-route"
                || cell.target.id != "exact-construction-private-webgpu-v1"
                || !non_session_operation_matches_registry_semantics(&operation, cell)
            {
                return None;
            }
            continue;
        };
        if operation.operation_instance_identity != "required-nonzero-monotonic-per-realm"
            || session.stages != ["requested", "commit", "repeat"]
        {
            return None;
        }
        let authority_kind = match session.decision_kind.as_str() {
            "typed-positive"
                if session.action.as_deref() == Some("gpu:operation")
                    && session.target_cell_disposition == "complete"
                    && operation.edge_classification == "closed"
                    && matches!(
                        operation.provider_submission.as_str(),
                        "semantic-call-promise-completion" | "semantic-call-device-timeline"
                    ) =>
            {
                positive_operation_names.push(operation.operation_id.clone());
                OperationAuthorityKind::TypedPositive
            }
            "structural-authority-reducing"
                if session.action.is_none()
                    && session.target_cell_disposition == "non-capability"
                    && operation.edge_classification == "non-capability"
                    && operation.provider_submission == "semantic-call-authority-reducing" =>
            {
                OperationAuthorityKind::StructuralAuthorityReducing
            }
            "structural-control-plane"
                if session.action.is_none()
                    && session.target_cell_disposition == "non-capability"
                    && operation.edge_classification == "non-capability"
                    && operation.provider_submission == "semantic-service-timeline" =>
            {
                OperationAuthorityKind::StructuralControlPlane
            }
            _ => return None,
        };
        let cell = cells.get(&operation.edge_id)?;
        let expected_cell_disposition = match authority_kind {
            OperationAuthorityKind::TypedPositive => "complete",
            OperationAuthorityKind::StructuralAuthorityReducing
            | OperationAuthorityKind::StructuralControlPlane => "non-capability",
        };
        let expected_positive = match authority_kind {
            OperationAuthorityKind::TypedPositive => "typed-gpu-operation-no-public-grant-issuer",
            OperationAuthorityKind::StructuralAuthorityReducing => {
                "not-applicable-authority-reducing"
            }
            OperationAuthorityKind::StructuralControlPlane => "not-applicable-control-plane",
        };
        if cell.id != operation.private_target_cell_id
            || cell.authority_session.as_ref() != Some(&session)
            || cell.capsec_disposition != expected_cell_disposition
            || cell.positive_authority != expected_positive
            || cell.target.kind != "construction-private-runtime-route"
            || cell.target.id != "exact-construction-private-webgpu-v1"
            || cell.support_disposition != "supported-construction-private-only"
            || cell.public_install_disposition != "absent"
            || cell.platform_support_claim != "none"
            || cell.implementation_branch_ids.len() != 1
            || (matches!(
                authority_kind,
                OperationAuthorityKind::TypedPositive
                    | OperationAuthorityKind::StructuralAuthorityReducing
            ) && cell.provider_bridge_edge_id.as_ref() != Some(&submit_bridge_edge))
            || (authority_kind == OperationAuthorityKind::StructuralControlPlane
                && cell.provider_bridge_edge_id.is_some())
            || operation.dispatch_class.is_empty()
            || operation.logical_execution_kind.is_empty()
        {
            return None;
        }
        let promise_required = match operation.promise_identity.as_str() {
            "required-nonzero-distinct-from-operation-instance" => true,
            "zero-non-applicable" => false,
            _ => return None,
        };
        let runtime_operation = RuntimeOperation {
            operation_name: operation.operation_id,
            wire_id: operation.wire_id,
            edge_id: operation.edge_id,
            private_target_cell_id: operation.private_target_cell_id,
            authority_kind,
            receiver_kind,
            target_kind,
            promise_required,
        };
        if operations
            .insert(runtime_operation.wire_id, runtime_operation)
            .is_some()
        {
            return None;
        }
    }
    let capture_operation_id = capture_operation_wire_id?;
    let mut presentation_branches = BTreeMap::new();
    let mut ordered_presentation_branch_ids = Vec::new();
    for branch in document.presentation_authority.branches {
        ordered_presentation_branch_ids.push(branch.id.clone());
        if !matches!(branch.id.as_str(), "acquire" | "present")
            || branch.operation_id != format!("navigator.gpu.canvas.{}", branch.id)
            || branch.action != "gpu:operation"
            || branch.stages != ["requested", "commit", "repeat"]
            || branch.target_cell_disposition != "complete"
            || !operation_edges.insert(branch.edge_id.clone())
            || !crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS
                .contains(&branch.edge_id.as_str())
        {
            return None;
        }
        let cell = cells.get(&branch.edge_id)?;
        let expected_session = RegistryAuthoritySession {
            decision_kind: "typed-positive".to_owned(),
            action: Some("gpu:operation".to_owned()),
            stages: vec![
                "requested".to_owned(),
                "commit".to_owned(),
                "repeat".to_owned(),
            ],
            target_cell_disposition: "complete".to_owned(),
        };
        if cell.id != branch.private_target_cell_id
            || cell.authority_session.as_ref() != Some(&expected_session)
            || cell.capsec_disposition != "complete"
            || cell.positive_authority != "typed-gpu-presentation-operation-no-public-grant-issuer"
            || cell.target.kind != "construction-private-runtime-route"
            || cell.target.id != "exact-construction-private-webgpu-v1"
            || cell.support_disposition != "supported-construction-private-only"
            || cell.public_install_disposition != "absent"
            || cell.platform_support_claim != "none"
            || cell.implementation_branch_ids.len() != 1
            || cell.provider_bridge_edge_id.as_ref() != Some(&submit_bridge_edge)
        {
            return None;
        }
        positive_operation_names.push(branch.operation_id.clone());
        let runtime_operation = RuntimeOperation {
            operation_name: branch.operation_id,
            wire_id: capture_operation_id,
            edge_id: branch.edge_id,
            private_target_cell_id: branch.private_target_cell_id,
            authority_kind: OperationAuthorityKind::TypedPositive,
            receiver_kind: object_kind("GPUCanvasContext")?,
            target_kind: object_kind("GPUTexture")?,
            promise_required: false,
        };
        if presentation_branches
            .insert(branch.id, runtime_operation)
            .is_some()
        {
            return None;
        }
    }
    positive_operation_names.sort();
    if operation_edges.len() != cells.len()
        || !operation_edges.iter().eq(cells.keys())
        || !is_sorted_unique(&ordered_names)
        || ordered_presentation_branch_ids != ["acquire", "present"]
        || !is_sorted_unique(&positive_operation_names)
        || {
            all_wire_ids.sort_unstable();
            all_wire_ids != provider.sorted_operation_ids
        }
    {
        return None;
    }
    let private_target_cells = cells
        .into_iter()
        .map(|(edge_id, cell)| {
            let disposition = match cell.capsec_disposition.as_str() {
                "complete" | "non-capability" => TargetCellDisposition::Complete,
                "closed" => TargetCellDisposition::Closed,
                _ => return None,
            };
            Some((edge_id, disposition))
        })
        .collect::<Option<BTreeMap<_, _>>>()?;
    Some(RuntimeRegistry {
        provider,
        operations,
        presentation_authority: RuntimePresentationAuthority {
            capture_operation_id,
            branches: presentation_branches,
        },
        operation_count,
        positive_operation_names,
        private_target_cells,
        raw_sha256,
    })
}

fn load_runtime_registry() -> Option<RuntimeRegistry> {
    load_runtime_registry_from_json(
        crate::capsec_registry_generated::CAPSEC_WEBGPU_PRIVATE_OPERATION_REGISTRY_JSON,
    )
}

fn runtime_registry() -> Option<&'static RuntimeRegistry> {
    static REGISTRY: OnceLock<Option<RuntimeRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(load_runtime_registry).as_ref()
}

pub(crate) fn provider_binding_matches_source_registry(
    binding: &capsec_semantics::arming::ExactGpuProviderBinding,
) -> bool {
    let Some(registry) = runtime_registry() else {
        return false;
    };
    binding.abi_version == GPU_SERVICE_ABI_V2
        && binding.topology == "isolated-per-logical-v1"
        && binding.profile_id == registry.provider.profile_id
        && digest_bytes(&binding.profile_digest) == Some(registry.provider.profile_digest)
        && digest_bytes(&binding.webgpu_c_vocabulary_digest)
            == Some(registry.provider.webgpu_c_vocabulary_digest)
        && digest_bytes(&binding.operation_set_digest)
            == Some(registry.provider.operation_set_digest)
        && digest_bytes(&binding.semantic_program_digest)
            == Some(registry.provider.semantic_program_digest)
        && binding
            .runtime_routing_digest
            .as_ref()
            .and_then(digest_bytes)
            == Some(registry.provider.runtime_routing_digest)
        && binding.operation_ids == registry.provider.sorted_operation_ids
}

/// Derive the exact private cells and positive selectors for the named Exact
/// Pre-1A product mode. No caller supplies operation names, selectors, or
/// cells. The raw checked-registry pin makes a future source-set change an
/// explicit code-review event instead of silently widening this experiment.
pub(crate) fn experimental_webgpu_pre1a_arming(
    binding: &capsec_semantics::arming::ExactGpuProviderBinding,
) -> Option<ExperimentalWebGpuPre1AArming> {
    if !cfg!(feature = "webgpu-binding") || !provider_binding_matches_source_registry(binding) {
        return None;
    }
    let registry = runtime_registry()?;
    if registry.operation_count != EXPERIMENTAL_WEBGPU_PRE1A_OPERATION_COUNT
        || registry.positive_operation_names.len()
            != EXPERIMENTAL_WEBGPU_PRE1A_POSITIVE_SELECTOR_COUNT
        || registry.private_target_cells.len()
            != EXPERIMENTAL_WEBGPU_PRE1A_PRIVATE_TARGET_CELL_COUNT
        || parse_hex_digest(EXPERIMENTAL_WEBGPU_PRE1A_REGISTRY_RAW_SHA256)? != registry.raw_sha256
    {
        return None;
    }
    let runtime_routing_digest = binding.runtime_routing_digest.clone()?;
    let positive_selectors = registry
        .positive_operation_names
        .iter()
        .map(|operation_id| {
            Some(AuthoritySelector {
                action: ActionId::new("gpu:operation").ok()?,
                resource: SelectorResource::GpuOperation {
                    profile_id: NonEmptyString::new(binding.profile_id.clone()).ok()?,
                    profile_digest: binding.profile_digest.clone(),
                    webgpu_c_vocabulary_digest: binding.webgpu_c_vocabulary_digest.clone(),
                    operation_set_digest: binding.operation_set_digest.clone(),
                    semantic_program_digest: binding.semantic_program_digest.clone(),
                    runtime_routing_digest: runtime_routing_digest.clone(),
                    operation_id: NonEmptyString::new(operation_id.clone()).ok()?,
                },
            })
        })
        .collect::<Option<Vec<_>>>()?;
    if !is_sorted_unique(&positive_selectors) {
        return None;
    }
    Some(ExperimentalWebGpuPre1AArming {
        operation_count: registry.operation_count,
        positive_selectors,
        private_target_cells: registry.private_target_cells.clone(),
    })
}

fn digest_is_nonzero(value: &[u8; 32]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn device_is_absent(device: &GpuDeviceIdentityV2) -> bool {
    *device == GpuDeviceIdentityV2::default()
}

fn device_is_valid(device: &GpuDeviceIdentityV2) -> bool {
    device_is_absent(device)
        || (device.logical_device_id != 0
            && device.logical_device_generation != 0
            && device.provider_generation != 0)
}

fn object_is_absent(object: &GpuObjectRefV2) -> bool {
    *object == GpuObjectRefV2::default()
}

fn object_is_valid(object: &GpuObjectRefV2, allow_absent: bool) -> bool {
    (allow_absent && object_is_absent(object))
        || ((1..=22).contains(&object.kind)
            && object.flags == 0
            && object.object_id != 0
            && object.object_generation != 0)
}

fn carrier_matches_operation(
    facts: &GpuAuthorityCarrierFacts,
    operation: &RuntimeOperation,
) -> bool {
    facts.operation_id == operation.wire_id
        && facts.topology_id == GPU_TOPOLOGY_ISOLATED_PER_LOGICAL_V2
        && facts.realm.runtime.runtime_address != 0
        && facts.realm.runtime.runtime_nonce != 0
        && facts.realm.realm_id != 0
        && facts.realm.realm_generation != 0
        && facts.account.account_id != 0
        && facts.account.account_generation != 0
        && digest_is_nonzero(&facts.account.authority_digest)
        && device_is_valid(&facts.ingress_device)
        && (device_is_absent(&facts.ingress_device)
            || facts.provider_generation == facts.ingress_device.provider_generation)
        && facts.operation_instance_id != 0
        && ((operation.promise_required && facts.promise_id != 0)
            || (!operation.promise_required && facts.promise_id == 0))
        && digest_is_nonzero(&facts.authority_context_digest)
        && object_is_valid(&facts.receiver, false)
        && facts.receiver.kind == operation.receiver_kind
        && object_is_valid(&facts.target, true)
        && facts.target.kind == operation.target_kind
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GpuAuthorityAttribution {
    pub context_kind: u32,
    pub actor: Principal,
    pub effect_owner: Principal,
    pub scheduler: Option<Principal>,
    pub constrained_principals: Vec<Principal>,
    pub policy_generation: u64,
    pub negative_generation: u64,
    pub dynamic_generation: u64,
    pub handle_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionStage {
    Captured,
    Requested,
    Commit,
    Repeat,
    EvaluatingAndThen,
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PresentationAuthorityBranch {
    Acquire,
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PresentationAuthorityMembership {
    context_token: u64,
    branch: PresentationAuthorityBranch,
    peer_session_id: u64,
}

#[derive(Clone)]
struct GpuAuthoritySession {
    context_id: u64,
    host: Arc<Host>,
    operation: RuntimeOperation,
    facts: GpuAuthorityCarrierFacts,
    attribution: GpuAuthorityAttribution,
    presented_handles: Option<Vec<ExactGpuAuthorityPresentedHandleV2>>,
    presentation: Option<PresentationAuthorityMembership>,
    stage: SessionStage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapturedPresentationAuthorityV2 {
    pub acquire_session_id: u64,
    pub present_session_id: u64,
}

#[derive(Default)]
struct GpuAuthoritySessionStore {
    sessions: HashMap<u64, GpuAuthoritySession>,
}

impl GpuAuthoritySessionStore {
    fn fresh_id(&self, excluded: &[u64]) -> Option<u64> {
        for _ in 0..32 {
            let mut bytes = [0u8; 8];
            getrandom::getrandom(&mut bytes).ok()?;
            let id = u64::from_ne_bytes(bytes);
            if id == 0
                || id == u64::MAX
                || excluded.contains(&id)
                || self.sessions.contains_key(&id)
            {
                continue;
            }
            return Some(id);
        }
        None
    }

    fn insert(&mut self, session: GpuAuthoritySession) -> Option<u64> {
        if self.sessions.len() >= MAX_GPU_AUTHORITY_SESSIONS {
            return None;
        }
        let id = self.fresh_id(&[])?;
        self.sessions.insert(id, session);
        Some(id)
    }

    fn insert_presentation_pair(
        &mut self,
        mut acquire: GpuAuthoritySession,
        mut present: GpuAuthoritySession,
    ) -> Option<CapturedPresentationAuthorityV2> {
        if self.sessions.len() > MAX_GPU_AUTHORITY_SESSIONS.saturating_sub(2) {
            return None;
        }
        let acquire_session_id = self.fresh_id(&[])?;
        let present_session_id = self.fresh_id(&[acquire_session_id])?;
        let context_token = self.fresh_id(&[acquire_session_id, present_session_id])?;
        acquire.presentation = Some(PresentationAuthorityMembership {
            context_token,
            branch: PresentationAuthorityBranch::Acquire,
            peer_session_id: present_session_id,
        });
        present.presentation = Some(PresentationAuthorityMembership {
            context_token,
            branch: PresentationAuthorityBranch::Present,
            peer_session_id: acquire_session_id,
        });
        self.sessions.insert(acquire_session_id, acquire);
        self.sessions.insert(present_session_id, present);
        Some(CapturedPresentationAuthorityV2 {
            acquire_session_id,
            present_session_id,
        })
    }
}

fn session_store() -> &'static Mutex<GpuAuthoritySessionStore> {
    static STORE: OnceLock<Mutex<GpuAuthoritySessionStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(GpuAuthoritySessionStore::default()))
}

#[cfg(test)]
fn presentation_recheck_reservation_hook() -> &'static Mutex<Option<Arc<std::sync::Barrier>>> {
    static HOOK: OnceLock<Mutex<Option<Arc<std::sync::Barrier>>>> = OnceLock::new();
    HOOK.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn pause_after_presentation_recheck_reservation() {
    let barrier = presentation_recheck_reservation_hook()
        .lock()
        .ok()
        .and_then(|hook| hook.clone());
    if let Some(barrier) = barrier {
        barrier.wait();
        barrier.wait();
    }
}

#[cfg(not(test))]
fn pause_after_presentation_recheck_reservation() {}

fn capture_prerequisites_hold(
    context_id: u64,
    host: &Host,
    attribution: &GpuAuthorityAttribution,
    facts: &GpuAuthorityCarrierFacts,
    operation: &RuntimeOperation,
) -> bool {
    if context_id == 0 || !matches!(attribution.context_kind, 1 | 2) {
        return false;
    }
    let Some(snapshot) = host.armed_snapshot() else {
        return false;
    };
    let Ok(Some(binding)) = snapshot.exact_gpu_provider_binding() else {
        return false;
    };
    if !provider_binding_matches_source_registry(&binding)
        || host.private_gpu_target_cell(&operation.edge_id) != TargetCellDisposition::Complete
        || !carrier_matches_operation(facts, operation)
        || facts.realm.runtime.runtime_nonce == 0
        || attribution.constrained_principals.is_empty()
        || !attribution
            .constrained_principals
            .contains(&attribution.actor)
        || !attribution
            .constrained_principals
            .contains(&attribution.effect_owner)
        || attribution
            .scheduler
            .as_ref()
            .is_some_and(|scheduler| !attribution.constrained_principals.contains(scheduler))
        || canonicalize_principal_set(attribution.constrained_principals.clone()).ok()
            != Some(attribution.constrained_principals.clone())
        || snapshot.generations().policy.get() != attribution.policy_generation
    {
        return false;
    }
    host.typed_generations().is_some_and(|generations| {
        generations.negative.get() == attribution.negative_generation
            && generations.dynamic.get() == attribution.dynamic_generation
            && generations.handle.get() == attribution.handle_generation
    })
}

pub(crate) fn capture_session(
    context_id: u64,
    host: Arc<Host>,
    attribution: GpuAuthorityAttribution,
    facts: GpuAuthorityCarrierFacts,
) -> Option<u64> {
    let registry = runtime_registry()?;
    let operation = registry.operations.get(&facts.operation_id)?.clone();
    if !capture_prerequisites_hold(context_id, &host, &attribution, &facts, &operation) {
        return None;
    }
    let session = GpuAuthoritySession {
        context_id,
        host,
        operation,
        facts: facts.clone(),
        attribution,
        presented_handles: None,
        presentation: None,
        stage: SessionStage::Captured,
    };
    let mut store = session_store().lock().ok()?;
    store.insert(session)
}

pub(crate) fn capture_presentation_authority(
    context_id: u64,
    host: Arc<Host>,
    attribution: GpuAuthorityAttribution,
    facts: GpuAuthorityCarrierFacts,
) -> Option<CapturedPresentationAuthorityV2> {
    let registry = runtime_registry()?;
    if facts.operation_id != registry.presentation_authority.capture_operation_id {
        return None;
    }
    let acquire_operation = registry
        .presentation_authority
        .branches
        .get("acquire")?
        .clone();
    let present_operation = registry
        .presentation_authority
        .branches
        .get("present")?
        .clone();
    if !capture_prerequisites_hold(context_id, &host, &attribution, &facts, &acquire_operation)
        || !capture_prerequisites_hold(context_id, &host, &attribution, &facts, &present_operation)
    {
        return None;
    }
    let presented_handles = canonical_presentation_presented_handles(&facts)?;
    let mut acquire = GpuAuthoritySession {
        context_id,
        host: Arc::clone(&host),
        operation: acquire_operation,
        facts: facts.clone(),
        attribution: attribution.clone(),
        presented_handles: Some(presented_handles.clone()),
        presentation: None,
        stage: SessionStage::Captured,
    };
    if evaluate_session(&mut acquire, Stage::Requested, presented_handles.clone())
        != GPU_AUTHORITY_ALLOWED
    {
        return None;
    }
    let present = GpuAuthoritySession {
        context_id,
        host,
        operation: present_operation,
        facts,
        attribution,
        presented_handles: Some(presented_handles),
        presentation: None,
        stage: SessionStage::Captured,
    };
    session_store()
        .lock()
        .ok()?
        .insert_presentation_pair(acquire, present)
}

fn same_presentation_target(
    retained: &GpuAuthoritySession,
    current: &GpuAuthorityCarrierFacts,
    authority_context_digest: &[u8; 32],
) -> bool {
    // A later same-epoch caller owns a fresh operation identity, ingress
    // ordinal, scope, and caller-context digest. Those transient facts are
    // evaluated independently and never rewrite the retained original pair.
    // This comparison binds only the immutable presentation target plus the
    // retained pair's original digest.
    retained.facts.operation_id == current.operation_id
        && retained.facts.topology_id == current.topology_id
        && retained.facts.realm == current.realm
        && retained.facts.account == current.account
        && retained.facts.ingress_device == current.ingress_device
        && retained.facts.provider_generation == current.provider_generation
        && retained.facts.adapter_ordinal == current.adapter_ordinal
        && retained.facts.queue_ingress_ordinal == current.queue_ingress_ordinal
        && retained.facts.authority_context_digest == *authority_context_digest
        && retained.facts.receiver == current.receiver
        && retained.facts.target == current.target
}

pub(crate) fn recheck_presentation_acquire_entry(
    context_id: u64,
    host: Arc<Host>,
    attribution: GpuAuthorityAttribution,
    facts: GpuAuthorityCarrierFacts,
    retained: CapturedPresentationAuthorityV2,
    retained_authority_context_digest: [u8; 32],
) -> i32 {
    let Some(registry) = runtime_registry() else {
        return GPU_AUTHORITY_INVALID;
    };
    let Some(acquire_operation) = registry
        .presentation_authority
        .branches
        .get("acquire")
        .cloned()
    else {
        return GPU_AUTHORITY_INVALID;
    };
    if facts.operation_id != registry.presentation_authority.capture_operation_id
        || !capture_prerequisites_hold(context_id, &host, &attribution, &facts, &acquire_operation)
    {
        return GPU_AUTHORITY_INVALID;
    }
    let Some(presented_handles) = canonical_presentation_presented_handles(&facts) else {
        return GPU_AUTHORITY_INVALID;
    };
    let reserved_stages = {
        let Ok(mut store) = session_store().lock() else {
            return GPU_AUTHORITY_INVALID;
        };
        let Some((acquire_stage, present_stage)) = (|| {
            let acquire = store.sessions.get(&retained.acquire_session_id)?;
            let present = store.sessions.get(&retained.present_session_id)?;
            let acquire_membership = acquire.presentation?;
            let present_membership = present.presentation?;
            (acquire.context_id == context_id
                && present.context_id == context_id
                && Arc::ptr_eq(&acquire.host, &host)
                && Arc::ptr_eq(&present.host, &host)
                && acquire_membership.branch == PresentationAuthorityBranch::Acquire
                && present_membership.branch == PresentationAuthorityBranch::Present
                && presentation_pair_is_exact(
                    retained.acquire_session_id,
                    acquire,
                    retained.present_session_id,
                    present,
                )
                && !matches!(
                    acquire.stage,
                    SessionStage::Denied | SessionStage::EvaluatingAndThen
                )
                && !matches!(
                    present.stage,
                    SessionStage::Denied | SessionStage::EvaluatingAndThen
                )
                && same_presentation_target(acquire, &facts, &retained_authority_context_digest)
                && acquire.presented_handles.as_ref() == Some(&presented_handles))
            .then_some((acquire.stage, present.stage))
        })() else {
            return GPU_AUTHORITY_INVALID;
        };
        store
            .sessions
            .get_mut(&retained.acquire_session_id)
            .expect("validated acquire branch remains retained")
            .stage = SessionStage::EvaluatingAndThen;
        store
            .sessions
            .get_mut(&retained.present_session_id)
            .expect("validated present branch remains retained")
            .stage = SessionStage::EvaluatingAndThen;
        (acquire_stage, present_stage)
    };
    let mut transient = GpuAuthoritySession {
        context_id,
        host,
        operation: acquire_operation,
        facts: facts.clone(),
        attribution,
        presented_handles: Some(presented_handles.clone()),
        presentation: None,
        stage: SessionStage::Captured,
    };
    pause_after_presentation_recheck_reservation();
    let status = evaluate_session(&mut transient, Stage::Requested, presented_handles);
    let reconciled = session_store().lock().is_ok_and(|mut store| {
        let exact_reserved_pair = {
            let Some(acquire) = store.sessions.get(&retained.acquire_session_id) else {
                return false;
            };
            let Some(present) = store.sessions.get(&retained.present_session_id) else {
                return false;
            };
            presentation_pair_is_exact(
                retained.acquire_session_id,
                acquire,
                retained.present_session_id,
                present,
            ) && acquire.stage == SessionStage::EvaluatingAndThen
                && present.stage == SessionStage::EvaluatingAndThen
                && same_presentation_target(acquire, &facts, &retained_authority_context_digest)
        };
        if !exact_reserved_pair {
            return false;
        }
        store
            .sessions
            .get_mut(&retained.acquire_session_id)
            .expect("reconciled acquire branch remains retained")
            .stage = reserved_stages.0;
        store
            .sessions
            .get_mut(&retained.present_session_id)
            .expect("reconciled present branch remains retained")
            .stage = reserved_stages.1;
        true
    });
    if reconciled {
        status
    } else {
        GPU_AUTHORITY_INVALID
    }
}

pub(crate) fn purge_context(context_id: u64) {
    let Ok(mut store) = session_store().lock() else {
        return;
    };
    store
        .sessions
        .retain(|_, session| session.context_id != context_id);
}

pub(crate) fn requested_or_later(context_id: u64, session_id: u64) -> bool {
    session_store().lock().is_ok_and(|store| {
        store.sessions.get(&session_id).is_some_and(|session| {
            session.context_id == context_id
                && matches!(
                    session.stage,
                    SessionStage::Requested
                        | SessionStage::Commit
                        | SessionStage::Repeat
                        | SessionStage::EvaluatingAndThen
                )
        })
    })
}

pub(crate) fn force_retire(context_id: u64, session_id: u64) -> bool {
    let Ok(mut store) = session_store().lock() else {
        return false;
    };
    let Some(session) = store.sessions.get(&session_id) else {
        return false;
    };
    if session.context_id != context_id {
        return false;
    }
    let Some(peer_session_id) = retire_peer_if_available(&store, session_id) else {
        return false;
    };
    store.sessions.remove(&session_id);
    if let Some(peer_session_id) = peer_session_id {
        store.sessions.remove(&peer_session_id);
    }
    true
}

pub(crate) fn retire_presentation_authority(
    context_id: u64,
    retained: CapturedPresentationAuthorityV2,
    authority_context_digest: [u8; 32],
) -> i32 {
    let Ok(mut store) = session_store().lock() else {
        return GPU_AUTHORITY_INVALID;
    };
    let (acquire, present) = match (
        store.sessions.get(&retained.acquire_session_id),
        store.sessions.get(&retained.present_session_id),
    ) {
        (None, None) => return GPU_AUTHORITY_STALE,
        (Some(acquire), Some(present)) => (acquire, present),
        _ => return GPU_AUTHORITY_INVALID,
    };
    if acquire.context_id != context_id
        || present.context_id != context_id
        || acquire.facts.authority_context_digest != authority_context_digest
        || present.facts.authority_context_digest != authority_context_digest
        || !presentation_pair_is_exact(
            retained.acquire_session_id,
            acquire,
            retained.present_session_id,
            present,
        )
        || acquire
            .presentation
            .is_none_or(|membership| membership.branch != PresentationAuthorityBranch::Acquire)
        || present
            .presentation
            .is_none_or(|membership| membership.branch != PresentationAuthorityBranch::Present)
    {
        return GPU_AUTHORITY_INVALID;
    }
    if acquire.stage == SessionStage::EvaluatingAndThen
        || present.stage == SessionStage::EvaluatingAndThen
    {
        return GPU_AUTHORITY_DENIED;
    }
    store.sessions.remove(&retained.acquire_session_id);
    store.sessions.remove(&retained.present_session_id);
    GPU_AUTHORITY_ALLOWED
}

fn authority_generations_are_current(session: &GpuAuthoritySession) -> bool {
    let Some(snapshot) = session.host.armed_snapshot() else {
        return false;
    };
    let Some(generations) = session.host.typed_generations() else {
        return false;
    };
    snapshot.generations().policy.get() == session.attribution.policy_generation
        && generations.negative.get() == session.attribution.negative_generation
        && generations.dynamic.get() == session.attribution.dynamic_generation
        && generations.handle.get() == session.attribution.handle_generation
}

fn captured_generation_set(
    session: &GpuAuthoritySession,
) -> Option<capsec_semantics::cache::GenerationSet> {
    Some(capsec_semantics::cache::GenerationSet {
        negative: capsec_semantics::model::Generation::new(session.attribution.negative_generation)
            .ok()?,
        dynamic: capsec_semantics::model::Generation::new(session.attribution.dynamic_generation)
            .ok()?,
        handle: capsec_semantics::model::Generation::new(session.attribution.handle_generation)
            .ok()?,
    })
}

fn presented_handle_key(handle: &ExactGpuAuthorityPresentedHandleV2) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&handle.account.account_id.to_le_bytes());
    key.extend_from_slice(&handle.account.account_generation.to_le_bytes());
    key.extend_from_slice(&handle.account.authority_digest);
    key.extend_from_slice(&handle.device.logical_device_id.to_le_bytes());
    key.extend_from_slice(&handle.device.logical_device_generation.to_le_bytes());
    key.extend_from_slice(&handle.device.provider_generation.to_le_bytes());
    key.extend_from_slice(&handle.object.kind.to_le_bytes());
    key.extend_from_slice(&handle.object.flags.to_le_bytes());
    key.extend_from_slice(&handle.object.object_id.to_le_bytes());
    key.extend_from_slice(&handle.object.object_generation.to_le_bytes());
    key
}

fn canonical_presentation_presented_handles(
    facts: &GpuAuthorityCarrierFacts,
) -> Option<Vec<ExactGpuAuthorityPresentedHandleV2>> {
    if object_is_absent(&facts.receiver)
        || object_is_absent(&facts.target)
        || device_is_absent(&facts.ingress_device)
    {
        return None;
    }
    let mut handles = vec![
        ExactGpuAuthorityPresentedHandleV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthorityPresentedHandleV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            account: facts.account,
            device: facts.ingress_device,
            object: facts.receiver,
        },
        ExactGpuAuthorityPresentedHandleV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthorityPresentedHandleV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            account: facts.account,
            device: facts.ingress_device,
            object: facts.target,
        },
    ];
    handles.sort_by_key(presented_handle_key);
    if handles[0] == handles[1] {
        return None;
    }
    Some(handles)
}

fn validate_presented_handles(
    session: &GpuAuthoritySession,
    handles: &[ExactGpuAuthorityPresentedHandleV2],
) -> bool {
    if handles.len() > MAX_GPU_PRESENTED_HANDLES {
        return false;
    }
    let mut previous: Option<Vec<u8>> = None;
    for handle in handles {
        if handle.struct_size != std::mem::size_of::<ExactGpuAuthorityPresentedHandleV2>() as u32
            || handle.abi_version != GPU_SERVICE_ABI_V2
            || handle.account != session.facts.account
            || !device_is_valid(&handle.device)
            || (!device_is_absent(&session.facts.ingress_device)
                && handle.device != session.facts.ingress_device)
            || (device_is_absent(&session.facts.ingress_device)
                && !device_is_absent(&handle.device)
                && (session.facts.provider_generation == 0
                    || handle.device.provider_generation != session.facts.provider_generation))
            || !object_is_valid(&handle.object, false)
        {
            return false;
        }
        let key = presented_handle_key(handle);
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return false;
        }
        previous = Some(key);
    }
    true
}

fn hash_identity(domain: &[u8], fields: &[&[u8]]) -> Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_le_bytes());
        digest.update(field);
    }
    let raw: [u8; 32] = digest.finalize().into();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    Digest::new(format!("sha256-{encoded}")).expect("SHA-256 is a valid semantic digest")
}

fn realm_digest(realm: &GpuRealmIdentityV2) -> Digest {
    hash_identity(
        b"ibex:exact-gpu-realm-identity:v2\0",
        &[
            &realm.runtime.runtime_address.to_le_bytes(),
            &realm.runtime.runtime_nonce.to_le_bytes(),
            &realm.realm_id.to_le_bytes(),
            &realm.realm_generation.to_le_bytes(),
        ],
    )
}

fn account_digest(realm: &GpuRealmIdentityV2, account: &GpuAccountIdentityV2) -> Digest {
    hash_identity(
        b"ibex:exact-gpu-account-identity:v2\0",
        &[
            &realm.runtime.runtime_address.to_le_bytes(),
            &realm.runtime.runtime_nonce.to_le_bytes(),
            &realm.realm_id.to_le_bytes(),
            &realm.realm_generation.to_le_bytes(),
            &account.account_id.to_le_bytes(),
            &account.account_generation.to_le_bytes(),
            &account.authority_digest,
        ],
    )
}

fn device_digest(
    realm: &GpuRealmIdentityV2,
    account: &GpuAccountIdentityV2,
    device: &GpuDeviceIdentityV2,
) -> Option<Digest> {
    (!device_is_absent(device)).then(|| {
        hash_identity(
            b"ibex:exact-gpu-device-identity:v2\0",
            &[
                &realm.runtime.runtime_address.to_le_bytes(),
                &realm.runtime.runtime_nonce.to_le_bytes(),
                &realm.realm_id.to_le_bytes(),
                &realm.realm_generation.to_le_bytes(),
                &account.account_id.to_le_bytes(),
                &account.account_generation.to_le_bytes(),
                &account.authority_digest,
                &device.logical_device_id.to_le_bytes(),
                &device.logical_device_generation.to_le_bytes(),
                &device.provider_generation.to_le_bytes(),
            ],
        )
    })
}

fn object_digest(
    role: &[u8],
    realm: &GpuRealmIdentityV2,
    account: &GpuAccountIdentityV2,
    device: &GpuDeviceIdentityV2,
    object: &GpuObjectRefV2,
) -> Option<Digest> {
    (!object_is_absent(object)).then(|| {
        hash_identity(
            b"ibex:exact-gpu-owned-object-identity:v2\0",
            &[
                role,
                &realm.runtime.runtime_address.to_le_bytes(),
                &realm.runtime.runtime_nonce.to_le_bytes(),
                &realm.realm_id.to_le_bytes(),
                &realm.realm_generation.to_le_bytes(),
                &account.account_id.to_le_bytes(),
                &account.account_generation.to_le_bytes(),
                &account.authority_digest,
                &device.logical_device_id.to_le_bytes(),
                &device.logical_device_generation.to_le_bytes(),
                &device.provider_generation.to_le_bytes(),
                &object.kind.to_le_bytes(),
                &object.flags.to_le_bytes(),
                &object.object_id.to_le_bytes(),
                &object.object_generation.to_le_bytes(),
            ],
        )
    })
}

fn presented_handle_digests(
    realm: &GpuRealmIdentityV2,
    handles: &[ExactGpuAuthorityPresentedHandleV2],
) -> Option<Vec<Digest>> {
    let mut digests = handles
        .iter()
        .map(|handle| {
            object_digest(
                b"presented-handle",
                realm,
                &handle.account,
                &handle.device,
                &handle.object,
            )
        })
        .collect::<Option<Vec<_>>>()?;
    digests.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    if !is_sorted_unique(&digests) {
        return None;
    }
    Some(digests)
}

fn stage_from_abi(stage: u32) -> Option<Stage> {
    match stage {
        1 => Some(Stage::Requested),
        2 => Some(Stage::Commit),
        3 => Some(Stage::Repeat),
        _ => None,
    }
}

fn stage_transition_is_valid(current: SessionStage, requested: Stage) -> bool {
    matches!(
        (current, requested),
        (SessionStage::Captured, Stage::Requested)
            | (SessionStage::Requested, Stage::Commit)
            | (SessionStage::Commit, Stage::Repeat)
            | (SessionStage::Repeat, Stage::Repeat)
    )
}

fn selector_for_session(session: &GpuAuthoritySession) -> Option<SelectorResource> {
    let snapshot = session.host.armed_snapshot()?;
    let binding = snapshot.exact_gpu_provider_binding().ok()??;
    Some(SelectorResource::GpuOperation {
        profile_id: NonEmptyString::new(binding.profile_id).ok()?,
        profile_digest: binding.profile_digest,
        webgpu_c_vocabulary_digest: binding.webgpu_c_vocabulary_digest,
        operation_set_digest: binding.operation_set_digest,
        semantic_program_digest: binding.semantic_program_digest,
        runtime_routing_digest: binding.runtime_routing_digest?,
        operation_id: NonEmptyString::new(session.operation.operation_name.clone()).ok()?,
    })
}

fn occurrence_for_session(
    session: &GpuAuthoritySession,
    stage: Stage,
    handles: &[ExactGpuAuthorityPresentedHandleV2],
) -> Option<EffectOccurrence> {
    let requested = selector_for_session(session)?;
    Some(EffectOccurrence {
        action: ActionId::new("gpu:operation").ok()?,
        stage,
        actor: session.attribution.actor.clone(),
        effect_owner: session.attribution.effect_owner.clone(),
        constrained_principals: session.attribution.constrained_principals.clone(),
        resource: OccurrenceResource::GpuOperationOccurrence {
            requested: Box::new(requested),
            realm_identity: realm_digest(&session.facts.realm),
            account_identity: account_digest(&session.facts.realm, &session.facts.account),
            device_identity: device_digest(
                &session.facts.realm,
                &session.facts.account,
                &session.facts.ingress_device,
            ),
            receiver_identity: object_digest(
                b"receiver",
                &session.facts.realm,
                &session.facts.account,
                &session.facts.ingress_device,
                &session.facts.receiver,
            )?,
            target_identity: object_digest(
                b"target",
                &session.facts.realm,
                &session.facts.account,
                &session.facts.ingress_device,
                &session.facts.target,
            ),
            presented_handle_identities: presented_handle_digests(&session.facts.realm, handles)?,
        },
    })
}

fn classify_single_typed_evaluation(
    receipt_count: usize,
    sole_receipt_allows: bool,
    continuation_present: bool,
) -> i32 {
    match (receipt_count, sole_receipt_allows, continuation_present) {
        (1, true, true) => GPU_AUTHORITY_ALLOWED,
        (1, false, false) => GPU_AUTHORITY_DENIED,
        _ => GPU_AUTHORITY_INVALID,
    }
}

fn evaluate_session(
    session: &mut GpuAuthoritySession,
    stage: Stage,
    handles: Vec<ExactGpuAuthorityPresentedHandleV2>,
) -> i32 {
    if session.stage == SessionStage::Denied {
        return GPU_AUTHORITY_DENIED;
    }
    if session.stage == SessionStage::EvaluatingAndThen {
        return GPU_AUTHORITY_INVALID;
    }
    if session.operation.authority_kind != OperationAuthorityKind::TypedPositive
        && !authority_generations_are_current(session)
    {
        session.stage = SessionStage::Denied;
        return if session.presentation.is_some() {
            GPU_AUTHORITY_DENIED
        } else {
            GPU_AUTHORITY_STALE
        };
    }
    if !stage_transition_is_valid(session.stage, stage)
        || !validate_presented_handles(session, &handles)
        || session
            .presented_handles
            .as_ref()
            .is_some_and(|bound| bound != &handles)
    {
        session.stage = SessionStage::Denied;
        return GPU_AUTHORITY_INVALID;
    }
    let Some(occurrence) = occurrence_for_session(session, stage, &handles) else {
        session.stage = SessionStage::Denied;
        return GPU_AUTHORITY_INVALID;
    };
    if capsec_semantics::containment::validate_occurrence_stage_facts(&occurrence).is_err() {
        session.stage = SessionStage::Denied;
        return GPU_AUTHORITY_INVALID;
    }

    let allowed = match session.operation.authority_kind {
        OperationAuthorityKind::StructuralAuthorityReducing
        | OperationAuthorityKind::StructuralControlPlane => true,
        OperationAuthorityKind::TypedPositive => {
            let Some((set, gate)) = typed_decision_for_session(session, stage, &handles) else {
                session.stage = SessionStage::Denied;
                return GPU_AUTHORITY_INVALID;
            };
            let Some(expected_generations) = captured_generation_set(session) else {
                session.stage = SessionStage::Denied;
                return GPU_AUTHORITY_INVALID;
            };
            let request = [(&set, std::slice::from_ref(&gate))];
            match session.host.evaluate_typed_decision_batch_and_then(
                &request,
                session.attribution.policy_generation,
                expected_generations,
                || (),
            ) {
                Ok(
                    super::TypedDecisionBatchAndThenResult::StalePolicyGeneration
                    | super::TypedDecisionBatchAndThenResult::StaleAuthorityGenerations,
                ) => {
                    session.stage = SessionStage::Denied;
                    return if session.presentation.is_some() {
                        GPU_AUTHORITY_DENIED
                    } else {
                        GPU_AUTHORITY_STALE
                    };
                }
                Ok(super::TypedDecisionBatchAndThenResult::Evaluated {
                    decisions,
                    continuation_result,
                }) => {
                    let status = classify_single_typed_evaluation(
                        decisions.len(),
                        decisions.first().is_some_and(|decision| {
                            matches!(
                                decision.outcome,
                                DecisionOutcome::Allow
                                    | DecisionOutcome::AllowWithWouldDenyEvidence
                            )
                        }),
                        continuation_result.is_some(),
                    );
                    if status == GPU_AUTHORITY_ALLOWED {
                        true
                    } else if status == GPU_AUTHORITY_DENIED {
                        false
                    } else {
                        session.stage = SessionStage::Denied;
                        return GPU_AUTHORITY_INVALID;
                    }
                }
                Err(_) => {
                    session.stage = SessionStage::Denied;
                    return GPU_AUTHORITY_INVALID;
                }
            }
        }
    };
    if !allowed {
        session.stage = SessionStage::Denied;
        return GPU_AUTHORITY_DENIED;
    }
    if session.presented_handles.is_none() {
        session.presented_handles = Some(handles);
    }
    session.stage = match stage {
        Stage::Requested => SessionStage::Requested,
        Stage::Commit => SessionStage::Commit,
        Stage::Repeat => SessionStage::Repeat,
        _ => unreachable!("stage_from_abi admits only GPU stages"),
    };
    GPU_AUTHORITY_ALLOWED
}

fn typed_decision_for_session(
    session: &GpuAuthoritySession,
    stage: Stage,
    handles: &[ExactGpuAuthorityPresentedHandleV2],
) -> Option<(DecisionSet, EffectGate)> {
    let occurrence = occurrence_for_session(session, stage, handles)?;
    capsec_semantics::containment::validate_occurrence_stage_facts(&occurrence).ok()?;
    let requested = occurrence.resource.requested_selector_resource()?;
    let set = DecisionSet {
        decision_set_schema: DecisionSetSchema::V1,
        operation_id: NonEmptyString::new(format!(
            "gpu-authority-session:{}:{}",
            session.facts.operation_instance_id, session.operation.operation_name
        ))
        .ok()?,
        atomicity_group: StableId::new(format!(
            "{}.authority-session",
            session.operation.private_target_cell_id
        ))
        .ok()?,
        combination: EffectCombination::Conjunction,
        context: DecisionContext {
            stage,
            actor: session.attribution.actor.clone(),
            constrained_principals: session.attribution.constrained_principals.clone(),
            presented_handle_ids: Vec::new(),
        },
        effects: vec![Effect {
            action: ActionId::new("gpu:operation").ok()?,
            effect_owner: session.attribution.effect_owner.clone(),
            resource: OccurrenceResource::GpuOperationOccurrence {
                requested: Box::new(requested),
                realm_identity: realm_digest(&session.facts.realm),
                account_identity: account_digest(&session.facts.realm, &session.facts.account),
                device_identity: device_digest(
                    &session.facts.realm,
                    &session.facts.account,
                    &session.facts.ingress_device,
                ),
                receiver_identity: object_digest(
                    b"receiver",
                    &session.facts.realm,
                    &session.facts.account,
                    &session.facts.ingress_device,
                    &session.facts.receiver,
                )?,
                target_identity: object_digest(
                    b"target",
                    &session.facts.realm,
                    &session.facts.account,
                    &session.facts.ingress_device,
                    &session.facts.target,
                ),
                presented_handle_identities: presented_handle_digests(
                    &session.facts.realm,
                    handles,
                )?,
            },
        }],
    };
    let gate = EffectGate {
        coverage_edge_id: StableId::new(session.operation.edge_id.clone()).ok()?,
        target_cell: session
            .host
            .private_gpu_target_cell(&session.operation.edge_id),
        definition_and_edge_predicates_satisfied: true,
    };
    Some((set, gate))
}

fn presentation_pair_is_exact(
    first_id: u64,
    first: &GpuAuthoritySession,
    second_id: u64,
    second: &GpuAuthoritySession,
) -> bool {
    let (Some(first_membership), Some(second_membership)) =
        (first.presentation, second.presentation)
    else {
        return false;
    };
    first_membership.context_token == second_membership.context_token
        && first_membership.peer_session_id == second_id
        && second_membership.peer_session_id == first_id
        && first_membership.branch != second_membership.branch
        && first.context_id == second.context_id
        && Arc::ptr_eq(&first.host, &second.host)
        && first.facts == second.facts
        && first.attribution == second.attribution
        && first.presented_handles == second.presented_handles
}

fn session_matches_reserved_snapshot(
    current: &GpuAuthoritySession,
    reserved: &GpuAuthoritySession,
) -> bool {
    current.stage == SessionStage::EvaluatingAndThen
        && current.context_id == reserved.context_id
        && Arc::ptr_eq(&current.host, &reserved.host)
        && current.operation == reserved.operation
        && current.facts == reserved.facts
        && current.attribution == reserved.attribution
        && current.presented_handles == reserved.presented_handles
        && current.presentation == reserved.presentation
}

fn retire_peer_if_available(
    store: &GpuAuthoritySessionStore,
    session_id: u64,
) -> Option<Option<u64>> {
    match classify_retire_target(store, session_id) {
        RetireTargetDisposition::Ready(peer_session_id) => Some(peer_session_id),
        RetireTargetDisposition::Busy | RetireTargetDisposition::Invalid => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetireTargetDisposition {
    Ready(Option<u64>),
    Busy,
    Invalid,
}

fn classify_retire_target(
    store: &GpuAuthoritySessionStore,
    session_id: u64,
) -> RetireTargetDisposition {
    let Some(session) = store.sessions.get(&session_id) else {
        return RetireTargetDisposition::Invalid;
    };
    if session.stage == SessionStage::EvaluatingAndThen {
        return RetireTargetDisposition::Busy;
    }
    let Some(membership) = session.presentation else {
        return RetireTargetDisposition::Ready(None);
    };
    let Some(peer) = store.sessions.get(&membership.peer_session_id) else {
        return RetireTargetDisposition::Invalid;
    };
    if peer.stage == SessionStage::EvaluatingAndThen {
        return RetireTargetDisposition::Busy;
    }
    if !presentation_pair_is_exact(session_id, session, membership.peer_session_id, peer) {
        return RetireTargetDisposition::Invalid;
    }
    RetireTargetDisposition::Ready(Some(membership.peer_session_id))
}

fn singular_presentation_transition_is_allowed(
    store: &GpuAuthoritySessionStore,
    session_id: u64,
    stage: Stage,
) -> bool {
    let Some(session) = store.sessions.get(&session_id) else {
        return false;
    };
    let Some(membership) = session.presentation else {
        return true;
    };
    let Some(peer) = store.sessions.get(&membership.peer_session_id) else {
        return false;
    };
    if !presentation_pair_is_exact(session_id, session, membership.peer_session_id, peer)
        || matches!(
            session.stage,
            SessionStage::Denied | SessionStage::EvaluatingAndThen
        )
        || matches!(
            peer.stage,
            SessionStage::Denied | SessionStage::EvaluatingAndThen
        )
    {
        return false;
    }
    match membership.branch {
        PresentationAuthorityBranch::Acquire => {
            stage == Stage::Commit
                && session.stage == SessionStage::Requested
                && peer.stage == SessionStage::Captured
        }
        PresentationAuthorityBranch::Present => {
            stage == Stage::Requested
                && session.stage == SessionStage::Captured
                && peer.stage == SessionStage::Commit
        }
    }
}

unsafe extern "C" fn evaluate_gpu_authority_session_v2(
    authority_context: *mut c_void,
    decision: *const ExactGpuAuthorityDecisionRequestV2,
) -> i32 {
    if !authority_context.is_null() || decision.is_null() {
        return GPU_AUTHORITY_INVALID;
    }
    let decision = unsafe { &*decision };
    if decision.struct_size != std::mem::size_of::<ExactGpuAuthorityDecisionRequestV2>() as u32
        || decision.abi_version != GPU_SERVICE_ABI_V2
        || decision.flags != 0
        || decision.facts.authority_session_id == 0
        || decision.presented_handle_count > MAX_GPU_PRESENTED_HANDLES
        || (decision.presented_handle_count != 0 && decision.presented_handles.is_null())
    {
        return GPU_AUTHORITY_INVALID;
    }
    let Some(stage) = stage_from_abi(decision.stage) else {
        return GPU_AUTHORITY_INVALID;
    };
    let handles = if decision.presented_handle_count == 0 {
        Vec::new()
    } else {
        unsafe {
            std::slice::from_raw_parts(decision.presented_handles, decision.presented_handle_count)
        }
        .to_vec()
    };
    let Ok(mut store) = session_store().lock() else {
        return GPU_AUTHORITY_INVALID;
    };
    if !store
        .sessions
        .contains_key(&decision.facts.authority_session_id)
    {
        return GPU_AUTHORITY_STALE;
    }
    if !singular_presentation_transition_is_allowed(
        &store,
        decision.facts.authority_session_id,
        stage,
    ) {
        return GPU_AUTHORITY_INVALID;
    }
    let Some(session) = store.sessions.get_mut(&decision.facts.authority_session_id) else {
        return GPU_AUTHORITY_STALE;
    };
    if !session.facts.matches_ffi(&decision.facts) {
        let peer_session_id = session
            .presentation
            .map(|membership| membership.peer_session_id);
        session.stage = SessionStage::Denied;
        if let Some(peer_session_id) = peer_session_id {
            if let Some(peer) = store.sessions.get_mut(&peer_session_id) {
                peer.stage = SessionStage::Denied;
            }
        }
        return GPU_AUTHORITY_STALE;
    }
    let peer_session_id = session
        .presentation
        .map(|membership| membership.peer_session_id);
    let status = evaluate_session(session, stage, handles);
    if status != GPU_AUTHORITY_ALLOWED {
        if let Some(peer_session_id) = peer_session_id {
            if let Some(peer) = store.sessions.get_mut(&peer_session_id) {
                peer.stage = SessionStage::Denied;
            }
        }
    }
    status
}

unsafe extern "C" fn evaluate_gpu_authority_batch_and_then_v2(
    authority_context: *mut c_void,
    batch: *const ExactGpuAuthorityDecisionBatchV2,
    continuation_context: *mut c_void,
    continuation: Option<ExactGpuAuthorityAllowedContinuationV2>,
) -> i32 {
    if !authority_context.is_null()
        || batch.is_null()
        || continuation_context.is_null()
        || continuation.is_none()
    {
        return GPU_AUTHORITY_INVALID;
    }
    let batch = unsafe { &*batch };
    if batch.struct_size != std::mem::size_of::<ExactGpuAuthorityDecisionBatchV2>() as u32
        || batch.abi_version != GPU_SERVICE_ABI_V2
        || batch.flags != 0
        || !matches!(batch.phase, 1 | 2)
        || batch.decision_count == 0
        || batch.decision_count > 2
        || batch.decisions.is_null()
    {
        return GPU_AUTHORITY_INVALID;
    }
    let decisions = unsafe { std::slice::from_raw_parts(batch.decisions, batch.decision_count) };
    let expected_stages = match batch.phase {
        1 if decisions.len() == 2 => [Some(Stage::Repeat), Some(Stage::Commit)],
        2 if decisions.len() == 1 => [Some(Stage::Repeat), None],
        _ => return GPU_AUTHORITY_INVALID,
    };
    for (index, decision) in decisions.iter().enumerate() {
        if decision.struct_size != std::mem::size_of::<ExactGpuAuthorityDecisionRequestV2>() as u32
            || decision.abi_version != GPU_SERVICE_ABI_V2
            || decision.flags != 0
            || decision.facts.authority_session_id == 0
            || decision.presented_handle_count != 2
            || decision.presented_handles.is_null()
            || stage_from_abi(decision.stage) != expected_stages[index]
        {
            return GPU_AUTHORITY_INVALID;
        }
    }
    let decision_handles = decisions
        .iter()
        .map(|decision| {
            unsafe {
                std::slice::from_raw_parts(
                    decision.presented_handles,
                    decision.presented_handle_count,
                )
            }
            .to_vec()
        })
        .collect::<Vec<_>>();
    let (evaluations, pair_reservations, expected_policy_generation, expected_generations, host) = {
        let Ok(mut store) = session_store().lock() else {
            return GPU_AUTHORITY_INVALID;
        };
        let session_ids = decisions
            .iter()
            .map(|decision| decision.facts.authority_session_id)
            .collect::<Vec<_>>();
        if !is_sorted_unique(&{
            let mut sorted = session_ids.clone();
            sorted.sort_unstable();
            sorted
        }) {
            return GPU_AUTHORITY_INVALID;
        }
        let Some(first) = store.sessions.get(&session_ids[0]) else {
            return GPU_AUTHORITY_STALE;
        };
        let Some(first_membership) = first.presentation else {
            return GPU_AUTHORITY_INVALID;
        };
        let peer_id = first_membership.peer_session_id;
        let Some(peer) = store.sessions.get(&peer_id) else {
            return GPU_AUTHORITY_STALE;
        };
        if !presentation_pair_is_exact(session_ids[0], first, peer_id, peer) {
            return GPU_AUTHORITY_INVALID;
        }
        let (acquire_id, acquire, present_id, present) = match first_membership.branch {
            PresentationAuthorityBranch::Acquire => (session_ids[0], first, peer_id, peer),
            PresentationAuthorityBranch::Present => (peer_id, peer, session_ids[0], first),
        };
        let exact_phase = match batch.phase {
            1 => {
                session_ids == [acquire_id, present_id]
                    && acquire.stage == SessionStage::Commit
                    && present.stage == SessionStage::Requested
            }
            2 => {
                session_ids == [present_id]
                    && acquire.stage == SessionStage::Repeat
                    && present.stage == SessionStage::Commit
            }
            _ => false,
        };
        if !exact_phase
            || matches!(
                acquire.stage,
                SessionStage::Denied | SessionStage::EvaluatingAndThen
            )
            || matches!(
                present.stage,
                SessionStage::Denied | SessionStage::EvaluatingAndThen
            )
            || decisions.iter().any(|decision| {
                store
                    .sessions
                    .get(&decision.facts.authority_session_id)
                    .is_none_or(|session| !session.facts.matches_ffi(&decision.facts))
            })
        {
            return GPU_AUTHORITY_INVALID;
        }
        let mut evaluations = Vec::with_capacity(decisions.len());
        for ((decision, stage), handles) in decisions
            .iter()
            .zip(expected_stages.into_iter().flatten())
            .zip(decision_handles.iter())
        {
            let session = store
                .sessions
                .get(&decision.facts.authority_session_id)
                .expect("preflight proved the session");
            if !validate_presented_handles(session, handles)
                || session.presented_handles.as_ref() != Some(handles)
            {
                return GPU_AUTHORITY_INVALID;
            }
            evaluations.push((
                decision.facts.authority_session_id,
                session.clone(),
                stage,
                handles.clone(),
            ));
        }
        let Some(expected_generations) = captured_generation_set(&evaluations[0].1) else {
            return GPU_AUTHORITY_INVALID;
        };
        let expected_policy_generation = evaluations[0].1.attribution.policy_generation;
        let host = Arc::clone(&evaluations[0].1.host);
        let pair_reservations = [(acquire_id, acquire.clone()), (present_id, present.clone())];
        for (session_id, _) in &pair_reservations {
            store
                .sessions
                .get_mut(session_id)
                .expect("preflight proved the session")
                .stage = SessionStage::EvaluatingAndThen;
        }
        (
            evaluations,
            pair_reservations,
            expected_policy_generation,
            expected_generations,
            host,
        )
    };
    let Some(continuation) = continuation else {
        return GPU_AUTHORITY_INVALID;
    };
    let mut decision_inputs = Vec::with_capacity(evaluations.len());
    for (_, session, stage, handles) in &evaluations {
        let Some(input) = typed_decision_for_session(session, *stage, handles) else {
            if let Ok(mut store) = session_store().lock() {
                for (session_id, _) in &pair_reservations {
                    if let Some(session) = store.sessions.get_mut(session_id) {
                        if session.stage == SessionStage::EvaluatingAndThen {
                            session.stage = SessionStage::Denied;
                        }
                    }
                }
            }
            return GPU_AUTHORITY_INVALID;
        };
        decision_inputs.push(input);
    }
    let request_refs = decision_inputs
        .iter()
        .map(|(set, gate)| (set, std::slice::from_ref(gate)))
        .collect::<Vec<_>>();
    let mut continuation_ran = false;
    let evaluation = host.evaluate_typed_decision_batch_and_then(
        &request_refs,
        expected_policy_generation,
        expected_generations,
        || {
            continuation_ran = true;
            // SAFETY: Native lends an exact synchronous continuation context.
            // The callback runs exactly once while Host's decision-context read
            // guard excludes revocation writers.
            unsafe { continuation(continuation_context) }
        },
    );
    let status = match evaluation {
        Ok(super::TypedDecisionBatchAndThenResult::StalePolicyGeneration)
        | Ok(super::TypedDecisionBatchAndThenResult::StaleAuthorityGenerations) => {
            GPU_AUTHORITY_DENIED
        }
        Ok(super::TypedDecisionBatchAndThenResult::Evaluated {
            decisions: receipts,
            continuation_result,
        }) if receipts.len() == evaluations.len()
            && receipts.iter().all(|receipt| {
                matches!(
                    receipt.outcome,
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                )
            })
            && continuation_result == Some(GPU_AUTHORITY_ALLOWED) =>
        {
            GPU_AUTHORITY_ALLOWED
        }
        Ok(super::TypedDecisionBatchAndThenResult::Evaluated {
            decisions: receipts,
            continuation_result: None,
        }) if !continuation_ran
            && !receipts.is_empty()
            && receipts.len() <= evaluations.len()
            && receipts
                .iter()
                .take(receipts.len().saturating_sub(1))
                .all(|receipt| {
                    matches!(
                        receipt.outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                    )
                })
            && receipts.last().is_some_and(|receipt| {
                !matches!(
                    receipt.outcome,
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                )
            }) =>
        {
            GPU_AUTHORITY_DENIED
        }
        Ok(super::TypedDecisionBatchAndThenResult::Evaluated { .. }) | Err(_) => {
            GPU_AUTHORITY_INVALID
        }
    };
    let reconciled = session_store().lock().is_ok_and(|mut store| {
        let exact_reserved_rows = pair_reservations.iter().all(|(session_id, reserved)| {
            store
                .sessions
                .get(session_id)
                .is_some_and(|current| session_matches_reserved_snapshot(current, reserved))
        });
        let exact_reserved_pair = exact_reserved_rows
            && store
                .sessions
                .get(&pair_reservations[0].0)
                .is_some_and(|acquire| {
                    store
                        .sessions
                        .get(&pair_reservations[1].0)
                        .is_some_and(|present| {
                            presentation_pair_is_exact(
                                pair_reservations[0].0,
                                acquire,
                                pair_reservations[1].0,
                                present,
                            )
                        })
                });
        if !exact_reserved_pair {
            return false;
        }
        for (session_id, reserved) in &pair_reservations {
            store
                .sessions
                .get_mut(session_id)
                .expect("validated reserved session remains present")
                .stage = if status == GPU_AUTHORITY_ALLOWED {
                evaluations
                    .iter()
                    .find(|(evaluated_id, _, _, _)| evaluated_id == session_id)
                    .map_or(
                        reserved.stage,
                        |(_, _, requested_stage, _)| match requested_stage {
                            Stage::Commit => SessionStage::Commit,
                            Stage::Repeat => SessionStage::Repeat,
                            _ => SessionStage::Denied,
                        },
                    )
            } else {
                SessionStage::Denied
            };
        }
        true
    });
    if reconciled {
        status
    } else {
        GPU_AUTHORITY_INVALID
    }
}

unsafe extern "C" fn retire_gpu_authority_session_v2(
    authority_context: *mut c_void,
    retire: *const ExactGpuAuthorityRetireV2,
) -> i32 {
    if !authority_context.is_null() || retire.is_null() {
        return GPU_AUTHORITY_INVALID;
    }
    let retire = unsafe { &*retire };
    if retire.struct_size != std::mem::size_of::<ExactGpuAuthorityRetireV2>() as u32
        || retire.abi_version != GPU_SERVICE_ABI_V2
        || retire.flags != 0
        || retire.reserved != 0
        || retire.facts.authority_session_id == 0
    {
        return GPU_AUTHORITY_INVALID;
    }
    let Ok(mut store) = session_store().lock() else {
        return GPU_AUTHORITY_INVALID;
    };
    let Some(session) = store.sessions.get(&retire.facts.authority_session_id) else {
        return GPU_AUTHORITY_STALE;
    };
    if !session.facts.matches_ffi(&retire.facts) {
        return GPU_AUTHORITY_INVALID;
    }
    let peer_session_id = match classify_retire_target(&store, retire.facts.authority_session_id) {
        RetireTargetDisposition::Ready(peer_session_id) => peer_session_id,
        RetireTargetDisposition::Busy => return GPU_AUTHORITY_DENIED,
        RetireTargetDisposition::Invalid => return GPU_AUTHORITY_INVALID,
    };
    store.sessions.remove(&retire.facts.authority_session_id);
    if let Some(peer_session_id) = peer_session_id {
        store.sessions.remove(&peer_session_id);
    }
    GPU_AUTHORITY_ALLOWED
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presentation_facts() -> GpuAuthorityCarrierFacts {
        GpuAuthorityCarrierFacts {
            operation_id: 3_157_634_281,
            topology_id: GPU_TOPOLOGY_ISOLATED_PER_LOGICAL_V2,
            realm: GpuRealmIdentityV2 {
                runtime: GpuRuntimeIdentityV2 {
                    runtime_address: 11,
                    runtime_nonce: 13,
                },
                realm_id: 17,
                realm_generation: 19,
            },
            account: GpuAccountIdentityV2 {
                account_id: 23,
                account_generation: 29,
                authority_digest: [0xa7; 32],
            },
            ingress_device: GpuDeviceIdentityV2 {
                logical_device_id: 31,
                logical_device_generation: 37,
                provider_generation: 41,
            },
            provider_generation: 41,
            operation_instance_id: 43,
            promise_id: 0,
            captured_scope_id: 0,
            adapter_ordinal: 0,
            device_ingress_ordinal: 47,
            queue_ingress_ordinal: 0,
            authority_context_digest: [0xc7; 32],
            receiver: GpuObjectRefV2 {
                kind: 22,
                flags: 0,
                object_id: 53,
                object_generation: 59,
            },
            target: GpuObjectRefV2 {
                kind: 6,
                flags: 0,
                object_id: 61,
                object_generation: 67,
            },
        }
    }

    fn request_adapter_facts() -> GpuAuthorityCarrierFacts {
        let operation = runtime_registry()
            .unwrap()
            .operations
            .values()
            .find(|operation| operation.operation_name == "GPU.requestAdapter")
            .unwrap();
        GpuAuthorityCarrierFacts {
            operation_id: operation.wire_id,
            topology_id: GPU_TOPOLOGY_ISOLATED_PER_LOGICAL_V2,
            realm: GpuRealmIdentityV2 {
                runtime: GpuRuntimeIdentityV2 {
                    runtime_address: 11,
                    runtime_nonce: 13,
                },
                realm_id: 17,
                realm_generation: 19,
            },
            account: GpuAccountIdentityV2 {
                account_id: 23,
                account_generation: 29,
                authority_digest: [0xa7; 32],
            },
            ingress_device: GpuDeviceIdentityV2::default(),
            provider_generation: 0,
            operation_instance_id: 43,
            promise_id: 47,
            captured_scope_id: 0,
            adapter_ordinal: 0,
            device_ingress_ordinal: 0,
            queue_ingress_ordinal: 0,
            authority_context_digest: [0xc7; 32],
            receiver: GpuObjectRefV2 {
                kind: 1,
                flags: 0,
                object_id: 53,
                object_generation: 59,
            },
            target: GpuObjectRefV2::default(),
        }
    }

    fn presentation_attribution() -> GpuAuthorityAttribution {
        let root = Principal::Root {
            identity: NonEmptyString::new("project-root").unwrap(),
        };
        GpuAuthorityAttribution {
            context_kind: 1,
            actor: root.clone(),
            effect_owner: root.clone(),
            scheduler: None,
            constrained_principals: vec![root],
            policy_generation: 1,
            negative_generation: 1,
            dynamic_generation: 1,
            handle_generation: 1,
        }
    }

    fn presentation_attribution_for_host(host: &Host) -> GpuAuthorityAttribution {
        let mut attribution = presentation_attribution();
        let snapshot = host.armed_snapshot().unwrap();
        let generations = host.typed_generations().unwrap();
        attribution.policy_generation = snapshot.generations().policy.get();
        attribution.negative_generation = generations.negative.get();
        attribution.dynamic_generation = generations.dynamic.get();
        attribution.handle_generation = generations.handle.get();
        attribution
    }

    fn presentation_session(
        branch: &str,
        facts: GpuAuthorityCarrierFacts,
        handles: Vec<ExactGpuAuthorityPresentedHandleV2>,
        host: Arc<Host>,
        stage: SessionStage,
    ) -> GpuAuthoritySession {
        GpuAuthoritySession {
            context_id: 71,
            host,
            operation: RuntimeOperation {
                operation_name: format!("navigator.gpu.canvas.{branch}"),
                wire_id: facts.operation_id,
                edge_id: format!("surface.webgpu.presentation.{branch}"),
                private_target_cell_id: format!("target.webgpu.presentation.{branch}"),
                authority_kind: OperationAuthorityKind::TypedPositive,
                receiver_kind: 22,
                target_kind: 6,
                promise_required: false,
            },
            facts,
            attribution: presentation_attribution(),
            presented_handles: Some(handles),
            presentation: None,
            stage,
        }
    }

    fn presentation_facts_ffi(
        facts: &GpuAuthorityCarrierFacts,
        session_id: u64,
    ) -> ExactGpuAuthoritySessionFactsV2 {
        ExactGpuAuthoritySessionFactsV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthoritySessionFactsV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            operation_id: facts.operation_id,
            topology_id: facts.topology_id,
            authority_session_id: session_id,
            realm: facts.realm,
            account: facts.account,
            ingress_device: facts.ingress_device,
            provider_generation: facts.provider_generation,
            operation_instance_id: facts.operation_instance_id,
            promise_id: facts.promise_id,
            captured_scope_id: facts.captured_scope_id,
            adapter_ordinal: facts.adapter_ordinal,
            device_ingress_ordinal: facts.device_ingress_ordinal,
            queue_ingress_ordinal: facts.queue_ingress_ordinal,
            authority_context_digest: facts.authority_context_digest,
            receiver: facts.receiver,
            target: facts.target,
        }
    }

    fn install_presentation_pair_for_test(
        host: Arc<Host>,
        facts: GpuAuthorityCarrierFacts,
        acquire_stage: SessionStage,
        present_stage: SessionStage,
    ) -> CapturedPresentationAuthorityV2 {
        let handles = canonical_presentation_presented_handles(&facts).unwrap();
        let attribution = presentation_attribution_for_host(&host);
        let mut acquire = presentation_session(
            "acquire",
            facts.clone(),
            handles.clone(),
            Arc::clone(&host),
            acquire_stage,
        );
        acquire.operation = runtime_registry()
            .unwrap()
            .presentation_authority
            .branches
            .get("acquire")
            .unwrap()
            .clone();
        acquire.attribution = attribution.clone();
        let mut present = presentation_session("present", facts, handles, host, present_stage);
        present.operation = runtime_registry()
            .unwrap()
            .presentation_authority
            .branches
            .get("present")
            .unwrap()
            .clone();
        present.attribution = attribution;
        let mut store = session_store().lock().unwrap();
        store.sessions.clear();
        store.insert_presentation_pair(acquire, present).unwrap()
    }

    fn digest_from_raw(raw: [u8; 32]) -> Digest {
        Digest::new(format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        ))
        .unwrap()
    }

    fn source_binding() -> capsec_semantics::arming::ExactGpuProviderBinding {
        let registry = runtime_registry().unwrap();
        capsec_semantics::arming::ExactGpuProviderBinding {
            schema: "exact/webgpu-provider/1".into(),
            abi_version: GPU_SERVICE_ABI_V2,
            profile_id: registry.provider.profile_id.clone(),
            profile_digest: digest_from_raw(registry.provider.profile_digest),
            webgpu_c_vocabulary_digest: digest_from_raw(
                registry.provider.webgpu_c_vocabulary_digest,
            ),
            operation_set_digest: digest_from_raw(registry.provider.operation_set_digest),
            semantic_program_digest: digest_from_raw(registry.provider.semantic_program_digest),
            runtime_routing_digest: Some(digest_from_raw(registry.provider.runtime_routing_digest)),
            operation_ids: registry.provider.sorted_operation_ids.clone(),
            topology: "isolated-per-logical-v1".into(),
        }
    }

    #[cfg(feature = "webgpu-binding")]
    fn experimental_presentation_host() -> Arc<Host> {
        let binding = source_binding();
        let arming = experimental_webgpu_pre1a_arming(&binding).unwrap();
        let snapshot = super::super::tests::example_armed_snapshot_with(|value| {
            value["exactGpuProvider"] = serde_json::to_value(&binding).unwrap();
            value["rootAuthorityCeiling"] = serde_json::json!({
                "kind": "bounded",
                "authorities": arming.positive_selectors.clone(),
            });
            value["protectedObjects"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "role": "exact-webgpu-profile",
                    "object": {
                        "platform": "unix",
                        "volume": "fixture-volume",
                        "file": "exact-webgpu-profile"
                    },
                    "deniedActions": ["fs:write"]
                }));
            let mut root = value["principals"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["principal"]["kind"] == "root")
                .unwrap()
                .clone();
            root["floor"] = serde_json::to_value(&arming.positive_selectors).unwrap();
            root["denials"] = serde_json::json!([]);
            root["escalationCeiling"] = serde_json::json!([]);
            root["imports"] = serde_json::json!({
                "builtins": [],
                "packages": []
            });
            root["endowments"] = serde_json::json!([]);
            value["principals"] = serde_json::json!([root]);
            value["packageGraph"]["nodes"] = serde_json::Value::Array(
                value["packageGraph"]["nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|node| node["principal"]["kind"] == "root")
                    .cloned()
                    .collect(),
            );
            value["packageGraph"]["importEdges"] = serde_json::json!([]);
            value["rootBindings"] = serde_json::Value::Array(
                value["rootBindings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|binding| binding["owner"].is_null())
                    .cloned()
                    .collect(),
            );
        });
        super::super::validate_exact_experimental_webgpu_pre1a_floor(
            &snapshot,
            &arming.positive_selectors,
        )
        .unwrap();
        let target_cells = crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGE_IDS
            .iter()
            .map(|edge| {
                (
                    (*edge).to_owned(),
                    capsec_semantics::decision::TargetCellDisposition::Closed,
                )
            })
            .collect();
        Arc::new(
            Host::new_armed_with_target_cells(
                super::super::HostConfig::default(),
                Arc::new(snapshot),
                target_cells,
                super::super::AuthenticatedPackageSourceState::default(),
                capsec_semantics::decision::TargetArmState::CompleteExperimentalPrivate,
                arming.private_target_cells,
            )
            .unwrap(),
        )
    }

    #[test]
    fn presentation_handles_are_exact_canonical_texture_then_context_facts() {
        let facts = presentation_facts();
        let handles = canonical_presentation_presented_handles(&facts).unwrap();
        assert_eq!(handles.len(), 2);
        assert_eq!(
            handles
                .iter()
                .map(|handle| handle.object.kind)
                .collect::<Vec<_>>(),
            [6, 22]
        );
        assert!(handles.iter().all(|handle| {
            handle.account == facts.account
                && handle.device == facts.ingress_device
                && handle.struct_size
                    == std::mem::size_of::<ExactGpuAuthorityPresentedHandleV2>() as u32
                && handle.abi_version == GPU_SERVICE_ABI_V2
        }));
        assert_eq!(handles[0].object, facts.target);
        assert_eq!(handles[1].object, facts.receiver);
    }

    #[cfg(feature = "webgpu-binding")]
    #[test]
    fn experimental_root_ceiling_admits_request_adapter_requested_stage() {
        let _guard = crate::host::abi::host_test_lock();
        let host = experimental_presentation_host();
        let facts = request_adapter_facts();
        session_store().lock().unwrap().sessions.clear();
        let session_id = capture_session(
            71,
            Arc::clone(&host),
            presentation_attribution_for_host(&host),
            facts.clone(),
        )
        .expect("the exact private requestAdapter session must capture");
        let handles = [ExactGpuAuthorityPresentedHandleV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthorityPresentedHandleV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            account: facts.account,
            device: GpuDeviceIdentityV2::default(),
            object: facts.receiver,
        }];
        let decision = ExactGpuAuthorityDecisionRequestV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthorityDecisionRequestV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            stage: 1,
            flags: 0,
            facts: presentation_facts_ffi(&facts, session_id),
            presented_handles: handles.as_ptr(),
            presented_handle_count: handles.len(),
        };
        assert_eq!(
            unsafe { evaluate_gpu_authority_session_v2(std::ptr::null_mut(), &decision) },
            GPU_AUTHORITY_ALLOWED
        );
        let retire = ExactGpuAuthorityRetireV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthorityRetireV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            flags: 0,
            reserved: 0,
            facts: decision.facts,
        };
        assert_eq!(
            unsafe { retire_gpu_authority_session_v2(std::ptr::null_mut(), &retire) },
            GPU_AUTHORITY_ALLOWED
        );
    }

    #[test]
    fn busy_presentation_pair_retire_is_atomic_and_exact() {
        let facts = presentation_facts();
        let handles = canonical_presentation_presented_handles(&facts).unwrap();
        let host = Arc::new(Host::closed_unarmed());
        let mut store = GpuAuthoritySessionStore::default();
        let retained = store
            .insert_presentation_pair(
                presentation_session(
                    "acquire",
                    facts.clone(),
                    handles.clone(),
                    Arc::clone(&host),
                    SessionStage::Repeat,
                ),
                presentation_session("present", facts, handles, host, SessionStage::Commit),
            )
            .unwrap();
        store
            .sessions
            .get_mut(&retained.present_session_id)
            .unwrap()
            .stage = SessionStage::EvaluatingAndThen;
        assert_eq!(
            retire_peer_if_available(&store, retained.acquire_session_id),
            None
        );
        assert_eq!(
            classify_retire_target(&store, retained.acquire_session_id),
            RetireTargetDisposition::Busy
        );
        assert_eq!(store.sessions.len(), 2);
        assert!(store.sessions.contains_key(&retained.acquire_session_id));
        assert!(store.sessions.contains_key(&retained.present_session_id));
        store
            .sessions
            .get_mut(&retained.present_session_id)
            .unwrap()
            .stage = SessionStage::Commit;
        assert_eq!(
            retire_peer_if_available(&store, retained.acquire_session_id),
            Some(Some(retained.present_session_id))
        );
        store
            .sessions
            .get_mut(&retained.present_session_id)
            .unwrap()
            .presentation = None;
        assert_eq!(
            classify_retire_target(&store, retained.acquire_session_id),
            RetireTargetDisposition::Invalid
        );
    }

    #[cfg(feature = "webgpu-binding")]
    #[test]
    fn singular_retire_status_distinguishes_busy_stale_and_structural_mismatch() {
        let _guard = crate::host::abi::host_test_lock();
        let facts = presentation_facts();
        let handles = canonical_presentation_presented_handles(&facts).unwrap();
        let host = experimental_presentation_host();
        let session = presentation_session(
            "singular-retire",
            facts.clone(),
            handles,
            host,
            SessionStage::EvaluatingAndThen,
        );
        let session_id = {
            let mut store = session_store().lock().unwrap();
            store.sessions.clear();
            store.insert(session).unwrap()
        };
        let mut retire = ExactGpuAuthorityRetireV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthorityRetireV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            flags: 0,
            reserved: 0,
            facts: presentation_facts_ffi(&facts, session_id),
        };
        assert_eq!(
            unsafe { retire_gpu_authority_session_v2(std::ptr::null_mut(), &retire) },
            GPU_AUTHORITY_DENIED
        );
        assert!(session_store()
            .lock()
            .unwrap()
            .sessions
            .contains_key(&session_id));

        retire.facts.operation_instance_id += 1;
        assert_eq!(
            unsafe { retire_gpu_authority_session_v2(std::ptr::null_mut(), &retire) },
            GPU_AUTHORITY_INVALID
        );
        retire.facts.operation_instance_id -= 1;
        session_store()
            .lock()
            .unwrap()
            .sessions
            .get_mut(&session_id)
            .unwrap()
            .stage = SessionStage::Requested;
        assert_eq!(
            unsafe { retire_gpu_authority_session_v2(std::ptr::null_mut(), &retire) },
            GPU_AUTHORITY_ALLOWED
        );
        assert_eq!(
            unsafe { retire_gpu_authority_session_v2(std::ptr::null_mut(), &retire) },
            GPU_AUTHORITY_STALE
        );
    }

    #[cfg(feature = "webgpu-binding")]
    #[test]
    fn pair_retire_status_distinguishes_busy_stale_and_structural_mismatch() {
        let _guard = crate::host::abi::host_test_lock();
        let facts = presentation_facts();
        let host = experimental_presentation_host();
        let retained = install_presentation_pair_for_test(
            Arc::clone(&host),
            facts.clone(),
            SessionStage::Repeat,
            SessionStage::EvaluatingAndThen,
        );
        assert_eq!(
            retire_presentation_authority(71, retained, facts.authority_context_digest,),
            GPU_AUTHORITY_DENIED
        );
        assert_eq!(session_store().lock().unwrap().sessions.len(), 2);
        session_store()
            .lock()
            .unwrap()
            .sessions
            .get_mut(&retained.present_session_id)
            .unwrap()
            .stage = SessionStage::Commit;
        assert_eq!(
            retire_presentation_authority(71, retained, [0xd9; 32]),
            GPU_AUTHORITY_INVALID
        );
        assert_eq!(
            retire_presentation_authority(71, retained, facts.authority_context_digest,),
            GPU_AUTHORITY_ALLOWED
        );
        assert_eq!(
            retire_presentation_authority(71, retained, facts.authority_context_digest,),
            GPU_AUTHORITY_STALE
        );

        let retained = install_presentation_pair_for_test(
            host,
            facts.clone(),
            SessionStage::Repeat,
            SessionStage::Commit,
        );
        session_store()
            .lock()
            .unwrap()
            .sessions
            .remove(&retained.present_session_id);
        assert_eq!(
            retire_presentation_authority(71, retained, facts.authority_context_digest,),
            GPU_AUTHORITY_INVALID
        );
        session_store().lock().unwrap().sessions.clear();
    }

    unsafe extern "C" fn allowed_test_continuation(context: *mut c_void) -> i32 {
        // SAFETY: the test lends one live u8 for this synchronous callback.
        unsafe { *context.cast::<u8>() += 1 };
        GPU_AUTHORITY_ALLOWED
    }

    struct ReconciliationFaultContext {
        remove_session_id: u64,
        calls: u8,
    }

    unsafe extern "C" fn remove_reserved_session_test_continuation(context: *mut c_void) -> i32 {
        // SAFETY: the test lends this exact context for the synchronous call.
        let context = unsafe { &mut *context.cast::<ReconciliationFaultContext>() };
        context.calls += 1;
        session_store()
            .lock()
            .unwrap()
            .sessions
            .remove(&context.remove_session_id);
        GPU_AUTHORITY_ALLOWED
    }

    #[test]
    fn typed_single_allow_without_continuation_is_structurally_invalid() {
        assert_eq!(
            classify_single_typed_evaluation(1, true, false),
            GPU_AUTHORITY_INVALID
        );
        assert_eq!(
            classify_single_typed_evaluation(1, true, true),
            GPU_AUTHORITY_ALLOWED
        );
        assert_eq!(
            classify_single_typed_evaluation(1, false, false),
            GPU_AUTHORITY_DENIED
        );
        assert_eq!(
            classify_single_typed_evaluation(1, false, true),
            GPU_AUTHORITY_INVALID
        );
    }

    #[cfg(feature = "webgpu-binding")]
    #[test]
    fn exact_shaped_presentation_batch_runs_allowed_continuation() {
        let _guard = crate::host::abi::host_test_lock();
        let facts = presentation_facts();
        let handles = canonical_presentation_presented_handles(&facts).unwrap();
        let host = experimental_presentation_host();
        let retained = install_presentation_pair_for_test(
            host,
            facts.clone(),
            SessionStage::Commit,
            SessionStage::Requested,
        );
        let decisions = [
            ExactGpuAuthorityDecisionRequestV2 {
                struct_size: std::mem::size_of::<ExactGpuAuthorityDecisionRequestV2>() as u32,
                abi_version: GPU_SERVICE_ABI_V2,
                stage: 3,
                flags: 0,
                facts: presentation_facts_ffi(&facts, retained.acquire_session_id),
                presented_handles: handles.as_ptr(),
                presented_handle_count: handles.len(),
            },
            ExactGpuAuthorityDecisionRequestV2 {
                struct_size: std::mem::size_of::<ExactGpuAuthorityDecisionRequestV2>() as u32,
                abi_version: GPU_SERVICE_ABI_V2,
                stage: 2,
                flags: 0,
                facts: presentation_facts_ffi(&facts, retained.present_session_id),
                presented_handles: handles.as_ptr(),
                presented_handle_count: handles.len(),
            },
        ];
        let batch = ExactGpuAuthorityDecisionBatchV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthorityDecisionBatchV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            phase: 1,
            flags: 0,
            decisions: decisions.as_ptr(),
            decision_count: decisions.len(),
        };
        let mut continuation_context = 0_u8;
        let status = unsafe {
            evaluate_gpu_authority_batch_and_then_v2(
                std::ptr::null_mut(),
                &batch,
                (&mut continuation_context as *mut u8).cast(),
                Some(allowed_test_continuation),
            )
        };
        assert_eq!(status, GPU_AUTHORITY_ALLOWED);
        assert_eq!(continuation_context, 1);
        {
            let store = session_store().lock().unwrap();
            assert_eq!(
                store
                    .sessions
                    .get(&retained.acquire_session_id)
                    .unwrap()
                    .stage,
                SessionStage::Repeat
            );
            assert_eq!(
                store
                    .sessions
                    .get(&retained.present_session_id)
                    .unwrap()
                    .stage,
                SessionStage::Commit
            );
        }

        let handoff_decision = [ExactGpuAuthorityDecisionRequestV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthorityDecisionRequestV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            stage: 3,
            flags: 0,
            facts: presentation_facts_ffi(&facts, retained.present_session_id),
            presented_handles: handles.as_ptr(),
            presented_handle_count: handles.len(),
        }];
        let handoff_batch = ExactGpuAuthorityDecisionBatchV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthorityDecisionBatchV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            phase: 2,
            flags: 0,
            decisions: handoff_decision.as_ptr(),
            decision_count: handoff_decision.len(),
        };
        let status = unsafe {
            evaluate_gpu_authority_batch_and_then_v2(
                std::ptr::null_mut(),
                &handoff_batch,
                (&mut continuation_context as *mut u8).cast(),
                Some(allowed_test_continuation),
            )
        };
        assert_eq!(status, GPU_AUTHORITY_ALLOWED);
        assert_eq!(continuation_context, 2);
        assert_eq!(
            session_store()
                .lock()
                .unwrap()
                .sessions
                .get(&retained.present_session_id)
                .unwrap()
                .stage,
            SessionStage::Repeat
        );

        session_store()
            .lock()
            .unwrap()
            .sessions
            .get_mut(&retained.present_session_id)
            .unwrap()
            .stage = SessionStage::Commit;
        let mut fault = ReconciliationFaultContext {
            remove_session_id: retained.acquire_session_id,
            calls: 0,
        };
        let status = unsafe {
            evaluate_gpu_authority_batch_and_then_v2(
                std::ptr::null_mut(),
                &handoff_batch,
                (&mut fault as *mut ReconciliationFaultContext).cast(),
                Some(remove_reserved_session_test_continuation),
            )
        };
        assert_eq!(status, GPU_AUTHORITY_INVALID);
        assert_eq!(fault.calls, 1);

        session_store().lock().unwrap().sessions.clear();
    }

    #[cfg(feature = "webgpu-binding")]
    #[test]
    fn malformed_presentation_generation_preflight_is_invalid_without_continuation() {
        let _guard = crate::host::abi::host_test_lock();
        let facts = presentation_facts();
        let handles = canonical_presentation_presented_handles(&facts).unwrap();
        let host = experimental_presentation_host();
        let retained = install_presentation_pair_for_test(
            host,
            facts.clone(),
            SessionStage::Commit,
            SessionStage::Requested,
        );
        {
            let mut store = session_store().lock().unwrap();
            for session_id in [retained.acquire_session_id, retained.present_session_id] {
                store
                    .sessions
                    .get_mut(&session_id)
                    .unwrap()
                    .attribution
                    .negative_generation = u64::MAX;
            }
        }
        let decisions = [
            ExactGpuAuthorityDecisionRequestV2 {
                struct_size: std::mem::size_of::<ExactGpuAuthorityDecisionRequestV2>() as u32,
                abi_version: GPU_SERVICE_ABI_V2,
                stage: 3,
                flags: 0,
                facts: presentation_facts_ffi(&facts, retained.acquire_session_id),
                presented_handles: handles.as_ptr(),
                presented_handle_count: handles.len(),
            },
            ExactGpuAuthorityDecisionRequestV2 {
                struct_size: std::mem::size_of::<ExactGpuAuthorityDecisionRequestV2>() as u32,
                abi_version: GPU_SERVICE_ABI_V2,
                stage: 2,
                flags: 0,
                facts: presentation_facts_ffi(&facts, retained.present_session_id),
                presented_handles: handles.as_ptr(),
                presented_handle_count: handles.len(),
            },
        ];
        let batch = ExactGpuAuthorityDecisionBatchV2 {
            struct_size: std::mem::size_of::<ExactGpuAuthorityDecisionBatchV2>() as u32,
            abi_version: GPU_SERVICE_ABI_V2,
            phase: 1,
            flags: 0,
            decisions: decisions.as_ptr(),
            decision_count: decisions.len(),
        };
        let mut continuation_context = 0_u8;
        let status = unsafe {
            evaluate_gpu_authority_batch_and_then_v2(
                std::ptr::null_mut(),
                &batch,
                (&mut continuation_context as *mut u8).cast(),
                Some(allowed_test_continuation),
            )
        };
        assert_eq!(status, GPU_AUTHORITY_INVALID);
        assert_eq!(continuation_context, 0);
        let store = session_store().lock().unwrap();
        assert_eq!(
            store
                .sessions
                .get(&retained.acquire_session_id)
                .unwrap()
                .stage,
            SessionStage::Commit
        );
        assert_eq!(
            store
                .sessions
                .get(&retained.present_session_id)
                .unwrap()
                .stage,
            SessionStage::Requested
        );
        drop(store);
        session_store().lock().unwrap().sessions.clear();
    }

    #[cfg(feature = "webgpu-binding")]
    #[test]
    fn same_epoch_recheck_uses_fresh_scope_without_mutating_original_pair() {
        let _guard = crate::host::abi::host_test_lock();
        let original = presentation_facts();
        let host = experimental_presentation_host();
        let retained = install_presentation_pair_for_test(
            Arc::clone(&host),
            original.clone(),
            SessionStage::Requested,
            SessionStage::Captured,
        );
        let mut current = original.clone();
        current.operation_instance_id = 73;
        current.device_ingress_ordinal = 79;
        current.captured_scope_id = 83;
        current.authority_context_digest = [0xd7; 32];
        assert_eq!(
            recheck_presentation_acquire_entry(
                71,
                Arc::clone(&host),
                presentation_attribution_for_host(&host),
                current,
                retained,
                original.authority_context_digest,
            ),
            GPU_AUTHORITY_ALLOWED
        );
        let store = session_store().lock().unwrap();
        for session_id in [retained.acquire_session_id, retained.present_session_id] {
            let session = store.sessions.get(&session_id).unwrap();
            assert_eq!(session.facts.captured_scope_id, 0);
            assert_eq!(session.facts.operation_instance_id, 43);
            assert_eq!(session.facts.device_ingress_ordinal, 47);
            assert_eq!(session.facts.authority_context_digest, [0xc7; 32]);
        }
        drop(store);
        session_store().lock().unwrap().sessions.clear();
    }

    #[cfg(feature = "webgpu-binding")]
    #[test]
    fn recheck_reservation_rejects_retire_and_fails_if_context_is_purged() {
        let _guard = crate::host::abi::host_test_lock();
        let original = presentation_facts();
        let host = experimental_presentation_host();
        let retained = install_presentation_pair_for_test(
            Arc::clone(&host),
            original.clone(),
            SessionStage::Requested,
            SessionStage::Captured,
        );
        let mut current = original.clone();
        current.operation_instance_id = 89;
        current.device_ingress_ordinal = 97;
        current.captured_scope_id = 101;
        current.authority_context_digest = [0xe7; 32];
        let barrier = Arc::new(std::sync::Barrier::new(2));
        *presentation_recheck_reservation_hook().lock().unwrap() = Some(Arc::clone(&barrier));
        let worker = std::thread::spawn({
            let host = Arc::clone(&host);
            move || {
                recheck_presentation_acquire_entry(
                    71,
                    Arc::clone(&host),
                    presentation_attribution_for_host(&host),
                    current,
                    retained,
                    original.authority_context_digest,
                )
            }
        });
        barrier.wait();
        assert!(!force_retire(71, retained.acquire_session_id));
        assert_eq!(session_store().lock().unwrap().sessions.len(), 2);
        purge_context(71);
        barrier.wait();
        assert_eq!(worker.join().unwrap(), GPU_AUTHORITY_INVALID);
        *presentation_recheck_reservation_hook().lock().unwrap() = None;
        assert!(session_store().lock().unwrap().sessions.is_empty());
    }

    #[test]
    fn private_registry_parser_rejects_malformed_duplicate_unknown_and_wildcard_rows() {
        assert!(load_runtime_registry_from_json("{").is_none());
        let source =
            crate::capsec_registry_generated::CAPSEC_WEBGPU_PRIVATE_OPERATION_REGISTRY_JSON;
        let value: serde_json::Value = serde_json::from_str(source).unwrap();

        let mut duplicate = value.clone();
        let first = duplicate["operations"][0].clone();
        duplicate["operations"].as_array_mut().unwrap().push(first);
        duplicate["operationCount"] = serde_json::json!(59);
        assert!(load_runtime_registry_from_json(&duplicate.to_string()).is_none());

        let mut unknown_edge = value.clone();
        unknown_edge["operations"][0]["edgeId"] = serde_json::json!("surface.unknown");
        assert!(load_runtime_registry_from_json(&unknown_edge.to_string()).is_none());

        let mut wildcard = value;
        let positive = wildcard["operations"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|operation| {
                operation
                    .pointer("/authoritySession/decisionKind")
                    .and_then(serde_json::Value::as_str)
                    == Some("typed-positive")
            })
            .unwrap();
        positive["authoritySession"]["action"] = serde_json::json!("gpu:*");
        assert!(load_runtime_registry_from_json(&wildcard.to_string()).is_none());
    }

    #[test]
    fn private_registry_raw_digest_matches_reviewed_pin() {
        let registry = load_runtime_registry().expect("generated private registry must parse");
        assert_eq!(
            registry.raw_sha256,
            parse_hex_digest(EXPERIMENTAL_WEBGPU_PRE1A_REGISTRY_RAW_SHA256)
                .expect("reviewed private registry digest must be valid hex")
        );
    }

    #[cfg(feature = "webgpu-binding")]
    #[test]
    fn experimental_projection_is_the_exact_pinned_private_set() {
        let binding = source_binding();
        let arming = experimental_webgpu_pre1a_arming(&binding).unwrap();
        assert_eq!(arming.operation_count, 63);
        assert_eq!(arming.private_target_cells.len(), 65);
        assert_eq!(arming.positive_selectors.len(), 23);
        assert!(arming
            .positive_selectors
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        assert!(arming.positive_selectors.iter().all(|selector| {
            selector.action.as_str() == "gpu:operation"
                && matches!(&selector.resource, SelectorResource::GpuOperation { .. })
        }));
        let registry = serde_json::from_str::<serde_json::Value>(
            crate::capsec_registry_generated::CAPSEC_WEBGPU_PRIVATE_OPERATION_REGISTRY_JSON,
        )
        .unwrap();
        let expected_edges = registry["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|operation| operation["edgeId"].as_str().unwrap().to_owned())
            .chain(
                registry["presentationAuthority"]["branches"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|branch| branch["edgeId"].as_str().unwrap().to_owned()),
            )
            .collect::<BTreeSet<_>>();
        assert_eq!(
            arming
                .private_target_cells
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            expected_edges
        );
        let expected_positive_operations = registry["operations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|operation| {
                operation
                    .pointer("/authoritySession/decisionKind")
                    .and_then(serde_json::Value::as_str)
                    == Some("typed-positive")
            })
            .map(|operation| operation["operationId"].as_str().unwrap().to_owned())
            .chain(
                registry["presentationAuthority"]["branches"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|branch| branch["operationId"].as_str().unwrap().to_owned()),
            )
            .collect::<BTreeSet<_>>();
        let actual_positive_operations = arming
            .positive_selectors
            .iter()
            .map(|selector| match &selector.resource {
                SelectorResource::GpuOperation {
                    profile_id,
                    profile_digest,
                    webgpu_c_vocabulary_digest,
                    operation_set_digest,
                    semantic_program_digest,
                    runtime_routing_digest,
                    operation_id,
                } => {
                    assert_eq!(profile_id.as_str(), binding.profile_id);
                    assert_eq!(profile_digest, &binding.profile_digest);
                    assert_eq!(
                        webgpu_c_vocabulary_digest,
                        &binding.webgpu_c_vocabulary_digest
                    );
                    assert_eq!(operation_set_digest, &binding.operation_set_digest);
                    assert_eq!(semantic_program_digest, &binding.semantic_program_digest);
                    assert_eq!(
                        Some(runtime_routing_digest),
                        binding.runtime_routing_digest.as_ref()
                    );
                    assert!(!operation_id.as_str().contains('*'));
                    operation_id.as_str().to_owned()
                }
                other => panic!("unexpected private selector resource: {other:?}"),
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_positive_operations, expected_positive_operations);
        assert_eq!(
            arming
                .private_target_cells
                .values()
                .filter(|cell| **cell == TargetCellDisposition::Closed)
                .count(),
            1
        );

        let mut widened = binding;
        widened.operation_ids.push(u32::MAX);
        assert!(experimental_webgpu_pre1a_arming(&widened).is_none());
    }

    #[cfg(not(feature = "webgpu-binding"))]
    #[test]
    fn experimental_projection_is_unavailable_when_feature_is_off() {
        assert!(experimental_webgpu_pre1a_arming(&source_binding()).is_none());
    }
}
