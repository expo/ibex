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
    canonicalize_principal_set, ActionId, DecisionContext, DecisionSet, DecisionSetSchema, Digest,
    Effect, EffectCombination, EffectOccurrence, NonEmptyString, OccurrenceResource, Principal,
    SelectorResource, StableId, Stage,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::Host;

const GPU_SERVICE_ABI_V2: u32 = 0x0002_0000;
const GPU_TOPOLOGY_ISOLATED_PER_LOGICAL_V2: u32 = 1;
const MAX_GPU_AUTHORITY_SESSIONS: usize = 1024;
const MAX_GPU_PRESENTED_HANDLES: usize = 256;

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

#[derive(Clone, Debug)]
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

fn load_runtime_registry() -> Option<RuntimeRegistry> {
    let value = capsec_semantics::strict_json::parse_strict(
        crate::capsec_registry_generated::CAPSEC_WEBGPU_PRIVATE_OPERATION_REGISTRY_JSON,
    )
    .ok()?;
    let document: RegistryDocument = serde_json::from_value(value).ok()?;
    if document.webgpu_operation_registry_schema != "ibex/webgpu-private-capsec-operations/1"
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
        || document.private_target_cell_count != document.operation_count
        || document.private_target_cell_count != document.private_target_cells.len()
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
    let mut operations = BTreeMap::new();
    let mut operation_edges = BTreeSet::new();
    let mut all_wire_ids = Vec::new();
    let mut ordered_names = Vec::new();
    for operation in document.operations {
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
    if operation_edges.len() != cells.len()
        || !operation_edges.iter().eq(cells.keys())
        || !is_sorted_unique(&ordered_names)
        || {
            all_wire_ids.sort_unstable();
            all_wire_ids != provider.sorted_operation_ids
        }
    {
        return None;
    }
    Some(RuntimeRegistry {
        provider,
        operations,
    })
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

#[derive(Clone)]
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
    Denied,
}

struct GpuAuthoritySession {
    context_id: u64,
    host: Arc<Host>,
    operation: RuntimeOperation,
    facts: GpuAuthorityCarrierFacts,
    attribution: GpuAuthorityAttribution,
    presented_handles: Option<Vec<ExactGpuAuthorityPresentedHandleV2>>,
    stage: SessionStage,
}

#[derive(Default)]
struct GpuAuthoritySessionStore {
    sessions: HashMap<u64, GpuAuthoritySession>,
}

impl GpuAuthoritySessionStore {
    fn insert(&mut self, session: GpuAuthoritySession) -> Option<u64> {
        if self.sessions.len() >= MAX_GPU_AUTHORITY_SESSIONS {
            return None;
        }
        for _ in 0..32 {
            let mut bytes = [0u8; 8];
            getrandom::getrandom(&mut bytes).ok()?;
            let id = u64::from_ne_bytes(bytes);
            if id == 0 || id == u64::MAX || self.sessions.contains_key(&id) {
                continue;
            }
            self.sessions.insert(id, session);
            return Some(id);
        }
        None
    }
}

fn session_store() -> &'static Mutex<GpuAuthoritySessionStore> {
    static STORE: OnceLock<Mutex<GpuAuthoritySessionStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(GpuAuthoritySessionStore::default()))
}

pub(crate) fn capture_session(
    context_id: u64,
    host: Arc<Host>,
    attribution: GpuAuthorityAttribution,
    facts: GpuAuthorityCarrierFacts,
) -> Option<u64> {
    if context_id == 0 || !matches!(attribution.context_kind, 1 | 2) {
        return None;
    }
    let snapshot = host.armed_snapshot()?;
    let binding = snapshot.exact_gpu_provider_binding().ok()??;
    if !provider_binding_matches_source_registry(&binding) {
        return None;
    }
    let registry = runtime_registry()?;
    let operation = registry.operations.get(&facts.operation_id)?.clone();
    if !carrier_matches_operation(&facts, &operation)
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
        || canonicalize_principal_set(attribution.constrained_principals.clone()).ok()?
            != attribution.constrained_principals
        || snapshot.generations().policy.get() != attribution.policy_generation
    {
        return None;
    }
    let generations = host.typed_generations()?;
    if generations.negative.get() != attribution.negative_generation
        || generations.dynamic.get() != attribution.dynamic_generation
        || generations.handle.get() != attribution.handle_generation
    {
        return None;
    }
    let session = GpuAuthoritySession {
        context_id,
        host,
        operation,
        facts,
        attribution,
        presented_handles: None,
        stage: SessionStage::Captured,
    };
    let mut store = session_store().lock().ok()?;
    store.insert(session)
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
                    SessionStage::Requested | SessionStage::Commit | SessionStage::Repeat
                )
        })
    })
}

pub(crate) fn force_retire(context_id: u64, session_id: u64) -> bool {
    let Ok(mut store) = session_store().lock() else {
        return false;
    };
    if !store
        .sessions
        .get(&session_id)
        .is_some_and(|session| session.context_id == context_id)
    {
        return false;
    }
    store.sessions.remove(&session_id);
    true
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

fn evaluate_session(
    session: &mut GpuAuthoritySession,
    stage: Stage,
    handles: Vec<ExactGpuAuthorityPresentedHandleV2>,
) -> i32 {
    if session.stage == SessionStage::Denied {
        return GPU_AUTHORITY_DENIED;
    }
    if !authority_generations_are_current(session) {
        session.stage = SessionStage::Denied;
        return GPU_AUTHORITY_STALE;
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
            let Some(requested) = occurrence.resource.requested_selector_resource() else {
                session.stage = SessionStage::Denied;
                return GPU_AUTHORITY_INVALID;
            };
            let set = DecisionSet {
                decision_set_schema: DecisionSetSchema::V1,
                operation_id: match NonEmptyString::new(format!(
                    "gpu-authority-session:{}:{}",
                    session.facts.operation_instance_id, session.operation.operation_name
                )) {
                    Ok(value) => value,
                    Err(_) => return GPU_AUTHORITY_INVALID,
                },
                atomicity_group: match StableId::new(format!(
                    "{}.authority-session",
                    session.operation.private_target_cell_id
                )) {
                    Ok(value) => value,
                    Err(_) => return GPU_AUTHORITY_INVALID,
                },
                combination: EffectCombination::Conjunction,
                context: DecisionContext {
                    stage,
                    actor: session.attribution.actor.clone(),
                    constrained_principals: session.attribution.constrained_principals.clone(),
                    presented_handle_ids: Vec::new(),
                },
                effects: vec![Effect {
                    action: ActionId::new("gpu:operation").expect("checked GPU action ID is valid"),
                    effect_owner: session.attribution.effect_owner.clone(),
                    resource: OccurrenceResource::GpuOperationOccurrence {
                        requested: Box::new(requested),
                        realm_identity: realm_digest(&session.facts.realm),
                        account_identity: account_digest(
                            &session.facts.realm,
                            &session.facts.account,
                        ),
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
                        )
                        .expect("validated receiver is present"),
                        target_identity: object_digest(
                            b"target",
                            &session.facts.realm,
                            &session.facts.account,
                            &session.facts.ingress_device,
                            &session.facts.target,
                        ),
                        presented_handle_identities: match presented_handle_digests(
                            &session.facts.realm,
                            &handles,
                        ) {
                            Some(identities) => identities,
                            None => return GPU_AUTHORITY_INVALID,
                        },
                    },
                }],
            };
            let gate = EffectGate {
                coverage_edge_id: match StableId::new(session.operation.edge_id.clone()) {
                    Ok(value) => value,
                    Err(_) => return GPU_AUTHORITY_INVALID,
                },
                target_cell: TargetCellDisposition::Complete,
                definition_and_edge_predicates_satisfied: true,
            };
            matches!(
                session.host.evaluate_typed_decision(&set, &[gate]),
                Ok(decision) if matches!(
                    decision.outcome,
                    DecisionOutcome::Allow | DecisionOutcome::AllowWithWouldDenyEvidence
                )
            )
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
    let Some(session) = store.sessions.get_mut(&decision.facts.authority_session_id) else {
        return GPU_AUTHORITY_STALE;
    };
    if !session.facts.matches_ffi(&decision.facts) {
        session.stage = SessionStage::Denied;
        return GPU_AUTHORITY_STALE;
    }
    evaluate_session(session, stage, handles)
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
        return GPU_AUTHORITY_STALE;
    }
    store.sessions.remove(&retire.facts.authority_session_id);
    GPU_AUTHORITY_ALLOWED
}

#[cfg(test)]
pub(crate) fn live_session_count_for_test() -> usize {
    session_store()
        .lock()
        .map(|store| store.sessions.len())
        .unwrap_or(MAX_GPU_AUTHORITY_SESSIONS)
}
