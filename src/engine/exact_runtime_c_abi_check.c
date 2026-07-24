/*
 * Independent C11 consumer for include/exact_runtime.h.
 *
 * Its always-built half proves that the public structured-evaluation ABI
 * remains valid C (not only C++) and that the version-two credential/result
 * field layout has not drifted.  The conformance-observer build also exposes
 * a C-owned runtime probe; Rust supplies only cross-thread orchestration.
 * @ref LLP 0024#6-evaluation-outcomes-and-the-abi
 */

#include "exact_runtime.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define IBEX_C_ABI_ASSERT(name, expression) \
  typedef char ibex_c_abi_assert_##name[(expression) ? 1 : -1]
#define IBEX_C_ABI_MEMBER_END(type, member) \
  (offsetof(type, member) + sizeof(((type*)0)->member))

IBEX_C_ABI_ASSERT(version, EX_HERMES_STRUCTURED_EVAL_ABI_VERSION == 2u);
IBEX_C_ABI_ASSERT(work_unit_event_version,
                  EX_HERMES_WORK_UNIT_EVENT_ABI_VERSION == 1u);
IBEX_C_ABI_ASSERT(cancellation_event_version,
                  EX_HERMES_CANCELLATION_EVENT_ABI_VERSION == 1u);
IBEX_C_ABI_ASSERT(async_failure_event_version,
                  EX_HERMES_ASYNC_FAILURE_EVENT_ABI_VERSION == 1u);
IBEX_C_ABI_ASSERT(cancellation_accepted_value,
                  EX_HERMES_CANCELLATION_ACCEPTED == 1u);
IBEX_C_ABI_ASSERT(cancellation_failed_value,
                  EX_HERMES_CANCELLATION_FAILED == 3u);
IBEX_C_ABI_ASSERT(cancellation_defeated_value,
                  EX_HERMES_CANCELLATION_DEFEATED == 4u);
IBEX_C_ABI_ASSERT(module_graph_unresolved_tla_value,
                  EX_HERMES_MODULE_GRAPH_UNRESOLVED_TOP_LEVEL_AWAIT == 4u);
IBEX_C_ABI_ASSERT(session_token_length, EX_HERMES_SESSION_TOKEN_LENGTH == 32u);
IBEX_C_ABI_ASSERT(request_binding_length,
                  EX_HERMES_REQUEST_BINDING_LENGTH == 32u);
IBEX_C_ABI_ASSERT(lowering_protocol_version,
                  EX_HERMES_SESSION_LOWERING_PROTOCOL_VERSION == 2u);
IBEX_C_ABI_ASSERT(import_plan_version,
                  EX_HERMES_SESSION_IMPORT_PLAN_ABI_VERSION == 4u);
IBEX_C_ABI_ASSERT(error_class_unclassified_value,
                  EX_HERMES_ERROR_CLASS_UNCLASSIFIED == 0u);
IBEX_C_ABI_ASSERT(error_class_error_value,
                  EX_HERMES_ERROR_CLASS_ERROR == 1u);
IBEX_C_ABI_ASSERT(error_class_aggregate_error_value,
                  EX_HERMES_ERROR_CLASS_AGGREGATE_ERROR == 2u);
IBEX_C_ABI_ASSERT(error_class_eval_error_value,
                  EX_HERMES_ERROR_CLASS_EVAL_ERROR == 3u);
IBEX_C_ABI_ASSERT(error_class_range_error_value,
                  EX_HERMES_ERROR_CLASS_RANGE_ERROR == 4u);
IBEX_C_ABI_ASSERT(error_class_reference_error_value,
                  EX_HERMES_ERROR_CLASS_REFERENCE_ERROR == 5u);
IBEX_C_ABI_ASSERT(error_class_syntax_error_value,
                  EX_HERMES_ERROR_CLASS_SYNTAX_ERROR == 6u);
IBEX_C_ABI_ASSERT(error_class_type_error_value,
                  EX_HERMES_ERROR_CLASS_TYPE_ERROR == 7u);
IBEX_C_ABI_ASSERT(error_class_uri_error_value,
                  EX_HERMES_ERROR_CLASS_URI_ERROR == 8u);
IBEX_C_ABI_ASSERT(error_class_timeout_error_value,
                  EX_HERMES_ERROR_CLASS_TIMEOUT_ERROR == 9u);
IBEX_C_ABI_ASSERT(error_class_quit_error_value,
                  EX_HERMES_ERROR_CLASS_QUIT_ERROR == 10u);
IBEX_C_ABI_ASSERT(vfs_result_ok_value,
                  EX_HOST_VFS_RESULT_OK == 0u);
IBEX_C_ABI_ASSERT(vfs_result_closed_value,
                  EX_HOST_VFS_RESULT_CLOSED_OPERATION == 1u);
IBEX_C_ABI_ASSERT(vfs_result_stale_session_value,
                  EX_HOST_VFS_RESULT_STALE_SESSION == 2u);
IBEX_C_ABI_ASSERT(vfs_result_malformed_value,
                  EX_HOST_VFS_RESULT_MALFORMED_INPUT == 3u);
IBEX_C_ABI_ASSERT(vfs_result_encoded_separator_value,
                  EX_HOST_VFS_RESULT_ENCODED_SEPARATOR == 4u);
IBEX_C_ABI_ASSERT(vfs_result_outside_mount_value,
                  EX_HOST_VFS_RESULT_OUTSIDE_MOUNT == 5u);
IBEX_C_ABI_ASSERT(vfs_result_synthetic_node_value,
                  EX_HOST_VFS_RESULT_SYNTHETIC_NODE == 6u);
IBEX_C_ABI_ASSERT(vfs_result_policy_denied_value,
                  EX_HOST_VFS_RESULT_POLICY_DENIED == 7u);
IBEX_C_ABI_ASSERT(vfs_result_absent_value,
                  EX_HOST_VFS_RESULT_ABSENT == 8u);
IBEX_C_ABI_ASSERT(vfs_result_symlink_depth_value,
                  EX_HOST_VFS_RESULT_SYMLINK_DEPTH == 9u);
IBEX_C_ABI_ASSERT(vfs_result_unmappable_link_value,
                  EX_HOST_VFS_RESULT_UNMAPPABLE_LINK == 10u);
IBEX_C_ABI_ASSERT(vfs_result_stale_identity_value,
                  EX_HOST_VFS_RESULT_STALE_IDENTITY == 11u);
IBEX_C_ABI_ASSERT(vfs_result_input_too_large_value,
                  EX_HOST_VFS_RESULT_INPUT_TOO_LARGE == 12u);
IBEX_C_ABI_ASSERT(vfs_result_host_error_value,
                  EX_HOST_VFS_RESULT_HOST_ERROR == 13u);
IBEX_C_ABI_ASSERT(decoded_image_version,
                  EXACT_GPU_DECODED_IMAGE_ABI_VERSION_V1 == 0x00010000u);
IBEX_C_ABI_ASSERT(decoded_image_png_value,
                  EXACT_GPU_DECODED_IMAGE_MIME_PNG_V1 == 1u);
IBEX_C_ABI_ASSERT(canvas_receipt_version,
                  EXACT_GPU_CANVAS_ATTACHMENT_RECEIPT_ABI_VERSION_V1 ==
                      0x00010000u);
IBEX_C_ABI_ASSERT(canvas_receipt_attached_value,
                  EXACT_GPU_CANVAS_ATTACHMENT_ATTACHED_V1 == 1u);
IBEX_C_ABI_ASSERT(canvas_receipt_rejected_value,
                  EXACT_GPU_CANVAS_ATTACHMENT_REJECTED_V1 == 2u);
IBEX_C_ABI_ASSERT(canvas_receipt_failure_first_value,
                  EXACT_GPU_CANVAS_ATTACHMENT_STALE_GENERATION_V1 == 1u);
IBEX_C_ABI_ASSERT(canvas_receipt_failure_last_value,
                  EXACT_GPU_CANVAS_ATTACHMENT_INTERNAL_V1 == 6u);
IBEX_C_ABI_ASSERT(canvas_receipt_sink_unavailable_value,
                  EXACT_GPU_CANVAS_RECEIPT_SINK_UNAVAILABLE_V1 == -6);
IBEX_C_ABI_ASSERT(canvas_bundle_unused_value,
                  EXACT_GPU_CANVAS_APP_BUNDLE_UNUSED_V1 == 1);
IBEX_C_ABI_ASSERT(canvas_bundle_cleanup_failed_value,
                  EXACT_GPU_CANVAS_APP_BUNDLE_CLEANUP_FAILED_V1 == -9);
IBEX_C_ABI_ASSERT(canvas_bundle_required_not_consumed_value,
                  EXACT_GPU_CANVAS_APP_BUNDLE_REQUIRED_NOT_CONSUMED_V1 ==
                      -10);
IBEX_C_ABI_ASSERT(canvas_bundle_cleanup_pending_value,
                  EXACT_GPU_CANVAS_APP_BUNDLE_CLEANUP_PENDING_V1 == -11);
IBEX_C_ABI_ASSERT(canvas_bundle_consume_required_value,
                  EXACT_GPU_CANVAS_APP_BUNDLE_CONSUME_REQUIRED_V1 == 1u);
IBEX_C_ABI_ASSERT(canvas_bundle_unused_valid_value,
                  EXACT_GPU_CANVAS_APP_BUNDLE_UNUSED_VALID_V1 == 2u);
IBEX_C_ABI_ASSERT(owned_bytes_data_first,
                  offsetof(ExHermesOwnedBytes, data) == 0u);
IBEX_C_ABI_ASSERT(value_handle_nonce_first,
                  offsetof(ExHermesValueHandle, runtime_nonce) == 0u);
IBEX_C_ABI_ASSERT(position_label_first,
                  offsetof(ExHermesSourcePosition, source_label) == 0u);
IBEX_C_ABI_ASSERT(position_line_after_label,
                  offsetof(ExHermesSourcePosition, line) ==
                      sizeof(ExHermesOwnedBytes));
IBEX_C_ABI_ASSERT(position_column_after_line,
                  offsetof(ExHermesSourcePosition, column) ==
                      sizeof(ExHermesOwnedBytes) + sizeof(uint32_t));
IBEX_C_ABI_ASSERT(credential_size_after_version,
                  offsetof(ExHermesSessionCredential, struct_size) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesSessionCredential, abi_version));
IBEX_C_ABI_ASSERT(credential_token_after_size,
                  offsetof(ExHermesSessionCredential, session_token) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesSessionCredential, struct_size));
IBEX_C_ABI_ASSERT(credential_binding_after_token,
                  offsetof(ExHermesSessionCredential, request_binding) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesSessionCredential, session_token));
IBEX_C_ABI_ASSERT(credential_ordinal_after_binding,
                  offsetof(ExHermesSessionCredential, ordinal) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesSessionCredential, request_binding));
IBEX_C_ABI_ASSERT(result_size_after_version,
                  offsetof(ExHermesEvaluationResult, struct_size) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, abi_version));
IBEX_C_ABI_ASSERT(result_outcome_after_size,
                  offsetof(ExHermesEvaluationResult, outcome_tag) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, struct_size));
IBEX_C_ABI_ASSERT(result_fault_after_outcome,
                  offsetof(ExHermesEvaluationResult, fault) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, outcome_tag));
IBEX_C_ABI_ASSERT(result_work_after_fault,
                  offsetof(ExHermesEvaluationResult, work_target_id) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, fault));
IBEX_C_ABI_ASSERT(result_value_after_work,
                  offsetof(ExHermesEvaluationResult, value) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, work_target_id));
IBEX_C_ABI_ASSERT(result_metadata_status_after_value,
                  offsetof(ExHermesEvaluationResult, throw_metadata_status) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, value));
IBEX_C_ABI_ASSERT(result_metadata_fields_after_status,
                  offsetof(ExHermesEvaluationResult, throw_metadata_fields) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, throw_metadata_status));
IBEX_C_ABI_ASSERT(result_error_class_after_metadata,
                  offsetof(ExHermesEvaluationResult, throw_error_class) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, throw_metadata_fields));
IBEX_C_ABI_ASSERT(result_lifecycle_after_error_class,
                  offsetof(ExHermesEvaluationResult, lifecycle_exit_code) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, throw_error_class));
IBEX_C_ABI_ASSERT(result_capabilities_after_lifecycle,
                  offsetof(ExHermesEvaluationResult, capability_flags) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, lifecycle_exit_code));
IBEX_C_ABI_ASSERT(result_message_after_capabilities,
                  offsetof(ExHermesEvaluationResult, message) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, capability_flags));
IBEX_C_ABI_ASSERT(result_stack_after_message,
                  offsetof(ExHermesEvaluationResult, stack) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, message));
IBEX_C_ABI_ASSERT(result_positions_after_stack,
                  offsetof(ExHermesEvaluationResult, positions) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, stack));
IBEX_C_ABI_ASSERT(result_position_count_after_positions,
                  offsetof(ExHermesEvaluationResult, position_count) >=
                      IBEX_C_ABI_MEMBER_END(
                          ExHermesEvaluationResult, positions));
#if UINTPTR_MAX == UINT64_MAX
/* LLP 0002 freezes every field and aggregate size on the supported 64-bit
 * ABI. Keep these assertions exhaustive: a new/reordered tail field must
 * require an intentional ABI-version amendment instead of merely preserving
 * the three early offsets an older harness happened to inspect. */
IBEX_C_ABI_ASSERT(owned_bytes_length_offset_64,
                  offsetof(ExHermesOwnedBytes, length) == 8u);
IBEX_C_ABI_ASSERT(owned_bytes_size_64,
                  sizeof(ExHermesOwnedBytes) == 16u);
IBEX_C_ABI_ASSERT(position_line_offset_64,
                  offsetof(ExHermesSourcePosition, line) == 16u);
IBEX_C_ABI_ASSERT(position_column_offset_64,
                  offsetof(ExHermesSourcePosition, column) == 20u);
IBEX_C_ABI_ASSERT(position_size_64,
                  sizeof(ExHermesSourcePosition) == 24u);
IBEX_C_ABI_ASSERT(value_handle_id_offset_64,
                  offsetof(ExHermesValueHandle, handle_id) == 8u);
IBEX_C_ABI_ASSERT(value_handle_size_64,
                  sizeof(ExHermesValueHandle) == 16u);
IBEX_C_ABI_ASSERT(credential_version_offset_64,
                  offsetof(ExHermesSessionCredential, abi_version) == 0u);
IBEX_C_ABI_ASSERT(credential_size_field_offset_64,
                  offsetof(ExHermesSessionCredential, struct_size) == 4u);
IBEX_C_ABI_ASSERT(credential_token_offset_64,
                  offsetof(ExHermesSessionCredential, session_token) == 8u);
IBEX_C_ABI_ASSERT(credential_binding_offset_64,
                  offsetof(ExHermesSessionCredential, request_binding) == 40u);
IBEX_C_ABI_ASSERT(credential_ordinal_offset_64,
                  offsetof(ExHermesSessionCredential, ordinal) == 72u);
IBEX_C_ABI_ASSERT(credential_size_64,
                  sizeof(ExHermesSessionCredential) == 80u);
IBEX_C_ABI_ASSERT(result_version_offset_64,
                  offsetof(ExHermesEvaluationResult, abi_version) == 0u);
IBEX_C_ABI_ASSERT(result_size_field_offset_64,
                  offsetof(ExHermesEvaluationResult, struct_size) == 4u);
IBEX_C_ABI_ASSERT(result_outcome_offset_64,
                  offsetof(ExHermesEvaluationResult, outcome_tag) == 8u);
IBEX_C_ABI_ASSERT(result_fault_offset_64,
                  offsetof(ExHermesEvaluationResult, fault) == 12u);
IBEX_C_ABI_ASSERT(result_work_offset_64,
                  offsetof(ExHermesEvaluationResult, work_target_id) == 16u);
IBEX_C_ABI_ASSERT(result_value_offset_64,
                  offsetof(ExHermesEvaluationResult, value) == 24u);
IBEX_C_ABI_ASSERT(result_metadata_status_offset_64,
                  offsetof(ExHermesEvaluationResult, throw_metadata_status) ==
                      40u);
IBEX_C_ABI_ASSERT(result_metadata_fields_offset_64,
                  offsetof(ExHermesEvaluationResult, throw_metadata_fields) ==
                      44u);
IBEX_C_ABI_ASSERT(result_error_class_offset_64,
                  offsetof(ExHermesEvaluationResult, throw_error_class) ==
                      48u);
IBEX_C_ABI_ASSERT(result_lifecycle_offset_64,
                  offsetof(ExHermesEvaluationResult, lifecycle_exit_code) ==
                      52u);
IBEX_C_ABI_ASSERT(result_capabilities_offset_64,
                  offsetof(ExHermesEvaluationResult, capability_flags) == 56u);
IBEX_C_ABI_ASSERT(result_message_offset_64,
                  offsetof(ExHermesEvaluationResult, message) == 64u);
IBEX_C_ABI_ASSERT(result_stack_offset_64,
                  offsetof(ExHermesEvaluationResult, stack) == 80u);
IBEX_C_ABI_ASSERT(result_positions_offset_64,
                  offsetof(ExHermesEvaluationResult, positions) == 96u);
IBEX_C_ABI_ASSERT(result_position_count_offset_64,
                  offsetof(ExHermesEvaluationResult, position_count) == 104u);
IBEX_C_ABI_ASSERT(result_size_64,
                  sizeof(ExHermesEvaluationResult) == 112u);
IBEX_C_ABI_ASSERT(decoded_image_identity_size_64,
                  sizeof(ExactGpuDecodedImageIdentityV1) == 32u);
IBEX_C_ABI_ASSERT(decoded_image_request_identity_offset_64,
                  offsetof(ExactGpuDecodedImageRequestV1, identity) == 24u);
IBEX_C_ABI_ASSERT(decoded_image_request_bytes_offset_64,
                  offsetof(ExactGpuDecodedImageRequestV1, encoded_bytes) ==
                      56u);
IBEX_C_ABI_ASSERT(decoded_image_request_size_64,
                  sizeof(ExactGpuDecodedImageRequestV1) == 72u);
IBEX_C_ABI_ASSERT(decoded_image_plane_identity_offset_64,
                  offsetof(ExactGpuDecodedImagePlaneV1, identity) == 48u);
IBEX_C_ABI_ASSERT(decoded_image_plane_decoded_offset_64,
                  offsetof(ExactGpuDecodedImagePlaneV1, decoded_bytes) == 96u);
IBEX_C_ABI_ASSERT(decoded_image_plane_hash_offset_64,
                  offsetof(ExactGpuDecodedImagePlaneV1, encoded_sha256) ==
                      112u);
IBEX_C_ABI_ASSERT(decoded_image_plane_size_64,
                  sizeof(ExactGpuDecodedImagePlaneV1) == 176u);
IBEX_C_ABI_ASSERT(decoded_image_host_api_size_64,
                  sizeof(ExactGpuDecodedImageHostApiV1) == 48u);
IBEX_C_ABI_ASSERT(decoded_image_descriptor_size_64,
                  sizeof(ExactHermesGpuDecodedImageDescriptorV1) == 24u);
IBEX_C_ABI_ASSERT(canvas_receipt_struct_size_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1, struct_size) ==
                      0u);
IBEX_C_ABI_ASSERT(canvas_receipt_version_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1, abi_version) ==
                      4u);
IBEX_C_ABI_ASSERT(canvas_receipt_outcome_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1, outcome) == 8u);
IBEX_C_ABI_ASSERT(canvas_receipt_failure_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1, failure) == 12u);
IBEX_C_ABI_ASSERT(canvas_receipt_protocol_root_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           protocol_root_id) == 16u);
IBEX_C_ABI_ASSERT(canvas_receipt_view_id_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1, view_id) == 20u);
IBEX_C_ABI_ASSERT(canvas_receipt_runtime_generation_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           runtime_generation) == 24u);
IBEX_C_ABI_ASSERT(canvas_receipt_root_instance_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           root_instance_id) == 32u);
IBEX_C_ABI_ASSERT(canvas_receipt_root_generation_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           root_generation) == 40u);
IBEX_C_ABI_ASSERT(canvas_receipt_commit_sequence_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           commit_sequence) == 48u);
IBEX_C_ABI_ASSERT(canvas_receipt_view_generation_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           view_generation) == 56u);
IBEX_C_ABI_ASSERT(canvas_receipt_handle_id_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1, handle_id) ==
                      64u);
IBEX_C_ABI_ASSERT(canvas_receipt_handle_generation_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           handle_generation) == 72u);
IBEX_C_ABI_ASSERT(canvas_receipt_attachment_id_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1, attachment_id) ==
                      80u);
IBEX_C_ABI_ASSERT(canvas_receipt_attachment_generation_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           attachment_generation) == 88u);
IBEX_C_ABI_ASSERT(canvas_receipt_context_id_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1, context_id) ==
                      96u);
IBEX_C_ABI_ASSERT(canvas_receipt_context_generation_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           context_generation) == 104u);
IBEX_C_ABI_ASSERT(canvas_receipt_width_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           drawing_buffer_width) == 112u);
IBEX_C_ABI_ASSERT(canvas_receipt_height_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           drawing_buffer_height) == 116u);
IBEX_C_ABI_ASSERT(canvas_receipt_digest_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           target_authority_digest) == 120u);
IBEX_C_ABI_ASSERT(canvas_receipt_account_token_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           surface_account_token) == 152u);
IBEX_C_ABI_ASSERT(canvas_receipt_account_generation_offset_64,
                  offsetof(ExactGpuCanvasAttachmentReceiptV1,
                           surface_account_generation) == 160u);
IBEX_C_ABI_ASSERT(canvas_receipt_size_64,
                  sizeof(ExactGpuCanvasAttachmentReceiptV1) == 168u);
IBEX_C_ABI_ASSERT(gpu_authority_facts_session_offset_64,
                  offsetof(ExactGpuAuthoritySessionFactsV2,
                           authority_session_id) == 16u);
IBEX_C_ABI_ASSERT(gpu_authority_facts_digest_offset_64,
                  offsetof(ExactGpuAuthoritySessionFactsV2,
                           authority_context_digest) == 184u);
IBEX_C_ABI_ASSERT(gpu_authority_facts_size_64,
                  sizeof(ExactGpuAuthoritySessionFactsV2) == 264u);
IBEX_C_ABI_ASSERT(gpu_authority_presented_handle_size_64,
                  sizeof(ExactGpuAuthorityPresentedHandleV2) == 104u);
IBEX_C_ABI_ASSERT(gpu_authority_decision_facts_offset_64,
                  offsetof(ExactGpuAuthorityDecisionRequestV2, facts) == 16u);
IBEX_C_ABI_ASSERT(gpu_authority_decision_size_64,
                  sizeof(ExactGpuAuthorityDecisionRequestV2) == 296u);
IBEX_C_ABI_ASSERT(gpu_authority_retire_size_64,
                  sizeof(ExactGpuAuthorityRetireV2) == 280u);
IBEX_C_ABI_ASSERT(gpu_authority_batch_decisions_offset_64,
                  offsetof(ExactGpuAuthorityDecisionBatchV2, decisions) ==
                      16u);
IBEX_C_ABI_ASSERT(gpu_authority_batch_count_offset_64,
                  offsetof(ExactGpuAuthorityDecisionBatchV2,
                           decision_count) == 24u);
IBEX_C_ABI_ASSERT(gpu_authority_batch_size_64,
                  sizeof(ExactGpuAuthorityDecisionBatchV2) == 32u);
IBEX_C_ABI_ASSERT(gpu_authority_batch_callback_offset_64,
                  offsetof(ExactGpuAuthoritySessionApiV2,
                           evaluate_batch_and_then) == 32u);
IBEX_C_ABI_ASSERT(gpu_authority_api_size_64,
                  sizeof(ExactGpuAuthoritySessionApiV2) == 40u);
IBEX_C_ABI_ASSERT(gpu_realm_open_authority_api_offset_64,
                  offsetof(ExactGpuRealmOpenV2, authority_session_api) == 96u);
IBEX_C_ABI_ASSERT(gpu_realm_open_size_64,
                  sizeof(ExactGpuRealmOpenV2) == 104u);
IBEX_C_ABI_ASSERT(gpu_semantic_call_authority_session_offset_64,
                  offsetof(ExactGpuSemanticCallV2, authority_session_id) ==
                      216u);
IBEX_C_ABI_ASSERT(gpu_semantic_call_size_64,
                  sizeof(ExactGpuSemanticCallV2) == 288u);
IBEX_C_ABI_ASSERT(gpu_provenance_authority_session_offset_64,
                  offsetof(ExactGpuOperationProvenanceV2,
                           authority_session_id) == 248u);
IBEX_C_ABI_ASSERT(gpu_provenance_size_64,
                  sizeof(ExactGpuOperationProvenanceV2) == 304u);
IBEX_C_ABI_ASSERT(gpu_cancel_authority_session_offset_64,
                  offsetof(ExactGpuCancelV2, authority_session_id) == 216u);
IBEX_C_ABI_ASSERT(gpu_cancel_size_64,
                  sizeof(ExactGpuCancelV2) == 272u);
#endif
IBEX_C_ABI_ASSERT(work_unit_target_offset,
                  offsetof(ExHermesWorkUnitEvent, target_id) == 16u);
IBEX_C_ABI_ASSERT(work_unit_scheduling_offset,
                  offsetof(ExHermesWorkUnitEvent, scheduling_id) == 24u);
IBEX_C_ABI_ASSERT(cancellation_resolution_offset,
                  offsetof(ExHermesCancellationEvent, resolution) == 8u);
IBEX_C_ABI_ASSERT(cancellation_target_offset,
                  offsetof(ExHermesCancellationEvent, target_id) == 16u);
IBEX_C_ABI_ASSERT(cancellation_event_size,
                  sizeof(ExHermesCancellationEvent) == 24u);
IBEX_C_ABI_ASSERT(async_failure_value_offset,
                  offsetof(ExHermesAsyncFailureEvent, value) == 16u);
IBEX_C_ABI_ASSERT(async_failure_context_offset,
                  offsetof(ExHermesAsyncFailureEvent, host_context_id) == 32u);
IBEX_C_ABI_ASSERT(async_failure_event_size,
                  sizeof(ExHermesAsyncFailureEvent) == 72u);
IBEX_C_ABI_ASSERT(declaration_kind_offset,
                  offsetof(ExHermesSessionDeclaration, kind) ==
                      sizeof(void*) + sizeof(size_t));
IBEX_C_ABI_ASSERT(import_plan_version_offset,
                  offsetof(ExHermesSessionImportPlan, abi_version) == 0u);
IBEX_C_ABI_ASSERT(import_plan_size_after_file_arguments,
                  sizeof(ExHermesSessionImportPlan) >=
                      offsetof(ExHermesSessionImportPlan,
                               reserved) +
                          sizeof(uint32_t));
IBEX_C_ABI_ASSERT(import_plan_source_id_after_file_arguments,
                  offsetof(ExHermesSessionImportPlan, source_id) >
                      offsetof(ExHermesSessionImportPlan,
                               file_argument_count));
IBEX_C_ABI_ASSERT(import_plan_generated_record_after_source_id,
                  offsetof(ExHermesSessionImportPlan,
                           generated_entry_record) >
                      offsetof(ExHermesSessionImportPlan,
                               source_id_length));
IBEX_C_ABI_ASSERT(file_argument_length_after_data,
                  offsetof(ExHermesUtf8Slice, length) >
                      offsetof(ExHermesUtf8Slice, data));
IBEX_C_ABI_ASSERT(static_import_specifier_after_header,
                  offsetof(ExHermesSessionStaticImport, specifier) >=
                      2u * sizeof(uint32_t));
IBEX_C_ABI_ASSERT(static_import_count_after_first,
                  offsetof(ExHermesSessionStaticImport, binding_count) >
                      offsetof(ExHermesSessionStaticImport, first_binding));
IBEX_C_ABI_ASSERT(import_binding_kind_after_names,
                  offsetof(ExHermesSessionImportBinding, kind) >
                      offsetof(ExHermesSessionImportBinding,
                               imported_name_length));

/* Function-pointer assignments type-check the callable C surface without
 * creating an executable ingress or requiring a link-time call. */
void ibex_exact_runtime_c_abi_typecheck(void) {
  uint32_t (*bind_session)(ExactHermesRuntime*, const uint8_t*, size_t) =
      ex_hermes_structured_session_bind;
  uint32_t (*admit_submission)(ExactHermesRuntime*,
                               const ExHermesSessionCredential*,
                               uint64_t*) =
      ex_hermes_structured_submission_admit;
  uint32_t (*settle_submission)(ExactHermesRuntime*,
                                const ExHermesSessionCredential*) =
      ex_hermes_structured_submission_settle;
  int (*evaluate_session)(ExactHermesRuntime*,
                          const ExHermesSessionCredential*,
                          const uint8_t*,
                          size_t,
                          const uint8_t*,
                          size_t,
                          ExHermesEvaluationResult*) =
      ex_hermes_eval_structured_session;
  int (*evaluate_lowered_session)(ExactHermesRuntime*,
                                  const ExHermesSessionCredential*,
                                  uint32_t,
                                  const uint8_t*,
                                  size_t,
                                  const uint8_t*,
                                  size_t,
                                  const uint8_t*,
                                  size_t,
                                  const ExHermesSessionDeclaration*,
                                  size_t,
                                  const ExHermesSessionImportPlan*,
                                  bool,
                                  ExHermesEvaluationResult*) =
      ex_hermes_eval_lowered_session;
  int32_t (*module_compile_factory)(ExactHermesRuntime*,
                                    uint64_t,
                                    uint32_t,
                                    uint32_t,
                                    uint64_t,
                                    const uint8_t*,
                                    size_t,
                                    const uint8_t*,
                                    size_t,
                                    const uint8_t*,
                                    size_t,
                                    const uint8_t*,
                                    size_t,
                                    const uint8_t*,
                                    size_t,
                                    ExactModuleRunnerHandle*,
                                    char**,
                                    uint64_t*) =
      ex_hermes_module_compile_factory;
  int32_t (*module_load_carrier_factory)(ExactHermesRuntime*,
                                         uint64_t,
                                         uint32_t,
                                         uint32_t,
                                         uint64_t,
                                         const uint8_t*,
                                         size_t,
                                         const uint8_t*,
                                         size_t,
                                         const uint8_t*,
                                         size_t,
                                         const uint8_t*,
                                         size_t,
                                         const uint8_t*,
                                         size_t,
                                         uint32_t,
                                         const uint8_t*,
                                         size_t,
                                         const uint8_t*,
                                         size_t,
                                         ExactModuleRunnerHandle*,
                                         char**,
                                         uint64_t*) =
      ex_hermes_module_load_carrier_factory;
  int32_t (*commonjs_record_evaluate)(ExactHermesRuntime*,
                                      uint64_t,
                                      ExactModuleRunnerHandle,
                                      int32_t*,
                                      char**,
                                      uint64_t*) =
      ex_hermes_commonjs_record_evaluate;
  int32_t (*commonjs_record_create_esm_adapter)(ExactHermesRuntime*,
                                                uint64_t,
                                                ExactModuleRunnerHandle,
                                                ExactModuleRunnerHandle*,
                                                char**,
                                                uint64_t*) =
      ex_hermes_commonjs_record_create_esm_adapter;
  int32_t (*module_record_instantiate)(ExactHermesRuntime*,
                                       uint64_t,
                                       ExactModuleRunnerHandle,
                                       const uint8_t*,
                                       size_t,
                                       const uint8_t*,
                                       size_t,
                                       int32_t,
                                       char**,
                                       uint64_t*) =
      ex_hermes_module_record_instantiate;
  int32_t (*module_record_run_declare)(ExactHermesRuntime*,
                                       uint64_t,
                                       ExactModuleRunnerHandle,
                                       char**,
                                       uint64_t*) =
      ex_hermes_module_record_run_declare;
  int32_t (*module_record_run_execute)(ExactHermesRuntime*,
                                       uint64_t,
                                       ExactModuleRunnerHandle,
                                       int32_t*,
                                       char**,
                                       uint64_t*) =
      ex_hermes_module_record_run_execute;
  int32_t (*module_record_poll_evaluation)(ExactHermesRuntime*,
                                           uint64_t,
                                           ExactModuleRunnerHandle,
                                           int32_t*,
                                           char**,
                                           uint64_t*) =
      ex_hermes_module_record_poll_evaluation;
  int32_t (*module_record_namespace_json)(ExactHermesRuntime*,
                                          uint64_t,
                                          ExactModuleRunnerHandle,
                                          char**,
                                          char**,
                                          uint64_t*) =
      ex_hermes_module_record_namespace_json;
  uint32_t (*begin_module_graph)(ExactHermesRuntime*,
                                 const ExHermesSessionCredential*,
                                 const ExHermesUtf8Slice*,
                                 size_t) =
      ex_hermes_structured_module_graph_begin;
  uint32_t (*suspend_module_graph)(ExactHermesRuntime*, uint64_t) =
      ex_hermes_structured_module_graph_suspend;
  uint32_t (*resume_module_graph)(ExactHermesRuntime*, uint64_t) =
      ex_hermes_structured_module_graph_resume;
  int (*finish_module_graph)(ExactHermesRuntime*,
                             uint64_t,
                             uint32_t,
                             uint64_t,
                             ExHermesEvaluationResult*) =
      ex_hermes_structured_module_graph_finish;
  int (*resume_structured_session)(ExactHermesRuntime*,
                                   uint64_t,
                                   ExHermesEvaluationResult*) =
      ex_hermes_resume_structured_session;
  uint32_t (*finish_bootstrap)(ExactHermesRuntime*) =
      ex_hermes_finish_bootstrap;
  uint32_t (*seal_armed_shared_runtime_globals)(ExactHermesRuntime*) =
      ex_hermes_seal_armed_shared_runtime_globals_v1;
  int32_t (*evaluate_gpu_canvas_immediate)(ExactHermesRuntime*,
                                           const uint8_t*,
                                           size_t,
                                           const char*,
                                           int,
                                           char**) =
      ex_hermes_eval_gpu_canvas_app_bundle_immediate_v1;
  int32_t (*evaluate_gpu_canvas_with_prelude_immediate)(
      ExactHermesRuntime*,
      const uint8_t*,
      size_t,
      const char*,
      const uint8_t*,
      size_t,
      const char*,
      int,
      char**) =
      ex_hermes_eval_gpu_canvas_app_bundle_with_prelude_immediate_v1;
  int32_t (*begin_app_bundle_evaluation)(ExactHermesRuntime*, uint32_t) =
      ex_hermes_begin_app_bundle_evaluation_v1;
  int32_t (*finish_app_bundle_evaluation)(ExactHermesRuntime*, uint32_t) =
      ex_hermes_finish_app_bundle_evaluation_v1;
  int32_t (*classify_prepared_startup)(ExactHermesRuntime*, uint32_t) =
      ex_hermes_classify_prepared_native_startup_v1;
  int32_t (*stage_prepared_startup)(ExactHermesRuntime*, char**) =
      ex_hermes_stage_prepared_native_startup_v1;
  int32_t (*run_prepared_app)(ExactHermesRuntime*, char**) =
      ex_hermes_run_prepared_app_v1;
  int32_t (*verify_prepared_startup_absent)(ExactHermesRuntime*) =
      ex_hermes_verify_prepared_native_startup_absent_v1;
  int32_t (*quarantine_runtime)(ExactHermesRuntime*) =
      ex_hermes_quarantine_runtime_v1;
  uint32_t (*runtime_is_quarantined)(const ExactHermesRuntime*) =
      ex_hermes_runtime_is_quarantined_v1;
  uint32_t (*take_work_unit)(ExactHermesRuntime*,
                             uint64_t,
                             ExHermesWorkUnitEvent*) =
      ex_hermes_take_work_unit_event;
  uint32_t (*take_cancellation)(ExactHermesRuntime*,
                                uint64_t,
                                ExHermesCancellationEvent*) =
      ex_hermes_take_cancellation_event;
  uint32_t (*take_async_failure)(ExactHermesRuntime*,
                                 ExHermesAsyncFailureEvent*) =
      ex_hermes_take_async_failure_event;
  uint64_t (*active_work_target)(ExactHermesRuntime*, uint64_t) =
      ex_hermes_structured_active_work_target;
  uint32_t (*cancel_work_target)(ExactHermesRuntime*, uint64_t, uint64_t) =
      ex_hermes_cancel_structured_work_target;
  int32_t (*authorize_exit)(uint64_t,
                            const uint64_t*,
                            size_t,
                            uint32_t,
                            int32_t,
                            uint32_t,
                            int32_t*) =
      ex_host_authorize_typed_lifecycle_exit_stack;
  uint32_t (*authorize_typed_fs)(uint64_t,
                                 uint64_t,
                                 const uint64_t*,
                                 size_t,
                                 const char*,
                                 uint32_t,
                                 uint32_t,
                                 int32_t,
                                 int32_t,
                                 int32_t,
                                 int32_t,
                                 const char*) =
      ex_host_authorize_typed_fs_stack;
  int32_t (*get_exit_code)(uint64_t,
                           const uint64_t*,
                           size_t,
                           int32_t*) =
      ex_host_lifecycle_exit_code_get_stack;
  int32_t (*set_exit_code)(uint64_t,
                           const uint64_t*,
                           size_t,
                           int32_t) =
      ex_host_lifecycle_exit_code_set_stack;
  uint32_t (*stage1_text)(ExactHermesRuntime*,
                          ExHermesValueHandle,
                          uint8_t**,
                          size_t*,
                          uint32_t*) =
      ex_hermes_value_stage1_text;
  uint32_t (*safe_throw_metadata)(ExactHermesRuntime*,
                                  ExHermesValueHandle,
                                  uint32_t*,
                                  uint32_t*,
                                  ExHermesOwnedBytes*,
                                  ExHermesOwnedBytes*) =
      ex_hermes_value_safe_throw_metadata;
  uint32_t (*display_ack)(ExactHermesRuntime*,
                          uint64_t,
                          ExHermesValueHandle,
                          bool) =
      ex_hermes_session_display_ack;
  int32_t (*descriptor_is_protected)(int32_t) =
      ex_host_session_descriptor_is_protected;
  int32_t (*descriptor_read_route)(int32_t) =
      ex_host_session_descriptor_read_route;
  int32_t (*descriptor_write_route)(int32_t) =
      ex_host_session_descriptor_write_route;
  int32_t (*descriptor_close_route)(int32_t) =
      ex_host_session_descriptor_close_route;
  int32_t (*descriptor_alias_source_route)(int32_t) =
      ex_host_session_descriptor_alias_source_route;
  int32_t (*descriptor_alias_target_route)(int32_t) =
      ex_host_session_descriptor_alias_target_route;
  int32_t (*terminal_stdio_query)(int32_t, int32_t*, uint16_t*, uint16_t*) =
      ex_host_terminal_session_stdio_query;
  void (*console_log_bytes)(int32_t, const uint8_t*, size_t) =
      ex_host_console_log_bytes;
  (void)bind_session;
  (void)admit_submission;
  (void)settle_submission;
  (void)evaluate_session;
  (void)evaluate_lowered_session;
  (void)module_compile_factory;
  (void)module_load_carrier_factory;
  (void)commonjs_record_evaluate;
  (void)commonjs_record_create_esm_adapter;
  (void)module_record_instantiate;
  (void)module_record_run_declare;
  (void)module_record_run_execute;
  (void)module_record_poll_evaluation;
  (void)module_record_namespace_json;
  (void)begin_module_graph;
  (void)suspend_module_graph;
  (void)resume_module_graph;
  (void)finish_module_graph;
  (void)resume_structured_session;
  (void)finish_bootstrap;
  (void)seal_armed_shared_runtime_globals;
  (void)evaluate_gpu_canvas_immediate;
  (void)evaluate_gpu_canvas_with_prelude_immediate;
  (void)begin_app_bundle_evaluation;
  (void)finish_app_bundle_evaluation;
  (void)classify_prepared_startup;
  (void)stage_prepared_startup;
  (void)run_prepared_app;
  (void)verify_prepared_startup_absent;
  (void)quarantine_runtime;
  (void)runtime_is_quarantined;
  (void)take_work_unit;
  (void)take_cancellation;
  (void)take_async_failure;
  (void)active_work_target;
  (void)cancel_work_target;
  (void)authorize_exit;
  (void)authorize_typed_fs;
  (void)get_exit_code;
  (void)set_exit_code;
  (void)stage1_text;
  (void)safe_throw_metadata;
  (void)display_ack;
  (void)descriptor_is_protected;
  (void)descriptor_read_route;
  (void)descriptor_write_route;
  (void)descriptor_close_route;
  (void)descriptor_alias_source_route;
  (void)descriptor_alias_target_route;
  (void)terminal_stdio_query;
  (void)console_log_bytes;
}

#if defined(IBEX_CAPSEC_CONFORMANCE_OBSERVER)

/* These controls are deliberately absent from production.  They let the C
 * consumer exercise failure/race branches of the public ABI deterministically
 * without making either control part of exact_runtime.h. */
extern void ibex_test_fail_next_structured_value_handle_allocation(void);
extern uint64_t ibex_test_structured_async_root_count(
    ExactHermesRuntime* runtime,
    uint32_t selector);
extern uint64_t ibex_test_take_destroyed_structured_value_handle_count(
    uint64_t runtime_nonce);
extern int32_t ibex_test_enable_work_unit_publication(
    ExactHermesRuntime* runtime);
extern int32_t ibex_test_release_blocking_native_work(
    ExactHermesRuntime* runtime);

typedef struct IbexExactRuntimeCAbiProbe {
  ExactHermesRuntime* runtime;
  ExHermesValueHandle handle;
} IbexExactRuntimeCAbiProbe;

static int ibex_c_abi_result_has_no_payload(
    const ExHermesEvaluationResult* result) {
  return result->value.runtime_nonce == 0 && result->value.handle_id == 0 &&
      result->throw_metadata_status == EX_HERMES_THROW_METADATA_UNAVAILABLE &&
      result->throw_metadata_fields == 0 &&
      result->throw_error_class == EX_HERMES_ERROR_CLASS_UNCLASSIFIED &&
      result->message.data == NULL &&
      result->message.length == 0 && result->stack.data == NULL &&
      result->stack.length == 0 && result->positions == NULL &&
      result->position_count == 0;
}

static int ibex_c_abi_eval_value(
    ExactHermesRuntime* runtime,
    const uint8_t* source,
    size_t source_length,
    ExHermesEvaluationResult* result) {
  static const uint8_t label[] = "ibex:c11-abi-probe";
  ex_hermes_evaluation_result_init(result);
  return ex_hermes_eval_structured_diagnostic(
      runtime,
      source,
      source_length,
      label,
      sizeof(label) - 1,
      result);
}

/* Mint a live value in `runtime` whose numeric handle id collides with an
 * existing handle from another runtime generation. Intermediate ids are
 * released, while the exact collision remains rooted for the caller. A small
 * bound keeps a corrupted allocator from turning a conformance failure into an
 * unbounded loop. */
static int ibex_c_abi_mint_colliding_handle(
    ExactHermesRuntime* runtime,
    uint64_t target_handle_id,
    ExHermesValueHandle* out_handle) {
  static const uint8_t source[] = "'collision'";
  ExHermesEvaluationResult candidate;
  ExHermesValueHandle handle = {0, 0};
  uint64_t attempt;
  if (runtime == NULL || out_handle == NULL || target_handle_id == 0 ||
      target_handle_id > 64) {
    return -1;
  }
  *out_handle = (ExHermesValueHandle){0, 0};
  for (attempt = 0; attempt < target_handle_id; ++attempt) {
    if (ibex_c_abi_eval_value(
            runtime, source, sizeof(source) - 1, &candidate) != 0) {
      return -2;
    }
    handle = candidate.value;
    if (candidate.outcome_tag != EX_HERMES_EVAL_OUTCOME_VALUE ||
        handle.runtime_nonce == 0 || handle.handle_id == 0 ||
        handle.handle_id > target_handle_id) {
      ex_hermes_evaluation_result_dispose(&candidate);
      if (handle.runtime_nonce != 0 && handle.handle_id != 0) {
        (void)ex_hermes_value_release(runtime, handle);
      }
      return -3;
    }
    ex_hermes_evaluation_result_dispose(&candidate);
    if (handle.handle_id == target_handle_id) {
      *out_handle = handle;
      return 0;
    }
    if (ex_hermes_value_release(runtime, handle) !=
        EX_HERMES_EVAL_FAULT_NONE) {
      return -4;
    }
  }
  return -5;
}

/* Prepare one live rooted string after proving explicit-length embedded-NUL
 * delivery, the typed allocation-failure branch, and wrong-runtime rejection.
 * The caller must invoke the wrong-thread probe and then the owner-thread
 * finish probe with the returned opaque context. */
int32_t ibex_exact_runtime_c_abi_probe_prepare(void** out_context) {
  static const uint8_t nul_source[] = "'left\\0right'";
  static const uint8_t expected[] = {
      'l', 'e', 'f', 't', 0, 'r', 'i', 'g', 'h', 't'};
  static const uint8_t oom_source[] = "42";
  static const uint8_t bounded_source[] = "'x'.repeat(17000)";
  IbexExactRuntimeCAbiProbe* context = NULL;
  ExactHermesRuntime* other_runtime = NULL;
  ExHermesEvaluationResult result;
  ExHermesEvaluationResult oom_result;
  ExHermesEvaluationResult bounded_result;
  ExHermesValueHandle other_handle = {0, 0};
  ExHermesValueHandle bounded_handle = {0, 0};
  uint8_t* rendered = NULL;
  size_t rendered_length = 0;
  uint32_t rendered_truncated = 0;
  int32_t status = -1;
  int result_initialized = 0;
  int oom_result_initialized = 0;
  int bounded_result_initialized = 0;

  if (out_context == NULL) return -2;
  *out_context = NULL;
  context = (IbexExactRuntimeCAbiProbe*)calloc(1, sizeof(*context));
  if (context == NULL) return -3;
  context->runtime = ex_hermes_create_diagnostic();
  if (context->runtime == NULL) {
    status = -4;
    goto fail;
  }
  if (ibex_test_enable_work_unit_publication(context->runtime) != 1) {
    status = -5;
    goto fail;
  }

  if (ibex_c_abi_eval_value(
          context->runtime,
          nul_source,
          sizeof(nul_source) - 1,
          &result) != 0) {
    status = -6;
    goto fail;
  }
  result_initialized = 1;
  if (result.outcome_tag != EX_HERMES_EVAL_OUTCOME_VALUE ||
      result.fault != EX_HERMES_EVAL_FAULT_NONE ||
      result.value.runtime_nonce == 0 || result.value.handle_id == 0) {
    status = -7;
    goto fail;
  }
  context->handle = result.value;
  if (ex_hermes_value_stage1_text(
          context->runtime,
          context->handle,
          &rendered,
          &rendered_length,
          &rendered_truncated) != EX_HERMES_EVAL_FAULT_NONE ||
      rendered == NULL || rendered_length != sizeof(expected) ||
      rendered_truncated != 0 ||
      memcmp(rendered, expected, sizeof(expected)) != 0) {
    status = -8;
    goto fail;
  }
  ex_hermes_free_string((char*)rendered);
  rendered = NULL;
  rendered_length = 0;
  rendered_truncated = 0;
  if (ibex_c_abi_eval_value(
          context->runtime,
          bounded_source,
          sizeof(bounded_source) - 1,
          &bounded_result) != 0) {
    status = -80;
    goto fail;
  }
  bounded_result_initialized = 1;
  bounded_handle = bounded_result.value;
  if (bounded_result.outcome_tag != EX_HERMES_EVAL_OUTCOME_VALUE ||
      ex_hermes_value_stage1_text(
          context->runtime,
          bounded_handle,
          &rendered,
          &rendered_length,
          &rendered_truncated) != EX_HERMES_EVAL_FAULT_NONE ||
      rendered == NULL || rendered_length != EX_HERMES_SAFE_TEXT_MAX_BYTES ||
      rendered_truncated != 1 ||
      memcmp(
          rendered + rendered_length -
              (sizeof(EX_HERMES_SAFE_TEXT_TRUNCATION_MARKER) - 1),
          EX_HERMES_SAFE_TEXT_TRUNCATION_MARKER,
          sizeof(EX_HERMES_SAFE_TEXT_TRUNCATION_MARKER) - 1) != 0) {
    status = -81;
    goto fail;
  }
  ex_hermes_free_string((char*)rendered);
  rendered = NULL;
  rendered_length = 0;
  rendered_truncated = 0;
  if (ex_hermes_value_release(context->runtime, bounded_handle) !=
      EX_HERMES_EVAL_FAULT_NONE) {
    status = -82;
    goto fail;
  }
  bounded_handle = (ExHermesValueHandle){0, 0};
  ex_hermes_evaluation_result_dispose(&bounded_result);
  bounded_result_initialized = 0;
  if (ibex_test_structured_async_root_count(context->runtime, 2) != 1) {
    status = -9;
    goto fail;
  }

  other_runtime = ex_hermes_create_diagnostic();
  if (other_runtime == NULL) {
    status = -10;
    goto fail;
  }
  if (ibex_test_enable_work_unit_publication(other_runtime) != 1) {
    status = -11;
    goto fail;
  }
  if (ibex_c_abi_mint_colliding_handle(
          other_runtime, context->handle.handle_id, &other_handle) != 0 ||
      other_handle.handle_id != context->handle.handle_id ||
      other_handle.runtime_nonce == context->handle.runtime_nonce ||
      ex_hermes_value_kind(other_runtime, other_handle) !=
          EX_HERMES_VALUE_STRING ||
      ibex_test_structured_async_root_count(other_runtime, 2) != 1) {
    status = -12;
    goto fail;
  }
  rendered = (uint8_t*)(uintptr_t)1;
  rendered_length = 99;
  rendered_truncated = 99;
  {
    uint32_t wrong_kind =
        ex_hermes_value_kind(other_runtime, context->handle);
    uint32_t wrong_text = ex_hermes_value_stage1_text(
        other_runtime,
        context->handle,
        &rendered,
        &rendered_length,
        &rendered_truncated);
    uint32_t wrong_release =
        ex_hermes_value_release(other_runtime, context->handle);
    if (wrong_kind != EX_HERMES_VALUE_INVALID ||
        wrong_text != EX_HERMES_EVAL_FAULT_STALE_HANDLE ||
        wrong_release != EX_HERMES_EVAL_FAULT_STALE_HANDLE ||
        rendered != NULL || rendered_length != 0 || rendered_truncated != 0 ||
        ibex_test_structured_async_root_count(context->runtime, 2) != 1 ||
        ex_hermes_value_kind(other_runtime, other_handle) !=
            EX_HERMES_VALUE_STRING ||
        ex_hermes_value_release(other_runtime, other_handle) !=
            EX_HERMES_EVAL_FAULT_NONE ||
        ibex_test_structured_async_root_count(other_runtime, 2) != 0) {
      if (rendered != NULL && rendered != (uint8_t*)(uintptr_t)1) {
        ex_hermes_free_string((char*)rendered);
        rendered = NULL;
      }
      status = -13;
      goto fail;
    }
  }
  other_handle = (ExHermesValueHandle){0, 0};
  ex_hermes_destroy(other_runtime);
  other_runtime = NULL;

  ibex_test_fail_next_structured_value_handle_allocation();
  if (ibex_c_abi_eval_value(
          context->runtime,
          oom_source,
          sizeof(oom_source) - 1,
          &oom_result) != 0) {
    status = -14;
    goto fail;
  }
  oom_result_initialized = 1;
  if (oom_result.outcome_tag != EX_HERMES_EVAL_OUTCOME_ENGINE_FAULT ||
      oom_result.fault != EX_HERMES_EVAL_FAULT_OUT_OF_MEMORY ||
      !ibex_c_abi_result_has_no_payload(&oom_result) ||
      ibex_test_structured_async_root_count(context->runtime, 2) != 1) {
    status = -15;
    goto fail;
  }
  ex_hermes_evaluation_result_dispose(&oom_result);
  oom_result_initialized = 0;
  ex_hermes_evaluation_result_dispose(&result);
  result_initialized = 0;
  *out_context = context;
  return 0;

fail:
  if (rendered != NULL && rendered != (uint8_t*)(uintptr_t)1) {
    ex_hermes_free_string((char*)rendered);
  }
  if (oom_result_initialized) {
    ex_hermes_evaluation_result_dispose(&oom_result);
  }
  if (bounded_result_initialized) {
    ex_hermes_evaluation_result_dispose(&bounded_result);
  }
  if (result_initialized) {
    ex_hermes_evaluation_result_dispose(&result);
  }
  if (other_runtime != NULL) {
    if (other_handle.runtime_nonce != 0 && other_handle.handle_id != 0) {
      (void)ex_hermes_value_release(other_runtime, other_handle);
    }
    ex_hermes_destroy(other_runtime);
  }
  if (context != NULL && context->runtime != NULL) {
    if (bounded_handle.runtime_nonce != 0 && bounded_handle.handle_id != 0) {
      (void)ex_hermes_value_release(context->runtime, bounded_handle);
    }
    if (context->handle.runtime_nonce != 0 && context->handle.handle_id != 0) {
      (void)ex_hermes_value_release(context->runtime, context->handle);
    }
    ex_hermes_destroy(context->runtime);
  }
  free(context);
  return status;
}

/* This function is called by a Rust-created foreign thread, but every public
 * ABI call and every expected wrong-thread assertion remains in C. */
int32_t ibex_exact_runtime_c_abi_probe_wrong_thread(void* opaque_context) {
  IbexExactRuntimeCAbiProbe* context =
      (IbexExactRuntimeCAbiProbe*)opaque_context;
  uint8_t* rendered = (uint8_t*)(uintptr_t)1;
  size_t rendered_length = 99;
  uint32_t rendered_truncated = 99;
  uint32_t metadata_fields = 99;
  uint32_t error_class = 99;
  ExHermesOwnedBytes message = {(uint8_t*)(uintptr_t)1, 99};
  ExHermesOwnedBytes stack = {(uint8_t*)(uintptr_t)1, 99};
  if (context == NULL || context->runtime == NULL) return -20;
  if (ex_hermes_value_kind(context->runtime, context->handle) !=
      EX_HERMES_VALUE_INVALID) {
    return -21;
  }
  if (ex_hermes_value_stage1_text(
          context->runtime,
          context->handle,
          &rendered,
          &rendered_length,
          &rendered_truncated) != EX_HERMES_EVAL_FAULT_WRONG_THREAD ||
      rendered != NULL || rendered_length != 0 || rendered_truncated != 0) {
    return -22;
  }
  if (ex_hermes_value_release(context->runtime, context->handle) !=
      EX_HERMES_EVAL_FAULT_WRONG_THREAD) {
    return -23;
  }
  if (ex_hermes_value_safe_throw_metadata(
          context->runtime,
          context->handle,
          &metadata_fields,
          &error_class,
          &message,
          &stack) != EX_HERMES_EVAL_FAULT_WRONG_THREAD ||
      metadata_fields != 0 ||
      error_class != EX_HERMES_ERROR_CLASS_UNCLASSIFIED ||
      message.data != NULL || message.length != 0 || stack.data != NULL ||
      stack.length != 0) {
    return -24;
  }
  return 0;
}

/* Finish on the runtime owner thread.  This proves that the foreign-thread
 * rejection did not consume the root, release is exact-once, and destroying a
 * runtime with one unreleased handle cleans that handle before Hermes dies. */
int32_t ibex_exact_runtime_c_abi_probe_finish(void* opaque_context) {
  static const uint8_t cleanup_source[] = "'cleanup'";
  IbexExactRuntimeCAbiProbe* context =
      (IbexExactRuntimeCAbiProbe*)opaque_context;
  ExHermesEvaluationResult cleanup_result;
  ExactHermesRuntime* replacement = NULL;
  ExHermesValueHandle destroyed_handle = {0, 0};
  ExHermesValueHandle replacement_handle = {0, 0};
  uint64_t destroyed_nonce = 0;
  uint8_t* rendered = NULL;
  size_t rendered_length = 0;
  uint32_t rendered_truncated = 0;
  int32_t status = 0;
  int cleanup_result_initialized = 0;

  if (context == NULL || context->runtime == NULL) return -30;
  if (ibex_test_structured_async_root_count(context->runtime, 2) != 1 ||
      ex_hermes_value_kind(context->runtime, context->handle) !=
          EX_HERMES_VALUE_STRING) {
    status = -31;
    goto done;
  }
  if (ex_hermes_value_release(context->runtime, context->handle) !=
          EX_HERMES_EVAL_FAULT_NONE ||
      ex_hermes_value_release(context->runtime, context->handle) !=
          EX_HERMES_EVAL_FAULT_STALE_HANDLE) {
    status = -32;
    goto done;
  }
  if (ex_hermes_value_stage1_text(
          context->runtime,
          context->handle,
          &rendered,
          &rendered_length,
          &rendered_truncated) != EX_HERMES_EVAL_FAULT_STALE_HANDLE ||
      rendered != NULL || rendered_length != 0 || rendered_truncated != 0 ||
      ibex_test_structured_async_root_count(context->runtime, 2) != 0) {
    status = -33;
    goto done;
  }
  context->handle = (ExHermesValueHandle){0, 0};

  if (ibex_c_abi_eval_value(
          context->runtime,
          cleanup_source,
          sizeof(cleanup_source) - 1,
          &cleanup_result) != 0) {
    status = -34;
    goto done;
  }
  cleanup_result_initialized = 1;
  if (cleanup_result.outcome_tag != EX_HERMES_EVAL_OUTCOME_VALUE ||
      cleanup_result.value.runtime_nonce == 0 ||
      cleanup_result.value.handle_id == 0 ||
      ibex_test_structured_async_root_count(context->runtime, 2) != 1) {
    status = -35;
    goto done;
  }
  destroyed_handle = cleanup_result.value;
  destroyed_nonce = ex_hermes_runtime_nonce(context->runtime);
  ex_hermes_evaluation_result_dispose(&cleanup_result);
  cleanup_result_initialized = 0;
  ex_hermes_destroy(context->runtime);
  context->runtime = NULL;

  if (ibex_test_take_destroyed_structured_value_handle_count(destroyed_nonce) !=
      1) {
    status = -36;
    goto done;
  }
  replacement = ex_hermes_create_diagnostic();
  if (replacement == NULL) {
    status = -37;
    goto done;
  }
  if (ibex_test_enable_work_unit_publication(replacement) != 1) {
    status = -38;
    goto done;
  }
  if (ibex_c_abi_mint_colliding_handle(
          replacement, destroyed_handle.handle_id, &replacement_handle) != 0 ||
      replacement_handle.handle_id != destroyed_handle.handle_id ||
      replacement_handle.runtime_nonce == destroyed_handle.runtime_nonce ||
      ex_hermes_value_kind(replacement, replacement_handle) !=
          EX_HERMES_VALUE_STRING) {
    status = -39;
    goto done;
  }
  rendered = (uint8_t*)(uintptr_t)1;
  rendered_length = 99;
  rendered_truncated = 99;
  {
    uint32_t wrong_kind =
        ex_hermes_value_kind(replacement, destroyed_handle);
    uint32_t wrong_text = ex_hermes_value_stage1_text(
        replacement,
        destroyed_handle,
        &rendered,
        &rendered_length,
        &rendered_truncated);
    uint32_t wrong_release =
        ex_hermes_value_release(replacement, destroyed_handle);
    if (wrong_kind != EX_HERMES_VALUE_INVALID ||
        wrong_text != EX_HERMES_EVAL_FAULT_STALE_HANDLE ||
        wrong_release != EX_HERMES_EVAL_FAULT_STALE_HANDLE ||
        rendered != NULL || rendered_length != 0 || rendered_truncated != 0 ||
        ex_hermes_value_kind(replacement, replacement_handle) !=
            EX_HERMES_VALUE_STRING ||
        ex_hermes_value_release(replacement, replacement_handle) !=
            EX_HERMES_EVAL_FAULT_NONE ||
        ibex_test_structured_async_root_count(replacement, 2) != 0) {
      if (rendered != NULL && rendered != (uint8_t*)(uintptr_t)1) {
        ex_hermes_free_string((char*)rendered);
        rendered = NULL;
      }
      status = -40;
      goto done;
    }
  }
  replacement_handle = (ExHermesValueHandle){0, 0};

done:
  if (cleanup_result_initialized) {
    ex_hermes_evaluation_result_dispose(&cleanup_result);
  }
  if (replacement != NULL) {
    if (replacement_handle.runtime_nonce != 0 &&
        replacement_handle.handle_id != 0) {
      (void)ex_hermes_value_release(replacement, replacement_handle);
    }
    ex_hermes_destroy(replacement);
  }
  if (context->runtime != NULL) {
    if (context->handle.runtime_nonce != 0 && context->handle.handle_id != 0) {
      (void)ex_hermes_value_release(context->runtime, context->handle);
    }
    ex_hermes_destroy(context->runtime);
  }
  free(context);
  return status;
}

/* Controller-thread half of the deterministic normal-return race. */
int32_t ibex_exact_runtime_c_abi_probe_cancel_then_release(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint64_t target_id) {
  uint64_t stale_target =
      target_id == UINT64_MAX ? target_id - 1 : target_id + 1;
  uint64_t active_target;
  uint32_t stale_status;
  uint32_t first_status;
  uint32_t second_status;
  int32_t release_status;
  if (runtime == NULL || runtime_nonce == 0 || target_id == 0 ||
      stale_target == 0) {
    return -40;
  }
  active_target =
      ex_hermes_structured_active_work_target(runtime, runtime_nonce);
  stale_status = ex_hermes_cancel_structured_work_target(
      runtime, runtime_nonce, stale_target);
  first_status = ex_hermes_cancel_structured_work_target(
      runtime, runtime_nonce, target_id);
  second_status = ex_hermes_cancel_structured_work_target(
      runtime, runtime_nonce, target_id);
  /* Always release the deterministic native callback, including when an ABI
   * assertion failed, so the owner thread can return and report the failure. */
  release_status = ibex_test_release_blocking_native_work(runtime);
  if (active_target != target_id) return -41;
  if (stale_status != EX_HERMES_CANCEL_STALE_TARGET) return -42;
  if (first_status != EX_HERMES_CANCEL_ACCEPTED ||
      second_status != EX_HERMES_CANCEL_ACCEPTED) {
    return -43;
  }
  if (release_status != 1) return -44;
  return 0;
}

/* Failure-path cleanup for the Rust thread orchestrating this C-owned race.
 * The guard using it is armed before publication is observed, so a missing
 * Begin record or a controller assertion cannot strand the owner thread in
 * the deterministic blocking callback. */
int32_t ibex_exact_runtime_c_abi_probe_release_blocking_work(
    ExactHermesRuntime* runtime) {
  return ibex_test_release_blocking_native_work(runtime);
}

/* Owner-thread half: normal return must defeat, not accept, the delivered
 * request; exactly one terminal record may be published for the target. */
int32_t ibex_exact_runtime_c_abi_probe_cancel_terminal(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    uint64_t target_id) {
  ExHermesCancellationEvent event = {
      EX_HERMES_CANCELLATION_EVENT_ABI_VERSION,
      (uint32_t)sizeof(ExHermesCancellationEvent),
      0,
      0,
      0};
  ExHermesCancellationEvent empty = {
      EX_HERMES_CANCELLATION_EVENT_ABI_VERSION,
      (uint32_t)sizeof(ExHermesCancellationEvent),
      0,
      0,
      0};
  if (runtime == NULL || runtime_nonce == 0 || target_id == 0) return -50;
  if (ex_hermes_take_cancellation_event(runtime, runtime_nonce, &event) !=
          EX_HERMES_CANCELLATION_EVENT_AVAILABLE ||
      event.target_id != target_id ||
      event.resolution != EX_HERMES_CANCELLATION_DEFEATED) {
    return -51;
  }
  if (ex_hermes_take_cancellation_event(runtime, runtime_nonce, &empty) !=
      EX_HERMES_CANCELLATION_EVENT_EMPTY) {
    return -52;
  }
  if (ex_hermes_cancel_structured_work_target(
          runtime, runtime_nonce, target_id) !=
      EX_HERMES_CANCEL_UNAVAILABLE) {
    return -53;
  }
  return 0;
}

#endif
