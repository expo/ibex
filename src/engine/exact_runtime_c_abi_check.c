/*
 * Independent C11 consumer for include/exact_runtime.h.
 *
 * This translation unit intentionally contains no implementation. Building it
 * proves that the public structured-evaluation ABI remains valid C (not only
 * C++) and that the version-two credential/result field layout has not drifted.
 * @ref LLP 0024#6-evaluation-outcomes-and-the-abi
 */

#include "exact_runtime.h"

#include <stddef.h>

#define IBEX_C_ABI_ASSERT(name, expression) \
  typedef char ibex_c_abi_assert_##name[(expression) ? 1 : -1]

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
IBEX_C_ABI_ASSERT(session_token_length, EX_HERMES_SESSION_TOKEN_LENGTH == 32u);
IBEX_C_ABI_ASSERT(request_binding_length,
                  EX_HERMES_REQUEST_BINDING_LENGTH == 32u);
IBEX_C_ABI_ASSERT(lowering_protocol_version,
                  EX_HERMES_SESSION_LOWERING_PROTOCOL_VERSION == 1u);
IBEX_C_ABI_ASSERT(import_plan_version,
                  EX_HERMES_SESSION_IMPORT_PLAN_ABI_VERSION == 4u);
IBEX_C_ABI_ASSERT(credential_token_offset,
                  offsetof(ExHermesSessionCredential, session_token) == 8u);
IBEX_C_ABI_ASSERT(credential_binding_offset,
                  offsetof(ExHermesSessionCredential, request_binding) == 40u);
IBEX_C_ABI_ASSERT(credential_ordinal_offset,
                  offsetof(ExHermesSessionCredential, ordinal) == 72u);
IBEX_C_ABI_ASSERT(result_work_offset,
                  offsetof(ExHermesEvaluationResult, work_target_id) == 16u);
IBEX_C_ABI_ASSERT(result_value_offset,
                  offsetof(ExHermesEvaluationResult, value) == 24u);
IBEX_C_ABI_ASSERT(result_capabilities_offset,
                  offsetof(ExHermesEvaluationResult, capability_flags) == 52u);
IBEX_C_ABI_ASSERT(position_line_after_label,
                  offsetof(ExHermesSourcePosition, line) ==
                      sizeof(ExHermesOwnedBytes));
IBEX_C_ABI_ASSERT(position_column_after_line,
                  offsetof(ExHermesSourcePosition, column) ==
                      sizeof(ExHermesOwnedBytes) + sizeof(uint32_t));
IBEX_C_ABI_ASSERT(result_positions_after_stack,
                  offsetof(ExHermesEvaluationResult, positions) >
                      offsetof(ExHermesEvaluationResult, stack));
IBEX_C_ABI_ASSERT(result_position_count_after_positions,
                  offsetof(ExHermesEvaluationResult, position_count) >
                      offsetof(ExHermesEvaluationResult, positions));
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
  int (*resume_structured_session)(ExactHermesRuntime*,
                                   uint64_t,
                                   ExHermesEvaluationResult*) =
      ex_hermes_resume_structured_session;
  uint32_t (*finish_bootstrap)(ExactHermesRuntime*) =
      ex_hermes_finish_bootstrap;
  uint32_t (*take_work_unit)(ExactHermesRuntime*, ExHermesWorkUnitEvent*) =
      ex_hermes_take_work_unit_event;
  uint32_t (*take_cancellation)(ExactHermesRuntime*,
                                ExHermesCancellationEvent*) =
      ex_hermes_take_cancellation_event;
  uint32_t (*take_async_failure)(ExactHermesRuntime*,
                                 ExHermesAsyncFailureEvent*) =
      ex_hermes_take_async_failure_event;
  uint64_t (*active_work_target)(ExactHermesRuntime*) =
      ex_hermes_structured_active_work_target;
  uint32_t (*cancel_work_target)(ExactHermesRuntime*, uint64_t) =
      ex_hermes_cancel_structured_work_target;
  int32_t (*authorize_exit)(uint64_t,
                            const uint64_t*,
                            size_t,
                            uint32_t,
                            int32_t,
                            uint32_t,
                            int32_t*) =
      ex_host_authorize_typed_lifecycle_exit_stack;
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
                          size_t*) =
      ex_hermes_value_stage1_text;
  uint32_t (*safe_throw_metadata)(ExactHermesRuntime*,
                                  ExHermesValueHandle,
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
  (void)resume_structured_session;
  (void)finish_bootstrap;
  (void)take_work_unit;
  (void)take_cancellation;
  (void)take_async_failure;
  (void)active_work_target;
  (void)cancel_work_target;
  (void)authorize_exit;
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
