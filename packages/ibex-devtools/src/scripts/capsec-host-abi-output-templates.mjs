/**
 * Author exact native-output probes for the Rust-owned Host ABI.
 *
 * This module deliberately does not turn an inventory row into evidence.  It
 * accepts only ABI families for which the companion Rust executor owns a
 * bounded invocation and cleanup recipe.  Platform-only target absence is
 * handled by `capsec-target-absence-output-templates.mjs` before this author is
 * consulted.
 *
 * @ref LLP 0002#the-rust-host-surface — Host ABI values cross a typed C
 * boundary and returned strings/buffers retain their native ownership rules.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * source inventory definition is an obligation, not execution evidence.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "./capsec-contract.mjs";
import { canonicalOutputDispositionKey } from "./capsec-output-dispositions.mjs";
import { HOST_ABI_OUTPUT_CONTRACT_SCHEMA } from "./capsec-surface-inventory.mjs";

export const HOST_ABI_OUTPUT_INVOCATION_SCHEMA =
  "ibex/capsec-host-abi-output-invocation/1";
export const HOST_ABI_OUTPUT_SOURCE_DESCRIPTOR_KIND =
  "source-bound-host-abi-output";
export const HOST_ABI_OUTPUT_PARTITION_SCHEMA =
  "ibex/capsec-host-abi-output-partition/1";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

const taggedDigest = (bytes) =>
  `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;

const descriptorDigest = (value) =>
  taggedDigest(Buffer.from(canonicalJson(value), "utf8"));

const HOST_FS_FUNCTIONS = new Set([
  "ex_host_fs_access",
  "ex_host_fs_append",
  "ex_host_fs_chmod",
  "ex_host_fs_close",
  "ex_host_fs_copy",
  "ex_host_fs_copy_exclusive",
  "ex_host_fs_fstat",
  "ex_host_fs_last_error",
  "ex_host_fs_lstat",
  "ex_host_fs_mkdir",
  "ex_host_fs_mkdir_recursive_result",
  "ex_host_fs_mkdtemp",
  "ex_host_fs_open",
  "ex_host_fs_pread",
  "ex_host_fs_pwrite",
  "ex_host_fs_read",
  "ex_host_fs_read_file",
  "ex_host_fs_readdir",
  "ex_host_fs_realpath",
  "ex_host_fs_rename",
  "ex_host_fs_rmdir",
  "ex_host_fs_seek",
  "ex_host_fs_stat",
  "ex_host_fs_statfs",
  "ex_host_fs_sync",
  "ex_host_fs_truncate",
  "ex_host_fs_unlink",
  "ex_host_fs_utimes",
  "ex_host_fs_write",
]);

const HOST_SQLITE_FUNCTIONS = new Set([
  "ex_host_sqlite_all",
  "ex_host_sqlite_close",
  "ex_host_sqlite_exec",
  "ex_host_sqlite_expanded_sql",
  "ex_host_sqlite_finalize",
  "ex_host_sqlite_get",
  "ex_host_sqlite_in_transaction",
  "ex_host_sqlite_open",
  "ex_host_sqlite_open_checked_fd",
  "ex_host_sqlite_open_isolated_memory",
  "ex_host_sqlite_prepare",
  "ex_host_sqlite_run",
  "ex_host_sqlite_values",
]);

const HOST_TERMINAL_FUNCTIONS = new Set([
  "ex_host_session_descriptor_alias_source_route",
  "ex_host_session_descriptor_alias_target_route",
  "ex_host_session_descriptor_close_route",
  "ex_host_session_descriptor_is_protected",
  "ex_host_session_descriptor_read_route",
  "ex_host_session_descriptor_write_route",
  "ex_host_terminal_session_close_is_noop",
  "ex_host_terminal_session_stdio_query",
]);

const HOST_BASIC_FUNCTIONS = new Set([
  "ex_host_armed_bootstrap_compatibility_flags",
  "ex_host_armed_endowments",
  "ex_host_check_capability",
  "ex_host_check_capability_no_follow_final",
  "ex_host_check_capability_stack",
  "ex_host_check_capability_stack_no_follow_final",
  "ex_host_check_handle_mint",
  "ex_host_check_import",
  "ex_host_claim_armed_context",
  "ex_host_claim_diagnostic_context",
  "ex_host_console_flush",
  "ex_host_console_log",
  "ex_host_console_log_bytes",
  "ex_host_enter_context",
  "ex_host_env_get",
  "ex_host_free_buffer",
  "ex_host_free_string",
  "ex_host_grant_capability",
  "ex_host_handle_check",
  "ex_host_handle_create",
  "ex_host_handle_revoke",
  "ex_host_handle_scoped",
  "ex_host_has_deputy_classes",
  "ex_host_init",
  "ex_host_is_allow_all",
  "ex_host_is_armed",
  "ex_host_legacy_authorization_cacheable",
  "ex_host_legacy_authorization_generation",
  "ex_host_log_event",
  "ex_host_module_resolve",
  "ex_host_module_resolve_meta",
  "ex_host_permission_request",
  "ex_host_permission_revoke",
  "ex_host_permission_status",
  "ex_host_random_fill",
  "ex_host_register_module_package",
  "ex_host_release_context",
  "ex_host_resolve_manifest_builtin_internal",
  "ex_host_restore_context",
  "ex_host_time_now_ms",
  "ex_host_version",
]);

const HERMES_STATELESS_FUNCTIONS = new Set([
  "ex_hermes_bytecode_version",
  "ex_hermes_create",
  "ex_hermes_current_principal_id",
  "ex_hermes_current_runtime_nonce",
  "ex_hermes_engine_binary_path",
  "ex_hermes_engine_mapped_object",
  "ex_hermes_evaluation_result_dispose",
  "ex_hermes_evaluation_result_init",
  "ex_hermes_free_string",
  // The GPU provider/decoded-image ABI version and descriptor-size getters
  // return compile-time constants from the loaded engine with no runtime or
  // provider state; the batch executor invokes each exact symbol directly.
  "ex_hermes_gpu_decoded_image_abi_version_v1",
  "ex_hermes_gpu_decoded_image_descriptor_size_v1",
  "ex_hermes_gpu_provider_abi_version",
  "ex_hermes_gpu_provider_abi_version_v2",
  "ex_hermes_gpu_provider_descriptor_size_v1",
  "ex_hermes_gpu_provider_descriptor_size_v2",
  "ex_hermes_module_preflight_bytecode",
  "ex_hermes_now_ms",
]);

const HERMES_DIAGNOSTIC_FUNCTIONS = new Set([
  "ex_hermes_callback_backlog",
  // Quarantine control and inspection execute against one owned diagnostic
  // runtime per invocation; quarantining an owned runtime is bounded and the
  // runtime is destroyed with the fixture.
  "ex_hermes_quarantine_runtime_v1",
  "ex_hermes_runtime_is_quarantined_v1",
  "ex_hermes_cancel_structured_work_target",
  "ex_hermes_create_diagnostic",
  "ex_hermes_debugger_enable",
  "ex_hermes_debugger_eval",
  "ex_hermes_debugger_get_script_source",
  "ex_hermes_debugger_get_scripts",
  "ex_hermes_debugger_next_event",
  "ex_hermes_debugger_set_breakpoint",
  "ex_hermes_destroy",
  "ex_hermes_eval",
  "ex_hermes_eval_structured_diagnostic",
  "ex_hermes_finish_bootstrap",
  "ex_hermes_gc",
  "ex_hermes_get_gc_stats",
  "ex_hermes_get_heap_info",
  "ex_hermes_has_pending_tasks",
  "ex_hermes_next_timer",
  "ex_hermes_poll",
  "ex_hermes_poll_with_external_keep_alive",
  "ex_hermes_resolve_host_call",
  "ex_hermes_runtime_nonce",
  "ex_hermes_schedule_watchdog_heartbeat_for_generation",
  "ex_hermes_seal_armed_shared_runtime_globals_v1",
  "ex_hermes_set_exact_host_call_async",
  "ex_hermes_set_host_call",
  "ex_hermes_set_host_call_async",
  "ex_hermes_set_keep_alive_on_async_error",
  "ex_hermes_structured_active_work_target",
  "ex_hermes_take_async_failure_event",
  "ex_hermes_take_cancellation_event",
  "ex_hermes_take_work_unit_event",
]);

const EVALUATION_RESULT_OUTPUT_SELECTORS = Object.freeze([
  "out:result.abi_version",
  "out:result.capability_flags",
  "out:result.fault",
  "out:result.lifecycle_exit_code",
  "out:result.message.data",
  "out:result.outcome_tag",
  "out:result.positions",
  "out:result.positions[].column",
  "out:result.positions[].line",
  "out:result.positions[].source_label.data",
  "out:result.stack.data",
  "out:result.struct_size",
  "out:result.throw_error_class",
  "out:result.throw_metadata_fields",
  "out:result.throw_metadata_status",
  "out:result.value.handle_id",
  "out:result.value.runtime_nonce",
  "out:result.work_target_id",
]);

const HERMES_WORKLET_FUNCTIONS = new Set([
  "ex_worklet_bind_shared_value_accessors",
  "ex_worklet_create",
  "ex_worklet_destroy",
  "ex_worklet_drain_logs",
  "ex_worklet_drain_scheduled",
  "ex_worklet_drain_scheduled_typed",
  "ex_worklet_generation",
  "ex_worklet_install",
  "ex_worklet_install_metrics",
  "ex_worklet_install_typed",
  "ex_worklet_invoke",
  "ex_worklet_invoke_typed",
  "ex_worklet_set_generation",
  "ex_worklet_set_measure_callback",
  "ex_worklet_take_scheduled_drop_count",
]);

const HERMES_DISPATCH_FUNCTIONS = new Set([
  "ex_hermes_dispatch_motion_rated_publish",
  "ex_hermes_dispatch_worklet_calls",
  "ex_hermes_dispatch_worklet_json_batch",
]);

const HERMES_VALUE_FUNCTIONS = new Set([
  "ex_hermes_session_display_ack",
  "ex_hermes_value_kind",
  "ex_hermes_value_release",
  "ex_hermes_value_safe_throw_metadata",
  "ex_hermes_value_stage1_text",
]);

const HOST_TYPED_AUTHORITY_FUNCTIONS = new Set([
  "ex_host_authorize_typed_environment_read_stack",
  "ex_host_authorize_typed_environment_write_stack",
  "ex_host_authorize_typed_fs_stack",
  "ex_host_authorize_typed_lifecycle_exit_stack",
  "ex_host_authorize_typed_listen_stack",
  "ex_host_authorize_typed_network_stack",
  "ex_host_authorize_typed_print_stack",
  "ex_host_authorize_typed_system_info_stack",
  "ex_host_authorize_typed_udp_datagram_stack",
  "ex_host_evaluate_typed_decision",
  "ex_host_lifecycle_exit_code_get_stack",
  "ex_host_lifecycle_exit_code_set_stack",
  "ex_host_typed_dynamic_grant",
  "ex_host_typed_dynamic_revoke",
  "ex_host_typed_generations",
  "ex_host_typed_handle_mint",
  "ex_host_typed_handle_revoke",
]);

const HOST_AUTHENTICATED_STATEFUL_FUNCTIONS = new Set([
  "ex_host_authorize_exact_endowment",
  "ex_host_build_exact_armed_embedder_artifacts",
  "ex_host_env_compiled_key_at",
  "ex_host_env_compiled_key_count",
  "ex_host_env_get",
  "ex_host_install_armed",
  "ex_host_install_armed_experimental_webgpu_pre1a",
  "ex_host_matches_armed_snapshot_digest",
  "ex_host_prepare_armed_embedder_artifacts",
  "ex_host_prepare_exact_armed_embedder_artifacts",
  "ex_host_random_fill",
  "ex_host_seal_bootstrap_phase",
  "ex_host_session_static_import_resolve",
  "ex_host_session_static_import_resolve_meta",
]);

// Stateful native families whose output shapes can be observed only while a
// bounded production fixture owns their runtime/session/server lifecycle.
// Membership is deliberately exact: adding a new ABI does not inherit an
// executor merely because its spelling shares a prefix.
const HOST_HTTP_FUNCTIONS = new Set([
  "ex_host_http_address",
  "ex_host_http_await_writable",
  "ex_host_http_await_writable_owned",
  "ex_host_http_cleanup_runtime",
  "ex_host_http_close",
  "ex_host_http_drain",
  "ex_host_http_has_pending_requests",
  "ex_host_http_has_referenced",
  "ex_host_http_is_referenced",
  "ex_host_http_poll",
  "ex_host_http_read_body",
  "ex_host_http_respond",
  "ex_host_http_respond_abort",
  "ex_host_http_respond_chunk",
  "ex_host_http_respond_chunk_try",
  "ex_host_http_respond_end",
  "ex_host_http_respond_end_try",
  "ex_host_http_respond_json",
  "ex_host_http_respond_stream",
  "ex_host_http_respond_string",
  "ex_host_http_respond_text",
  "ex_host_http_serve",
  "ex_host_http_wait",
  "ex_host_http_wait_owned",
]);

const HERMES_SESSION_STATEFUL_FUNCTIONS = new Set([
  "ex_hermes_eval_lowered_session",
  "ex_hermes_eval_structured_session",
  "ex_hermes_resume_structured_session",
  "ex_hermes_structured_module_graph_begin",
  "ex_hermes_structured_module_graph_finish",
  "ex_hermes_structured_module_graph_resume",
  "ex_hermes_structured_module_graph_suspend",
  "ex_hermes_structured_session_bind",
  "ex_hermes_structured_submission_admit",
  "ex_hermes_structured_submission_settle",
]);

const HERMES_MODULE_RUNNER_FUNCTIONS = new Set([
  "ex_hermes_commonjs_create_record",
  "ex_hermes_commonjs_record_create_esm_adapter",
  "ex_hermes_commonjs_record_declare_export",
  "ex_hermes_commonjs_record_evaluate",
  "ex_hermes_commonjs_record_link_computed_dynamic_import",
  "ex_hermes_commonjs_record_link_dynamic_import",
  "ex_hermes_commonjs_record_link_require",
  "ex_hermes_commonjs_record_link_require_esm",
  "ex_hermes_graph_context_create",
  "ex_hermes_graph_context_retain",
  "ex_hermes_module_compile_factory",
  "ex_hermes_module_create_record",
  "ex_hermes_module_load_carrier_factory",
  "ex_hermes_module_pin_generation",
  "ex_hermes_module_record_declare_export",
  "ex_hermes_module_record_instantiate",
  "ex_hermes_module_record_link_dependency",
  "ex_hermes_module_record_link_computed_dynamic_import",
  "ex_hermes_module_record_link_dynamic_import",
  "ex_hermes_module_record_link_export",
  "ex_hermes_module_record_link_import",
  "ex_hermes_module_record_namespace_json",
  "ex_hermes_module_record_poll_evaluation",
  "ex_hermes_module_record_run_declare",
  "ex_hermes_module_record_run_execute",
  "ex_hermes_module_release_handle",
  "ex_hermes_module_unpin_generation",
]);

const STRUCTURED_VFS_OUTPUT_OPERATIONS = new Map([
  ...[
    "ex_host_vfs_bind_runtime",
    "ex_host_vfs_chdir",
    "ex_host_vfs_get_cwd",
    "ex_host_vfs_resolve_path",
    "ex_host_vfs_unbind_runtime",
  ].map((functionName) => [
    [functionName, "[[return]]", functionName, "javascript", "absent"].join("\0"),
    Object.freeze({
      kind: "rust-host-authenticated-javascript-absence",
      targetVariant: "default",
    }),
  ]),
  [
    [
      "ex_host_vfs_resolve_path",
      "out:backing",
      "ex_host_vfs_resolve_path.out_backing",
      "javascript",
      "absent",
    ].join("\0"),
    Object.freeze({
      kind: "rust-host-authenticated-javascript-absence",
      targetVariant: "default",
    }),
  ],
  ...[
    ["ex_host_vfs_chdir", "out:virtual", "ex_host_vfs_chdir.out_virtual"],
    ["ex_host_vfs_get_cwd", "out:virtual", "ex_host_vfs_get_cwd.out_virtual"],
    [
      "ex_host_vfs_resolve_path",
      "out:virtual",
      "ex_host_vfs_resolve_path.out_virtual",
    ],
  ].map(([functionName, output, alias]) => [
    [functionName, output, alias, "private-native", "success"].join("\0"),
    Object.freeze({
      kind: "rust-host-authenticated-vfs-structured-output",
      targetVariant: "default",
    }),
  ]),
]);

// Non-return selectors whose companion native family captures the caller
// storage (or owned pointee) immediately after the exact ABI call. Keep this
// list independent from catalog policy: source contracts decide membership;
// this list only states which selectors have a bounded executor.
const BOUNDED_FAMILY_OUTPUT_SELECTORS = new Set([
  "ex_host_env_compiled_key_at\0out:buf",
  "ex_host_fs_pread\0out:buf",
  "ex_host_fs_read\0out:buf",
  "ex_host_fs_read_file\0out:errno",
  "ex_host_fs_read_file\0out:len",
  "ex_host_terminal_session_stdio_query\0out:columns",
  "ex_host_terminal_session_stdio_query\0out:is_tty",
  "ex_host_terminal_session_stdio_query\0out:rows",
  "ex_hermes_engine_mapped_object\0out:device",
  "ex_hermes_engine_mapped_object\0out:inode",
  "ex_hermes_eval\0out:value",
  "ex_hermes_module_preflight_bytecode\0out:error",
  ...["ex_hermes_evaluation_result_dispose", "ex_hermes_evaluation_result_init"]
    .flatMap((functionName) =>
      EVALUATION_RESULT_OUTPUT_SELECTORS
        .filter(
          (selector) =>
            !selector.startsWith("out:result.positions[].") ||
            functionName === "ex_hermes_eval_structured_diagnostic",
        )
        .map((selector) => `${functionName}\0${selector}`),
    ),
  ...EVALUATION_RESULT_OUTPUT_SELECTORS.map(
    (selector) => `ex_hermes_eval_structured_diagnostic\0${selector}`,
  ),
  ...[
    "associated_evaluation",
    "dropped_count",
    "event_id",
    "host_context_id",
    "kind",
    "owning_principal_id",
    "principal_status",
    "value.handle_id",
    "value.runtime_nonce",
  ].map((member) => `ex_hermes_take_async_failure_event\0out:event.${member}`),
  ...["resolution", "target_id"].map(
    (member) => `ex_hermes_take_cancellation_event\0out:event.${member}`,
  ),
  ...["kind", "phase", "scheduling_id", "target_id"].map(
    (member) => `ex_hermes_take_work_unit_event\0out:event.${member}`,
  ),
  "ex_worklet_install\0out:error",
  "ex_worklet_invoke\0out:result_json",
  ...[
    "callback:read_callback/0.epoch",
    "callback:read_callback/0.generation",
    "callback:read_callback/0.slot",
    "callback:read_callback/2",
    "callback:write_callback/0.epoch",
    "callback:write_callback/0.generation",
    "callback:write_callback/0.slot",
    "callback:write_callback/1",
    "callback:write_callback/2",
  ].map(
    (selector) =>
      `ex_worklet_bind_shared_value_accessors\0${selector}`,
  ),
  "ex_worklet_drain_scheduled_typed\0out:calls",
  "ex_worklet_install_metrics\0out:metrics",
  "ex_worklet_install_typed\0out:error",
  "ex_worklet_install_typed\0out:identity",
  "ex_worklet_invoke_typed\0out:output_count",
  "ex_worklet_invoke_typed\0out:outputs",
  "ex_worklet_set_measure_callback\0callback:callback/0",
  "ex_worklet_set_measure_callback\0callback:callback/2",
  "ex_host_authorize_typed_lifecycle_exit_stack\0out:code",
  "ex_host_lifecycle_exit_code_get_stack\0out:code",
  "ex_host_typed_generations\0out:dynamic",
  "ex_host_typed_generations\0out:handle",
  "ex_host_typed_generations\0out:negative",
  "ex_host_env_get\0out:buf",
  "ex_host_random_fill\0out:buf",
  "ex_hermes_dispatch_worklet_calls\0out:delivered",
  "ex_hermes_value_safe_throw_metadata\0out:error_class",
  "ex_hermes_value_safe_throw_metadata\0out:message.data",
  "ex_hermes_value_safe_throw_metadata\0out:metadata_fields",
  "ex_hermes_value_safe_throw_metadata\0out:stack.data",
  "ex_hermes_value_stage1_text\0out:data",
  "ex_hermes_value_stage1_text\0out:truncated",
  "ex_hermes_schedule_watchdog_heartbeat_for_generation\0callback:callback/0",
  ...[
    "callback:callback/0",
    "callback:callback/1",
  ].map((selector) => `ex_hermes_set_host_call\0${selector}`),
  ...[
    "callback:callback/0",
    "callback:callback/1",
    "callback:callback/2",
    "callback:callback/3",
  ].map((selector) => `ex_hermes_set_host_call_async\0${selector}`),
  ...[
    "callback:callback/0",
    "callback:callback/1",
    "callback:callback/2",
    "callback:callback/3",
    "callback:callback/5",
  ].map((selector) => `ex_hermes_set_exact_host_call_async\0${selector}`),
  "ex_hermes_set_host_wake_hook\0callback:hook/0",
]);

const AUTHENTICATED_VFS_OUTPUT_SELECTORS = new Set([
  "ex_host_vfs_bind_runtime\0[[return]]",
  "ex_host_vfs_chdir\0[[return]]",
  "ex_host_vfs_chdir\0out:errno",
  "ex_host_vfs_get_cwd\0[[return]]",
  "ex_host_vfs_get_cwd\0out:errno",
  "ex_host_vfs_resolve_path\0[[return]]",
  "ex_host_vfs_resolve_path\0out:errno",
  "ex_host_vfs_unbind_runtime\0[[return]]",
]);

// These are deliberately exact selector recipes rather than a general rule
// for ABI buffers.  The native executor owns a bounded call for each row and
// independently validates the resulting value class without reading the
// disposition policy.
const PATH_OUTPUT_OPERATIONS = new Map([
  [
    "ex_hermes_engine_binary_path\0out:out",
    Object.freeze({
      operation: Object.freeze({
        kind: "native-hermes-stateless-path-output",
        targetVariant: "default",
      }),
      output: Object.freeze({
        kind: "buffer",
        lengthParameter: "out_len",
        ownership: Object.freeze({ kind: "caller-storage" }),
        parameter: "out",
        role: "output",
        selector: "out:out",
      }),
    }),
  ],
  ...[
    ["ex_host_vfs_chdir", "out:virtual", "out_virtual", "out_virtual_len"],
    ["ex_host_vfs_get_cwd", "out:virtual", "out_virtual", "out_virtual_len"],
    [
      "ex_host_vfs_resolve_path",
      "out:virtual",
      "out_virtual",
      "out_virtual_len",
    ],
    [
      "ex_host_vfs_resolve_path",
      "out:backing",
      "out_backing",
      "out_backing_len",
    ],
  ].map(([functionName, selector, parameter, lengthParameter]) => [
    `${functionName}\0${selector}`,
    Object.freeze({
      operation: Object.freeze({
        kind: "rust-host-authenticated-vfs-path-output",
        targetVariant: "default",
      }),
      output: Object.freeze({
        kind: "buffer",
        lengthParameter,
        ownership: Object.freeze({
          kind: "caller-owned",
          releaseFunction: "ex_host_free_buffer",
        }),
        parameter,
        role: "output",
        selector,
      }),
    }),
  ]),
]);

const OWNED_HOST_STRING_RETURN = Object.freeze({
  kind: "pointer",
  ownership: Object.freeze({
    kind: "caller-owned",
    releaseFunction: "ex_host_free_string",
  }),
  role: "return",
  selector: "[[return]]",
});

const LEGACY_HOST_PATH_FUNCTIONS = Object.freeze([
  "ex_host_fs_mkdir_recursive_result",
  "ex_host_fs_mkdtemp",
  "ex_host_fs_realpath",
]);

const LEGACY_HOST_SOURCE_REQUIREMENTS = Object.freeze({
  ex_host_fs_mkdir_recursive_result: Object.freeze({
    armedRefusalBefore: Object.freeze([
      "path.is_null()",
      "CStr::from_ptr(path)",
      "cursor.exists()",
      "std::fs::create_dir_all(&path)",
    ]),
  }),
  ex_host_fs_mkdtemp: Object.freeze({
    armedRefusalBefore: Object.freeze([
      "prefix.is_null()",
      "CStr::from_ptr(prefix)",
      "getrandom(&mut rng_bytes)",
      "std::fs::create_dir(&dir_path)",
    ]),
  }),
  ex_host_fs_realpath: Object.freeze({
    armedRefusalBefore: Object.freeze([
      "path.is_null()",
      "CStr::from_ptr(path)",
      "std::fs::canonicalize(&path)",
    ]),
  }),
  ex_host_fs_readdir: Object.freeze({ armedRefusalBefore: Object.freeze([]) }),
});

const legacyHostOutputOperationKey = ({
  functionName,
  output,
  alias,
  mode,
  returnVariant,
}) => [functionName, output, alias, mode, returnVariant].join("\0");

const LEGACY_HOST_OUTPUT_OPERATIONS = new Map([
  ...LEGACY_HOST_PATH_FUNCTIONS.flatMap((functionName) =>
    [
      ["unarmed", "success"],
      ["unarmed", "error"],
      ["armed", "refused"],
    ].map(([mode, returnVariant]) => [
      legacyHostOutputOperationKey({
        functionName,
        output: "[[return]]",
        alias: functionName,
        mode,
        returnVariant,
      }),
      Object.freeze({
        operation: Object.freeze({
          kind: "rust-host-legacy-path-output",
          mode,
          returnVariant,
          sourceSelector: "[[return]]",
          targetVariant: "default",
        }),
        output: Object.freeze({
          ...OWNED_HOST_STRING_RETURN,
          projection: Object.freeze({
            catalogSelector: "[[return]]",
            kind: "whole-return",
          }),
        }),
      }),
    ]),
  ),
  [
    legacyHostOutputOperationKey({
      functionName: "ex_host_fs_readdir",
      output: "array-items",
      alias: "ex_host_fs_readdir[]",
      mode: "all",
      returnVariant: "success",
    }),
    Object.freeze({
      operation: Object.freeze({
        kind: "rust-host-legacy-directory-output",
        mode: "all",
        returnVariant: "success",
        sourceSelector: "[[return]]",
        targetVariant: "default",
      }),
      output: Object.freeze({
        ...OWNED_HOST_STRING_RETURN,
        projection: Object.freeze({
          catalogSelector: "array-items",
          kind: "json-array-items",
        }),
      }),
    }),
  ],
]);

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function pathOutputOperationFor(functionName, outputSelector) {
  return PATH_OUTPUT_OPERATIONS.get(`${functionName}\0${outputSelector}`) ?? null;
}

function legacyHostOutputOperationFor(functionName, key) {
  if (!key) return null;
  return (
    LEGACY_HOST_OUTPUT_OPERATIONS.get(
      legacyHostOutputOperationKey({
        functionName,
        output: key.output,
        alias: key.alias,
        mode: key.mode,
        returnVariant: key.returnVariant,
      }),
    ) ?? null
  );
}

function structuredVfsOutputOperationFor(functionName, key) {
  if (!key) return null;
  return (
    STRUCTURED_VFS_OUTPUT_OPERATIONS.get(
      [
        functionName,
        key.output,
        key.alias,
        key.mode,
        key.returnVariant,
      ].join("\0"),
    ) ?? null
  );
}

function operationFor(functionName, outputSelector = "[[return]]", key = null) {
  const legacyOutput = legacyHostOutputOperationFor(functionName, key);
  if (legacyOutput) return structuredClone(legacyOutput.operation);
  const structuredVfsOutput = structuredVfsOutputOperationFor(
    functionName,
    key,
  );
  if (structuredVfsOutput) return structuredClone(structuredVfsOutput);
  const pathOutput = pathOutputOperationFor(functionName, outputSelector);
  if (pathOutput) return structuredClone(pathOutput.operation);
  if (
    AUTHENTICATED_VFS_OUTPUT_SELECTORS.has(
      `${functionName}\0${outputSelector}`,
    )
  ) {
    return {
      kind: "rust-host-authenticated-vfs-output",
      targetVariant: "default",
    };
  }
  if (HERMES_SESSION_STATEFUL_FUNCTIONS.has(functionName)) {
    return {
      kind: "native-hermes-authenticated-session-runtime",
      targetVariant: "default",
    };
  }
  if (HERMES_MODULE_RUNNER_FUNCTIONS.has(functionName)) {
    return {
      kind: "native-hermes-module-runner-runtime",
      targetVariant: "default",
    };
  }
  if (
    outputSelector !== "[[return]]" &&
    !BOUNDED_FAMILY_OUTPUT_SELECTORS.has(
      `${functionName}\0${outputSelector}`,
    )
  ) {
    return null;
  }
  if (HOST_FS_FUNCTIONS.has(functionName)) return { kind: "rust-host-fs-sandbox" };
  if (HOST_SQLITE_FUNCTIONS.has(functionName)) {
    return { kind: "rust-host-sqlite-memory" };
  }
  if (HOST_TERMINAL_FUNCTIONS.has(functionName)) {
    return { kind: "rust-host-terminal-inert" };
  }
  if (HOST_TYPED_AUTHORITY_FUNCTIONS.has(functionName)) {
    return { kind: "rust-host-authenticated-typed-authority" };
  }
  if (HOST_AUTHENTICATED_STATEFUL_FUNCTIONS.has(functionName)) {
    return { kind: "rust-host-authenticated-stateful-output" };
  }
  if (HOST_HTTP_FUNCTIONS.has(functionName)) {
    return { kind: "rust-host-http-live-server" };
  }
  if (functionName === "ex_hermes_create_armed") {
    return {
      kind: "native-hermes-authenticated-armed-create",
      targetVariant: "default",
    };
  }
  if (functionName === "ex_hermes_try_destroy") {
    return {
      kind: "native-hermes-owned-runtime-teardown",
      targetVariant: "default",
    };
  }
  if (functionName === "ex_hermes_set_host_wake_hook") {
    return { kind: "rust-host-wake-hook-callback" };
  }
  if (HOST_BASIC_FUNCTIONS.has(functionName)) {
    return { kind: "rust-host-bounded-basic" };
  }
  if (HERMES_STATELESS_FUNCTIONS.has(functionName)) {
    return {
      kind: "native-hermes-stateless-current-target",
      targetVariant: "default",
    };
  }
  if (HERMES_DIAGNOSTIC_FUNCTIONS.has(functionName)) {
    return {
      kind: "native-hermes-diagnostic-runtime",
      targetVariant: "default",
    };
  }
  if (HERMES_DISPATCH_FUNCTIONS.has(functionName)) {
    return {
      kind: "native-hermes-bounded-dispatch-runtime",
      targetVariant: "default",
    };
  }
  if (HERMES_VALUE_FUNCTIONS.has(functionName)) {
    return {
      kind: "native-hermes-owned-value-runtime",
      targetVariant: "default",
    };
  }
  if (HERMES_WORKLET_FUNCTIONS.has(functionName)) {
    return {
      kind: "native-hermes-worklet-runtime",
      targetVariant: "default",
    };
  }
  return null;
}

function legacyHostSourceSafetyBinding(functionName, sourceRefs) {
  const requirement = LEGACY_HOST_SOURCE_REQUIREMENTS[functionName];
  if (!requirement) return null;
  const sourceRef = `src/host/abi.rs#${functionName}`;
  requireCondition(
    sourceRefs.length === 1 && sourceRefs[0] === sourceRef,
    `${functionName}: legacy Host output lost its exact Rust source ref`,
  );
  const sourcePath = "src/host/abi.rs";
  const bytes = fs.readFileSync(path.join(repoRoot, sourcePath));
  const source = bytes.toString("utf8");
  const functionStart = source.indexOf(`fn ${functionName}(`);
  requireCondition(
    functionStart >= 0,
    `${functionName}: legacy Host output definition is absent`,
  );
  const nextDefinition = source.indexOf("\n#[no_mangle]", functionStart + 1);
  const functionSource = source.slice(
    functionStart,
    nextDefinition < 0 ? source.length : nextDefinition,
  );
  const ownershipWindow = source.slice(
    Math.max(0, functionStart - 800),
    nextDefinition < 0 ? source.length : nextDefinition,
  );
  requireCondition(
    ownershipWindow.includes("ex_host_free_string"),
    `${functionName}: returned string ownership is not source-annotated`,
  );
  if (requirement.armedRefusalBefore.length > 0) {
    const guard = "if refuse_armed_legacy_path_output()";
    const guardIndex = functionSource.indexOf(guard);
    requireCondition(
      guardIndex >= 0 &&
        requirement.armedRefusalBefore.every(
          (token) => functionSource.indexOf(token) > guardIndex,
        ),
      `${functionName}: armed refusal no longer precedes path decode, lookup, randomness, or mutation`,
    );
  }
  return {
    path: sourcePath,
    rawContentDigest: taggedDigest(bytes),
    returnOwnership: {
      kind: "caller-owned",
      releaseFunction: "ex_host_free_string",
      sourceToken: "ex_host_free_string",
    },
    ...(requirement.armedRefusalBefore.length > 0
      ? {
          armedRefusalOrder: {
            guard: "if refuse_armed_legacy_path_output()",
            precedes: [...requirement.armedRefusalBefore],
          },
        }
      : {}),
  };
}

function sourceFileBindings(sourceRefs, functionName) {
  const files = [...new Set(sourceRefs.map((sourceRef) => sourceRef.split("#")[0]))]
    .sort(compareText);
  return files.map((sourcePath) => {
    requireCondition(
      sourcePath.length > 0 &&
        !path.isAbsolute(sourcePath) &&
        !sourcePath.split("/").includes(".."),
      `${functionName}: invalid source path ${JSON.stringify(sourcePath)}`,
    );
    const absolute = path.resolve(repoRoot, sourcePath);
    requireCondition(
      absolute.startsWith(`${repoRoot}${path.sep}`),
      `${functionName}: source path escaped the repository`,
    );
    const bytes = fs.readFileSync(absolute);
    requireCondition(
      bytes.includes(Buffer.from(functionName, "utf8")),
      `${functionName}: named symbol is absent from ${sourcePath}`,
    );
    return {
      path: sourcePath,
      rawContentDigest: taggedDigest(bytes),
    };
  });
}

function selectedOutputContracts(
  selectedDefinitions,
  functionName,
  outputSelector,
) {
  const outputContracts = [];
  const selectedChannels = [];
  for (const definition of selectedDefinitions) {
    const contract = definition.outputContract;
    requireCondition(
      contract?.schema === HOST_ABI_OUTPUT_CONTRACT_SCHEMA &&
        contract.functionName === functionName &&
        contract.sourceRef === definition.sourceRef &&
        contract.language === definition.language &&
        Array.isArray(contract.outputChannels) &&
        contract.return?.role,
      `${functionName}: selected definition lost its source-derived output contract`,
    );
    const selected = contract.outputChannels.filter(
      (channel) => channel.selector === outputSelector,
    );
    if (outputSelector === "[[return]]") {
      requireCondition(
        (contract.return.role === "none" && selected.length === 0) ||
          (contract.return.role === "value" &&
            selected.length === 1 &&
            selected[0].role === "return"),
        `${functionName}: syntactic return slot disagrees with output channels`,
      );
    } else {
      requireCondition(
        selected.length === 1,
        `${functionName}: selected output ${outputSelector} is not exact in the source contract`,
      );
    }
    outputContracts.push(structuredClone(contract));
    selectedChannels.push(
      selected.length === 0 ? null : structuredClone(selected[0]),
    );
  }
  return { outputContracts, selectedChannels };
}

function exactPathOutputBinding(functionName, outputSelector, selectedChannels) {
  const binding = pathOutputOperationFor(functionName, outputSelector);
  if (!binding) return null;
  const expected = canonicalJson(binding.output);
  requireCondition(
    selectedChannels.length > 0 &&
      selectedChannels.every((channel) => canonicalJson(channel) === expected),
    `${functionName}: bounded path output ${outputSelector} lost its exact source ownership contract`,
  );
  return binding;
}

function exactLegacyHostOutputBinding({
  functionName,
  key,
  outputContracts,
  selectedChannels,
  sourceRefs,
}) {
  const binding = legacyHostOutputOperationFor(functionName, key);
  if (!binding) return null;
  requireCondition(
    key.contextId === "host.private-native-call-initialized",
    `${functionName}: legacy Host output lost its private ABI execution context`,
  );
  requireCondition(
    outputContracts.length > 0 &&
      outputContracts.every(
        (contract) =>
          contract.return.role === "value" &&
          contract.return.kind === "pointer" &&
          canonicalJson(contract.return.ownership) ===
            canonicalJson(OWNED_HOST_STRING_RETURN.ownership) &&
          contract.status === "resolved" &&
          canonicalJson(contract.unresolved) === canonicalJson([]),
      ) &&
      selectedChannels.every(
        (channel) =>
          channel?.selector === "[[return]]" &&
          channel.role === "return" &&
          channel.kind === "pointer" &&
          canonicalJson(channel.ownership) ===
            canonicalJson(OWNED_HOST_STRING_RETURN.ownership),
      ),
    `${functionName}: legacy Host pointer return contract drifted`,
  );
  return {
    binding,
    sourceSafetyBinding: legacyHostSourceSafetyBinding(
      functionName,
      sourceRefs,
    ),
  };
}

/**
 * Return one loaded-engine/native output-record probe, or null when this
 * tranche has no sound bounded executor.  `targetAbsenceBinding` is an exact
 * binding from the separate target-absence author and always wins.
 */
export function authoredHostAbiOutputProbe({
  catalogRow,
  surface,
  coverageEdge,
  targetAbsenceBinding = null,
}) {
  if (targetAbsenceBinding) return null;
  const key = catalogRow?.key;
  if (key?.sourceKind !== "host-abi") return null;
  const functionName = coverageEdge?.surface?.name;
  requireCondition(
    coverageEdge?.id === key.surfaceId &&
      coverageEdge.surface?.kind === "host-abi" &&
      surface?.kind === "host-abi" &&
      surface.name === functionName &&
      surface.observedKey === `host-abi:${functionName}`,
    `${key.surfaceId}: Host ABI output source/coverage identity drift`,
  );
  const legacyOutput = legacyHostOutputOperationFor(functionName, key);
  const structuredVfsOutput = structuredVfsOutputOperationFor(
    functionName,
    key,
  );
  if (key.mode !== "all" && !legacyOutput && !structuredVfsOutput) return null;
  const operation = operationFor(functionName, key.output, key);
  if (!operation) return null;

  const pathOutput = structuredVfsOutput
    ? null
    : pathOutputOperationFor(functionName, key.output);
  if (pathOutput) {
    requireCondition(
      key.alias === functionName &&
        key.returnVariant === "default" &&
        key.contextId === "host.private-native-call-initialized",
      `${functionName}: bounded path output lost its exact private Host-ABI key`,
    );
  }

  const inventorySourceRefs = [
    ...new Set([
      ...(surface.sourceRefs ?? []),
      ...(catalogRow.discovery?.sourceRefs ?? []),
    ]),
  ].sort(compareText);
  const definitions = surface.metadata?.definitions;
  const isRustOperation = operation.kind.startsWith("rust-host-");
  const selectedDefinitions = Array.isArray(definitions)
    ? definitions.filter(
        (definition) =>
          definition.targetVariant === (operation.targetVariant ?? "default") &&
          definition.language === (isRustOperation ? "rust" : "c++"),
      )
    : [];
  const sourceRefs = [
    ...new Set(selectedDefinitions.map((definition) => definition.sourceRef)),
  ].sort(compareText);
  requireCondition(
    inventorySourceRefs.length > 0 &&
      selectedDefinitions.length > 0 &&
      sourceRefs.every((sourceRef) => inventorySourceRefs.includes(sourceRef)) &&
      (!isRustOperation ||
        definitions.every(
          (definition) =>
            definition.language === "rust" || definition.weak === true,
        )),
    `${functionName}: bounded Host ABI route lost its exact compiled definition`,
  );
  const sourceOutputSelector = legacyOutput
    ? legacyOutput.operation.sourceSelector
    : key.output;
  const { outputContracts, selectedChannels } = selectedOutputContracts(
    selectedDefinitions,
    functionName,
    sourceOutputSelector,
  );
  let selectedOutput;
  let sourceSafetyBinding;
  if (legacyOutput) {
    const exact = exactLegacyHostOutputBinding({
      functionName,
      key,
      outputContracts,
      selectedChannels,
      sourceRefs,
    });
    requireCondition(
      exact,
      `${functionName}: legacy Host output has no exact bounded binding`,
    );
    selectedOutput = structuredClone(exact.binding.output);
    sourceSafetyBinding = exact.sourceSafetyBinding;
  } else if (key.output === "[[return]]") {
    const selected = selectedChannels[0];
    if (
      !selected ||
      !selectedChannels.every(
        (channel) => canonicalJson(channel) === canonicalJson(selected),
      ) ||
      !outputContracts.every(
        (contract) =>
          contract.status === "resolved" &&
          Array.isArray(contract.unresolved) &&
          contract.unresolved.length === 0,
      )
    ) {
      return null;
    }
    if (
      selected.kind === "scalar" &&
      selected.role === "return" &&
      selected.ownership?.kind === "not-applicable"
    ) {
      selectedOutput = {
        kind: "scalar",
        ownership: "not-applicable",
        selector: "[[return]]",
      };
    } else if (
      selected.kind === "pointer" &&
      selected.role === "return" &&
      selected.ownership?.kind === "caller-owned" &&
      typeof selected.ownership.releaseFunction === "string"
    ) {
      selectedOutput = structuredClone(selected);
    } else {
      return null;
    }
  } else {
    requireCondition(
      outputContracts.every(
        (contract) =>
          contract.status === "resolved" &&
          Array.isArray(contract.unresolved) &&
          contract.unresolved.length === 0,
      ),
      `${functionName}: bounded path output contract is unresolved`,
    );
    const binding = exactPathOutputBinding(
      functionName,
      key.output,
      selectedChannels,
    );
    if (binding) {
      selectedOutput = structuredClone(binding.output);
    } else {
      const selected = selectedChannels[0];
      requireCondition(
        selected &&
          selectedChannels.every(
            (channel) => canonicalJson(channel) === canonicalJson(selected),
          ) &&
          new Set(["aggregate", "buffer", "pointer", "scalar"]).has(
            selected.kind,
          ) &&
          new Set(["callback-payload", "output", "inout"]).has(
            selected.role,
          ),
        `${functionName}: bounded output ${key.output} lost its exact source contract`,
      );
      selectedOutput = structuredClone(selected);
    }
  }

  const sourceDescriptor = {
    kind: HOST_ABI_OUTPUT_SOURCE_DESCRIPTOR_KIND,
    invocationSchema: HOST_ABI_OUTPUT_INVOCATION_SCHEMA,
    functionName,
    catalogOutput: key.output,
    catalogMode: key.mode,
    returnVariant: key.returnVariant,
    inventorySourceRefs,
    sourceRefs,
    sourceFiles: sourceFileBindings(sourceRefs, functionName),
    definitions: structuredClone(definitions),
    selectedDefinitions: structuredClone(selectedDefinitions),
    outputContractSchema: HOST_ABI_OUTPUT_CONTRACT_SCHEMA,
    outputContracts,
    selectedOutput,
    ...(sourceSafetyBinding ? { sourceSafetyBinding } : {}),
    operation,
  };
  const sourceDescriptorDigest = descriptorDigest(sourceDescriptor);
  return {
    kind: "loaded-engine-return-record",
    fixtureId: `host-abi-output-${sourceDescriptorDigest.slice(7, 23)}`,
    sourceDescriptor,
    sourceDescriptorDigest,
    recordPath: [key.output],
  };
}

export function hostAbiOutputExecutorCoverage(
  functionName,
  outputSelector = "[[return]]",
  key = null,
) {
  const operation = operationFor(functionName, outputSelector, key);
  return operation ? structuredClone(operation) : null;
}

export function hostAbiOutputResidualReason({ catalogRow, surface }) {
  if (catalogRow?.key?.sourceKind !== "host-abi") return null;
  const legacyOutput = legacyHostOutputOperationFor(
    surface?.name,
    catalogRow.key,
  );
  const structuredVfsOutput = structuredVfsOutputOperationFor(
    surface?.name,
    catalogRow.key,
  );
  const operation = operationFor(
    surface?.name,
    catalogRow.key.output,
    catalogRow.key,
  );
  if (
    catalogRow.key.mode !== "all" &&
    !legacyOutput &&
    !structuredVfsOutput
  ) {
    return "private-vfs-return-record-requires-authenticated-runtime-session";
  }
  if (operation) {
    const expectedLanguage = operation.kind.startsWith("rust-host-")
      ? "rust"
      : "c++";
    const definitions = (surface?.metadata?.definitions ?? []).filter(
      (definition) =>
        definition.targetVariant === (operation.targetVariant ?? "default") &&
        definition.language === expectedLanguage,
    );
    const sourceOutputSelector = legacyOutput
      ? legacyOutput.operation.sourceSelector
      : catalogRow.key.output;
    const { outputContracts: contracts, selectedChannels } =
      selectedOutputContracts(
        definitions,
        surface.name,
        sourceOutputSelector,
      );
    if (legacyOutput) {
      exactLegacyHostOutputBinding({
        functionName: surface.name,
        key: catalogRow.key,
        outputContracts: contracts,
        selectedChannels,
        sourceRefs: [
          ...new Set(definitions.map((definition) => definition.sourceRef)),
        ].sort(compareText),
      });
      return null;
    }
    if (catalogRow.key.output !== "[[return]]") {
      if (!structuredVfsOutput) {
        exactPathOutputBinding(
          surface.name,
          catalogRow.key.output,
          selectedChannels,
        );
      }
      return null;
    }
    const returnKinds = new Set(
      contracts.map((contract) =>
        contract.return.role === "none" ? "void" : contract.return.kind,
      ),
    );
    if (returnKinds.size !== 1)
      return "selected-definitions-disagree-on-return-contract";
    const [returnKind] = returnKinds;
    if (returnKind === "void")
      return "void-abi-has-no-syntactic-return-slot";
    if (returnKind === "pointer")
      return "pointer-return-ownership-is-not-source-bound";
    if (returnKind === "aggregate")
      return "aggregate-return-normalization-is-not-source-bound";
    if (returnKind === "unknown") return "return-contract-is-unresolved";
    return null;
  }
  const variants = new Set(
    (surface?.metadata?.definitions ?? []).map(
      (definition) => definition.targetVariant,
    ),
  );
  if (
    variants.size > 0 &&
    [...variants].every((variant) => new Set(["android", "ios"]).has(variant))
  ) {
    return "platform-only-route-requires-separate-target-absence-evidence";
  }
  if (surface?.name?.startsWith("ex_host_http_")) {
    return "http-server-route-requires-owned-live-server-state";
  }
  if (surface?.name?.startsWith("ex_worklet_")) {
    return "worklet-route-requires-owned-runtime-and-worklet-state";
  }
  if (surface?.name?.startsWith("ex_hermes_debugger_")) {
    return "debugger-route-requires-owned-live-debug-session";
  }
  if (surface?.name === "ex_hermes_create_armed") {
    return "armed-runtime-creation-requires-hermes-promise-rejection-checkpoint-hook";
  }
  if (surface?.name?.startsWith("ex_hermes_")) {
    return "engine-route-requires-owned-armed-or-diagnostic-runtime-state";
  }
  if (surface?.name?.startsWith("ex_host_vfs_")) {
    return "vfs-route-requires-authenticated-runtime-session";
  }
  if (
    /^ex_host_(?:authorize_typed|evaluate_typed|typed_|lifecycle_)/u.test(
      surface?.name ?? "",
    )
  ) {
    return "typed-authority-route-requires-authenticated-armed-context";
  }
  return "stateful-host-abi-route-has-no-bounded-output-template";
}

/**
 * Partition the complete Host ABI catalog into exact target-absence bindings,
 * executable native probes, and explicit residuals.  This is the integration
 * boundary used by the master sweep: it rejects both an orphan result key and
 * an input catalog key that disappears during authoring.
 */
export function buildHostAbiOutputProbePartition({
  catalog,
  coverage,
  surfaces,
  targetAbsenceBindings = [],
}) {
  requireCondition(Array.isArray(catalog?.rows), "output catalog has no rows");
  requireCondition(Array.isArray(coverage?.edges), "coverage registry has no edges");
  requireCondition(Array.isArray(surfaces), "source inventory has no surfaces");
  requireCondition(
    Array.isArray(targetAbsenceBindings),
    "target-absence bindings must be an array",
  );

  const catalogRows = catalog.rows.filter(
    (row) => row.key?.sourceKind === "host-abi",
  );
  const catalogByKey = new Map();
  for (const row of catalogRows) {
    const canonicalKey = canonicalOutputDispositionKey(
      row.key,
      "Host ABI catalog key",
    );
    requireCondition(
      !catalogByKey.has(canonicalKey),
      `${canonicalKey}: duplicate Host ABI catalog key`,
    );
    catalogByKey.set(canonicalKey, row);
  }

  const edgesById = new Map();
  for (const edge of coverage.edges) {
    requireCondition(
      !edgesById.has(edge.id),
      `${edge.id}: duplicate coverage edge`,
    );
    edgesById.set(edge.id, edge);
  }
  const surfacesByObservedKey = new Map();
  for (const surface of surfaces) {
    if (surface.kind !== "host-abi") continue;
    requireCondition(
      typeof surface.observedKey === "string" &&
        !surfacesByObservedKey.has(surface.observedKey),
      `${surface.observedKey}: duplicate or invalid Host ABI source surface`,
    );
    surfacesByObservedKey.set(surface.observedKey, surface);
  }

  const targetAbsenceByKey = new Map();
  for (const binding of targetAbsenceBindings) {
    const canonicalKey = canonicalOutputDispositionKey(
      binding?.key,
      "Host ABI target-absence key",
    );
    requireCondition(
      binding.key.sourceKind === "host-abi" && catalogByKey.has(canonicalKey),
      `${canonicalKey}: target-absence binding is not an exact Host ABI catalog row`,
    );
    requireCondition(
      !targetAbsenceByKey.has(canonicalKey),
      `${canonicalKey}: duplicate Host ABI target-absence binding`,
    );
    targetAbsenceByKey.set(canonicalKey, binding);
  }

  const targetAbsence = [];
  const rows = [];
  const residuals = [];
  const emittedKeys = new Set();
  for (const catalogRow of catalogRows) {
    const canonicalKey = canonicalOutputDispositionKey(catalogRow.key);
    const edge = edgesById.get(catalogRow.key.surfaceId);
    requireCondition(
      edge?.surface?.kind === "host-abi",
      `${catalogRow.key.surfaceId}: missing Host ABI coverage edge`,
    );
    const surface = surfacesByObservedKey.get(
      `host-abi:${edge.surface.name}`,
    );
    requireCondition(
      surface,
      `${edge.id}: missing Host ABI source-inventory surface`,
    );
    const targetAbsenceBinding = targetAbsenceByKey.get(canonicalKey) ?? null;
    const probe = authoredHostAbiOutputProbe({
      catalogRow,
      surface,
      coverageEdge: edge,
      targetAbsenceBinding,
    });
    if (targetAbsenceBinding) {
      targetAbsence.push(structuredClone(targetAbsenceBinding));
    } else if (probe) {
      rows.push({ key: structuredClone(catalogRow.key), probe });
    } else {
      residuals.push({
        key: structuredClone(catalogRow.key),
        reason: hostAbiOutputResidualReason({ catalogRow, surface }),
      });
    }
    requireCondition(
      !emittedKeys.has(canonicalKey),
      `${canonicalKey}: Host ABI output key was emitted twice`,
    );
    emittedKeys.add(canonicalKey);
  }

  requireCondition(
    emittedKeys.size === catalogByKey.size &&
      [...catalogByKey.keys()].every((key) => emittedKeys.has(key)) &&
      [...emittedKeys].every((key) => catalogByKey.has(key)),
    "Host ABI output partition is not bidirectional with the catalog",
  );
  const compareRows = (left, right) =>
    compareText(
      canonicalOutputDispositionKey(left.key),
      canonicalOutputDispositionKey(right.key),
    );
  targetAbsence.sort(compareRows);
  rows.sort(compareRows);
  residuals.sort(compareRows);
  return {
    hostAbiOutputPartitionSchema: HOST_ABI_OUTPUT_PARTITION_SCHEMA,
    targetAbsenceBindings: targetAbsence,
    rows,
    residuals,
  };
}
