// Test-only native output executor.
//
// @ref LLP 0002#memory-ownership-rules-observed — every native string,
// buffer, file, SQLite statement, and context minted here is released through
// its owning ABI.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — the
// executor rechecks exact source identities and records only actual returns.
// @ref LLP 0023#6-path-bearing-observables — private native path bytes never
// enter the evidence artifact; the executor records only their validated class.

use super::*;
use base64::Engine as _;
use serde_json::{json, Value};
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

const DESCRIPTOR_KIND: &str = "source-bound-host-abi-output";
const INVOCATION_SCHEMA: &str = "ibex/capsec-host-abi-output-invocation/1";
const OUTPUT_CONTRACT_SCHEMA: &str = "ibex/host-abi-output-contract/1";
const PRIVATE_NATIVE_PATH_CLASS: &str = "private-native-path";
const VIRTUAL_ABSOLUTE_CLASS: &str = "virtual-absolute";
const HOST_ABI_EACCES: &str = "HOST_ABI_EACCES";
const HOST_ABI_EEXIST: &str = "HOST_ABI_EEXIST";
const HOST_ABI_ENOENT: &str = "HOST_ABI_ENOENT";
const HOST_ABI_EPERM: &str = "HOST_ABI_EPERM";

#[derive(Clone, Copy)]
struct ExpectedPathOutputContract {
    kind: &'static str,
    length_parameter: &'static str,
    normalized_class: &'static str,
    operation: &'static str,
    ownership_kind: &'static str,
    parameter: &'static str,
    release_function: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct ExpectedLegacyOutputContract {
    alias: &'static str,
    catalog_selector: &'static str,
    mode: &'static str,
    operation: &'static str,
    projection_kind: &'static str,
    return_variant: &'static str,
}

fn expected_legacy_output_contract(
    function_name: &str,
    selector: &str,
    alias: &str,
    mode: &str,
    return_variant: &str,
) -> Option<ExpectedLegacyOutputContract> {
    let mode: &'static str = match mode {
        "all" => "all",
        "armed" => "armed",
        "unarmed" => "unarmed",
        _ => return None,
    };
    let return_variant: &'static str = match return_variant {
        "error" => "error",
        "refused" => "refused",
        "success" => "success",
        _ => return None,
    };
    let contract = match (function_name, selector, alias, mode, return_variant) {
        (
            "ex_host_fs_mkdir_recursive_result",
            "[[return]]",
            "ex_host_fs_mkdir_recursive_result",
            mode @ ("unarmed" | "armed"),
            return_variant @ ("success" | "error" | "refused"),
        ) if (mode, return_variant) != ("armed", "success")
            && (mode, return_variant) != ("armed", "error")
            && (mode, return_variant) != ("unarmed", "refused") =>
        {
            ExpectedLegacyOutputContract {
                alias: "ex_host_fs_mkdir_recursive_result",
                catalog_selector: "[[return]]",
                mode,
                operation: "rust-host-legacy-path-output",
                projection_kind: "whole-return",
                return_variant,
            }
        }
        (
            "ex_host_fs_mkdtemp",
            "[[return]]",
            "ex_host_fs_mkdtemp",
            mode @ ("unarmed" | "armed"),
            return_variant @ ("success" | "error" | "refused"),
        ) if (mode, return_variant) != ("armed", "success")
            && (mode, return_variant) != ("armed", "error")
            && (mode, return_variant) != ("unarmed", "refused") =>
        {
            ExpectedLegacyOutputContract {
                alias: "ex_host_fs_mkdtemp",
                catalog_selector: "[[return]]",
                mode,
                operation: "rust-host-legacy-path-output",
                projection_kind: "whole-return",
                return_variant,
            }
        }
        (
            "ex_host_fs_realpath",
            "[[return]]",
            "ex_host_fs_realpath",
            mode @ ("unarmed" | "armed"),
            return_variant @ ("success" | "error" | "refused"),
        ) if (mode, return_variant) != ("armed", "success")
            && (mode, return_variant) != ("armed", "error")
            && (mode, return_variant) != ("unarmed", "refused") =>
        {
            ExpectedLegacyOutputContract {
                alias: "ex_host_fs_realpath",
                catalog_selector: "[[return]]",
                mode,
                operation: "rust-host-legacy-path-output",
                projection_kind: "whole-return",
                return_variant,
            }
        }
        ("ex_host_fs_readdir", "array-items", "ex_host_fs_readdir[]", "all", "success") => {
            ExpectedLegacyOutputContract {
                alias: "ex_host_fs_readdir[]",
                catalog_selector: "array-items",
                mode: "all",
                operation: "rust-host-legacy-directory-output",
                projection_kind: "json-array-items",
                return_variant: "success",
            }
        }
        _ => return None,
    };
    Some(contract)
}

fn expected_legacy_selected_output(contract: ExpectedLegacyOutputContract) -> Value {
    json!({
        "kind": "pointer",
        "ownership": {
            "kind": "caller-owned",
            "releaseFunction": "ex_host_free_string",
        },
        "role": "return",
        "selector": "[[return]]",
        "projection": {
            "catalogSelector": contract.catalog_selector,
            "kind": contract.projection_kind,
        },
    })
}

fn legacy_source_requirements(function_name: &str) -> Option<&'static [&'static str]> {
    match function_name {
        "ex_host_fs_mkdir_recursive_result" => Some(&[
            "path.is_null()",
            "CStr::from_ptr(path)",
            "cursor.exists()",
            "std::fs::create_dir_all(&path)",
        ]),
        "ex_host_fs_mkdtemp" => Some(&[
            "prefix.is_null()",
            "CStr::from_ptr(prefix)",
            "getrandom(&mut rng_bytes)",
            "std::fs::create_dir(&dir_path)",
        ]),
        "ex_host_fs_realpath" => Some(&[
            "path.is_null()",
            "CStr::from_ptr(path)",
            "std::fs::canonicalize(&path)",
        ]),
        "ex_host_fs_readdir" => Some(&[]),
        _ => None,
    }
}

fn expected_legacy_source_safety_binding(function_name: &str) -> Result<Value, String> {
    let precedes = legacy_source_requirements(function_name)
        .ok_or_else(|| format!("{function_name}: no legacy source requirements"))?;
    let source_path = "src/host/abi.rs";
    let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(source_path))
        .map_err(|error| format!("{function_name}: read {source_path}: {error}"))?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|_| format!("{function_name}: {source_path} is not UTF-8"))?;
    let function_token = format!("fn {function_name}(");
    let function_start = source
        .find(&function_token)
        .ok_or_else(|| format!("{function_name}: legacy definition is absent"))?;
    let remaining = &source[function_start..];
    let function_end = remaining
        .get(1..)
        .and_then(|tail| tail.find("\n#[no_mangle]").map(|offset| offset + 1))
        .unwrap_or(remaining.len());
    let function_source = &remaining[..function_end];
    let ownership_start = function_start.saturating_sub(800);
    let ownership_window = &source[ownership_start..function_start + function_end];
    if !ownership_window.contains("ex_host_free_string") {
        return Err(format!(
            "{function_name}: returned string ownership is not source-annotated"
        ));
    }
    if !precedes.is_empty() {
        let guard = "if refuse_armed_legacy_path_output()";
        let guard_index = function_source
            .find(guard)
            .ok_or_else(|| format!("{function_name}: armed refusal guard is absent"))?;
        if precedes.iter().any(|token| {
            function_source
                .find(token)
                .is_none_or(|index| index <= guard_index)
        }) {
            return Err(format!(
                "{function_name}: armed refusal no longer precedes path decode, lookup, randomness, or mutation"
            ));
        }
    }
    let mut binding = json!({
        "path": source_path,
        "rawContentDigest": tagged_bytes_digest(&bytes),
        "returnOwnership": {
            "kind": "caller-owned",
            "releaseFunction": "ex_host_free_string",
            "sourceToken": "ex_host_free_string",
        },
    });
    if !precedes.is_empty() {
        binding["armedRefusalOrder"] = json!({
            "guard": "if refuse_armed_legacy_path_output()",
            "precedes": precedes,
        });
    }
    Ok(binding)
}

fn expected_path_output_contract(
    function_name: &str,
    selector: &str,
) -> Option<ExpectedPathOutputContract> {
    let contract = match (function_name, selector) {
        ("ex_hermes_engine_binary_path", "out:out") => ExpectedPathOutputContract {
            kind: "buffer",
            length_parameter: "out_len",
            normalized_class: PRIVATE_NATIVE_PATH_CLASS,
            operation: "native-hermes-stateless-path-output",
            ownership_kind: "caller-storage",
            parameter: "out",
            release_function: None,
        },
        ("ex_host_vfs_chdir", "out:virtual") => ExpectedPathOutputContract {
            kind: "buffer",
            length_parameter: "out_virtual_len",
            normalized_class: VIRTUAL_ABSOLUTE_CLASS,
            operation: "rust-host-authenticated-vfs-path-output",
            ownership_kind: "caller-owned",
            parameter: "out_virtual",
            release_function: Some("ex_host_free_buffer"),
        },
        ("ex_host_vfs_get_cwd", "out:virtual") => ExpectedPathOutputContract {
            kind: "buffer",
            length_parameter: "out_virtual_len",
            normalized_class: VIRTUAL_ABSOLUTE_CLASS,
            operation: "rust-host-authenticated-vfs-path-output",
            ownership_kind: "caller-owned",
            parameter: "out_virtual",
            release_function: Some("ex_host_free_buffer"),
        },
        ("ex_host_vfs_resolve_path", "out:virtual") => ExpectedPathOutputContract {
            kind: "buffer",
            length_parameter: "out_virtual_len",
            normalized_class: VIRTUAL_ABSOLUTE_CLASS,
            operation: "rust-host-authenticated-vfs-path-output",
            ownership_kind: "caller-owned",
            parameter: "out_virtual",
            release_function: Some("ex_host_free_buffer"),
        },
        ("ex_host_vfs_resolve_path", "out:backing") => ExpectedPathOutputContract {
            kind: "buffer",
            length_parameter: "out_backing_len",
            normalized_class: PRIVATE_NATIVE_PATH_CLASS,
            operation: "rust-host-authenticated-vfs-path-output",
            ownership_kind: "caller-owned",
            parameter: "out_backing",
            release_function: Some("ex_host_free_buffer"),
        },
        _ => return None,
    };
    Some(contract)
}

fn expected_path_selected_output(contract: ExpectedPathOutputContract, selector: &str) -> Value {
    let ownership = match contract.release_function {
        Some(release_function) => json!({
            "kind": contract.ownership_kind,
            "releaseFunction": release_function,
        }),
        None => json!({ "kind": contract.ownership_kind }),
    };
    json!({
        "kind": contract.kind,
        "lengthParameter": contract.length_parameter,
        "ownership": ownership,
        "parameter": contract.parameter,
        "role": "output",
        "selector": selector,
    })
}

const EVALUATION_RESULT_SELECTORS: &[&str] = &[
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
];

fn is_evaluation_result_selector(function_name: &str, selector: &str) -> bool {
    let supported_function = matches!(
        function_name,
        "ex_hermes_eval_structured_diagnostic"
            | "ex_hermes_evaluation_result_dispose"
            | "ex_hermes_evaluation_result_init"
    );
    supported_function
        && EVALUATION_RESULT_SELECTORS.contains(&selector)
        && (function_name == "ex_hermes_eval_structured_diagnostic"
            || !selector.starts_with("out:result.positions[]."))
}

fn is_bounded_family_output_selector(function_name: &str, selector: &str) -> bool {
    is_evaluation_result_selector(function_name, selector)
        || matches!(
            (function_name, selector),
            ("ex_host_fs_pread", "out:buf")
                | ("ex_host_fs_read", "out:buf")
                | ("ex_host_fs_read_file", "out:errno" | "out:len")
                | (
                    "ex_host_terminal_session_stdio_query",
                    "out:columns" | "out:is_tty" | "out:rows"
                )
                | ("ex_hermes_engine_mapped_object", "out:device" | "out:inode")
                | (
                    "ex_host_vfs_chdir" | "ex_host_vfs_get_cwd" | "ex_host_vfs_resolve_path",
                    "out:errno"
                )
                | ("ex_hermes_eval", "out:value")
                | (
                    "ex_hermes_take_async_failure_event",
                    "out:event.associated_evaluation"
                        | "out:event.dropped_count"
                        | "out:event.event_id"
                        | "out:event.host_context_id"
                        | "out:event.kind"
                        | "out:event.owning_principal_id"
                        | "out:event.principal_status"
                        | "out:event.value.handle_id"
                        | "out:event.value.runtime_nonce"
                )
                | (
                    "ex_hermes_take_cancellation_event",
                    "out:event.resolution" | "out:event.target_id"
                )
                | (
                    "ex_hermes_take_work_unit_event",
                    "out:event.kind"
                        | "out:event.phase"
                        | "out:event.scheduling_id"
                        | "out:event.target_id"
                )
                | ("ex_worklet_install", "out:error")
                | ("ex_worklet_invoke", "out:result_json")
                | (
                    "ex_worklet_bind_shared_value_accessors",
                    "callback:read_callback/0.epoch"
                        | "callback:read_callback/0.generation"
                        | "callback:read_callback/0.slot"
                        | "callback:read_callback/2"
                        | "callback:write_callback/0.epoch"
                        | "callback:write_callback/0.generation"
                        | "callback:write_callback/0.slot"
                        | "callback:write_callback/1"
                        | "callback:write_callback/2"
                )
                | ("ex_worklet_drain_scheduled_typed", "out:calls")
                | ("ex_worklet_install_metrics", "out:metrics")
                | ("ex_worklet_install_typed", "out:error" | "out:identity")
                | (
                    "ex_worklet_invoke_typed",
                    "out:output_count" | "out:outputs"
                )
                | (
                    "ex_worklet_set_measure_callback",
                    "callback:callback/0" | "callback:callback/2"
                )
                | ("ex_host_authorize_typed_lifecycle_exit_stack", "out:code")
                | ("ex_host_lifecycle_exit_code_get_stack", "out:code")
                | (
                    "ex_host_typed_generations",
                    "out:dynamic" | "out:handle" | "out:negative"
                )
                | ("ex_host_env_get", "out:buf")
                | ("ex_host_random_fill", "out:buf")
                | ("ex_hermes_dispatch_worklet_calls", "out:delivered")
                | (
                    "ex_hermes_value_safe_throw_metadata",
                    "out:error_class"
                        | "out:message.data"
                        | "out:metadata_fields"
                        | "out:stack.data"
                )
                | ("ex_hermes_value_stage1_text", "out:data" | "out:truncated")
                | (
                    "ex_hermes_schedule_watchdog_heartbeat_for_generation",
                    "callback:callback/0"
                )
                | (
                    "ex_hermes_set_host_call",
                    "callback:callback/0" | "callback:callback/1"
                )
                | (
                    "ex_hermes_set_host_call_async",
                    "callback:callback/0"
                        | "callback:callback/1"
                        | "callback:callback/2"
                        | "callback:callback/3"
                )
                | (
                    "ex_hermes_set_exact_host_call_async",
                    "callback:callback/0"
                        | "callback:callback/1"
                        | "callback:callback/2"
                        | "callback:callback/3"
                        | "callback:callback/5"
                )
                | ("ex_hermes_set_host_wake_hook", "callback:hook/0")
        )
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeOwnedBytes {
    data: *mut u8,
    length: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeSourcePosition {
    source_label: NativeOwnedBytes,
    line: u32,
    column: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeValueHandle {
    runtime_nonce: u64,
    handle_id: u64,
}

#[repr(C)]
struct NativeEvaluationResult {
    abi_version: u32,
    struct_size: u32,
    outcome_tag: u32,
    fault: u32,
    work_target_id: u64,
    value: NativeValueHandle,
    throw_metadata_status: u32,
    throw_metadata_fields: u32,
    throw_error_class: u32,
    lifecycle_exit_code: i32,
    capability_flags: u32,
    message: NativeOwnedBytes,
    stack: NativeOwnedBytes,
    positions: *mut NativeSourcePosition,
    position_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeWorkletSharedValueHandle {
    slot: u32,
    generation: u32,
    epoch: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeWorkletCapture {
    kind: u32,
    scalar: f32,
    shared_value: NativeWorkletSharedValueHandle,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeWorkletScheduledCall {
    source_identity: u64,
    source_sequence: u64,
    generation: u64,
    callback_identity: u32,
    argument_count: u32,
    arguments: [f32; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeWorkletInstallMetrics {
    source_install_count: u64,
    reused_install_count: u64,
    source_install_total_ns: u64,
    source_install_max_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeMotionRatedPublishSample {
    channel_identity: u64,
    dirty_generation: u64,
    sample_time_ns: u64,
    value_count: u32,
    flags: u32,
    values: [f32; 8],
}

impl NativeEvaluationResult {
    fn zeroed() -> Self {
        Self {
            abi_version: 0,
            struct_size: 0,
            outcome_tag: 0,
            fault: 0,
            work_target_id: 0,
            value: NativeValueHandle {
                runtime_nonce: 0,
                handle_id: 0,
            },
            throw_metadata_status: 0,
            throw_metadata_fields: 0,
            throw_error_class: 0,
            lifecycle_exit_code: 0,
            capability_flags: 0,
            message: NativeOwnedBytes {
                data: std::ptr::null_mut(),
                length: 0,
            },
            stack: NativeOwnedBytes {
                data: std::ptr::null_mut(),
                length: 0,
            },
            positions: std::ptr::null_mut(),
            position_count: 0,
        }
    }
}

extern "C" {
    fn ex_hermes_create() -> *mut HermesRuntimeOpaque;
    fn ex_hermes_engine_binary_path(out: *mut std::os::raw::c_char, out_len: usize) -> i32;
    fn ex_hermes_engine_mapped_object(out_device: *mut u64, out_inode: *mut u64) -> i32;
    fn ex_hermes_bytecode_version() -> u32;
    fn ex_hermes_evaluation_result_init(result: *mut NativeEvaluationResult);
    fn ex_hermes_evaluation_result_dispose(result: *mut NativeEvaluationResult);
    fn ex_hermes_eval_structured_diagnostic(
        runtime: *mut HermesRuntimeOpaque,
        source: *const u8,
        source_length: usize,
        source_label: *const u8,
        source_label_length: usize,
        result: *mut NativeEvaluationResult,
    ) -> i32;
    fn ex_hermes_value_release(runtime: *mut HermesRuntimeOpaque, handle: NativeValueHandle)
        -> u32;
    fn ex_hermes_value_kind(runtime: *mut HermesRuntimeOpaque, handle: NativeValueHandle) -> u32;
    fn ex_hermes_value_stage1_text(
        runtime: *mut HermesRuntimeOpaque,
        handle: NativeValueHandle,
        out_data: *mut *mut u8,
        out_length: *mut usize,
        out_truncated: *mut u32,
    ) -> u32;
    fn ex_hermes_value_safe_throw_metadata(
        runtime: *mut HermesRuntimeOpaque,
        handle: NativeValueHandle,
        metadata_fields: *mut u32,
        error_class: *mut u32,
        message: *mut NativeOwnedBytes,
        stack: *mut NativeOwnedBytes,
    ) -> u32;
    fn ex_hermes_session_display_ack(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
        handle: NativeValueHandle,
        displayed: bool,
    ) -> u32;
    fn ex_hermes_callback_backlog(runtime: *mut HermesRuntimeOpaque) -> u32;
    fn ex_hermes_set_keep_alive_on_async_error(runtime: *mut HermesRuntimeOpaque, enabled: i32);
    fn ex_hermes_gc(runtime: *mut HermesRuntimeOpaque);
    fn ex_hermes_get_heap_info(
        runtime: *mut HermesRuntimeOpaque,
        include_expensive: i32,
    ) -> *mut std::os::raw::c_char;
    fn ex_hermes_get_gc_stats(runtime: *mut HermesRuntimeOpaque) -> *mut std::os::raw::c_char;

    fn ex_worklet_create() -> *mut HermesRuntimeOpaque;
    fn ex_worklet_destroy(runtime: *mut HermesRuntimeOpaque);
    fn ex_worklet_set_generation(runtime: *mut HermesRuntimeOpaque, generation: u64);
    fn ex_worklet_generation(runtime: *mut HermesRuntimeOpaque) -> u64;
    fn ex_worklet_install(
        runtime: *mut HermesRuntimeOpaque,
        worklet_id: *const std::os::raw::c_char,
        source: *const u8,
        source_len: usize,
        generation: u64,
        out_error: *mut *mut std::os::raw::c_char,
    ) -> i32;
    fn ex_worklet_invoke(
        runtime: *mut HermesRuntimeOpaque,
        worklet_id: *const std::os::raw::c_char,
        args_json: *const std::os::raw::c_char,
        out_result_json: *mut *mut std::os::raw::c_char,
    ) -> i32;
    fn ex_worklet_install_typed(
        runtime: *mut HermesRuntimeOpaque,
        install_format: u32,
        artifact: *const u8,
        artifact_len: usize,
        captures: *const NativeWorkletCapture,
        capture_count: u32,
        generation: u64,
        out_identity: *mut u64,
        out_error: *mut *mut std::os::raw::c_char,
    ) -> i32;
    fn ex_worklet_invoke_typed(
        runtime: *mut HermesRuntimeOpaque,
        identity: u64,
        inputs: *const f32,
        input_count: u32,
        outputs: *mut f32,
        output_capacity: u32,
        out_output_count: *mut u32,
    ) -> i32;
    fn ex_worklet_install_metrics(
        runtime: *mut HermesRuntimeOpaque,
        out_metrics: *mut NativeWorkletInstallMetrics,
    ) -> i32;
    fn ex_worklet_bind_shared_value_accessors(
        runtime: *mut HermesRuntimeOpaque,
        read_callback: Option<
            extern "C" fn(
                handle: NativeWorkletSharedValueHandle,
                out_value: *mut f32,
                context: *mut std::ffi::c_void,
            ) -> u32,
        >,
        write_callback: Option<
            extern "C" fn(
                handle: NativeWorkletSharedValueHandle,
                value: f32,
                context: *mut std::ffi::c_void,
            ) -> u32,
        >,
        context: *mut std::ffi::c_void,
    ) -> i32;
    fn ex_worklet_set_measure_callback(
        runtime: *mut HermesRuntimeOpaque,
        callback: Option<
            extern "C" fn(
                node_id: u32,
                out_frame4: *mut f32,
                context: *mut std::ffi::c_void,
            ) -> i32,
        >,
        context: *mut std::ffi::c_void,
    );
    fn ex_worklet_drain_logs(runtime: *mut HermesRuntimeOpaque) -> *mut std::os::raw::c_char;
    fn ex_worklet_drain_scheduled(runtime: *mut HermesRuntimeOpaque) -> *mut std::os::raw::c_char;
    fn ex_worklet_drain_scheduled_typed(
        runtime: *mut HermesRuntimeOpaque,
        out_calls: *mut NativeWorkletScheduledCall,
        capacity: u32,
    ) -> u32;
    fn ex_worklet_take_scheduled_drop_count(runtime: *mut HermesRuntimeOpaque) -> u64;
    fn ex_hermes_dispatch_worklet_calls(
        runtime: *mut HermesRuntimeOpaque,
        calls: *const NativeWorkletScheduledCall,
        count: u32,
        out_delivered: *mut u32,
    ) -> i32;
    fn ex_hermes_dispatch_worklet_json_batch(
        runtime: *mut HermesRuntimeOpaque,
        batch_json: *const u8,
        batch_len: usize,
        generation: u64,
    ) -> i32;
    fn ex_hermes_dispatch_motion_rated_publish(
        runtime: *mut HermesRuntimeOpaque,
        sample: *const NativeMotionRatedPublishSample,
    ) -> i32;
    fn ex_hermes_schedule_watchdog_heartbeat_for_generation(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        callback: extern "C" fn(context: *mut std::ffi::c_void),
        context: *mut std::ffi::c_void,
    );
}

fn tagged_bytes_digest(bytes: &[u8]) -> String {
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(bytes))
    )
}

fn tagged_jcs_digest(value: &Value) -> String {
    tagged_bytes_digest(
        &capsec_semantics::canonical::to_jcs_bytes(value)
            .expect("serialize Host ABI descriptor as JCS"),
    )
}

fn raw(kind: &str, shape: &str, value: Value) -> Value {
    json!({
        "kind": kind,
        "rawValueShape": shape,
        "value": value,
        "errorCode": null,
    })
}

fn returned_number(value: impl Into<Value>) -> Value {
    raw("return", "number", value.into())
}

fn returned_undefined() -> Value {
    raw("return", "undefined", Value::Null)
}

fn returned_null() -> Value {
    raw("return", "null", Value::Null)
}

fn returned_string(value: String) -> Value {
    raw("return", "string", Value::String(value))
}

fn returned_object() -> Value {
    raw("return", "object", Value::Null)
}

// The sweep's error outcome is named `throw` because most executors observe
// JavaScript. For this C ABI tranche it carries the actual NULL return shape
// plus the errno that the executor independently read immediately afterward.
fn failed_with_error_code(error_code: &str) -> Value {
    json!({
        "kind": "throw",
        "rawValueShape": "null",
        "value": null,
        "errorCode": error_code,
    })
}

fn c_string(path: &Path) -> CString {
    CString::new(path.to_string_lossy().as_bytes()).expect("Host ABI fixture path contains NUL")
}

fn take_host_string(pointer: *mut std::ffi::c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    crate::host::abi::ex_host_free_string(pointer);
    Some(value)
}

fn raw_host_string(pointer: *mut std::ffi::c_char) -> Value {
    take_host_string(pointer).map_or_else(returned_null, returned_string)
}

fn take_hermes_string(pointer: *mut std::os::raw::c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    unsafe { ex_hermes_free_string(pointer) };
    Some(value)
}

fn raw_hermes_string(pointer: *mut std::os::raw::c_char) -> Value {
    take_hermes_string(pointer).map_or_else(returned_null, returned_string)
}

fn native_owned_bytes_value(bytes: NativeOwnedBytes) -> Result<Value, String> {
    if bytes.data.is_null() {
        return if bytes.length == 0 {
            Ok(Value::Null)
        } else {
            Err("structured result had a null buffer with nonzero length".into())
        };
    }
    if bytes.length > 1 << 20 {
        return Err("structured result buffer exceeded the evidence bound".into());
    }
    // SAFETY: the result owns `length` bytes until the enclosing result is
    // disposed; callers invoke this helper before disposal.
    let value = unsafe { std::slice::from_raw_parts(bytes.data, bytes.length) };
    Ok(json!(value))
}

fn evaluation_result_observation(
    result: &NativeEvaluationResult,
    selector: &str,
) -> Result<Value, String> {
    let positions = if result.positions.is_null() {
        if result.position_count != 0 {
            return Err("structured result had null positions with a nonzero count".into());
        }
        &[][..]
    } else {
        if result.position_count > 1024 {
            return Err("structured result exceeded the position evidence bound".into());
        }
        // SAFETY: the result owns `position_count` initialized position rows
        // until disposal, which happens only after this projection returns.
        unsafe { std::slice::from_raw_parts(result.positions, result.position_count) }
    };
    let observation = match selector {
        "out:result.abi_version" => returned_number(result.abi_version),
        "out:result.capability_flags" => returned_number(result.capability_flags),
        "out:result.fault" => returned_number(result.fault),
        "out:result.lifecycle_exit_code" => returned_number(result.lifecycle_exit_code),
        "out:result.message.data" => match native_owned_bytes_value(result.message)? {
            Value::Null => returned_null(),
            value => raw("return", "array", value),
        },
        "out:result.outcome_tag" => returned_number(result.outcome_tag),
        "out:result.positions" => {
            let rows = positions
                .iter()
                .map(|position| {
                    Ok(json!({
                        "column": position.column,
                        "line": position.line,
                        "sourceLabel": native_owned_bytes_value(position.source_label)?,
                    }))
                })
                .collect::<Result<Vec<Value>, String>>()?;
            raw("return", "array", json!(rows))
        }
        "out:result.positions[].column" => raw(
            "return",
            "array",
            json!(positions
                .iter()
                .map(|position| position.column)
                .collect::<Vec<_>>()),
        ),
        "out:result.positions[].line" => raw(
            "return",
            "array",
            json!(positions
                .iter()
                .map(|position| position.line)
                .collect::<Vec<_>>()),
        ),
        "out:result.positions[].source_label.data" => {
            let labels = positions
                .iter()
                .map(|position| native_owned_bytes_value(position.source_label))
                .collect::<Result<Vec<_>, _>>()?;
            raw("return", "array", json!(labels))
        }
        "out:result.stack.data" => match native_owned_bytes_value(result.stack)? {
            Value::Null => returned_null(),
            value => raw("return", "array", value),
        },
        "out:result.struct_size" => returned_number(result.struct_size),
        "out:result.throw_error_class" => returned_number(result.throw_error_class),
        "out:result.throw_metadata_fields" => returned_number(result.throw_metadata_fields),
        "out:result.throw_metadata_status" => returned_number(result.throw_metadata_status),
        "out:result.value.handle_id" => returned_number(result.value.handle_id),
        "out:result.value.runtime_nonce" => returned_number(result.value.runtime_nonce),
        "out:result.work_target_id" => returned_number(result.work_target_id),
        other => return Err(format!("unsupported structured result selector {other}")),
    };
    Ok(observation)
}

struct FsSandbox {
    root: PathBuf,
}

impl FsSandbox {
    fn new() -> Self {
        let nonce = format!(
            "ibex-capsec-host-abi-output-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("fixture clock before epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(nonce);
        std::fs::create_dir(&root).expect("create Host ABI output fixture directory");
        let root =
            std::fs::canonicalize(root).expect("canonicalize Host ABI output fixture directory");
        Self { root }
    }

    fn reset_file(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::write(&path, b"host-abi-output").expect("write Host ABI fixture file");
        path
    }
}

impl Drop for FsSandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn validate_virtual_absolute(bytes: &[u8]) -> Result<(), String> {
    let value = std::str::from_utf8(bytes).map_err(|_| "VFS output was not UTF-8".to_string())?;
    if value != "/project" && !value.starts_with("/project/") {
        return Err("VFS output was not rooted in the virtual project namespace".into());
    }
    if value.contains('\\')
        || value
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return Err("VFS output was not a normalized virtual absolute path".into());
    }
    Ok(())
}

fn validate_private_native_path(bytes: &[u8], expected_root: Option<&Path>) -> Result<(), String> {
    if bytes.is_empty() || bytes.contains(&0) {
        return Err("private native path output was empty or contained NUL".into());
    }

    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStrExt as _;
        Path::new(std::ffi::OsStr::from_bytes(bytes))
    };
    #[cfg(not(unix))]
    let decoded = std::str::from_utf8(bytes)
        .map_err(|_| "private native path output was not platform UTF-8".to_string())?;
    #[cfg(not(unix))]
    let path = Path::new(decoded);

    if !path.is_absolute() {
        return Err("private native path output was not absolute".into());
    }
    if let Some(root) = expected_root {
        if !path.starts_with(root) {
            return Err("private VFS backing path escaped its authenticated mount".into());
        }
    } else if std::fs::metadata(path).is_err() {
        return Err("private engine path did not identify a mapped filesystem object".into());
    }
    Ok(())
}

unsafe fn take_owned_host_buffer(data: *mut u8, len: u64) -> Result<Vec<u8>, String> {
    let len_usize = usize::try_from(len).map_err(|_| "Host output length overflow".to_string())?;
    if data.is_null() {
        return if len == 0 {
            Ok(Vec::new())
        } else {
            Err("Host output pointer was null for a non-zero length".into())
        };
    }
    // SAFETY: a successful Host ABI call transfers exactly `len` readable
    // bytes, and this helper releases that same allocation before returning.
    let bytes = unsafe { std::slice::from_raw_parts(data, len_usize) }.to_vec();
    crate::host::abi::ex_host_free_buffer(data, len);
    Ok(bytes)
}

struct OwnedAuthenticatedVfsRuntime {
    bound: std::cell::Cell<bool>,
    context_id: u64,
    previous_context: u64,
    root: PathBuf,
    runtime_nonce: u64,
    _reset: super::HostResetGuard,
    _engine_lock: tokio::sync::MutexGuard<'static, ()>,
}

impl OwnedAuthenticatedVfsRuntime {
    fn new(sandbox: &FsSandbox) -> Result<Self, String> {
        let engine_lock = hermes_engine_test_lock().blocking_lock();
        std::fs::create_dir_all(sandbox.root.join("node_modules/image-lib"))
            .map_err(|_| "create authenticated VFS package fixture".to_string())?;
        let (reset, digest) =
            install_armed_test_host_at(Some(&sandbox.root), true, true, true, Vec::new());
        let digest =
            CString::new(digest).map_err(|_| "armed Host digest contained NUL".to_string())?;
        let context_id = unsafe { crate::host::abi::ex_host_claim_armed_context(digest.as_ptr()) };
        if context_id == 0 {
            return Err("authenticated VFS Host context could not be claimed".into());
        }
        let runtime_nonce = 0x4341_5053_4543_5646_u64;
        if crate::host::abi::ex_host_vfs_bind_runtime(context_id, runtime_nonce) != 0 {
            crate::host::abi::ex_host_release_context(context_id);
            return Err("authenticated VFS Host context could not bind its runtime nonce".into());
        }
        let previous_context = crate::host::abi::ex_host_enter_context(context_id);
        if previous_context == u64::MAX {
            let _ = crate::host::abi::ex_host_vfs_unbind_runtime(runtime_nonce);
            crate::host::abi::ex_host_release_context(context_id);
            return Err("authenticated VFS Host context could not become active".into());
        }
        Ok(Self {
            bound: std::cell::Cell::new(true),
            context_id,
            previous_context,
            root: sandbox.root.clone(),
            runtime_nonce,
            _reset: reset,
            _engine_lock: engine_lock,
        })
    }

    fn runtime_nonce(&self) -> u64 {
        self.runtime_nonce
    }
}

impl Drop for OwnedAuthenticatedVfsRuntime {
    fn drop(&mut self) {
        if self.context_id != 0 {
            crate::host::abi::ex_host_restore_context(self.previous_context);
            if self.bound.replace(false) {
                let _ = crate::host::abi::ex_host_vfs_unbind_runtime(self.runtime_nonce);
            }
            crate::host::abi::ex_host_release_context(self.context_id);
            self.context_id = 0;
        }
    }
}

fn execute_engine_path_output(function_name: &str, selector: &str) -> Result<Value, String> {
    if (function_name, selector) != ("ex_hermes_engine_binary_path", "out:out") {
        return Err(format!(
            "unsupported stateless Hermes path output {function_name}:{selector}"
        ));
    }
    let mut output = [0_i8; 4096];
    let status = unsafe { ex_hermes_engine_binary_path(output.as_mut_ptr(), output.len()) };
    let length = usize::try_from(status)
        .ok()
        .filter(|length| *length < output.len())
        .ok_or("engine binary path output failed or exceeded its bounded buffer")?;
    if output[length] != 0 {
        return Err("engine binary path output was not NUL terminated".into());
    }
    let bytes = output[..length]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    validate_private_native_path(&bytes, None)?;
    Ok(returned_string(PRIVATE_NATIVE_PATH_CLASS.into()))
}

fn execute_vfs_path_output(
    runtime: &OwnedAuthenticatedVfsRuntime,
    function_name: &str,
    selector: &str,
) -> Result<Value, String> {
    let runtime_nonce = runtime.runtime_nonce();
    if runtime_nonce == 0 {
        return Err("authenticated VFS runtime became stale".into());
    }
    if function_name == "ex_host_vfs_bind_runtime" {
        return Ok(returned_number(crate::host::abi::EX_HOST_VFS_RESULT_OK));
    }
    if function_name == "ex_host_vfs_unbind_runtime" {
        let status = crate::host::abi::ex_host_vfs_unbind_runtime(runtime_nonce);
        if status == crate::host::abi::EX_HOST_VFS_RESULT_OK {
            runtime.bound.set(false);
        }
        return Ok(returned_number(status));
    }
    let root_principals = [0_u64];
    let mut backing_data = std::ptr::null_mut();
    let mut backing_len = 0_u64;
    let mut virtual_data = std::ptr::null_mut();
    let mut virtual_len = 0_u64;
    let mut host_errno = 0_i32;
    let status = match function_name {
        "ex_host_vfs_chdir" => {
            let input = b"/project";
            unsafe {
                crate::host::abi::ex_host_vfs_chdir(
                    runtime_nonce,
                    0,
                    root_principals.as_ptr(),
                    root_principals.len(),
                    input.as_ptr(),
                    input.len() as u64,
                    &mut virtual_data,
                    &mut virtual_len,
                    &mut host_errno,
                )
            }
        }
        "ex_host_vfs_get_cwd" => unsafe {
            crate::host::abi::ex_host_vfs_get_cwd(
                runtime_nonce,
                0,
                root_principals.as_ptr(),
                root_principals.len(),
                &mut virtual_data,
                &mut virtual_len,
                &mut host_errno,
            )
        },
        "ex_host_vfs_resolve_path" => {
            let input = b"/project/host-abi-output.js";
            unsafe {
                crate::host::abi::ex_host_vfs_resolve_path(
                    runtime_nonce,
                    input.as_ptr(),
                    input.len() as u64,
                    &mut backing_data,
                    &mut backing_len,
                    &mut virtual_data,
                    &mut virtual_len,
                    &mut host_errno,
                )
            }
        }
        other => return Err(format!("unsupported authenticated VFS path output {other}")),
    };
    let backing = unsafe { take_owned_host_buffer(backing_data, backing_len) }?;
    let virtual_path = unsafe { take_owned_host_buffer(virtual_data, virtual_len) }?;
    if status != crate::host::abi::EX_HOST_VFS_RESULT_OK || host_errno != 0 {
        return Err(format!(
            "authenticated VFS output call failed with status {status} and errno {host_errno}"
        ));
    }
    if selector == "[[return]]" {
        return Ok(returned_number(status));
    }
    if selector == "out:errno" {
        return Ok(returned_number(host_errno));
    }
    let normalized_class = match selector {
        "out:virtual" => {
            validate_virtual_absolute(&virtual_path)?;
            VIRTUAL_ABSOLUTE_CLASS
        }
        "out:backing" if function_name == "ex_host_vfs_resolve_path" => {
            validate_private_native_path(&backing, Some(&runtime.root))?;
            PRIVATE_NATIVE_PATH_CLASS
        }
        _ => {
            return Err(format!(
                "unsupported authenticated VFS selector {function_name}:{selector}"
            ))
        }
    };
    Ok(returned_string(normalized_class.into()))
}

struct OwnedAuthenticatedTypedContext {
    context_id: u64,
    runtime_nonce: u64,
    digest: String,
    previous_context: u64,
    _reset: super::HostResetGuard,
    _engine_lock: tokio::sync::MutexGuard<'static, ()>,
}

impl OwnedAuthenticatedTypedContext {
    fn new(sandbox: &FsSandbox) -> Result<Self, String> {
        let engine_lock = hermes_engine_test_lock().blocking_lock();
        std::fs::create_dir_all(sandbox.root.join("node_modules/image-lib"))
            .map_err(|error| format!("create typed-authority package fixture: {error}"))?;
        let (reset, digest) =
            install_armed_test_host_at(Some(&sandbox.root), true, true, true, Vec::new());
        Self::claim(reset, digest, engine_lock)
    }

    fn new_exact() -> Result<Self, String> {
        let engine_lock = hermes_engine_test_lock().blocking_lock();
        let (reset, digest) = install_armed_exact_test_host();
        Self::claim(reset, digest, engine_lock)
    }

    fn claim(
        reset: super::HostResetGuard,
        digest: String,
        engine_lock: tokio::sync::MutexGuard<'static, ()>,
    ) -> Result<Self, String> {
        let digest_c = CString::new(digest.as_str())
            .map_err(|_| "armed Host digest contained NUL".to_string())?;
        let context_id =
            unsafe { crate::host::abi::ex_host_claim_armed_context(digest_c.as_ptr()) };
        if context_id == 0 {
            return Err("typed-authority Host context could not be claimed".into());
        }
        let previous_context = crate::host::abi::ex_host_enter_context(context_id);
        if previous_context == u64::MAX {
            crate::host::abi::ex_host_release_context(context_id);
            return Err("typed-authority Host context could not become active".into());
        }
        let candidate = context_id ^ 0x5646_5354_5950_4544_u64;
        let runtime_nonce = if candidate == 0 { 1 } else { candidate };
        if crate::host::abi::ex_host_vfs_bind_runtime(context_id, runtime_nonce)
            != crate::host::abi::EX_HOST_VFS_RESULT_OK
        {
            crate::host::abi::ex_host_restore_context(previous_context);
            crate::host::abi::ex_host_release_context(context_id);
            return Err("typed-authority VFS generation could not be bound".into());
        }
        Ok(Self {
            context_id,
            runtime_nonce,
            digest,
            previous_context,
            _reset: reset,
            _engine_lock: engine_lock,
        })
    }

    fn context_id(&self) -> u64 {
        self.context_id
    }

    fn digest(&self) -> &str {
        &self.digest
    }

    fn runtime_nonce(&self) -> u64 {
        self.runtime_nonce
    }
}

impl Drop for OwnedAuthenticatedTypedContext {
    fn drop(&mut self) {
        if self.context_id != 0 {
            let _ = crate::host::abi::ex_host_vfs_unbind_runtime(self.runtime_nonce);
            crate::host::abi::ex_host_restore_context(self.previous_context);
            crate::host::abi::ex_host_release_context(self.context_id);
            self.context_id = 0;
        }
    }
}

fn root_principal_json() -> Value {
    json!({"kind": "root", "identity": "project-root"})
}

fn typed_process_spawn_authority_json() -> Value {
    json!({
        "cap": "process:spawn",
        "resource": {
            "kind": "executable",
            "logicalName": "git",
            "path": {
                "root": "absolute",
                "components": [
                    {"encoding": "utf8", "value": "usr"},
                    {"encoding": "utf8", "value": "bin"},
                    {"encoding": "utf8", "value": "git"},
                ],
                "hostBound": true,
            },
            "contentDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
    })
}

fn typed_handle_request_bytes() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "actor": root_principal_json(),
        "holder": root_principal_json(),
        "authority": {
            "cap": "fs:read",
            "resource": {
                "kind": "path-tree",
                "path": {"root": "project", "components": []},
            },
        },
    }))
    .expect("serialize bounded typed handle request")
}

fn mint_bounded_typed_handle() -> Result<String, String> {
    let root = [0_u64];
    let request = typed_handle_request_bytes();
    let returned = unsafe {
        crate::host::abi::ex_host_typed_handle_mint(
            0,
            root.as_ptr(),
            root.len(),
            request.as_ptr(),
            request.len(),
        )
    };
    let envelope = take_host_string(returned)
        .ok_or("typed handle mint returned NULL in an authenticated context")?;
    let parsed: Value = serde_json::from_str(&envelope)
        .map_err(|error| format!("typed handle mint returned invalid JSON: {error}"))?;
    parsed["handleId"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("typed handle mint did not succeed: {envelope}"))
}

fn execute_typed_authority(
    function_name: &str,
    selector: &str,
    sandbox: &FsSandbox,
) -> Result<Value, String> {
    let context = OwnedAuthenticatedTypedContext::new(sandbox)?;
    let root = [0_u64];
    let observation = match function_name {
        "ex_host_authorize_typed_environment_read_stack" => {
            let name = b"PATH";
            returned_number(unsafe {
                crate::host::abi::ex_host_authorize_typed_environment_read_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    0,
                    0,
                    name.as_ptr(),
                    name.len(),
                )
            })
        }
        "ex_host_authorize_typed_environment_write_stack" => {
            let name = b"IBEX_CAPSEC_OUTPUT";
            returned_number(unsafe {
                crate::host::abi::ex_host_authorize_typed_environment_write_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    0,
                    name.as_ptr(),
                    name.len(),
                )
            })
        }
        "ex_host_authorize_typed_fs_stack" => {
            let path = sandbox.root.join("typed-authority-input.txt");
            std::fs::write(&path, b"typed-authority")
                .map_err(|error| format!("write typed-authority fixture: {error}"))?;
            let path = c_string(&path);
            returned_number(unsafe {
                crate::host::abi::ex_host_authorize_typed_fs_stack(
                    context.runtime_nonce(),
                    0,
                    root.as_ptr(),
                    root.len(),
                    path.as_ptr(),
                    0,
                    1,
                    -1,
                    -1,
                    1,
                    0,
                    std::ptr::null(),
                )
            })
        }
        "ex_host_authorize_typed_lifecycle_exit_stack" => {
            let mut code = i32::MIN;
            let status = unsafe {
                crate::host::abi::ex_host_authorize_typed_lifecycle_exit_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    1,
                    7,
                    1,
                    &mut code,
                )
            };
            if selector == "out:code" {
                if status != 1 || code == i32::MIN {
                    return Err(format!(
                        "typed lifecycle exit did not initialize out:code (status {status})"
                    ));
                }
                returned_number(code)
            } else {
                returned_number(status)
            }
        }
        "ex_host_authorize_typed_listen_stack" => {
            let host = CString::new("127.0.0.1").unwrap();
            returned_number(unsafe {
                crate::host::abi::ex_host_authorize_typed_listen_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    0,
                    host.as_ptr(),
                    3000,
                    0,
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                )
            })
        }
        "ex_host_authorize_typed_network_stack" => {
            let host = CString::new("127.0.0.1").unwrap();
            let candidates = CString::new("[]").unwrap();
            returned_number(unsafe {
                crate::host::abi::ex_host_authorize_typed_network_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    1,
                    host.as_ptr(),
                    443,
                    0,
                    candidates.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                )
            })
        }
        "ex_host_authorize_typed_print_stack" => returned_number(unsafe {
            crate::host::abi::ex_host_authorize_typed_print_stack(0, root.as_ptr(), root.len(), 0)
        }),
        "ex_host_authorize_typed_system_info_stack" => returned_number(unsafe {
            crate::host::abi::ex_host_authorize_typed_system_info_stack(
                0,
                root.as_ptr(),
                root.len(),
                0,
                2,
                0,
            )
        }),
        "ex_host_authorize_typed_udp_datagram_stack" => {
            let host = CString::new("127.0.0.1").unwrap();
            let connection = CString::new("capsec-output-udp").unwrap();
            returned_number(unsafe {
                crate::host::abi::ex_host_authorize_typed_udp_datagram_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    host.as_ptr(),
                    5353,
                    connection.as_ptr(),
                )
            })
        }
        "ex_host_evaluate_typed_decision" => {
            let decision = b"{}";
            let gates = b"[]";
            raw_host_string(unsafe {
                crate::host::abi::ex_host_evaluate_typed_decision(
                    decision.as_ptr(),
                    decision.len(),
                    gates.as_ptr(),
                    gates.len(),
                )
            })
        }
        "ex_host_lifecycle_exit_code_get_stack" => {
            let _ = unsafe {
                crate::host::abi::ex_host_lifecycle_exit_code_set_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    73,
                )
            };
            let mut code = i32::MIN;
            let status = unsafe {
                crate::host::abi::ex_host_lifecycle_exit_code_get_stack(
                    0,
                    root.as_ptr(),
                    root.len(),
                    &mut code,
                )
            };
            if selector == "out:code" {
                if status != 1 || code == i32::MIN {
                    return Err(format!(
                        "typed lifecycle getter did not initialize out:code (status {status})"
                    ));
                }
                returned_number(code)
            } else {
                returned_number(status)
            }
        }
        "ex_host_lifecycle_exit_code_set_stack" => returned_number(unsafe {
            crate::host::abi::ex_host_lifecycle_exit_code_set_stack(
                0,
                root.as_ptr(),
                root.len(),
                73,
            )
        }),
        "ex_host_typed_dynamic_grant" => {
            let request = serde_json::to_vec(&json!({
                "grantId": "capsec-output-grant",
                "principal": root_principal_json(),
                "authority": typed_process_spawn_authority_json(),
            }))
            .expect("serialize bounded dynamic grant request");
            returned_number(unsafe {
                crate::host::abi::ex_host_typed_dynamic_grant(0, request.as_ptr(), request.len())
            })
        }
        "ex_host_typed_dynamic_revoke" => {
            let request = br#""capsec-output-missing-grant""#;
            returned_number(unsafe {
                crate::host::abi::ex_host_typed_dynamic_revoke(0, request.as_ptr(), request.len())
            })
        }
        "ex_host_typed_generations" => {
            let mut negative = u64::MAX;
            let mut dynamic = u64::MAX;
            let mut handle = u64::MAX;
            let status = unsafe {
                crate::host::abi::ex_host_typed_generations(
                    &mut negative,
                    &mut dynamic,
                    &mut handle,
                )
            };
            if selector != "[[return]]" && status != 1 {
                return Err("typed generation call did not initialize caller storage".into());
            }
            match selector {
                "out:negative" => returned_number(negative),
                "out:dynamic" => returned_number(dynamic),
                "out:handle" => returned_number(handle),
                _ => returned_number(status),
            }
        }
        "ex_host_typed_handle_mint" => {
            let request = typed_handle_request_bytes();
            raw_host_string(unsafe {
                crate::host::abi::ex_host_typed_handle_mint(
                    0,
                    root.as_ptr(),
                    root.len(),
                    request.as_ptr(),
                    request.len(),
                )
            })
        }
        "ex_host_typed_handle_revoke" => {
            let handle = mint_bounded_typed_handle()?;
            let request = serde_json::to_vec(&handle)
                .map_err(|error| format!("serialize bounded handle revocation: {error}"))?;
            returned_number(unsafe {
                crate::host::abi::ex_host_typed_handle_revoke(0, request.as_ptr(), request.len())
            })
        }
        other => return Err(format!("unsupported typed-authority Host ABI {other}")),
    };
    Ok(observation)
}

fn execute_authenticated_stateful_host(
    function_name: &str,
    selector: &str,
    sandbox: &FsSandbox,
) -> Result<Value, String> {
    let context = if function_name == "ex_host_authorize_exact_endowment" {
        OwnedAuthenticatedTypedContext::new_exact()?
    } else {
        OwnedAuthenticatedTypedContext::new(sandbox)?
    };
    let observation = match function_name {
        "ex_host_authorize_exact_endowment" => {
            let manifest =
                CString::new("sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA").unwrap();
            let operations = [7_u32, 11_u32];
            let status = unsafe {
                crate::host::abi::ex_host_authorize_exact_endowment(
                    context.context_id(),
                    1,
                    manifest.as_ptr(),
                    operations.as_ptr(),
                    operations.len(),
                )
            };
            if status != 1 {
                return Err(format!(
                    "claimed Exact endowment was not authorized (status {status})"
                ));
            }
            returned_number(status)
        }
        "ex_host_env_get" => {
            let key = CString::new("PATH").unwrap();
            let mut buffer = [0_i8; 8192];
            let length = crate::host::abi::ex_host_env_get(
                key.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            );
            if length < 0 || length as usize >= buffer.len() {
                return Err(format!(
                    "bounded environment read failed or exceeded its buffer ({length})"
                ));
            }
            let bytes = buffer[..length as usize]
                .iter()
                .map(|byte| *byte as u8)
                .collect::<Vec<_>>();
            if selector == "out:buf" {
                raw("return", "array", json!(bytes))
            } else {
                returned_number(length)
            }
        }
        "ex_host_install_armed" => {
            let invalid_snapshot = b"{}";
            let invalid_expected = b"{}";
            returned_number(unsafe {
                crate::host::abi::ex_host_install_armed(
                    invalid_snapshot.as_ptr(),
                    invalid_snapshot.len(),
                    invalid_expected.as_ptr(),
                    invalid_expected.len(),
                )
            })
        }
        "ex_host_matches_armed_snapshot_digest" => {
            let digest = CString::new(context.digest()).unwrap();
            let status =
                unsafe { crate::host::abi::ex_host_matches_armed_snapshot_digest(digest.as_ptr()) };
            if status != 1 {
                return Err("claimed Host did not match its authenticated digest".into());
            }
            returned_number(status)
        }
        "ex_host_prepare_armed_embedder_artifacts" => {
            let snapshot = b"{}";
            let expected = b"{}";
            raw_host_string(unsafe {
                crate::host::abi::ex_host_prepare_armed_embedder_artifacts(
                    snapshot.as_ptr(),
                    snapshot.len(),
                    expected.as_ptr(),
                    expected.len(),
                )
            })
        }
        "ex_host_random_fill" => {
            let mut buffer = [0_u8; 32];
            let status =
                crate::host::abi::ex_host_random_fill(buffer.as_mut_ptr(), buffer.len() as u32);
            if status != 0 {
                return Err(format!("Host random fill failed with status {status}"));
            }
            if selector == "out:buf" {
                raw("return", "array", json!(buffer))
            } else {
                returned_number(status)
            }
        }
        "ex_host_session_static_import_resolve" | "ex_host_session_static_import_resolve_meta" => {
            let referrer = serde_json::to_vec(&json!({
                "root": "project",
                "components": [],
            }))
            .expect("serialize bounded logical referrer");
            let specifier = b"node:path";
            let output = if function_name == "ex_host_session_static_import_resolve" {
                crate::host::abi::ex_host_session_static_import_resolve(
                    referrer.as_ptr(),
                    referrer.len(),
                    specifier.as_ptr(),
                    specifier.len(),
                )
            } else {
                crate::host::abi::ex_host_session_static_import_resolve_meta(
                    referrer.as_ptr(),
                    referrer.len(),
                    specifier.as_ptr(),
                    specifier.len(),
                )
            };
            raw_host_string(output)
        }
        other => return Err(format!("unsupported authenticated Host ABI {other}")),
    };
    if selector != "[[return]]"
        && !matches!(function_name, "ex_host_env_get" | "ex_host_random_fill")
    {
        return Err(format!(
            "unsupported authenticated Host output {function_name}:{selector}"
        ));
    }
    Ok(observation)
}

fn expect_null_host_string_with_errno(
    pointer: *mut std::ffi::c_char,
    expected_errno: i32,
    function_name: &str,
) -> Result<(), String> {
    if !pointer.is_null() {
        crate::host::abi::ex_host_free_string(pointer);
        return Err(format!(
            "{function_name}: error fixture unexpectedly returned an owned string"
        ));
    }
    let observed = crate::host::abi::ex_host_fs_last_error();
    if observed != expected_errno {
        return Err(format!(
            "{function_name}: expected errno {expected_errno}, observed {observed}"
        ));
    }
    Ok(())
}

fn prime_non_eperm_fs_error(sandbox: &FsSandbox) -> Result<(), String> {
    fresh_legacy_host();
    let missing = sandbox.root.join("prime-non-eperm-missing");
    let missing = c_string(&missing);
    expect_null_host_string_with_errno(
        crate::host::abi::ex_host_fs_realpath(missing.as_ptr()),
        libc::ENOENT,
        "armed-refusal-primer",
    )
}

fn install_legacy_armed_fixture(sandbox: &FsSandbox) -> Result<super::HostResetGuard, String> {
    std::fs::create_dir_all(sandbox.root.join("node_modules/image-lib"))
        .map_err(|error| format!("create armed legacy Host package fixture: {error}"))?;
    let (reset, _digest) =
        install_armed_test_host_at(Some(&sandbox.root), true, true, true, Vec::new());
    if crate::host::abi::ex_host_is_armed() != 1 {
        return Err("legacy Host refusal fixture did not install an armed Host".into());
    }
    Ok(reset)
}

fn execute_legacy_path_success(function_name: &str, sandbox: &FsSandbox) -> Result<Value, String> {
    fresh_legacy_host();
    let returned = match function_name {
        "ex_host_fs_mkdir_recursive_result" => {
            let first_created = sandbox.root.join("legacy-mkdir-success");
            let target = first_created.join("child");
            if target.exists() || first_created.exists() {
                return Err("recursive mkdir success fixture was not fresh".into());
            }
            let target_c = c_string(&target);
            let returned = take_host_string(crate::host::abi::ex_host_fs_mkdir_recursive_result(
                target_c.as_ptr(),
            ))
            .ok_or("recursive mkdir success returned NULL")?;
            if Path::new(&returned) != first_created || !target.is_dir() {
                return Err("recursive mkdir success returned the wrong first-created path".into());
            }
            returned
        }
        "ex_host_fs_mkdtemp" => {
            let prefix = sandbox.root.join("legacy-mkdtemp-success-");
            let prefix_text = prefix.to_string_lossy().into_owned();
            let prefix_c = CString::new(prefix_text.as_bytes())
                .map_err(|_| "mkdtemp success prefix contained NUL".to_string())?;
            let returned =
                take_host_string(crate::host::abi::ex_host_fs_mkdtemp(prefix_c.as_ptr(), 0))
                    .ok_or("mkdtemp success returned NULL")?;
            let returned_path = Path::new(&returned);
            if !returned_path.is_dir()
                || !returned.starts_with(&prefix_text)
                || returned.len() != prefix_text.len() + 6
            {
                return Err("mkdtemp success returned an invalid owned directory".into());
            }
            std::fs::remove_dir(returned_path)
                .map_err(|error| format!("remove mkdtemp success fixture: {error}"))?;
            returned
        }
        "ex_host_fs_realpath" => {
            let input = sandbox.reset_file("legacy-realpath-success.txt");
            let expected = std::fs::canonicalize(&input)
                .map_err(|error| format!("canonicalize realpath fixture: {error}"))?;
            let input_c = c_string(&input);
            let returned =
                take_host_string(crate::host::abi::ex_host_fs_realpath(input_c.as_ptr()))
                    .ok_or("realpath success returned NULL")?;
            if Path::new(&returned) != expected {
                return Err("realpath success returned a different canonical target".into());
            }
            returned
        }
        other => return Err(format!("unsupported legacy path success route {other}")),
    };
    validate_private_native_path(returned.as_bytes(), Some(&sandbox.root))?;
    Ok(returned_string(PRIVATE_NATIVE_PATH_CLASS.into()))
}

fn execute_legacy_path_error(function_name: &str, sandbox: &FsSandbox) -> Result<Value, String> {
    let error_code = match function_name {
        "ex_host_fs_mkdir_recursive_result" => {
            fresh_legacy_host();
            let target = sandbox.reset_file("legacy-mkdir-error-existing-file");
            let before = std::fs::read(&target)
                .map_err(|error| format!("read recursive mkdir error fixture: {error}"))?;
            let target_c = c_string(&target);
            expect_null_host_string_with_errno(
                crate::host::abi::ex_host_fs_mkdir_recursive_result(target_c.as_ptr()),
                libc::EEXIST,
                function_name,
            )?;
            if std::fs::read(&target).ok().as_deref() != Some(before.as_slice()) {
                return Err("recursive mkdir error mutated its existing-file target".into());
            }
            HOST_ABI_EEXIST
        }
        "ex_host_fs_mkdtemp" => {
            crate::host::abi::install_host(crate::host::Host::closed_unarmed());
            if crate::host::abi::ex_host_is_armed() != 0 {
                return Err("mkdtemp error fixture unexpectedly installed an armed Host".into());
            }
            let prefix = format!("legacy-mkdtemp-denied-{}-", std::process::id());
            let before = std::fs::read_dir(std::env::temp_dir())
                .map_err(|error| format!("read temp directory before mkdtemp error: {error}"))?
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
                .count();
            let prefix_c = CString::new(prefix.as_bytes())
                .map_err(|_| "mkdtemp error prefix contained NUL".to_string())?;
            expect_null_host_string_with_errno(
                crate::host::abi::ex_host_fs_mkdtemp(prefix_c.as_ptr(), 0),
                libc::EACCES,
                function_name,
            )?;
            let after = std::fs::read_dir(std::env::temp_dir())
                .map_err(|error| format!("read temp directory after mkdtemp error: {error}"))?
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
                .count();
            if before != after {
                return Err("mkdtemp denial created an unexpected directory".into());
            }
            HOST_ABI_EACCES
        }
        "ex_host_fs_realpath" => {
            fresh_legacy_host();
            let missing = sandbox.root.join("legacy-realpath-error-missing");
            if missing.exists() {
                return Err("realpath error fixture unexpectedly exists".into());
            }
            let missing_c = c_string(&missing);
            expect_null_host_string_with_errno(
                crate::host::abi::ex_host_fs_realpath(missing_c.as_ptr()),
                libc::ENOENT,
                function_name,
            )?;
            if missing.exists() {
                return Err("realpath error mutated its missing target".into());
            }
            HOST_ABI_ENOENT
        }
        other => return Err(format!("unsupported legacy path error route {other}")),
    };
    Ok(failed_with_error_code(error_code))
}

fn execute_legacy_path_refusal(function_name: &str, sandbox: &FsSandbox) -> Result<Value, String> {
    prime_non_eperm_fs_error(sandbox)?;
    let _reset = install_legacy_armed_fixture(sandbox)?;
    let nonce = format!("{}-{}", std::process::id(), function_name);
    match function_name {
        "ex_host_fs_mkdir_recursive_result" => {
            let target = sandbox
                .root
                .join(format!("armed-recursive-mkdir-refused-{nonce}"));
            if target.exists() {
                return Err("armed recursive mkdir target was not fresh".into());
            }
            let target_c = c_string(&target);
            expect_null_host_string_with_errno(
                crate::host::abi::ex_host_fs_mkdir_recursive_result(target_c.as_ptr()),
                libc::EPERM,
                function_name,
            )?;
            if target.exists() {
                return Err("armed recursive mkdir refusal mutated its target".into());
            }
        }
        "ex_host_fs_mkdtemp" => {
            let prefix = format!("armed-mkdtemp-refused-{nonce}-");
            let matching_entries = || -> Result<usize, String> {
                Ok(std::fs::read_dir(std::env::temp_dir())
                    .map_err(|error| format!("read temp directory for armed mkdtemp: {error}"))?
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
                    .count())
            };
            let before = matching_entries()?;
            let prefix_c = CString::new(prefix.as_bytes())
                .map_err(|_| "armed mkdtemp prefix contained NUL".to_string())?;
            expect_null_host_string_with_errno(
                crate::host::abi::ex_host_fs_mkdtemp(prefix_c.as_ptr(), 0),
                libc::EPERM,
                function_name,
            )?;
            if matching_entries()? != before {
                return Err("armed mkdtemp refusal consumed randomness into a directory".into());
            }
        }
        "ex_host_fs_realpath" => {
            let target = sandbox.root.join(format!("armed-realpath-refused-{nonce}"));
            if target.exists() {
                return Err("armed realpath target was not fresh".into());
            }
            let target_c = c_string(&target);
            expect_null_host_string_with_errno(
                crate::host::abi::ex_host_fs_realpath(target_c.as_ptr()),
                libc::EPERM,
                function_name,
            )?;
            if target.exists() {
                return Err("armed realpath refusal mutated its lookup target".into());
            }
        }
        other => return Err(format!("unsupported armed legacy path refusal {other}")),
    }
    Ok(failed_with_error_code(HOST_ABI_EPERM))
}

fn execute_legacy_readdir(sandbox: &FsSandbox) -> Result<Value, String> {
    fresh_legacy_host();
    let directory = sandbox.root.join("legacy-readdir-success");
    std::fs::create_dir(&directory).map_err(|error| format!("create readdir fixture: {error}"))?;
    std::fs::write(directory.join("alpha"), b"alpha")
        .map_err(|error| format!("write readdir alpha fixture: {error}"))?;
    std::fs::write(directory.join("beta.txt"), b"beta")
        .map_err(|error| format!("write readdir beta fixture: {error}"))?;
    let directory_c = c_string(&directory);
    let payload = take_host_string(crate::host::abi::ex_host_fs_readdir(directory_c.as_ptr()))
        .ok_or("readdir success returned NULL")?;
    let mut names: Vec<String> = serde_json::from_str(&payload)
        .map_err(|error| format!("parse actual readdir JSON: {error}"))?;
    names.sort();
    if names != ["alpha", "beta.txt"]
        || names.iter().any(|name| {
            name.is_empty()
                || matches!(name.as_str(), "." | "..")
                || name.contains('/')
                || name.contains('\\')
        })
    {
        return Err("readdir success did not return the exact basename fixture".into());
    }
    Ok(raw("return", "array", json!(names)))
}

fn execute_legacy_output(validated: &ValidatedRow, sandbox: &FsSandbox) -> Result<Value, String> {
    let result = match (
        validated.operation.as_str(),
        validated.mode.as_str(),
        validated.return_variant.as_str(),
    ) {
        ("rust-host-legacy-path-output", "unarmed", "success") => {
            execute_legacy_path_success(&validated.function_name, sandbox)
        }
        ("rust-host-legacy-path-output", "unarmed", "error") => {
            execute_legacy_path_error(&validated.function_name, sandbox)
        }
        ("rust-host-legacy-path-output", "armed", "refused") => {
            execute_legacy_path_refusal(&validated.function_name, sandbox)
        }
        ("rust-host-legacy-directory-output", "all", "success") => execute_legacy_readdir(sandbox),
        _ => Err(format!(
            "{}: unsupported bounded legacy Host output mode/variant",
            validated.function_name
        )),
    };
    // These compatibility probes deliberately replace the process Host. Do
    // not let a strict/armed case influence ordinary rows that follow it in
    // catalog order.
    fresh_legacy_host();
    result
}

fn open_fixture(path: &Path, flags: u32) -> *mut crate::host::abi::ExactFileHandle {
    let path = c_string(path);
    let handle = crate::host::abi::ex_host_fs_open(path.as_ptr(), flags);
    assert!(!handle.is_null(), "open Host ABI fixture");
    handle
}

fn execute_fs(function_name: &str, selector: &str, sandbox: &FsSandbox) -> Result<Value, String> {
    let file = sandbox.reset_file(&format!("{function_name}.txt"));
    let path = c_string(&file);
    let bytes = b"bounded";
    let result = match function_name {
        "ex_host_fs_access" => {
            returned_number(crate::host::abi::ex_host_fs_access(path.as_ptr(), 4))
        }
        "ex_host_fs_append" => returned_number(crate::host::abi::ex_host_fs_append(
            path.as_ptr(),
            bytes.as_ptr(),
            bytes.len() as u32,
        )),
        "ex_host_fs_chmod" => {
            returned_number(crate::host::abi::ex_host_fs_chmod(path.as_ptr(), 0o600))
        }
        "ex_host_fs_close" => {
            let handle = open_fixture(&file, 1);
            crate::host::abi::ex_host_fs_close(handle);
            returned_undefined()
        }
        "ex_host_fs_copy" | "ex_host_fs_copy_exclusive" => {
            let destination = sandbox.root.join(format!("{function_name}-copy.txt"));
            let destination = c_string(&destination);
            let value = if function_name == "ex_host_fs_copy" {
                crate::host::abi::ex_host_fs_copy(path.as_ptr(), destination.as_ptr())
            } else {
                crate::host::abi::ex_host_fs_copy_exclusive(path.as_ptr(), destination.as_ptr())
            };
            returned_number(value)
        }
        "ex_host_fs_fstat" => {
            let handle = open_fixture(&file, 1);
            let value = raw_host_string(crate::host::abi::ex_host_fs_fstat(handle));
            crate::host::abi::ex_host_fs_close(handle);
            value
        }
        "ex_host_fs_last_error" => returned_number(crate::host::abi::ex_host_fs_last_error()),
        "ex_host_fs_lstat" => raw_host_string(crate::host::abi::ex_host_fs_lstat(path.as_ptr())),
        "ex_host_fs_mkdir" => {
            let directory = c_string(&sandbox.root.join("mkdir"));
            returned_number(crate::host::abi::ex_host_fs_mkdir(directory.as_ptr(), 0))
        }
        "ex_host_fs_mkdir_recursive_result" => {
            let directory = c_string(&sandbox.root.join("recursive").join("child"));
            raw_host_string(crate::host::abi::ex_host_fs_mkdir_recursive_result(
                directory.as_ptr(),
            ))
        }
        "ex_host_fs_mkdtemp" => {
            let prefix = CString::new("ibex-capsec-host-output-").unwrap();
            let pointer = crate::host::abi::ex_host_fs_mkdtemp(prefix.as_ptr(), 0);
            let value = take_host_string(pointer);
            if let Some(path) = value.as_deref() {
                let _ = std::fs::remove_dir(path);
            }
            value.map_or_else(returned_null, returned_string)
        }
        "ex_host_fs_open" => {
            let handle = crate::host::abi::ex_host_fs_open(path.as_ptr(), 1);
            if handle.is_null() {
                returned_null()
            } else {
                crate::host::abi::ex_host_fs_close(handle);
                returned_object()
            }
        }
        "ex_host_fs_pread" | "ex_host_fs_read" => {
            let handle = open_fixture(&file, 1);
            let mut buffer = [0_u8; 8];
            let value = if function_name == "ex_host_fs_pread" {
                crate::host::abi::ex_host_fs_pread(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    0,
                )
            } else {
                crate::host::abi::ex_host_fs_read(handle, buffer.as_mut_ptr(), buffer.len() as u32)
            };
            crate::host::abi::ex_host_fs_close(handle);
            if selector == "out:buf" {
                let written = usize::try_from(value)
                    .map_err(|_| format!("{function_name}: bounded read failed"))?
                    .min(buffer.len());
                raw("return", "array", json!(&buffer[..written]))
            } else {
                returned_number(value)
            }
        }
        "ex_host_fs_pwrite" | "ex_host_fs_write" => {
            let handle = open_fixture(&file, 3);
            let value = if function_name == "ex_host_fs_pwrite" {
                crate::host::abi::ex_host_fs_pwrite(handle, bytes.as_ptr(), bytes.len() as u32, 0)
            } else {
                crate::host::abi::ex_host_fs_write(handle, bytes.as_ptr(), bytes.len() as u32)
            };
            crate::host::abi::ex_host_fs_close(handle);
            returned_number(value)
        }
        "ex_host_fs_read_file" => {
            let mut length = 0_u64;
            let mut errno = 0_i32;
            let pointer =
                crate::host::abi::ex_host_fs_read_file(path.as_ptr(), &mut length, &mut errno);
            let value = if pointer.is_null() {
                None
            } else {
                let value =
                    unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec();
                crate::host::abi::ex_host_free_buffer(pointer, length);
                Some(value)
            };
            match selector {
                "out:errno" => returned_number(errno),
                "out:len" => returned_number(length),
                _ => value.map_or_else(returned_null, |value| raw("return", "array", json!(value))),
            }
        }
        "ex_host_fs_readdir" => {
            let root = c_string(&sandbox.root);
            raw_host_string(crate::host::abi::ex_host_fs_readdir(root.as_ptr()))
        }
        "ex_host_fs_realpath" => {
            raw_host_string(crate::host::abi::ex_host_fs_realpath(path.as_ptr()))
        }
        "ex_host_fs_rename" => {
            let destination = c_string(&sandbox.root.join("renamed.txt"));
            returned_number(crate::host::abi::ex_host_fs_rename(
                path.as_ptr(),
                destination.as_ptr(),
            ))
        }
        "ex_host_fs_rmdir" => {
            let directory_path = sandbox.root.join("rmdir");
            std::fs::create_dir(&directory_path).unwrap();
            let directory = c_string(&directory_path);
            returned_number(crate::host::abi::ex_host_fs_rmdir(directory.as_ptr()))
        }
        "ex_host_fs_seek" => {
            let handle = open_fixture(&file, 1);
            let value = crate::host::abi::ex_host_fs_seek(handle, 1);
            crate::host::abi::ex_host_fs_close(handle);
            returned_number(value)
        }
        "ex_host_fs_stat" => raw_host_string(crate::host::abi::ex_host_fs_stat(path.as_ptr())),
        "ex_host_fs_statfs" => raw_host_string(crate::host::abi::ex_host_fs_statfs(path.as_ptr())),
        "ex_host_fs_sync" => {
            let handle = open_fixture(&file, 3);
            let value = crate::host::abi::ex_host_fs_sync(handle, 1);
            crate::host::abi::ex_host_fs_close(handle);
            returned_number(value)
        }
        "ex_host_fs_truncate" => {
            returned_number(crate::host::abi::ex_host_fs_truncate(path.as_ptr(), 4))
        }
        "ex_host_fs_unlink" => returned_number(crate::host::abi::ex_host_fs_unlink(path.as_ptr())),
        "ex_host_fs_utimes" => returned_number(crate::host::abi::ex_host_fs_utimes(
            path.as_ptr(),
            1_700_000_000.0,
            1_700_000_001.0,
        )),
        other => return Err(format!("unsupported Rust Host FS function {other}")),
    };
    Ok(result)
}

fn prepare_sqlite(db: u64, sql: &str) -> (u64, String) {
    let sql = CString::new(sql).unwrap();
    let text = take_host_string(crate::host::abi::ex_host_sqlite_prepare(db, sql.as_ptr()))
        .expect("prepare SQLite fixture");
    let value: Value = serde_json::from_str(&text).expect("parse SQLite prepare result");
    let handle = value["handle"].as_u64().expect("SQLite prepare handle");
    (handle, text)
}

fn open_sqlite_memory() -> u64 {
    let handle = crate::host::abi::ex_host_sqlite_open_isolated_memory(std::ptr::null());
    assert_ne!(handle, 0, "open isolated SQLite output fixture");
    handle
}

fn execute_sqlite(function_name: &str, sandbox: &FsSandbox) -> Result<Value, String> {
    let result = match function_name {
        "ex_host_sqlite_open" => {
            let memory = CString::new(":memory:").unwrap();
            let db = crate::host::abi::ex_host_sqlite_open(memory.as_ptr(), std::ptr::null());
            assert_ne!(db, 0);
            let raw = returned_number(db);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_open_checked_fd" => {
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd as _;
                let file_path = sandbox.reset_file("checked.sqlite");
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(file_path)
                    .unwrap();
                let db = crate::host::abi::ex_host_sqlite_open_checked_fd(
                    file.as_raw_fd(),
                    std::ptr::null(),
                );
                if db == 0 {
                    returned_number(0)
                } else {
                    let raw = returned_number(db);
                    assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
                    raw
                }
            }
            #[cfg(not(unix))]
            {
                returned_number(crate::host::abi::ex_host_sqlite_open_checked_fd(
                    -1,
                    std::ptr::null(),
                ))
            }
        }
        "ex_host_sqlite_open_isolated_memory" => {
            let db = open_sqlite_memory();
            let raw = returned_number(db);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_close" => {
            let db = open_sqlite_memory();
            returned_number(crate::host::abi::ex_host_sqlite_close(db))
        }
        "ex_host_sqlite_prepare" => {
            let db = open_sqlite_memory();
            let (statement, text) = prepare_sqlite(db, "SELECT 1 AS value");
            assert_eq!(crate::host::abi::ex_host_sqlite_finalize(statement), 0);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            returned_string(text)
        }
        "ex_host_sqlite_finalize" => {
            let db = open_sqlite_memory();
            let (statement, _) = prepare_sqlite(db, "SELECT 1");
            let raw = returned_number(crate::host::abi::ex_host_sqlite_finalize(statement));
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_expanded_sql" => {
            let db = open_sqlite_memory();
            let (statement, _) = prepare_sqlite(db, "SELECT 1");
            let raw = raw_host_string(crate::host::abi::ex_host_sqlite_expanded_sql(statement));
            assert_eq!(crate::host::abi::ex_host_sqlite_finalize(statement), 0);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_in_transaction" => {
            let db = open_sqlite_memory();
            let raw = returned_number(crate::host::abi::ex_host_sqlite_in_transaction(db));
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        name @ ("ex_host_sqlite_all" | "ex_host_sqlite_get" | "ex_host_sqlite_values") => {
            let db = open_sqlite_memory();
            let (statement, _) = prepare_sqlite(db, "SELECT 1 AS value");
            let pointer = match name {
                "ex_host_sqlite_all" => {
                    crate::host::abi::ex_host_sqlite_all(statement, std::ptr::null())
                }
                "ex_host_sqlite_get" => {
                    crate::host::abi::ex_host_sqlite_get(statement, std::ptr::null())
                }
                _ => crate::host::abi::ex_host_sqlite_values(statement, std::ptr::null()),
            };
            let raw = raw_host_string(pointer);
            assert_eq!(crate::host::abi::ex_host_sqlite_finalize(statement), 0);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_run" => {
            let db = open_sqlite_memory();
            let (statement, _) = prepare_sqlite(db, "CREATE TABLE output(value INTEGER)");
            let raw = raw_host_string(crate::host::abi::ex_host_sqlite_run(
                statement,
                std::ptr::null(),
            ));
            assert_eq!(crate::host::abi::ex_host_sqlite_finalize(statement), 0);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_exec" => {
            let db = open_sqlite_memory();
            let sql = CString::new("CREATE TABLE output(value INTEGER)").unwrap();
            let raw = raw_host_string(crate::host::abi::ex_host_sqlite_exec(
                db,
                sql.as_ptr(),
                std::ptr::null(),
            ));
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        other => return Err(format!("unsupported Rust Host SQLite function {other}")),
    };
    Ok(result)
}

fn execute_terminal(function_name: &str, selector: &str) -> Result<Value, String> {
    let result = match function_name {
        "ex_host_session_descriptor_alias_source_route" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_alias_source_route(0))
        }
        "ex_host_session_descriptor_alias_target_route" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_alias_target_route(3))
        }
        "ex_host_session_descriptor_close_route" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_close_route(1))
        }
        "ex_host_session_descriptor_is_protected" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_is_protected(3))
        }
        "ex_host_session_descriptor_read_route" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_read_route(0))
        }
        "ex_host_session_descriptor_write_route" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_write_route(1))
        }
        "ex_host_terminal_session_close_is_noop" => {
            returned_number(crate::host::abi::ex_host_terminal_session_close_is_noop(1))
        }
        "ex_host_terminal_session_stdio_query" => {
            let (mut tty, mut columns, mut rows) = (0_i32, 0_u16, 0_u16);
            let status = unsafe {
                crate::host::abi::ex_host_terminal_session_stdio_query(
                    0,
                    &mut tty,
                    &mut columns,
                    &mut rows,
                )
            };
            match selector {
                "out:is_tty" => returned_number(tty),
                "out:columns" => returned_number(columns),
                "out:rows" => returned_number(rows),
                _ => returned_number(status),
            }
        }
        other => return Err(format!("unsupported inert terminal Host ABI {other}")),
    };
    Ok(result)
}

fn fresh_legacy_host() {
    assert_ne!(
        crate::host::abi::install_host(crate::host::Host::default_legacy()),
        0,
        "install isolated legacy Host ABI output fixture"
    );
}

fn execute_basic(function_name: &str) -> Result<Value, String> {
    fresh_legacy_host();
    let capability = CString::new("fs:read:/project/output.js").unwrap();
    let specifier = CString::new("node:path").unwrap();
    let package = CString::new("output-package").unwrap();
    let locator = CString::new("output-package@1.0.0").unwrap();
    let integrity = CString::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    let event = CString::new("output-shape").unwrap();
    let root_stack = [0_u64];
    let result = match function_name {
        "ex_host_armed_bootstrap_compatibility_flags" => {
            returned_number(crate::host::abi::ex_host_armed_bootstrap_compatibility_flags())
        }
        "ex_host_armed_endowments" => raw_host_string(crate::host::abi::ex_host_armed_endowments()),
        "ex_host_check_capability" => returned_number(crate::host::abi::ex_host_check_capability(
            0,
            capability.as_ptr(),
        )),
        "ex_host_check_capability_no_follow_final" => returned_number(
            crate::host::abi::ex_host_check_capability_no_follow_final(0, capability.as_ptr()),
        ),
        "ex_host_check_capability_stack" => {
            returned_number(crate::host::abi::ex_host_check_capability_stack(
                root_stack.as_ptr(),
                1,
                capability.as_ptr(),
            ))
        }
        "ex_host_check_capability_stack_no_follow_final" => returned_number(
            crate::host::abi::ex_host_check_capability_stack_no_follow_final(
                root_stack.as_ptr(),
                1,
                capability.as_ptr(),
            ),
        ),
        "ex_host_check_handle_mint" => returned_number(
            crate::host::abi::ex_host_check_handle_mint(0, capability.as_ptr()),
        ),
        "ex_host_check_import" => returned_number(crate::host::abi::ex_host_check_import(
            0,
            specifier.as_ptr(),
            std::ptr::null(),
        )),
        "ex_host_claim_armed_context" => returned_number(unsafe {
            crate::host::abi::ex_host_claim_armed_context(integrity.as_ptr())
        }),
        "ex_host_claim_diagnostic_context" => {
            let context = crate::host::abi::ex_host_claim_diagnostic_context();
            let raw = returned_number(context);
            if context != 0 {
                crate::host::abi::ex_host_release_context(context);
            }
            raw
        }
        "ex_host_console_flush" => {
            crate::host::abi::ex_host_console_flush(0);
            returned_undefined()
        }
        "ex_host_console_log" => {
            crate::host::abi::ex_host_console_log(0, event.as_ptr());
            returned_undefined()
        }
        "ex_host_console_log_bytes" => {
            unsafe { crate::host::abi::ex_host_console_log_bytes(0, std::ptr::null(), 0) };
            returned_undefined()
        }
        "ex_host_enter_context" => {
            let context = crate::host::abi::ex_host_claim_diagnostic_context();
            assert_ne!(context, 0);
            let previous = crate::host::abi::ex_host_enter_context(context);
            crate::host::abi::ex_host_restore_context(previous);
            crate::host::abi::ex_host_release_context(context);
            returned_number(previous)
        }
        "ex_host_env_get" => {
            let key = CString::new("PATH").unwrap();
            returned_number(crate::host::abi::ex_host_env_get(
                key.as_ptr(),
                std::ptr::null_mut(),
                0,
            ))
        }
        "ex_host_free_buffer" => {
            crate::host::abi::ex_host_free_buffer(std::ptr::null_mut(), 0);
            returned_undefined()
        }
        "ex_host_free_string" => {
            crate::host::abi::ex_host_free_string(std::ptr::null_mut());
            returned_undefined()
        }
        "ex_host_grant_capability" => {
            crate::host::abi::ex_host_grant_capability(0, capability.as_ptr());
            returned_undefined()
        }
        "ex_host_handle_check" => returned_number(crate::host::abi::ex_host_handle_check(
            0,
            capability.as_ptr(),
        )),
        "ex_host_handle_create" => {
            let handle = crate::host::abi::ex_host_handle_create(capability.as_ptr());
            let raw = returned_number(handle);
            crate::host::abi::ex_host_handle_revoke(handle);
            raw
        }
        "ex_host_handle_revoke" => {
            let handle = crate::host::abi::ex_host_handle_create(capability.as_ptr());
            crate::host::abi::ex_host_handle_revoke(handle);
            returned_undefined()
        }
        "ex_host_handle_scoped" => {
            let parent = crate::host::abi::ex_host_handle_create(capability.as_ptr());
            let narrower = CString::new("/project/output.js").unwrap();
            let child = crate::host::abi::ex_host_handle_scoped(parent, narrower.as_ptr());
            let raw = returned_number(child);
            crate::host::abi::ex_host_handle_revoke(parent);
            raw
        }
        "ex_host_has_deputy_classes" => {
            returned_number(crate::host::abi::ex_host_has_deputy_classes())
        }
        "ex_host_init" => {
            crate::host::abi::ex_host_init();
            returned_undefined()
        }
        "ex_host_is_allow_all" => returned_number(crate::host::abi::ex_host_is_allow_all()),
        "ex_host_is_armed" => returned_number(crate::host::abi::ex_host_is_armed()),
        "ex_host_legacy_authorization_cacheable" => {
            returned_number(crate::host::abi::ex_host_legacy_authorization_cacheable())
        }
        "ex_host_legacy_authorization_generation" => {
            returned_number(crate::host::abi::ex_host_legacy_authorization_generation())
        }
        "ex_host_log_event" => {
            crate::host::abi::ex_host_log_event(event.as_ptr(), 0, capability.as_ptr(), 1);
            returned_undefined()
        }
        "ex_host_module_resolve" => raw_host_string(crate::host::abi::ex_host_module_resolve(
            0,
            specifier.as_ptr(),
            std::ptr::null(),
        )),
        "ex_host_module_resolve_meta" => raw_host_string(
            crate::host::abi::ex_host_module_resolve_meta(0, specifier.as_ptr(), std::ptr::null()),
        ),
        "ex_host_permission_request" => returned_number(
            crate::host::abi::ex_host_permission_request(capability.as_ptr()),
        ),
        "ex_host_permission_revoke" => {
            crate::host::abi::ex_host_permission_revoke(capability.as_ptr());
            returned_undefined()
        }
        "ex_host_permission_status" => returned_number(
            crate::host::abi::ex_host_permission_status(capability.as_ptr()),
        ),
        "ex_host_random_fill" => {
            let mut bytes = [0_u8; 16];
            returned_number(crate::host::abi::ex_host_random_fill(
                bytes.as_mut_ptr(),
                bytes.len() as u32,
            ))
        }
        "ex_host_register_module_package" => {
            crate::host::abi::ex_host_register_module_package(
                1,
                package.as_ptr(),
                locator.as_ptr(),
                integrity.as_ptr(),
            );
            returned_undefined()
        }
        "ex_host_release_context" => {
            let context = crate::host::abi::ex_host_claim_diagnostic_context();
            assert_ne!(context, 0);
            crate::host::abi::ex_host_release_context(context);
            returned_undefined()
        }
        "ex_host_resolve_manifest_builtin_internal" => raw_host_string(
            crate::host::abi::ex_host_resolve_manifest_builtin_internal(specifier.as_ptr()),
        ),
        "ex_host_restore_context" => {
            crate::host::abi::ex_host_restore_context(0);
            returned_undefined()
        }
        "ex_host_time_now_ms" => returned_number(crate::host::abi::ex_host_time_now_ms()),
        "ex_host_version" => returned_number(crate::host::abi::ex_host_version()),
        other => return Err(format!("unsupported bounded basic Host ABI {other}")),
    };
    Ok(result)
}

struct OwnedDiagnosticRuntime {
    raw: *mut HermesRuntimeOpaque,
}

impl OwnedDiagnosticRuntime {
    fn new() -> Result<Self, String> {
        fresh_legacy_host();
        let raw = unsafe { ex_hermes_create_diagnostic() };
        if raw.is_null() {
            Err("ex_hermes_create_diagnostic returned NULL".into())
        } else {
            Ok(Self { raw })
        }
    }

    fn destroy(mut self) {
        unsafe { ex_hermes_destroy(self.raw) };
        self.raw = std::ptr::null_mut();
    }
}

impl Drop for OwnedDiagnosticRuntime {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ex_hermes_destroy(self.raw) };
        }
    }
}

fn execute_authenticated_armed_create(sandbox: &FsSandbox) -> Result<Value, String> {
    let _engine_lock = hermes_engine_test_lock().blocking_lock();
    std::fs::create_dir_all(sandbox.root.join("node_modules/image-lib"))
        .map_err(|error| format!("create armed-runtime package fixture: {error}"))?;
    let (_reset, digest) =
        install_armed_test_host_at(Some(&sandbox.root), true, true, true, Vec::new());
    let digest = CString::new(digest).unwrap();
    let runtime = unsafe { ex_hermes_create_armed(digest.as_ptr()) };
    if runtime.is_null() {
        return Err("ex_hermes_create_armed returned NULL for its claimed Host context".into());
    }
    unsafe { ex_hermes_destroy(runtime) };
    Ok(returned_object())
}

fn execute_bounded_dispatch(function_name: &str, selector: &str) -> Result<Value, String> {
    let runtime = OwnedDiagnosticRuntime::new()?;
    let observation = match function_name {
        "ex_hermes_dispatch_worklet_calls" => {
            let call = NativeWorkletScheduledCall {
                source_identity: 11,
                source_sequence: 1,
                generation: 1,
                callback_identity: 17,
                argument_count: 2,
                arguments: [1.5, 2.5, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            };
            let mut delivered = u32::MAX;
            let status =
                unsafe { ex_hermes_dispatch_worklet_calls(runtime.raw, &call, 1, &mut delivered) };
            if delivered == u32::MAX {
                return Err("worklet dispatch did not initialize out:delivered".into());
            }
            if selector == "out:delivered" {
                returned_number(delivered)
            } else {
                returned_number(status)
            }
        }
        "ex_hermes_dispatch_worklet_json_batch" => {
            let batch = br#"[{"name":"bounded","args":[1]}]"#;
            returned_number(unsafe {
                ex_hermes_dispatch_worklet_json_batch(runtime.raw, batch.as_ptr(), batch.len(), 1)
            })
        }
        "ex_hermes_dispatch_motion_rated_publish" => {
            let sample = NativeMotionRatedPublishSample {
                channel_identity: 23,
                dirty_generation: 1,
                sample_time_ns: 101,
                value_count: 2,
                flags: 1,
                values: [3.0, 4.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            };
            returned_number(unsafe {
                ex_hermes_dispatch_motion_rated_publish(runtime.raw, &sample)
            })
        }
        other => return Err(format!("unsupported bounded dispatch ABI {other}")),
    };
    Ok(observation)
}

fn free_native_owned_bytes(bytes: NativeOwnedBytes) {
    if !bytes.data.is_null() {
        unsafe { ex_hermes_free_string(bytes.data.cast()) };
    }
}

fn execute_owned_value(function_name: &str, selector: &str) -> Result<Value, String> {
    let runtime = OwnedDiagnosticRuntime::new()?;
    let source: &[u8] = match function_name {
        "ex_hermes_value_safe_throw_metadata" => b"throw new Error('bounded safe throw metadata')",
        "ex_hermes_value_stage1_text" => b"'bounded stage one text'",
        _ => b"({answer:42})",
    };
    let source_label = b"ibex:capsec-host-abi-owned-value";
    let mut result = NativeEvaluationResult::zeroed();
    unsafe { ex_hermes_evaluation_result_init(&mut result) };
    let evaluation_status = unsafe {
        ex_hermes_eval_structured_diagnostic(
            runtime.raw,
            source.as_ptr(),
            source.len(),
            source_label.as_ptr(),
            source_label.len(),
            &mut result,
        )
    };
    if evaluation_status != 0 || result.value.handle_id == 0 {
        unsafe { ex_hermes_evaluation_result_dispose(&mut result) };
        return Err(format!(
            "diagnostic value fixture failed with status {evaluation_status} and handle {}",
            result.value.handle_id
        ));
    }
    let handle = result.value;
    let mut released = false;
    let observation: Result<Value, String> = match function_name {
        "ex_hermes_session_display_ack" => Ok(returned_number(unsafe {
            ex_hermes_session_display_ack(runtime.raw, 1, handle, true)
        })),
        "ex_hermes_value_kind" => Ok(returned_number(unsafe {
            ex_hermes_value_kind(runtime.raw, handle)
        })),
        "ex_hermes_value_release" => {
            let status = unsafe { ex_hermes_value_release(runtime.raw, handle) };
            released = true;
            Ok(returned_number(status))
        }
        "ex_hermes_value_safe_throw_metadata" => {
            let mut metadata_fields = 0_u32;
            let mut error_class = 0_u32;
            let mut message = NativeOwnedBytes {
                data: std::ptr::null_mut(),
                length: 0,
            };
            let mut stack = NativeOwnedBytes {
                data: std::ptr::null_mut(),
                length: 0,
            };
            let status = unsafe {
                ex_hermes_value_safe_throw_metadata(
                    runtime.raw,
                    handle,
                    &mut metadata_fields,
                    &mut error_class,
                    &mut message,
                    &mut stack,
                )
            };
            let projected = match selector {
                "out:error_class" => Ok(raw("return", "number", Value::from(error_class))),
                "out:metadata_fields" => Ok(returned_number(metadata_fields)),
                "out:message.data" => native_owned_bytes_value(message).map(|value| {
                    if value.is_null() {
                        returned_null()
                    } else {
                        raw("return", "array", value)
                    }
                }),
                "out:stack.data" => native_owned_bytes_value(stack).map(|value| {
                    if value.is_null() {
                        returned_null()
                    } else {
                        raw("return", "array", value)
                    }
                }),
                _ => Ok(returned_number(status)),
            };
            free_native_owned_bytes(message);
            free_native_owned_bytes(stack);
            projected
        }
        "ex_hermes_value_stage1_text" => {
            let mut data = std::ptr::null_mut();
            let mut length = 0_usize;
            let mut truncated = 0_u32;
            let status = unsafe {
                ex_hermes_value_stage1_text(
                    runtime.raw,
                    handle,
                    &mut data,
                    &mut length,
                    &mut truncated,
                )
            };
            let projected = match selector {
                "out:data" => {
                    if data.is_null() {
                        Ok(returned_null())
                    } else if length > 1 << 20 {
                        Err("Stage-1 text exceeded the evidence bound".into())
                    } else {
                        let bytes = unsafe { std::slice::from_raw_parts(data, length) };
                        Ok(raw("return", "array", json!(bytes)))
                    }
                }
                "out:length" => Ok(returned_number(length)),
                "out:truncated" => Ok(returned_number(truncated)),
                _ => Ok(returned_number(status)),
            };
            if !data.is_null() {
                unsafe { ex_hermes_free_string(data.cast()) };
            }
            projected
        }
        other => Err(format!("unsupported owned value ABI {other}")),
    };
    if !released {
        let _ = unsafe { ex_hermes_value_release(runtime.raw, handle) };
    }
    unsafe { ex_hermes_evaluation_result_dispose(&mut result) };
    observation
}

fn copied_callback_c_string(value: *const std::os::raw::c_char) -> Option<String> {
    if value.is_null() {
        None
    } else {
        // SAFETY: each native callback contract lends a NUL-terminated string
        // for the duration of the callback. Copy it before returning.
        Some(
            unsafe { CStr::from_ptr(value) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}

#[derive(Clone, Debug, Default)]
struct BoundedSyncHostCallObservation {
    invoked: bool,
    operation: Option<String>,
    arguments_json: Option<String>,
}

fn bounded_sync_host_call_observation() -> &'static std::sync::Mutex<BoundedSyncHostCallObservation>
{
    static OBSERVATION: std::sync::OnceLock<std::sync::Mutex<BoundedSyncHostCallObservation>> =
        std::sync::OnceLock::new();
    OBSERVATION.get_or_init(|| std::sync::Mutex::new(BoundedSyncHostCallObservation::default()))
}

extern "C" fn bounded_sync_host_call(
    op: *const std::os::raw::c_char,
    args_json: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_char {
    let mut observation = bounded_sync_host_call_observation()
        .lock()
        .expect("bounded sync host-call observation lock poisoned");
    observation.invoked = true;
    observation.operation = copied_callback_c_string(op);
    observation.arguments_json = copied_callback_c_string(args_json);
    // NULL is a documented successful callback result and requires no cross-
    // allocator ownership assumption. The callback payload inputs are the
    // outputs under test here.
    std::ptr::null_mut()
}

#[derive(Clone, Debug, Default)]
struct BoundedAsyncHostCallObservation {
    invoked: bool,
    expected_runtime: usize,
    actual_runtime: usize,
    call_id: u64,
    operation: Option<String>,
    arguments_json: Option<String>,
}

fn bounded_async_host_call_observation(
) -> &'static std::sync::Mutex<BoundedAsyncHostCallObservation> {
    static OBSERVATION: std::sync::OnceLock<std::sync::Mutex<BoundedAsyncHostCallObservation>> =
        std::sync::OnceLock::new();
    OBSERVATION.get_or_init(|| std::sync::Mutex::new(BoundedAsyncHostCallObservation::default()))
}

extern "C" fn bounded_async_host_call(
    runtime: *mut HermesRuntimeOpaque,
    call_id: u64,
    op: *const std::os::raw::c_char,
    args_json: *const std::os::raw::c_char,
) {
    let mut observation = bounded_async_host_call_observation()
        .lock()
        .expect("bounded async host-call observation lock poisoned");
    observation.invoked = true;
    observation.actual_runtime = runtime as usize;
    observation.call_id = call_id;
    observation.operation = copied_callback_c_string(op);
    observation.arguments_json = copied_callback_c_string(args_json);
}

#[derive(Debug, Default)]
struct BoundedExactHostCallObservation {
    invoked: bool,
    expected_runtime: usize,
    actual_runtime: usize,
    call_id: u64,
    operation_id: u32,
    payload: Vec<u8>,
    expected_context: usize,
    actual_context: usize,
}

extern "C" fn bounded_exact_host_call(
    runtime: *mut HermesRuntimeOpaque,
    call_id: u64,
    operation_id: u32,
    payload: *const u8,
    payload_len: usize,
    context: *mut std::ffi::c_void,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: the executor owns this state on the runtime thread, passes its
    // exact address as the callback context, and keeps it alive through the
    // synchronous Promise-executor callback.
    let observation = unsafe { &mut *context.cast::<BoundedExactHostCallObservation>() };
    observation.invoked = true;
    observation.actual_runtime = runtime as usize;
    observation.call_id = call_id;
    observation.operation_id = operation_id;
    observation.actual_context = context as usize;
    observation.payload = if payload.is_null() {
        Vec::new()
    } else {
        // SAFETY: the callback lends `payload_len` readable bytes for this
        // invocation; copy them before returning.
        unsafe { std::slice::from_raw_parts(payload, payload_len) }.to_vec()
    };
}

#[derive(Debug)]
struct BoundedOpaqueCallbackObservation {
    marker: u64,
    expected_context: usize,
    actual_context: usize,
    invoked: bool,
}

extern "C" fn bounded_opaque_callback(context: *mut std::ffi::c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: wake and watchdog recipes keep this state alive until the
    // synchronous notification/poll has delivered the queued callback.
    let observation = unsafe { &mut *context.cast::<BoundedOpaqueCallbackObservation>() };
    observation.actual_context = context as usize;
    observation.invoked = true;
}

fn evaluate_bounded_callback_source(
    runtime: *mut HermesRuntimeOpaque,
    source: &[u8],
) -> Result<(), String> {
    let source_url = CString::new("ibex:capsec-host-abi-callback-output").unwrap();
    let mut output = std::ptr::null_mut();
    let status = unsafe {
        ex_hermes_eval(
            runtime,
            source.as_ptr(),
            source.len(),
            source_url.as_ptr(),
            0,
            &mut output,
        )
    };
    let detail = take_hermes_string(output);
    if status == 0 {
        Ok(())
    } else {
        Err(format!(
            "bounded callback trigger failed with status {status}: {}",
            detail.unwrap_or_else(|| "missing Hermes diagnostic".into())
        ))
    }
}

fn execute_host_wake_hook_callback(selector: &str) -> Result<Value, String> {
    if selector != "callback:hook/0" {
        return Err(format!("unsupported host wake-hook selector {selector}"));
    }
    let mut observation = BoundedOpaqueCallbackObservation {
        marker: 0x4952_4558,
        expected_context: 0,
        actual_context: 0,
        invoked: false,
    };
    let context = (&mut observation as *mut BoundedOpaqueCallbackObservation).cast();
    observation.expected_context = context as usize;
    ibex_runtime::engine::ex_hermes_set_host_wake_hook(Some(bounded_opaque_callback), context);
    ibex_runtime::engine::ex_hermes_notify_callback();
    ibex_runtime::engine::ex_hermes_set_host_wake_hook(None, std::ptr::null_mut());
    if !observation.invoked
        || observation.actual_context != observation.expected_context
        || observation.marker != 0x4952_4558
    {
        return Err("host wake hook did not receive its exact live context".into());
    }
    Ok(returned_object())
}

fn execute_hermes_stateless(function_name: &str, selector: &str) -> Result<Value, String> {
    let result = match function_name {
        "ex_hermes_bytecode_version" => returned_number(unsafe { ex_hermes_bytecode_version() }),
        "ex_hermes_create" => {
            let runtime = unsafe { ex_hermes_create() };
            if runtime.is_null() {
                returned_null()
            } else {
                unsafe { ex_hermes_destroy(runtime) };
                returned_object()
            }
        }
        "ex_hermes_current_principal_id" => {
            returned_number(unsafe { ex_hermes_current_principal_id() })
        }
        "ex_hermes_current_runtime_nonce" => {
            returned_number(unsafe { ex_hermes_current_runtime_nonce() })
        }
        "ex_hermes_engine_binary_path" => {
            let mut path = [0_i8; 4096];
            returned_number(unsafe { ex_hermes_engine_binary_path(path.as_mut_ptr(), path.len()) })
        }
        "ex_hermes_engine_mapped_object" => {
            let (mut device, mut inode) = (0_u64, 0_u64);
            let status = unsafe { ex_hermes_engine_mapped_object(&mut device, &mut inode) };
            match selector {
                "out:device" => returned_number(device),
                "out:inode" => returned_number(inode),
                _ => returned_number(status),
            }
        }
        "ex_hermes_evaluation_result_dispose" => {
            let mut result = NativeEvaluationResult::zeroed();
            unsafe {
                ex_hermes_evaluation_result_init(&mut result);
                ex_hermes_evaluation_result_dispose(&mut result);
            }
            evaluation_result_observation(&result, selector)?
        }
        "ex_hermes_evaluation_result_init" => {
            let mut result = NativeEvaluationResult::zeroed();
            unsafe { ex_hermes_evaluation_result_init(&mut result) };
            let observation = evaluation_result_observation(&result, selector)?;
            unsafe { ex_hermes_evaluation_result_dispose(&mut result) };
            observation
        }
        "ex_hermes_free_string" => {
            unsafe { ex_hermes_free_string(std::ptr::null_mut()) };
            returned_undefined()
        }
        "ex_hermes_now_ms" => returned_number(unsafe { ex_hermes_now_ms() }),
        other => return Err(format!("unsupported stateless Hermes ABI {other}")),
    };
    Ok(result)
}

fn execute_hermes_diagnostic(function_name: &str, selector: &str) -> Result<Value, String> {
    let runtime = OwnedDiagnosticRuntime::new()?;
    let result = match function_name {
        "ex_hermes_callback_backlog" => {
            returned_number(unsafe { ex_hermes_callback_backlog(runtime.raw) })
        }
        "ex_hermes_cancel_structured_work_target" => {
            returned_number(unsafe { ex_hermes_cancel_structured_work_target(runtime.raw, 0) })
        }
        "ex_hermes_create_diagnostic" => returned_object(),
        "ex_hermes_debugger_enable" => {
            returned_number(unsafe { ex_hermes_debugger_enable(runtime.raw) })
        }
        "ex_hermes_debugger_eval" => {
            let _ = unsafe { ex_hermes_debugger_enable(runtime.raw) };
            let expression = CString::new("1 + 1").unwrap();
            raw_hermes_string(unsafe {
                ex_hermes_debugger_eval(runtime.raw, expression.as_ptr(), 0)
            })
        }
        "ex_hermes_debugger_get_script_source" => {
            let _ = unsafe { ex_hermes_debugger_enable(runtime.raw) };
            raw_hermes_string(unsafe { ex_hermes_debugger_get_script_source(runtime.raw, 0) })
        }
        "ex_hermes_debugger_get_scripts" => {
            let _ = unsafe { ex_hermes_debugger_enable(runtime.raw) };
            raw_hermes_string(unsafe { ex_hermes_debugger_get_scripts(runtime.raw) })
        }
        "ex_hermes_debugger_next_event" => {
            let _ = unsafe { ex_hermes_debugger_enable(runtime.raw) };
            raw_hermes_string(unsafe { ex_hermes_debugger_next_event(runtime.raw) })
        }
        "ex_hermes_debugger_set_breakpoint" => {
            let _ = unsafe { ex_hermes_debugger_enable(runtime.raw) };
            raw_hermes_string(unsafe {
                ex_hermes_debugger_set_breakpoint(runtime.raw, 0, 1, 1, std::ptr::null())
            })
        }
        "ex_hermes_destroy" => {
            runtime.destroy();
            return Ok(returned_undefined());
        }
        "ex_hermes_eval" => {
            let source = b"void 0";
            let source_url = CString::new("ibex:capsec-host-abi-output").unwrap();
            let mut output = std::ptr::null_mut();
            let status = unsafe {
                ex_hermes_eval(
                    runtime.raw,
                    source.as_ptr(),
                    source.len(),
                    source_url.as_ptr(),
                    0,
                    &mut output,
                )
            };
            let output = raw_hermes_string(output);
            if selector == "out:value" {
                output
            } else {
                returned_number(status)
            }
        }
        "ex_hermes_eval_structured_diagnostic" => {
            let source = b"throw new Error('bounded structured output')";
            let source_label = b"ibex:capsec-host-abi-structured-output";
            let mut output = NativeEvaluationResult::zeroed();
            unsafe { ex_hermes_evaluation_result_init(&mut output) };
            let status = unsafe {
                ex_hermes_eval_structured_diagnostic(
                    runtime.raw,
                    source.as_ptr(),
                    source.len(),
                    source_label.as_ptr(),
                    source_label.len(),
                    &mut output,
                )
            };
            let observation = if selector == "[[return]]" {
                returned_number(status)
            } else {
                evaluation_result_observation(&output, selector)?
            };
            if output.value.handle_id != 0 {
                let _ = unsafe { ex_hermes_value_release(runtime.raw, output.value) };
            }
            unsafe { ex_hermes_evaluation_result_dispose(&mut output) };
            observation
        }
        "ex_hermes_finish_bootstrap" => {
            returned_number(unsafe { ex_hermes_finish_bootstrap(runtime.raw) })
        }
        "ex_hermes_gc" => {
            unsafe { ex_hermes_gc(runtime.raw) };
            returned_undefined()
        }
        "ex_hermes_get_gc_stats" => {
            raw_hermes_string(unsafe { ex_hermes_get_gc_stats(runtime.raw) })
        }
        "ex_hermes_get_heap_info" => {
            raw_hermes_string(unsafe { ex_hermes_get_heap_info(runtime.raw, 0) })
        }
        "ex_hermes_has_pending_tasks" => {
            returned_number(unsafe { ex_hermes_has_pending_tasks(runtime.raw) })
        }
        "ex_hermes_next_timer" => returned_number(unsafe { ex_hermes_next_timer(runtime.raw) }),
        "ex_hermes_poll" => {
            returned_number(unsafe { ex_hermes_poll(runtime.raw, ex_hermes_now_ms()) })
        }
        "ex_hermes_resolve_host_call" => {
            let payload = CString::new("null").unwrap();
            unsafe { ex_hermes_resolve_host_call(runtime.raw, 1, payload.as_ptr()) };
            returned_undefined()
        }
        "ex_hermes_runtime_nonce" => {
            returned_number(unsafe { ex_hermes_runtime_nonce(runtime.raw) })
        }
        "ex_hermes_schedule_watchdog_heartbeat_for_generation" => {
            let mut observation = BoundedOpaqueCallbackObservation {
                marker: 0x5741_5443,
                expected_context: 0,
                actual_context: 0,
                invoked: false,
            };
            let context = (&mut observation as *mut BoundedOpaqueCallbackObservation).cast();
            observation.expected_context = context as usize;
            let nonce = unsafe { ex_hermes_runtime_nonce(runtime.raw) };
            unsafe {
                ex_hermes_schedule_watchdog_heartbeat_for_generation(
                    runtime.raw,
                    nonce,
                    bounded_opaque_callback,
                    context,
                )
            };
            let _ = unsafe { ex_hermes_poll(runtime.raw, ex_hermes_now_ms()) };
            if !observation.invoked
                || observation.actual_context != observation.expected_context
                || observation.marker != 0x5741_5443
            {
                return Err(
                    "generation-bearing watchdog did not deliver its exact live context".into(),
                );
            }
            returned_object()
        }
        "ex_hermes_set_exact_host_call_async" => {
            let mut observation = BoundedExactHostCallObservation {
                expected_runtime: runtime.raw as usize,
                ..Default::default()
            };
            let context = (&mut observation as *mut BoundedExactHostCallObservation).cast();
            observation.expected_context = context as usize;
            let operations = [7_u32];
            let status = unsafe {
                ex_hermes_set_exact_host_call_async(
                    runtime.raw,
                    1,
                    operations.as_ptr(),
                    operations.len(),
                    std::ptr::null(),
                    bounded_exact_host_call,
                    context,
                )
            };
            if selector == "[[return]]" {
                returned_number(status)
            } else {
                if status != 0 {
                    return Err(format!(
                        "Exact host-call callback install failed with status {status}"
                    ));
                }
                evaluate_bounded_callback_source(
                    runtime.raw,
                    b"exact.invokeHostAsync(7, new Uint8Array([3, 5, 8])); void 0",
                )?;
                if !observation.invoked {
                    return Err("Exact host-call callback was not invoked".into());
                }
                match selector {
                    "callback:callback/0"
                        if observation.actual_runtime == observation.expected_runtime =>
                    {
                        returned_object()
                    }
                    "callback:callback/1" => returned_number(observation.call_id),
                    "callback:callback/2" => returned_number(observation.operation_id),
                    "callback:callback/3" => raw("return", "array", json!(observation.payload)),
                    "callback:callback/5"
                        if observation.actual_context == observation.expected_context =>
                    {
                        returned_object()
                    }
                    other => {
                        return Err(format!(
                            "unsupported or mismatched Exact host-call callback selector {other}"
                        ))
                    }
                }
            }
        }
        "ex_hermes_set_host_call" => {
            *bounded_sync_host_call_observation()
                .lock()
                .expect("bounded sync host-call observation lock poisoned") =
                BoundedSyncHostCallObservation::default();
            unsafe { ex_hermes_set_host_call(runtime.raw, bounded_sync_host_call) };
            evaluate_bounded_callback_source(
                runtime.raw,
                b"__hostCall('bounded.sync', {answer: 42})",
            )?;
            let observation = bounded_sync_host_call_observation()
                .lock()
                .expect("bounded sync host-call observation lock poisoned")
                .clone();
            if !observation.invoked {
                return Err("synchronous host-call callback was not invoked".into());
            }
            match selector {
                "callback:callback/0" => returned_string(
                    observation
                        .operation
                        .ok_or("synchronous host-call callback received a null operation")?,
                ),
                "callback:callback/1" => returned_string(
                    observation
                        .arguments_json
                        .ok_or("synchronous host-call callback received null arguments")?,
                ),
                other => {
                    return Err(format!(
                        "unsupported synchronous host-call callback selector {other}"
                    ))
                }
            }
        }
        "ex_hermes_set_host_call_async" => {
            *bounded_async_host_call_observation()
                .lock()
                .expect("bounded async host-call observation lock poisoned") =
                BoundedAsyncHostCallObservation {
                    expected_runtime: runtime.raw as usize,
                    ..BoundedAsyncHostCallObservation::default()
                };
            unsafe { ex_hermes_set_host_call_async(runtime.raw, bounded_async_host_call) };
            evaluate_bounded_callback_source(
                runtime.raw,
                b"__hostCallAsync('bounded.async', [2, 4, 6]); void 0",
            )?;
            let observation = bounded_async_host_call_observation()
                .lock()
                .expect("bounded async host-call observation lock poisoned")
                .clone();
            if !observation.invoked {
                return Err("asynchronous host-call callback was not invoked".into());
            }
            match selector {
                "callback:callback/0"
                    if observation.actual_runtime == observation.expected_runtime =>
                {
                    returned_object()
                }
                "callback:callback/1" => returned_number(observation.call_id),
                "callback:callback/2" => returned_string(
                    observation
                        .operation
                        .ok_or("asynchronous host-call callback received a null operation")?,
                ),
                "callback:callback/3" => returned_string(
                    observation
                        .arguments_json
                        .ok_or("asynchronous host-call callback received null arguments")?,
                ),
                other => {
                    return Err(format!(
                        "unsupported or mismatched async host-call callback selector {other}"
                    ))
                }
            }
        }
        "ex_hermes_set_keep_alive_on_async_error" => {
            unsafe { ex_hermes_set_keep_alive_on_async_error(runtime.raw, 1) };
            returned_undefined()
        }
        "ex_hermes_structured_active_work_target" => {
            returned_number(unsafe { ex_hermes_structured_active_work_target(runtime.raw) })
        }
        "ex_hermes_take_async_failure_event" => {
            let mut event = NativeAsyncFailureEvent::current();
            let status = unsafe { ex_hermes_take_async_failure_event(runtime.raw, &mut event) };
            match selector {
                "out:event.associated_evaluation" => returned_number(event.associated_evaluation),
                "out:event.dropped_count" => returned_number(event.dropped_count),
                "out:event.event_id" => returned_number(event.event_id),
                "out:event.host_context_id" => returned_number(event.host_context_id),
                "out:event.kind" => returned_number(event.kind),
                "out:event.owning_principal_id" => returned_number(event.owning_principal_id),
                "out:event.principal_status" => returned_number(event.principal_status),
                "out:event.value.handle_id" => returned_number(event.value_handle_id),
                "out:event.value.runtime_nonce" => returned_number(event.value_runtime_nonce),
                _ => returned_number(status),
            }
        }
        "ex_hermes_take_cancellation_event" => {
            let mut event = NativeCancellationEvent::current();
            let status = unsafe { ex_hermes_take_cancellation_event(runtime.raw, &mut event) };
            match selector {
                "out:event.resolution" => returned_number(event.resolution),
                "out:event.target_id" => returned_number(event.target_id),
                _ => returned_number(status),
            }
        }
        "ex_hermes_take_work_unit_event" => {
            let mut event = NativeWorkUnitEvent::current();
            let status = unsafe { ex_hermes_take_work_unit_event(runtime.raw, &mut event) };
            match selector {
                "out:event.kind" => returned_number(event.kind),
                "out:event.phase" => returned_number(event.phase),
                "out:event.scheduling_id" => returned_number(event.scheduling_id),
                "out:event.target_id" => returned_number(event.target_id),
                _ => returned_number(status),
            }
        }
        other => return Err(format!("unsupported diagnostic Hermes ABI {other}")),
    };
    Ok(result)
}

struct OwnedWorkletRuntime {
    raw: *mut HermesRuntimeOpaque,
}

impl OwnedWorkletRuntime {
    fn new() -> Result<Self, String> {
        let raw = unsafe { ex_worklet_create() };
        if raw.is_null() {
            Err("ex_worklet_create returned NULL".into())
        } else {
            Ok(Self { raw })
        }
    }

    fn destroy(mut self) {
        unsafe { ex_worklet_destroy(self.raw) };
        self.raw = std::ptr::null_mut();
    }
}

impl Drop for OwnedWorkletRuntime {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ex_worklet_destroy(self.raw) };
        }
    }
}

fn install_bounded_worklet(
    runtime: *mut HermesRuntimeOpaque,
    worklet_id: &CString,
) -> Result<i32, String> {
    let source = b"(function(event){ return event; })";
    let mut error = std::ptr::null_mut();
    let status = unsafe {
        ex_worklet_install(
            runtime,
            worklet_id.as_ptr(),
            source.as_ptr(),
            source.len(),
            1,
            &mut error,
        )
    };
    let detail = take_hermes_string(error);
    if status == 1 {
        Err(format!(
            "bounded worklet install failed: {}",
            detail.unwrap_or_else(|| "missing diagnostic".into())
        ))
    } else {
        Ok(status)
    }
}

fn install_bounded_typed_worklet(
    runtime: *mut HermesRuntimeOpaque,
    source: &[u8],
    captures: &[NativeWorkletCapture],
) -> Result<(i32, u64, Option<String>), String> {
    let mut identity = 0_u64;
    let mut error = std::ptr::null_mut();
    let status = unsafe {
        ex_worklet_install_typed(
            runtime,
            1,
            source.as_ptr(),
            source.len(),
            captures.as_ptr(),
            captures.len() as u32,
            1,
            &mut identity,
            &mut error,
        )
    };
    let detail = take_hermes_string(error);
    if status != 0 && detail.is_none() {
        return Err(format!(
            "typed worklet install returned {status} without a diagnostic"
        ));
    }
    Ok((status, identity, detail))
}

fn require_bounded_typed_worklet(
    runtime: *mut HermesRuntimeOpaque,
    source: &[u8],
    captures: &[NativeWorkletCapture],
) -> Result<u64, String> {
    let (status, identity, detail) = install_bounded_typed_worklet(runtime, source, captures)?;
    if status != 0 || identity == 0 {
        return Err(format!(
            "bounded typed worklet install failed: {}",
            detail.unwrap_or_else(|| format!("status {status}"))
        ));
    }
    Ok(identity)
}

fn invoke_bounded_typed_worklet(
    runtime: *mut HermesRuntimeOpaque,
    identity: u64,
) -> Result<(i32, [f32; 4], u32), String> {
    let inputs = [2.0_f32, 3.0_f32];
    let mut outputs = [f32::NAN; 4];
    let mut output_count = 0_u32;
    let status = unsafe {
        ex_worklet_invoke_typed(
            runtime,
            identity,
            inputs.as_ptr(),
            inputs.len() as u32,
            outputs.as_mut_ptr(),
            outputs.len() as u32,
            &mut output_count,
        )
    };
    if status != 0 || output_count > outputs.len() as u32 {
        return Err(format!(
            "bounded typed worklet invocation failed with status {status} and count {output_count}"
        ));
    }
    Ok((status, outputs, output_count))
}

#[derive(Default)]
struct BoundedSharedValueCallbackState {
    read_context_matches: bool,
    read_handle: Option<NativeWorkletSharedValueHandle>,
    write_context_matches: bool,
    write_handle: Option<NativeWorkletSharedValueHandle>,
    write_value: Option<f32>,
}

extern "C" fn bounded_shared_value_read(
    handle: NativeWorkletSharedValueHandle,
    out_value: *mut f32,
    context: *mut std::ffi::c_void,
) -> u32 {
    if context.is_null() || out_value.is_null() {
        return 1;
    }
    // SAFETY: the executor passes a live callback state for the duration of
    // the synchronous typed invocation, and the worklet runtime does not
    // retain callback invocations past that call.
    let state = unsafe { &mut *context.cast::<BoundedSharedValueCallbackState>() };
    state.read_context_matches = true;
    state.read_handle = Some(handle);
    unsafe { *out_value = 7.5 };
    0
}

extern "C" fn bounded_shared_value_write(
    handle: NativeWorkletSharedValueHandle,
    value: f32,
    context: *mut std::ffi::c_void,
) -> u32 {
    if context.is_null() {
        return 1;
    }
    // SAFETY: see `bounded_shared_value_read`.
    let state = unsafe { &mut *context.cast::<BoundedSharedValueCallbackState>() };
    state.write_context_matches = true;
    state.write_handle = Some(handle);
    state.write_value = Some(value);
    0
}

fn execute_shared_value_callback(
    selector: &str,
    runtime: *mut HermesRuntimeOpaque,
) -> Result<Value, String> {
    let mut state = BoundedSharedValueCallbackState::default();
    let context = (&mut state as *mut BoundedSharedValueCallbackState).cast();
    let bind_status = unsafe {
        ex_worklet_bind_shared_value_accessors(
            runtime,
            Some(bounded_shared_value_read),
            Some(bounded_shared_value_write),
            context,
        )
    };
    if bind_status != 0 {
        return Err(format!(
            "shared-value accessor bind failed with status {bind_status}"
        ));
    }
    let capture = NativeWorkletCapture {
        kind: 3,
        scalar: 0.0,
        shared_value: NativeWorkletSharedValueHandle {
            slot: 17,
            generation: 23,
            epoch: 31,
        },
    };
    let source = b"(function(){var value=worklet.captureGet(0);worklet.captureSet(0,value+1);worklet.output(0,value);})";
    let identity = require_bounded_typed_worklet(runtime, source, &[capture])?;
    let _ = invoke_bounded_typed_worklet(runtime, identity)?;
    unsafe {
        let _ = ex_worklet_bind_shared_value_accessors(runtime, None, None, std::ptr::null_mut());
    }
    let read = state
        .read_handle
        .ok_or("typed worklet did not invoke the shared-value read callback")?;
    let write = state
        .write_handle
        .ok_or("typed worklet did not invoke the shared-value write callback")?;
    let observation = match selector {
        "callback:read_callback/0.slot" => returned_number(read.slot),
        "callback:read_callback/0.generation" => returned_number(read.generation),
        "callback:read_callback/0.epoch" => returned_number(read.epoch),
        "callback:read_callback/2" if state.read_context_matches => returned_object(),
        "callback:write_callback/0.slot" => returned_number(write.slot),
        "callback:write_callback/0.generation" => returned_number(write.generation),
        "callback:write_callback/0.epoch" => returned_number(write.epoch),
        "callback:write_callback/1" => returned_number(
            state
                .write_value
                .ok_or("shared-value write callback did not receive a value")?,
        ),
        "callback:write_callback/2" if state.write_context_matches => returned_object(),
        other => {
            return Err(format!(
                "unsupported shared-value callback selector {other}"
            ))
        }
    };
    Ok(observation)
}

#[derive(Default)]
struct BoundedMeasureCallbackState {
    context_matches: bool,
    node_id: Option<u32>,
}

extern "C" fn bounded_measure_callback(
    node_id: u32,
    out_frame4: *mut f32,
    context: *mut std::ffi::c_void,
) -> i32 {
    if context.is_null() || out_frame4.is_null() {
        return 0;
    }
    // SAFETY: the executor keeps both callback state and the four-float
    // caller buffer alive for the synchronous typed invocation.
    let state = unsafe { &mut *context.cast::<BoundedMeasureCallbackState>() };
    state.context_matches = true;
    state.node_id = Some(node_id);
    let frame = [1.0_f32, 2.0, 3.0, 4.0];
    unsafe { std::ptr::copy_nonoverlapping(frame.as_ptr(), out_frame4, frame.len()) };
    1
}

fn execute_measure_callback(
    selector: &str,
    runtime: *mut HermesRuntimeOpaque,
) -> Result<Value, String> {
    let mut state = BoundedMeasureCallbackState::default();
    let context = (&mut state as *mut BoundedMeasureCallbackState).cast();
    unsafe { ex_worklet_set_measure_callback(runtime, Some(bounded_measure_callback), context) };
    let source =
        b"(function(){var frame=measure(41);worklet.output(0,frame===null?-1:frame.width);})";
    let identity = require_bounded_typed_worklet(runtime, source, &[])?;
    let _ = invoke_bounded_typed_worklet(runtime, identity)?;
    unsafe { ex_worklet_set_measure_callback(runtime, None, std::ptr::null_mut()) };
    match selector {
        "callback:callback/0" => {
            Ok(returned_number(state.node_id.ok_or(
                "typed worklet did not invoke the measure callback",
            )?))
        }
        "callback:callback/2" if state.context_matches => Ok(returned_object()),
        other => Err(format!("unsupported measure callback selector {other}")),
    }
}

fn execute_worklet(function_name: &str, selector: &str) -> Result<Value, String> {
    let runtime = OwnedWorkletRuntime::new()?;
    unsafe { ex_worklet_set_generation(runtime.raw, 1) };
    let worklet_id = CString::new("capsec-host-abi-output").unwrap();
    let result = match function_name {
        "ex_worklet_bind_shared_value_accessors" => {
            if selector == "[[return]]" {
                returned_number(unsafe {
                    ex_worklet_bind_shared_value_accessors(
                        runtime.raw,
                        None,
                        None,
                        std::ptr::null_mut(),
                    )
                })
            } else {
                execute_shared_value_callback(selector, runtime.raw)?
            }
        }
        "ex_worklet_create" => returned_object(),
        "ex_worklet_destroy" => {
            runtime.destroy();
            return Ok(returned_undefined());
        }
        "ex_worklet_drain_logs" => raw_hermes_string(unsafe { ex_worklet_drain_logs(runtime.raw) }),
        "ex_worklet_drain_scheduled" => {
            raw_hermes_string(unsafe { ex_worklet_drain_scheduled(runtime.raw) })
        }
        "ex_worklet_drain_scheduled_typed" => {
            let source = b"(function(){worklet.runOnJS(77,1.5,2.5);})";
            let identity = require_bounded_typed_worklet(runtime.raw, source, &[])?;
            let _ = invoke_bounded_typed_worklet(runtime.raw, identity)?;
            let mut calls = [NativeWorkletScheduledCall::default(); 2];
            let count = unsafe {
                ex_worklet_drain_scheduled_typed(
                    runtime.raw,
                    calls.as_mut_ptr(),
                    calls.len() as u32,
                )
            };
            if selector == "out:calls" {
                raw(
                    "return",
                    "array",
                    json!(calls[..count as usize]
                        .iter()
                        .map(|call| json!({
                            "argumentCount": call.argument_count,
                            "arguments": &call.arguments[..call.argument_count as usize],
                            "callbackIdentity": call.callback_identity,
                            "generation": call.generation,
                            "sourceIdentity": call.source_identity,
                            "sourceSequence": call.source_sequence,
                        }))
                        .collect::<Vec<_>>()),
                )
            } else {
                returned_number(count)
            }
        }
        "ex_worklet_generation" => returned_number(unsafe { ex_worklet_generation(runtime.raw) }),
        "ex_worklet_install" => {
            if selector == "out:error" {
                let invalid_source = b"not valid JavaScript }";
                let mut error = std::ptr::null_mut();
                let _status = unsafe {
                    ex_worklet_install(
                        runtime.raw,
                        worklet_id.as_ptr(),
                        invalid_source.as_ptr(),
                        invalid_source.len(),
                        1,
                        &mut error,
                    )
                };
                raw_hermes_string(error)
            } else {
                returned_number(install_bounded_worklet(runtime.raw, &worklet_id)?)
            }
        }
        "ex_worklet_install_metrics" => {
            let source = b"(function(){worklet.output(0,1);})";
            let _ = require_bounded_typed_worklet(runtime.raw, source, &[])?;
            let mut metrics = NativeWorkletInstallMetrics::default();
            let status = unsafe { ex_worklet_install_metrics(runtime.raw, &mut metrics) };
            if selector == "out:metrics" {
                raw(
                    "return",
                    "object",
                    json!({
                        "reusedInstallCount": metrics.reused_install_count,
                        "sourceInstallCount": metrics.source_install_count,
                        "sourceInstallMaxNs": metrics.source_install_max_ns,
                        "sourceInstallTotalNs": metrics.source_install_total_ns,
                    }),
                )
            } else {
                returned_number(status)
            }
        }
        "ex_worklet_install_typed" => {
            let source = if selector == "out:error" {
                &b"not valid JavaScript }"[..]
            } else {
                &b"(function(){worklet.output(0,1);})"[..]
            };
            let (status, identity, error) =
                install_bounded_typed_worklet(runtime.raw, source, &[])?;
            match selector {
                "out:error" => error.map_or_else(returned_null, returned_string),
                "out:identity" => returned_number(identity),
                _ => returned_number(status),
            }
        }
        "ex_worklet_invoke" => {
            if install_bounded_worklet(runtime.raw, &worklet_id)? != 0 {
                return Err("bounded worklet was not installed at the active generation".into());
            }
            let args = CString::new("{\"value\":1}").unwrap();
            let mut output = std::ptr::null_mut();
            let status = unsafe {
                ex_worklet_invoke(runtime.raw, worklet_id.as_ptr(), args.as_ptr(), &mut output)
            };
            if selector == "out:result_json" {
                raw_hermes_string(output)
            } else {
                let _ = take_hermes_string(output);
                returned_number(status)
            }
        }
        "ex_worklet_invoke_typed" => {
            let source = b"(function(a,b){worklet.output(0,a+b);worklet.output(1,a*b);})";
            let identity = require_bounded_typed_worklet(runtime.raw, source, &[])?;
            let (status, outputs, output_count) =
                invoke_bounded_typed_worklet(runtime.raw, identity)?;
            match selector {
                "out:output_count" => returned_number(output_count),
                "out:outputs" => raw("return", "array", json!(outputs)),
                _ => returned_number(status),
            }
        }
        "ex_worklet_set_generation" => {
            unsafe { ex_worklet_set_generation(runtime.raw, 2) };
            returned_undefined()
        }
        "ex_worklet_set_measure_callback" => execute_measure_callback(selector, runtime.raw)?,
        "ex_worklet_take_scheduled_drop_count" => {
            returned_number(unsafe { ex_worklet_take_scheduled_drop_count(runtime.raw) })
        }
        other => return Err(format!("unsupported worklet Hermes ABI {other}")),
    };
    Ok(result)
}

fn compiled_host_abi_edges() -> std::collections::BTreeMap<String, String> {
    let coverage: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/registry/coverage-edges.json"
    )))
    .expect("compiled coverage registry is JSON");
    coverage["edges"]
        .as_array()
        .expect("compiled coverage edges")
        .iter()
        .filter(|edge| edge["surface"]["kind"] == "host-abi")
        .map(|edge| {
            (
                edge["id"].as_str().unwrap().to_owned(),
                edge["surface"]["name"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[derive(Clone)]
struct ValidatedRow {
    function_name: String,
    mode: String,
    operation: String,
    release_function: Option<String>,
    return_variant: String,
    selected_output_kind: String,
    selector: String,
}

fn validate_row(row: &Value) -> Result<ValidatedRow, String> {
    let key = row
        .get("key")
        .and_then(Value::as_object)
        .ok_or("missing output key")?;
    let probe = row
        .get("probe")
        .and_then(Value::as_object)
        .ok_or("missing output probe")?;
    let selector = key
        .get("output")
        .and_then(Value::as_str)
        .ok_or("missing output selector")?;
    let alias = key
        .get("alias")
        .and_then(Value::as_str)
        .ok_or("missing output alias")?;
    let mode = key
        .get("mode")
        .and_then(Value::as_str)
        .ok_or("missing output mode")?;
    let return_variant = key
        .get("returnVariant")
        .and_then(Value::as_str)
        .ok_or("missing return variant")?;
    if key.get("sourceKind").and_then(Value::as_str) != Some("host-abi")
        || probe.get("kind").and_then(Value::as_str) != Some("loaded-engine-return-record")
    {
        return Err("Host ABI output row selected an unsupported key or proof kind".into());
    }
    let descriptor = probe
        .get("sourceDescriptor")
        .ok_or("missing source descriptor")?;
    let function_name = descriptor["functionName"]
        .as_str()
        .ok_or("missing function name")?;
    let expected_path_contract = expected_path_output_contract(function_name, selector);
    let expected_legacy_contract =
        expected_legacy_output_contract(function_name, selector, alias, mode, return_variant);
    if mode != "all" && expected_legacy_contract.is_none() {
        return Err(format!(
            "{function_name}: non-default Host ABI mode has no bounded native executor"
        ));
    }
    if selector != "[[return]]"
        && expected_path_contract.is_none()
        && expected_legacy_contract.is_none()
        && !is_bounded_family_output_selector(function_name, selector)
    {
        return Err(format!(
            "{function_name}: output selector has no bounded native executor"
        ));
    }
    if expected_path_contract.is_some()
        && (key.get("alias").and_then(Value::as_str) != Some(function_name)
            || key.get("returnVariant").and_then(Value::as_str) != Some("default")
            || key.get("contextId").and_then(Value::as_str)
                != Some("host.private-native-call-initialized"))
    {
        return Err(format!("{function_name}: bounded path output key drift"));
    }
    if let Some(expected) = expected_legacy_contract {
        if alias != expected.alias
            || mode != expected.mode
            || return_variant != expected.return_variant
            || key.get("contextId").and_then(Value::as_str)
                != Some("host.private-native-call-initialized")
        {
            return Err(format!("{function_name}: bounded legacy output key drift"));
        }
    }
    if descriptor["kind"] != DESCRIPTOR_KIND
        || descriptor["invocationSchema"] != INVOCATION_SCHEMA
        || descriptor["catalogOutput"] != selector
        || descriptor["catalogMode"] != key["mode"]
        || descriptor["returnVariant"] != key["returnVariant"]
        || probe["sourceDescriptorDigest"] != tagged_jcs_digest(descriptor)
        || probe["recordPath"] != json!([selector])
    {
        return Err(format!("{function_name}: source descriptor drift"));
    }
    let edge_id = key
        .get("surfaceId")
        .and_then(Value::as_str)
        .ok_or("missing surface id")?;
    if compiled_host_abi_edges().get(edge_id).map(String::as_str) != Some(function_name) {
        return Err(format!("{function_name}: compiled coverage identity drift"));
    }
    let source_files = descriptor["sourceFiles"]
        .as_array()
        .ok_or("missing source files")?;
    if source_files.is_empty() {
        return Err(format!("{function_name}: source file binding is empty"));
    }
    for binding in source_files {
        let source_path = binding["path"].as_str().ok_or("missing source path")?;
        let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(source_path))
            .map_err(|error| format!("{function_name}: read {source_path}: {error}"))?;
        if binding["rawContentDigest"] != tagged_bytes_digest(&bytes)
            || !bytes
                .windows(function_name.len())
                .any(|window| window == function_name.as_bytes())
        {
            return Err(format!("{function_name}: exact source binding drift"));
        }
    }
    let operation = descriptor["operation"]["kind"]
        .as_str()
        .ok_or("missing operation")?;
    if let Some(expected) = expected_path_contract {
        if operation != expected.operation || descriptor["operation"]["targetVariant"] != "default"
        {
            return Err(format!(
                "{function_name}: bounded path operation binding drift"
            ));
        }
    }
    if let Some(expected) = expected_legacy_contract {
        if operation != expected.operation
            || descriptor["operation"]["targetVariant"] != "default"
            || descriptor["operation"]["mode"] != expected.mode
            || descriptor["operation"]["returnVariant"] != expected.return_variant
            || descriptor["operation"]["sourceSelector"] != "[[return]]"
        {
            return Err(format!(
                "{function_name}: bounded legacy output operation binding drift"
            ));
        }
        let expected_source_binding = expected_legacy_source_safety_binding(function_name)?;
        if descriptor.get("sourceSafetyBinding") != Some(&expected_source_binding) {
            return Err(format!(
                "{function_name}: legacy ownership/refusal source binding drift"
            ));
        }
    } else if descriptor.get("sourceSafetyBinding").is_some() {
        return Err(format!(
            "{function_name}: non-legacy output carried a legacy source binding"
        ));
    }
    let expected_language = if operation.starts_with("rust-host-") {
        "rust"
    } else if operation.starts_with("native-hermes-") {
        "c++"
    } else {
        return Err(format!("{function_name}: unsupported operation family"));
    };
    let selected_definitions = descriptor["selectedDefinitions"]
        .as_array()
        .ok_or("missing selected definitions")?;
    if selected_definitions.is_empty()
        || selected_definitions.iter().any(|definition| {
            definition["language"] != expected_language
                || definition["targetVariant"] != "default"
                || !descriptor["sourceRefs"]
                    .as_array()
                    .is_some_and(|refs| refs.contains(&definition["sourceRef"]))
        })
    {
        return Err(format!(
            "{function_name}: selected compiled definition drift"
        ));
    }
    let output_contracts = descriptor["outputContracts"]
        .as_array()
        .ok_or("missing source-derived output contracts")?;
    let selected_output = &descriptor["selectedOutput"];
    let (expected_selected_output, selected_output_kind, release_function) =
        if let Some(contract) = expected_path_contract {
            (
                expected_path_selected_output(contract, selector),
                contract.kind.to_owned(),
                contract.release_function.map(str::to_owned),
            )
        } else if let Some(contract) = expected_legacy_contract {
            (
                expected_legacy_selected_output(contract),
                "pointer".to_owned(),
                Some("ex_host_free_string".to_owned()),
            )
        } else if selector == "[[return]]" {
            match selected_output["kind"].as_str() {
                Some("scalar") => (
                    json!({
                        "kind": "scalar",
                        "ownership": "not-applicable",
                        "selector": "[[return]]"
                    }),
                    "scalar".to_owned(),
                    None,
                ),
                Some("pointer") => {
                    let release = selected_output["ownership"]["releaseFunction"]
                        .as_str()
                        .ok_or_else(|| {
                            format!("{function_name}: owned pointer return has no release function")
                        })?;
                    if !matches!(
                        release,
                        "ex_host_free_buffer"
                            | "ex_host_free_string"
                            | "ex_host_fs_close"
                            | "ex_hermes_destroy"
                            | "ex_hermes_free_string"
                            | "ex_worklet_destroy"
                    ) {
                        return Err(format!(
                            "{function_name}: unreviewed pointer return release function {release}"
                        ));
                    }
                    (
                        json!({
                            "kind": "pointer",
                            "ownership": {
                                "kind": "caller-owned",
                                "releaseFunction": release,
                            },
                            "role": "return",
                            "selector": "[[return]]",
                        }),
                        "pointer".to_owned(),
                        Some(release.to_owned()),
                    )
                }
                _ => {
                    return Err(format!(
                        "{function_name}: unsupported selected return output contract"
                    ))
                }
            }
        } else {
            let kind = selected_output["kind"]
                .as_str()
                .ok_or_else(|| format!("{function_name}: selected output has no kind"))?;
            let role = selected_output["role"]
                .as_str()
                .ok_or_else(|| format!("{function_name}: selected output has no role"))?;
            let ownership = selected_output["ownership"]["kind"]
                .as_str()
                .ok_or_else(|| format!("{function_name}: selected output has no ownership"))?;
            if selected_output["selector"] != selector
                || !matches!(kind, "aggregate" | "buffer" | "pointer" | "scalar")
                || !matches!(role, "callback-payload" | "output" | "inout")
                || !matches!(
                    ownership,
                    "borrowed" | "caller-owned" | "caller-storage" | "not-applicable"
                )
            {
                return Err(format!(
                    "{function_name}: unsupported bounded non-return output contract"
                ));
            }
            let release = selected_output["ownership"]["releaseFunction"]
                .as_str()
                .map(str::to_owned);
            if ownership == "caller-owned"
                && !matches!(
                    release.as_deref(),
                    Some("ex_hermes_evaluation_result_dispose" | "ex_hermes_free_string")
                )
            {
                return Err(format!(
                    "{function_name}: bounded non-return ownership has an unreviewed release"
                ));
            }
            (selected_output.clone(), kind.to_owned(), release)
        };
    if descriptor["outputContractSchema"] != OUTPUT_CONTRACT_SCHEMA
        || descriptor["selectedOutput"] != expected_selected_output
        || output_contracts.len() != selected_definitions.len()
    {
        return Err(format!(
            "{function_name}: selected output contract binding drift"
        ));
    }
    for (definition, contract) in selected_definitions.iter().zip(output_contracts) {
        let base_drift = contract["schema"] != OUTPUT_CONTRACT_SCHEMA
            || contract["functionName"] != function_name
            || contract["sourceRef"] != definition["sourceRef"]
            || contract["language"] != definition["language"]
            || definition.get("outputContract") != Some(contract);
        let source_selector = if expected_legacy_contract.is_some() {
            "[[return]]"
        } else {
            selector
        };
        let selected_channel = contract["outputChannels"].as_array().and_then(|channels| {
            let selected = channels
                .iter()
                .filter(|channel| channel["selector"] == source_selector)
                .collect::<Vec<_>>();
            (selected.len() == 1).then_some(selected[0])
        });
        let output_drift = if let Some(expected) = expected_path_contract {
            contract["status"] != "resolved"
                || contract["unresolved"] != json!([])
                || selected_channel.is_none_or(|channel| {
                    channel["kind"] != expected.kind
                        || channel["role"] != "output"
                        || channel["parameter"] != expected.parameter
                        || channel["lengthParameter"] != expected.length_parameter
                        || channel["ownership"]["kind"] != expected.ownership_kind
                        || match expected.release_function {
                            Some(release) => channel["ownership"]["releaseFunction"] != release,
                            None => channel["ownership"].get("releaseFunction").is_some(),
                        }
                })
        } else if expected_legacy_contract.is_some() {
            contract["status"] != "resolved"
                || contract["unresolved"] != json!([])
                || contract["return"]["role"] != "value"
                || contract["return"]["kind"] != "pointer"
                || contract["return"]["ownership"]["kind"] != "caller-owned"
                || contract["return"]["ownership"]["releaseFunction"] != "ex_host_free_string"
                || selected_channel.is_none_or(|channel| {
                    channel["role"] != "return"
                        || channel["kind"] != "pointer"
                        || channel["ownership"]["kind"] != "caller-owned"
                        || channel["ownership"]["releaseFunction"] != "ex_host_free_string"
                })
        } else if selector != "[[return]]" {
            contract["status"] != "resolved"
                || contract["unresolved"] != json!([])
                || selected_channel != Some(selected_output)
        } else if selected_output_kind == "pointer" {
            let release = release_function
                .as_deref()
                .expect("validated pointer selected a release function");
            contract["status"] != "resolved"
                || contract["unresolved"] != json!([])
                || contract["return"]["role"] != "value"
                || contract["return"]["kind"] != "pointer"
                || contract["return"]["ownership"]["kind"] != "caller-owned"
                || contract["return"]["ownership"]["releaseFunction"] != release
                || selected_channel.is_none_or(|channel| {
                    channel["role"] != "return"
                        || channel["kind"] != "pointer"
                        || channel["ownership"]["kind"] != "caller-owned"
                        || channel["ownership"]["releaseFunction"] != release
                })
        } else {
            contract["status"] != "resolved"
                || contract["unresolved"] != json!([])
                || contract["return"]["role"] != "value"
                || contract["return"]["kind"] != "scalar"
                || contract["return"]["ownership"]["kind"] != "not-applicable"
                || selected_channel.is_none_or(|channel| {
                    channel["role"] != "return" || channel["kind"] != "scalar"
                })
        };
        if base_drift || output_drift {
            return Err(format!(
                "{function_name}: source-derived selected output contract drift"
            ));
        }
    }
    Ok(ValidatedRow {
        function_name: function_name.to_owned(),
        mode: mode.to_owned(),
        operation: operation.to_owned(),
        release_function,
        return_variant: return_variant.to_owned(),
        selected_output_kind,
        selector: selector.to_owned(),
    })
}

fn return_record_result(row: &Value, raw: Value) -> Value {
    json!({
        "key": row["key"],
        "proof": {
            "kind": "loaded-engine-return-record",
            "fixtureId": row["probe"]["fixtureId"],
            "sourceDescriptorDigest": row["probe"]["sourceDescriptorDigest"],
            "outputContractSchema": row["probe"]["sourceDescriptor"]["outputContractSchema"],
            "selectedOutput": row["probe"]["sourceDescriptor"]["selectedOutput"],
            "recordPath": row["probe"]["recordPath"],
            "rawValueShape": raw["rawValueShape"],
        },
        "raw": raw,
    })
}

fn validate_bounded_observation(validated: &ValidatedRow, raw: Value) -> Result<Value, String> {
    if validated.operation == "rust-host-legacy-path-output" {
        let expected_error = match (
            validated.function_name.as_str(),
            validated.mode.as_str(),
            validated.return_variant.as_str(),
        ) {
            (_, "unarmed", "success") => None,
            ("ex_host_fs_mkdir_recursive_result", "unarmed", "error") => Some(HOST_ABI_EEXIST),
            ("ex_host_fs_mkdtemp", "unarmed", "error") => Some(HOST_ABI_EACCES),
            ("ex_host_fs_realpath", "unarmed", "error") => Some(HOST_ABI_ENOENT),
            (_, "armed", "refused") => Some(HOST_ABI_EPERM),
            _ => {
                return Err(format!(
                    "{}: unsupported legacy path observation variant",
                    validated.function_name
                ))
            }
        };
        if let Some(error_code) = expected_error {
            if raw["kind"] != "throw"
                || raw["rawValueShape"] != "null"
                || !raw["value"].is_null()
                || raw["errorCode"] != error_code
            {
                return Err(format!(
                    "{}: legacy path failure lost its observed null/errno result",
                    validated.function_name
                ));
            }
        } else if raw["kind"] != "return"
            || raw["rawValueShape"] != "string"
            || raw["value"] != PRIVATE_NATIVE_PATH_CLASS
            || !raw["errorCode"].is_null()
        {
            return Err(format!(
                "{}: legacy path success persisted native bytes instead of its validated class",
                validated.function_name
            ));
        }
        return Ok(raw);
    }

    if validated.operation == "rust-host-legacy-directory-output" {
        let names = raw["value"]
            .as_array()
            .ok_or_else(|| "legacy readdir output was not an actual JSON array".to_string())?;
        if raw["kind"] != "return"
            || raw["rawValueShape"] != "array"
            || !raw["errorCode"].is_null()
            || names.is_empty()
            || names.iter().any(|name| {
                name.as_str().is_none_or(|name| {
                    name.is_empty()
                        || matches!(name, "." | "..")
                        || name.contains('/')
                        || name.contains('\\')
                })
            })
        {
            return Err("legacy readdir output did not contain only nonempty basenames".into());
        }
        return Ok(raw);
    }

    if validated.selector == "[[return]]" {
        let shape_is_valid = match (
            validated.selected_output_kind.as_str(),
            validated.release_function.as_deref(),
        ) {
            ("scalar", None) => raw["rawValueShape"] == "number",
            ("pointer", Some("ex_host_free_string" | "ex_hermes_free_string")) => {
                raw["rawValueShape"] == "string" || raw["rawValueShape"] == "null"
            }
            ("pointer", Some("ex_host_free_buffer")) => {
                raw["rawValueShape"] == "array" || raw["rawValueShape"] == "null"
            }
            ("pointer", Some("ex_host_fs_close" | "ex_hermes_destroy" | "ex_worklet_destroy")) => {
                raw["rawValueShape"] == "object" || raw["rawValueShape"] == "null"
            }
            _ => false,
        };
        if raw["kind"] != "return" || !shape_is_valid || !raw["errorCode"].is_null() {
            return Err(format!(
                "{}: selected return ownership produced an incompatible runtime fact",
                validated.function_name
            ));
        }
        return Ok(raw);
    }

    if is_bounded_family_output_selector(&validated.function_name, &validated.selector) {
        let shape_is_valid = if validated.selector.contains("[]") {
            raw["rawValueShape"] == "array"
        } else if matches!(
            (
                validated.function_name.as_str(),
                validated.selector.as_str()
            ),
            (
                "ex_worklet_bind_shared_value_accessors",
                "callback:read_callback/2" | "callback:write_callback/2"
            ) | ("ex_worklet_set_measure_callback", "callback:callback/2")
                | ("ex_worklet_install_metrics", "out:metrics")
                | (
                    "ex_hermes_schedule_watchdog_heartbeat_for_generation",
                    "callback:callback/0"
                )
                | ("ex_hermes_set_host_call_async", "callback:callback/0")
                | (
                    "ex_hermes_set_exact_host_call_async",
                    "callback:callback/0" | "callback:callback/5"
                )
                | ("ex_hermes_set_host_wake_hook", "callback:hook/0")
        ) {
            raw["rawValueShape"] == "object"
        } else if (
            validated.function_name.as_str(),
            validated.selector.as_str(),
        ) == ("ex_worklet_drain_scheduled_typed", "out:calls")
        {
            raw["rawValueShape"] == "array"
        } else {
            match validated.selected_output_kind.as_str() {
                "scalar" => raw["rawValueShape"] == "number",
                "aggregate" | "buffer" => {
                    raw["rawValueShape"] == "array" || raw["rawValueShape"] == "null"
                }
                "pointer" => raw["rawValueShape"] == "string" || raw["rawValueShape"] == "null",
                _ => false,
            }
        };
        if raw["kind"] != "return" || !shape_is_valid || !raw["errorCode"].is_null() {
            return Err(format!(
                "{}: bounded non-return output produced an incompatible runtime fact",
                validated.function_name
            ));
        }
        return Ok(raw);
    }

    let expected = expected_path_output_contract(&validated.function_name, &validated.selector)
        .ok_or_else(|| {
            format!(
                "{}: selected path output has no native class validator",
                validated.function_name
            )
        })?;
    if raw["kind"] != "return"
        || raw["rawValueShape"] != "string"
        || raw["value"] != expected.normalized_class
        || !raw["errorCode"].is_null()
    {
        return Err(format!(
            "{}: path output executor did not emit only its normalized class",
            validated.function_name
        ));
    }
    Ok(raw)
}

fn execute_immediate_host_abi_output(
    validated: &ValidatedRow,
    sandbox: &FsSandbox,
) -> Result<Value, String> {
    let function_name = validated.function_name.as_str();
    let raw = match validated.operation.as_str() {
        "rust-host-fs-sandbox" => execute_fs(function_name, &validated.selector, sandbox),
        "rust-host-sqlite-memory" => execute_sqlite(function_name, sandbox),
        "rust-host-terminal-inert" => execute_terminal(function_name, &validated.selector),
        "rust-host-bounded-basic" => execute_basic(function_name),
        "native-hermes-stateless-current-target" => {
            execute_hermes_stateless(function_name, &validated.selector)
        }
        "native-hermes-diagnostic-runtime" => {
            execute_hermes_diagnostic(function_name, &validated.selector)
        }
        "native-hermes-authenticated-armed-create" => execute_authenticated_armed_create(sandbox),
        "native-hermes-bounded-dispatch-runtime" => {
            execute_bounded_dispatch(function_name, &validated.selector)
        }
        "native-hermes-owned-value-runtime" => {
            execute_owned_value(function_name, &validated.selector)
        }
        "rust-host-wake-hook-callback" => execute_host_wake_hook_callback(&validated.selector),
        "native-hermes-worklet-runtime" => execute_worklet(function_name, &validated.selector),
        "native-hermes-stateless-path-output" => {
            execute_engine_path_output(function_name, &validated.selector)
        }
        "rust-host-authenticated-stateful-output"
        | "rust-host-authenticated-typed-authority"
        | "rust-host-authenticated-vfs-output"
        | "rust-host-authenticated-vfs-path-output" => {
            return Err(format!(
                "{function_name}: authenticated Host output was scheduled as an immediate call"
            ))
        }
        "rust-host-legacy-path-output" | "rust-host-legacy-directory-output" => {
            execute_legacy_output(validated, sandbox)
        }
        other => Err(format!(
            "{function_name}: unsupported Host ABI operation {other}"
        )),
    }?;
    validate_bounded_observation(validated, raw)
}

pub(super) fn execute_host_abi_output_rows(rows: &[Value]) -> (Vec<Value>, Vec<Value>) {
    if rows.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let sandbox = FsSandbox::new();
    let validated = rows.iter().map(validate_row).collect::<Vec<_>>();
    let mut executions = (0..rows.len()).map(|_| None).collect::<Vec<_>>();

    // Execute all compatibility/default-host rows first. They may install a
    // diagnostic Host. The authenticated VFS runtime is then constructed once
    // and remains the selected armed Host for the entire VFS tranche.
    for (index, validation) in validated.iter().enumerate() {
        match validation {
            Err(reason) => executions[index] = Some(Err(reason.clone())),
            Ok(row)
                if row.operation != "rust-host-authenticated-vfs-path-output"
                    && row.operation != "rust-host-authenticated-vfs-output"
                    && row.operation != "rust-host-authenticated-typed-authority"
                    && row.operation != "rust-host-authenticated-stateful-output" =>
            {
                executions[index] = Some(execute_immediate_host_abi_output(row, &sandbox));
            }
            Ok(_) => {}
        }
    }

    let vfs_indices = validated
        .iter()
        .enumerate()
        .filter_map(|(index, validation)| {
            validation
                .as_ref()
                .ok()
                .filter(|row| {
                    row.operation == "rust-host-authenticated-vfs-path-output"
                        || row.operation == "rust-host-authenticated-vfs-output"
                })
                .map(|_| index)
        })
        .collect::<Vec<_>>();
    if !vfs_indices.is_empty() {
        match OwnedAuthenticatedVfsRuntime::new(&sandbox) {
            Ok(runtime) => {
                for index in vfs_indices {
                    let row = validated[index]
                        .as_ref()
                        .expect("VFS index was selected from validated rows");
                    let execution =
                        execute_vfs_path_output(&runtime, &row.function_name, &row.selector)
                            .and_then(|raw| validate_bounded_observation(row, raw));
                    executions[index] = Some(execution);
                }
            }
            Err(reason) => {
                for index in vfs_indices {
                    executions[index] = Some(Err(reason.clone()));
                }
            }
        }
    }

    let typed_indices = validated
        .iter()
        .enumerate()
        .filter_map(|(index, validation)| {
            validation
                .as_ref()
                .ok()
                .filter(|row| row.operation == "rust-host-authenticated-typed-authority")
                .map(|_| index)
        })
        .collect::<Vec<_>>();
    for index in typed_indices {
        let row = validated[index]
            .as_ref()
            .expect("typed-authority index was selected from validated rows");
        let execution = execute_typed_authority(&row.function_name, &row.selector, &sandbox)
            .and_then(|raw| validate_bounded_observation(row, raw));
        executions[index] = Some(execution);
    }

    let stateful_indices = validated
        .iter()
        .enumerate()
        .filter_map(|(index, validation)| {
            validation
                .as_ref()
                .ok()
                .filter(|row| row.operation == "rust-host-authenticated-stateful-output")
                .map(|_| index)
        })
        .collect::<Vec<_>>();
    for index in stateful_indices {
        let row = validated[index]
            .as_ref()
            .expect("stateful Host index was selected from validated rows");
        let execution =
            execute_authenticated_stateful_host(&row.function_name, &row.selector, &sandbox)
                .and_then(|raw| validate_bounded_observation(row, raw));
        executions[index] = Some(execution);
    }

    let mut observations = Vec::with_capacity(rows.len());
    let mut unexercisable = Vec::new();
    for (row, execution) in rows.iter().zip(executions) {
        match execution.expect("every Host ABI output row must receive an execution result") {
            Ok(raw) => observations.push(return_record_result(row, raw)),
            Err(reason) => unexercisable.push(json!({ "key": row["key"], "reason": reason })),
        }
    }
    (observations, unexercisable)
}

fn authored_path_test_row(function_name: &str, selector: &str) -> Value {
    let expected = expected_path_output_contract(function_name, selector)
        .expect("test row must select a bounded path output");
    let (language, source_path) = if function_name.starts_with("ex_host_") {
        ("rust", "src/host/abi.rs")
    } else {
        ("c++", "src/engine/hermes_runtime.cc")
    };
    let source_ref = format!("{source_path}#{function_name}");
    let source_bytes =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(source_path)).unwrap();
    let ownership = match expected.release_function {
        Some(release_function) => json!({
            "kind": expected.ownership_kind,
            "releaseFunction": release_function,
        }),
        None => json!({ "kind": expected.ownership_kind }),
    };
    let output_contract = json!({
        "bufferLengthPairs": [{
            "bufferParameter": expected.parameter,
            "direction": "output",
            "lengthParameter": expected.length_parameter,
        }],
        "functionName": function_name,
        "language": language,
        "outputChannels": [
            {
                "kind": "scalar",
                "ownership": {"kind": "not-applicable"},
                "role": "return",
                "selector": "[[return]]",
            },
            {
                "kind": expected.kind,
                "lengthParameter": expected.length_parameter,
                "ownership": ownership,
                "parameter": expected.parameter,
                "role": "output",
                "selector": selector,
            }
        ],
        "parameters": [],
        "return": {
            "kind": "scalar",
            "ownership": {"kind": "not-applicable"},
            "role": "value",
            "type": {"canonical": "test-scalar", "tokens": ["test-scalar"]},
        },
        "schema": OUTPUT_CONTRACT_SCHEMA,
        "sourceRef": source_ref,
        "status": "resolved",
        "unresolved": [],
    });
    let definition = json!({
        "language": language,
        "outputContract": output_contract,
        "sourceRef": source_ref,
        "targetVariant": "default",
        "unsafe": language == "rust",
        "weak": false,
    });
    let descriptor = json!({
        "kind": DESCRIPTOR_KIND,
        "invocationSchema": INVOCATION_SCHEMA,
        "functionName": function_name,
        "catalogOutput": selector,
        "catalogMode": "all",
        "returnVariant": "default",
        "inventorySourceRefs": [source_ref],
        "sourceRefs": [source_ref],
        "sourceFiles": [{
            "path": source_path,
            "rawContentDigest": tagged_bytes_digest(&source_bytes),
        }],
        "definitions": [definition],
        "selectedDefinitions": [definition],
        "outputContractSchema": OUTPUT_CONTRACT_SCHEMA,
        "outputContracts": [output_contract],
        "selectedOutput": expected_path_selected_output(expected, selector),
        "operation": {
            "kind": expected.operation,
            "targetVariant": "default",
        },
    });
    let edge_id = compiled_host_abi_edges()
        .into_iter()
        .find_map(|(id, name)| (name == function_name).then_some(id))
        .expect("bounded path output has a compiled coverage edge");
    json!({
        "key": {
            "surfaceId": edge_id,
            "output": selector,
            "alias": function_name,
            "mode": "all",
            "sourceKind": "host-abi",
            "returnVariant": "default",
            "contextId": "host.private-native-call-initialized",
        },
        "probe": {
            "kind": "loaded-engine-return-record",
            "fixtureId": format!("host-abi-output-test-{function_name}-{selector}"),
            "sourceDescriptorDigest": tagged_jcs_digest(&descriptor),
            "sourceDescriptor": descriptor,
            "recordPath": [selector],
        },
    })
}

fn authored_legacy_test_row(
    function_name: &str,
    selector: &str,
    alias: &str,
    mode: &str,
    return_variant: &str,
) -> Value {
    let expected =
        expected_legacy_output_contract(function_name, selector, alias, mode, return_variant)
            .expect("test row must select an exact bounded legacy Host output");
    let source_path = "src/host/abi.rs";
    let source_ref = format!("{source_path}#{function_name}");
    let source_bytes =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(source_path)).unwrap();
    let output_contract = json!({
        "bufferLengthPairs": [],
        "functionName": function_name,
        "language": "rust",
        "outputChannels": [{
            "kind": "pointer",
            "ownership": {
                "kind": "caller-owned",
                "releaseFunction": "ex_host_free_string",
            },
            "role": "return",
            "selector": "[[return]]",
        }],
        "parameters": [],
        "return": {
            "kind": "pointer",
            "ownership": {
                "kind": "caller-owned",
                "releaseFunction": "ex_host_free_string",
            },
            "role": "value",
            "type": {
                "canonical": "* mut c_char",
                "tokens": ["*", "mut", "c_char"],
            },
        },
        "schema": OUTPUT_CONTRACT_SCHEMA,
        "sourceRef": source_ref,
        "status": "resolved",
        "unresolved": [],
    });
    let definition = json!({
        "language": "rust",
        "outputContract": output_contract,
        "sourceRef": source_ref,
        "targetVariant": "default",
        "unsafe": false,
        "weak": false,
    });
    let descriptor = json!({
        "kind": DESCRIPTOR_KIND,
        "invocationSchema": INVOCATION_SCHEMA,
        "functionName": function_name,
        "catalogOutput": selector,
        "catalogMode": mode,
        "returnVariant": return_variant,
        "inventorySourceRefs": [source_ref],
        "sourceRefs": [source_ref],
        "sourceFiles": [{
            "path": source_path,
            "rawContentDigest": tagged_bytes_digest(&source_bytes),
        }],
        "definitions": [definition],
        "selectedDefinitions": [definition],
        "outputContractSchema": OUTPUT_CONTRACT_SCHEMA,
        "outputContracts": [output_contract],
        "selectedOutput": expected_legacy_selected_output(expected),
        "sourceSafetyBinding": expected_legacy_source_safety_binding(function_name).unwrap(),
        "operation": {
            "kind": expected.operation,
            "mode": expected.mode,
            "returnVariant": expected.return_variant,
            "sourceSelector": "[[return]]",
            "targetVariant": "default",
        },
    });
    let edge_id = compiled_host_abi_edges()
        .into_iter()
        .find_map(|(id, name)| (name == function_name).then_some(id))
        .expect("bounded legacy Host output has a compiled coverage edge");
    json!({
        "key": {
            "surfaceId": edge_id,
            "output": selector,
            "alias": alias,
            "mode": mode,
            "sourceKind": "host-abi",
            "returnVariant": return_variant,
            "contextId": "host.private-native-call-initialized",
        },
        "probe": {
            "kind": "loaded-engine-return-record",
            "fixtureId": format!(
                "host-abi-output-test-{function_name}-{mode}-{return_variant}-{selector}"
            ),
            "sourceDescriptorDigest": tagged_jcs_digest(&descriptor),
            "sourceDescriptor": descriptor,
            "recordPath": [selector],
        },
    })
}

#[test]
fn host_abi_output_executor_rejects_an_unbound_source_digest() {
    let mut row = authored_path_test_row("ex_hermes_engine_binary_path", "out:out");
    row["probe"]["sourceDescriptorDigest"] =
        Value::String("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
    assert!(validate_row(&row).is_err());
}

#[test]
fn host_abi_output_executor_rejects_rewritten_path_ownership_even_when_resigned() {
    let mut row = authored_path_test_row("ex_host_vfs_resolve_path", "out:backing");
    row["probe"]["sourceDescriptor"]["selectedOutput"]["ownership"] =
        json!({"kind": "caller-storage"});
    row["probe"]["sourceDescriptor"]["selectedDefinitions"][0]["outputContract"]
        ["outputChannels"][1]["ownership"] = json!({"kind": "caller-storage"});
    row["probe"]["sourceDescriptor"]["outputContracts"][0]["outputChannels"][1]["ownership"] =
        json!({"kind": "caller-storage"});
    row["probe"]["sourceDescriptorDigest"] =
        Value::String(tagged_jcs_digest(&row["probe"]["sourceDescriptor"]));
    let error = validate_row(&row)
        .err()
        .expect("rewritten source ownership must fail closed");
    assert!(error.contains("output contract binding drift"));
}

#[test]
fn host_abi_path_outputs_persist_only_validated_class_markers() {
    let rows = [
        ("ex_hermes_engine_binary_path", "out:out"),
        ("ex_host_vfs_chdir", "out:virtual"),
        ("ex_host_vfs_get_cwd", "out:virtual"),
        ("ex_host_vfs_resolve_path", "out:virtual"),
        ("ex_host_vfs_resolve_path", "out:backing"),
    ]
    .into_iter()
    .map(|(function_name, selector)| authored_path_test_row(function_name, selector))
    .collect::<Vec<_>>();
    let (results, unexercisable) = execute_host_abi_output_rows(&rows);
    assert!(
        unexercisable.is_empty(),
        "bounded path outputs were not executable: {unexercisable:?}"
    );
    assert_eq!(results.len(), rows.len());
    let markers = results
        .iter()
        .map(|result| result["raw"]["value"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        markers,
        [
            PRIVATE_NATIVE_PATH_CLASS,
            VIRTUAL_ABSOLUTE_CLASS,
            VIRTUAL_ABSOLUTE_CLASS,
            VIRTUAL_ABSOLUTE_CLASS,
            PRIVATE_NATIVE_PATH_CLASS,
        ]
    );
    for result in &results {
        assert_eq!(result["raw"]["kind"], "return");
        assert_eq!(result["raw"]["rawValueShape"], "string");
        assert!(matches!(
            result["raw"]["value"].as_str(),
            Some(PRIVATE_NATIVE_PATH_CLASS | VIRTUAL_ABSOLUTE_CLASS)
        ));
    }
}

#[test]
fn legacy_host_path_variants_and_readdir_emit_only_bounded_observations() {
    let rows = [
        (
            "ex_host_fs_mkdir_recursive_result",
            "[[return]]",
            "ex_host_fs_mkdir_recursive_result",
            "unarmed",
            "success",
        ),
        (
            "ex_host_fs_mkdir_recursive_result",
            "[[return]]",
            "ex_host_fs_mkdir_recursive_result",
            "unarmed",
            "error",
        ),
        (
            "ex_host_fs_mkdir_recursive_result",
            "[[return]]",
            "ex_host_fs_mkdir_recursive_result",
            "armed",
            "refused",
        ),
        (
            "ex_host_fs_mkdtemp",
            "[[return]]",
            "ex_host_fs_mkdtemp",
            "unarmed",
            "success",
        ),
        (
            "ex_host_fs_mkdtemp",
            "[[return]]",
            "ex_host_fs_mkdtemp",
            "unarmed",
            "error",
        ),
        (
            "ex_host_fs_mkdtemp",
            "[[return]]",
            "ex_host_fs_mkdtemp",
            "armed",
            "refused",
        ),
        (
            "ex_host_fs_realpath",
            "[[return]]",
            "ex_host_fs_realpath",
            "unarmed",
            "success",
        ),
        (
            "ex_host_fs_realpath",
            "[[return]]",
            "ex_host_fs_realpath",
            "unarmed",
            "error",
        ),
        (
            "ex_host_fs_realpath",
            "[[return]]",
            "ex_host_fs_realpath",
            "armed",
            "refused",
        ),
        (
            "ex_host_fs_readdir",
            "array-items",
            "ex_host_fs_readdir[]",
            "all",
            "success",
        ),
    ]
    .into_iter()
    .map(|(function_name, selector, alias, mode, return_variant)| {
        authored_legacy_test_row(function_name, selector, alias, mode, return_variant)
    })
    .collect::<Vec<_>>();
    let (results, unexercisable) = execute_host_abi_output_rows(&rows);
    assert!(
        unexercisable.is_empty(),
        "bounded legacy Host outputs were not executable: {unexercisable:?}"
    );
    assert_eq!(results.len(), rows.len());
    let observations = results
        .iter()
        .map(|result| result["raw"].clone())
        .collect::<Vec<_>>();
    assert_eq!(observations[0]["value"], PRIVATE_NATIVE_PATH_CLASS);
    assert_eq!(observations[1]["errorCode"], HOST_ABI_EEXIST);
    assert_eq!(observations[2]["errorCode"], HOST_ABI_EPERM);
    assert_eq!(observations[3]["value"], PRIVATE_NATIVE_PATH_CLASS);
    assert_eq!(observations[4]["errorCode"], HOST_ABI_EACCES);
    assert_eq!(observations[5]["errorCode"], HOST_ABI_EPERM);
    assert_eq!(observations[6]["value"], PRIVATE_NATIVE_PATH_CLASS);
    assert_eq!(observations[7]["errorCode"], HOST_ABI_ENOENT);
    assert_eq!(observations[8]["errorCode"], HOST_ABI_EPERM);
    assert_eq!(
        observations[9],
        raw("return", "array", json!(["alpha", "beta.txt"]))
    );
    for success in [&observations[0], &observations[3], &observations[6]] {
        assert_eq!(success["rawValueShape"], "string");
        assert_eq!(success["value"], PRIVATE_NATIVE_PATH_CLASS);
        assert!(success["value"]
            .as_str()
            .is_some_and(|value| !value.contains('/') && !value.contains('\\')));
    }
}

#[test]
fn legacy_host_output_executor_rejects_a_resigned_mode_variant_mismatch() {
    let mut row = authored_legacy_test_row(
        "ex_host_fs_realpath",
        "[[return]]",
        "ex_host_fs_realpath",
        "armed",
        "refused",
    );
    row["key"]["mode"] = Value::String("unarmed".into());
    row["probe"]["sourceDescriptor"]["catalogMode"] = Value::String("unarmed".into());
    row["probe"]["sourceDescriptorDigest"] =
        Value::String(tagged_jcs_digest(&row["probe"]["sourceDescriptor"]));
    let error = validate_row(&row)
        .err()
        .expect("rewritten legacy Host mode must fail closed");
    assert!(
        error.contains("source descriptor drift")
            || error.contains("operation binding drift")
            || error.contains("no bounded native executor")
    );
}

#[test]
fn capsec_host_abi_output_batch() {
    let Ok(plan_path) = std::env::var("IBEX_CAPSEC_HOST_ABI_OUTPUT_PLAN") else {
        eprintln!("IBEX_CAPSEC_HOST_ABI_OUTPUT_PLAN is unset; skipping Host ABI output batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_HOST_ABI_OUTPUT_BATCH_OUTPUT")
        .expect("Host ABI output batch requires an owned output path");
    let bytes = std::fs::read(plan_path).expect("read Host ABI output plan");
    let text = std::str::from_utf8(&bytes).expect("Host ABI output plan is UTF-8");
    let plan = capsec_semantics::strict_json::parse_strict(text)
        .expect("Host ABI output plan is strict JSON");
    let rows = plan["rows"].as_array().expect("Host ABI output plan rows");
    let (results, unexercisable) = execute_host_abi_output_rows(rows);
    assert_eq!(
        results.len() + unexercisable.len(),
        rows.len(),
        "every authored Host ABI output row is accounted for"
    );
    let artifact = json!({
        "hostAbiOutputExecutorBatchSchema": "ibex/capsec-host-abi-output-executor-batch/1",
        "results": results,
        "unexercisable": unexercisable,
    });
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("create owned Host ABI output batch");
    serde_json::to_writer_pretty(&mut output, &artifact).expect("write Host ABI output batch");
    use std::io::Write as _;
    output
        .write_all(b"\n")
        .expect("terminate Host ABI output batch");
}
