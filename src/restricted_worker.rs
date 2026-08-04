//! Dedicated-thread restricted external-script worker ABI.
//!
//! The public handle owns only bounded typed queues and a control lease. It is
//! deliberately a different Rust/C type from `ExactHermesRuntime`, preventing
//! generic eval, debugger, module-loader, or host-call entry points from being
//! applied to an external script.
//! @ref LLP 0048#61-native-construction-and-ownership-seam

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ibex_sfe_format::app_bound::{
    LimitsV1, RESTRICTED_WORKER_ARMING_SCHEMA_V1, RESTRICTED_WORKER_BROKER_V1,
};
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const OK: i32 = 0;
const EMPTY: i32 = 1;
const INVALID: i32 = -1;
const ABI_MISMATCH: i32 = -2;
const STALE: i32 = -3;
const LIFECYCLE: i32 = -4;
const CEILING: i32 = -5;
const QUEUE: i32 = -6;
const IDENTITY: i32 = -7;
const UNSUPPORTED: i32 = -8;
const ENGINE: i32 = -9;
const ABI_VERSION: u32 = 1;
const MAX_ARMING: usize = 4 * 1024;
const MAX_LIMITS: usize = 2 * 1024;
const MAX_SOURCE: usize = 4 * 1024 * 1024;
const MAX_SOURCE_MAP: usize = 8 * 1024 * 1024;
const MAX_SOURCE_PATH: usize = 16 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalTransformWireV1 {
    schema: &'static str,
    callable_source: String,
    composed_source_map: String,
    source_digest: String,
    transformed_source_digest: String,
    source_map_digest: String,
    has_default_export: bool,
}

#[repr(C)]
pub struct ExRestrictedWorkerOptionsV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub arming_json: *const u8,
    pub arming_json_len: usize,
    pub limits_json: *const u8,
    pub limits_json_len: usize,
}

#[repr(C)]
pub struct ExRestrictedWorkerEventV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub tag: u32,
    pub fault: u32,
    pub runtime_nonce: u64,
    pub bytes: *mut u8,
    pub bytes_len: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArmingV1 {
    schema: String,
    principal: PrincipalV1,
    transformed_source_digest: String,
    source_map_digest: String,
    engine_compatibility_digest: String,
    language_profile_digest: String,
    worker_policy_digest: String,
    broker_protocol: String,
    global_inventory_digest: String,
    effective_limits_digest: String,
    dynamic_code: String,
    module_registry: String,
    capabilities: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrincipalV1 {
    kind: String,
    app_binding_digest: String,
    source_digest: String,
    run_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FrameV1 {
    schema: String,
    run_id: String,
    sequence: u64,
    #[serde(rename = "type")]
    frame_type: String,
    body: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartBodyV1 {
    profile: ProfileV1,
    source_digest: String,
    transformed_source_digest: String,
    source_map_digest: String,
    args: Vec<String>,
    surface: SurfaceV1,
    limits: LimitsV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileV1 {
    language: String,
    language_digest: String,
    worker_policy: String,
    worker_policy_digest: String,
    broker: String,
    globals_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SurfaceV1 {
    envelope_digest: String,
    functions: Vec<SurfaceFunctionV1>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SurfaceFunctionV1 {
    id: String,
    kind: String,
    alias: Option<String>,
}

enum Command {
    Start {
        source: Vec<u8>,
        source_map: Vec<u8>,
        frame: Vec<u8>,
        result: SyncSender<i32>,
    },
    Frame(Vec<u8>),
    Interrupt,
    Destroy,
}
impl Command {
    fn frame_len(&self) -> usize {
        match self {
            Self::Start { frame, .. } | Self::Frame(frame) => frame.len(),
            Self::Interrupt | Self::Destroy => 0,
        }
    }
}
enum Event {
    Frame(Vec<u8>),
    Fault(u32),
    Closed,
}

struct State {
    started: bool,
    closed: bool,
    producer: Option<ThreadId>,
    consumer: Option<ThreadId>,
}

unsafe extern "C" {
    fn ibex_private_restricted_engine_create_v1(
        heap_bytes: u64,
        emit: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32,
        digest: unsafe extern "C" fn(*const u8, usize, *mut u8, usize) -> i32,
        context: *mut c_void,
    ) -> *mut c_void;
    fn ibex_private_restricted_engine_start_v1(
        engine: *mut c_void,
        source: *const u8,
        source_len: usize,
        start_frame: *const u8,
        start_frame_len: usize,
    ) -> i32;
    fn ibex_private_restricted_engine_submit_v1(
        engine: *mut c_void,
        frame: *const u8,
        frame_len: usize,
    ) -> i32;
    fn ibex_private_restricted_engine_interrupt_v1(engine: *mut c_void) -> i32;
    fn ibex_private_restricted_engine_destroy_v1(engine: *mut c_void);
}

#[no_mangle]
pub unsafe extern "C" fn ibex_private_external_script_transform_v1(
    path: *const u8,
    path_len: usize,
    source: *const u8,
    source_len: usize,
    output: *mut *mut u8,
    output_len: *mut usize,
) -> i32 {
    if !output.is_null() {
        unsafe { *output = ptr::null_mut() }
    }
    if !output_len.is_null() {
        unsafe { *output_len = 0 }
    }
    if output.is_null() || output_len.is_null() {
        return INVALID;
    }
    let path = match unsafe { borrowed(path, path_len, 1, MAX_SOURCE_PATH) }
        .and_then(|bytes| std::str::from_utf8(bytes).map_err(|_| IDENTITY))
    {
        Ok(value) => value,
        Err(status) => return status,
    };
    let source = match unsafe { borrowed(source, source_len, 0, MAX_SOURCE) }
        .and_then(|bytes| std::str::from_utf8(bytes).map_err(|_| IDENTITY))
    {
        Ok(value) => value,
        Err(status) => return status,
    };
    let transformed = match crate::module_loader::producer_spike::transform_external_script_v1(
        std::path::Path::new(path),
        source,
    ) {
        Ok(value) => value,
        Err(_) => return IDENTITY,
    };
    let callable_source = match String::from_utf8(transformed.callable_source) {
        Ok(value) => value,
        Err(_) => return ENGINE,
    };
    let composed_source_map = match String::from_utf8(transformed.composed_source_map) {
        Ok(value) => value,
        Err(_) => return ENGINE,
    };
    let wire = ExternalTransformWireV1 {
        schema: "ibex/external-script-transform/1",
        source_digest: digest(source.as_bytes()),
        transformed_source_digest: digest(callable_source.as_bytes()),
        source_map_digest: digest(composed_source_map.as_bytes()),
        callable_source,
        composed_source_map,
        has_default_export: transformed.has_default_export,
    };
    let bytes = match serde_json::to_vec(&wire) {
        Ok(value) => value,
        Err(_) => return ENGINE,
    };
    let allocation = unsafe { libc::malloc(bytes.len()) }.cast::<u8>();
    if allocation.is_null() {
        return ENGINE;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());
        *output = allocation;
        *output_len = bytes.len();
    }
    OK
}

#[no_mangle]
pub unsafe extern "C" fn ibex_private_external_script_transform_dispose_v1(bytes: *mut u8) {
    if !bytes.is_null() {
        unsafe { libc::free(bytes.cast()) }
    }
}

unsafe extern "C" fn digest_sha256(
    bytes: *const u8,
    len: usize,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if bytes.is_null() || output.is_null() || output_len != 32 {
        return -1;
    }
    let input = unsafe { std::slice::from_raw_parts(bytes, len) };
    let value = Sha256::digest(input);
    unsafe { ptr::copy_nonoverlapping(value.as_ptr(), output, value.len()) };
    0
}

#[repr(C)]
pub struct ExactRestrictedWorkerV1 {
    nonce: u64,
    coordinator: ThreadId,
    limits: LimitsV1,
    limits_bytes: Vec<u8>,
    arming: ArmingV1,
    commands: SyncSender<Command>,
    events: Mutex<Receiver<Event>>,
    state: Mutex<State>,
    owner: Mutex<Option<JoinHandle<()>>>,
    engine: Arc<AtomicPtr<c_void>>,
    command_bytes: Arc<AtomicUsize>,
    event_bytes: Arc<AtomicUsize>,
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}
fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256-")
        .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
        .is_some_and(|v| v.len() == 32)
}

fn strict_canonical<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, i32> {
    let text = std::str::from_utf8(bytes).map_err(|_| IDENTITY)?;
    let value = capsec_semantics::strict_json::parse_strict(text).map_err(|_| IDENTITY)?;
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&value).map_err(|_| IDENTITY)?;
    if canonical != bytes {
        return Err(IDENTITY);
    }
    serde_json::from_value(value).map_err(|_| IDENTITY)
}

fn valid_run_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

fn exact_body_keys(body: &serde_json::Value, expected: &[&str]) -> bool {
    let Some(object) = body.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn valid_parent_frame_body(frame_type: &str, body: &serde_json::Value) -> bool {
    let string = |key: &str| body.get(key).is_some_and(serde_json::Value::is_string);
    match frame_type {
        "callResult" => {
            let Some(ok) = body.get("ok").and_then(serde_json::Value::as_bool) else {
                return false;
            };
            string("callId")
                && if ok {
                    exact_body_keys(body, &["callId", "ok", "value"])
                } else {
                    exact_body_keys(body, &["callId", "error", "ok"])
                        && body.get("error").is_some_and(serde_json::Value::is_object)
                }
        }
        "liveOpened" => {
            let Some(ok) = body.get("ok").and_then(serde_json::Value::as_bool) else {
                return false;
            };
            string("subscriptionId")
                && if ok {
                    exact_body_keys(body, &["ok", "subscriptionId"])
                } else {
                    exact_body_keys(body, &["error", "ok", "subscriptionId"])
                        && body.get("error").is_some_and(serde_json::Value::is_object)
                }
        }
        "liveValue" => {
            string("subscriptionId") && exact_body_keys(body, &["subscriptionId", "value"])
        }
        "liveTerminal" => {
            string("subscriptionId")
                && body.get("error").is_some_and(serde_json::Value::is_object)
                && exact_body_keys(body, &["error", "subscriptionId"])
        }
        "liveClosed" => string("subscriptionId") && exact_body_keys(body, &["subscriptionId"]),
        "timerFired" => string("timerId") && exact_body_keys(body, &["timerId"]),
        "abort" => {
            let reason = body.get("reason").and_then(serde_json::Value::as_str);
            let signal = body.get("signal");
            let reason_ok = matches!(
                reason,
                Some(
                    "settled"
                        | "run-timeout"
                        | "resource-exceeded"
                        | "broker-failure"
                        | "script-failure"
                        | "parent-signal"
                        | "engine-fault"
                )
            );
            let signal_ok = if reason == Some("parent-signal") {
                signal
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|value| (1..=64).contains(&value))
            } else {
                signal.is_some_and(serde_json::Value::is_null)
            };
            reason_ok && signal_ok && exact_body_keys(body, &["reason", "signal"])
        }
        _ => false,
    }
}
fn live_nonces() -> &'static Mutex<BTreeSet<u64>> {
    static NONCES: OnceLock<Mutex<BTreeSet<u64>>> = OnceLock::new();
    NONCES.get_or_init(|| Mutex::new(BTreeSet::new()))
}
fn validate_arming(a: &ArmingV1, limits: &LimitsV1) -> Result<(), i32> {
    let digests = [
        &a.principal.app_binding_digest,
        &a.principal.source_digest,
        &a.transformed_source_digest,
        &a.source_map_digest,
        &a.engine_compatibility_digest,
        &a.language_profile_digest,
        &a.worker_policy_digest,
        &a.global_inventory_digest,
        &a.effective_limits_digest,
    ];
    if a.schema != RESTRICTED_WORKER_ARMING_SCHEMA_V1
        || a.principal.kind != "external-script"
        || !valid_run_id(&a.principal.run_id)
        || !digests.iter().all(|v| valid_digest(v))
        || a.broker_protocol != RESTRICTED_WORKER_BROKER_V1
        || a.dynamic_code != "disabled"
        || a.module_registry != "empty"
        || a.capabilities != ["broker:snapback-app-cli:1"]
        || limits.digest().map_err(|_| IDENTITY)? != a.effective_limits_digest
    {
        return Err(IDENTITY);
    }
    Ok(())
}

struct EmitContext {
    sender: SyncSender<Event>,
    run_id: String,
    next_sequence: Mutex<u64>,
    frame_bytes: usize,
    queued_bytes: Arc<AtomicUsize>,
}

fn reserve_bytes(counter: &AtomicUsize, amount: usize, maximum: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(amount) else {
            return false;
        };
        if next > maximum {
            return false;
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}
unsafe extern "C" fn emit_frame(context: *mut c_void, bytes: *const u8, len: usize) -> i32 {
    if context.is_null() || bytes.is_null() || len == 0 {
        return -1;
    }
    let context = unsafe { &*(context as *const EmitContext) };
    if len > context.frame_bytes {
        return -1;
    }
    let frame = unsafe { std::slice::from_raw_parts(bytes, len) };
    let parsed: FrameV1 = match strict_canonical(frame) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let mut next = match context.next_sequence.try_lock() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let known = matches!(
        parsed.frame_type.as_str(),
        "call"
            | "liveOpen"
            | "liveClose"
            | "timerSet"
            | "timerClear"
            | "console"
            | "settlementBegin"
            | "settlementChunk"
            | "settlementEnd"
            | "failed"
    );
    if parsed.schema != RESTRICTED_WORKER_BROKER_V1
        || parsed.run_id != context.run_id
        || parsed.sequence != *next
        || !known
    {
        return -1;
    }
    *next = match next.checked_add(1) {
        Some(v) => v,
        None => return -1,
    };
    if !reserve_bytes(
        &context.queued_bytes,
        len,
        context.frame_bytes.saturating_mul(2),
    ) {
        return -1;
    }
    match context.sender.try_send(Event::Frame(frame.to_vec())) {
        Ok(()) => 0,
        Err(_) => {
            context.queued_bytes.fetch_sub(len, Ordering::AcqRel);
            -1
        }
    }
}

fn owner_loop(
    commands: Receiver<Command>,
    events: SyncSender<Event>,
    arming: ArmingV1,
    limits: LimitsV1,
    engine_slot: Arc<AtomicPtr<c_void>>,
    ready: SyncSender<bool>,
    command_bytes: Arc<AtomicUsize>,
    event_bytes: Arc<AtomicUsize>,
) {
    let limits_bytes = capsec_semantics::canonical::to_jcs_bytes(
        &serde_json::to_value(&limits).expect("limits serialize"),
    )
    .expect("limits canonicalize");
    let emit_context = EmitContext {
        sender: events.clone(),
        run_id: arming.principal.run_id.clone(),
        next_sequence: Mutex::new(1),
        frame_bytes: limits.frame_bytes as usize,
        queued_bytes: event_bytes,
    };
    let engine = unsafe {
        ibex_private_restricted_engine_create_v1(
            limits.heap_bytes,
            emit_frame,
            digest_sha256,
            (&emit_context as *const EmitContext).cast_mut().cast(),
        )
    };
    if engine.is_null() {
        let _ = ready.send(false);
        return;
    }
    engine_slot.store(engine, Ordering::Release);
    let _ = ready.send(true);
    let mut started = false;
    let mut expected_parent_sequence = 1u64;
    let mut closed = false;
    while let Ok(command) = commands.recv() {
        command_bytes.fetch_sub(command.frame_len(), Ordering::AcqRel);
        match command {
            Command::Start {
                source,
                source_map,
                frame,
                result,
            } => {
                if started
                    || closed
                    || digest(&source) != arming.transformed_source_digest
                    || digest(&source_map) != arming.source_map_digest
                {
                    closed = true;
                    let _ = result.send(IDENTITY);
                    continue;
                }
                let parsed: FrameV1 = match strict_canonical(&frame) {
                    Ok(v) => v,
                    Err(_) => {
                        closed = true;
                        let _ = result.send(IDENTITY);
                        continue;
                    }
                };
                let limits_canonical = parsed
                    .body
                    .get("limits")
                    .and_then(|value| capsec_semantics::canonical::to_jcs_bytes(value).ok());
                let body: StartBodyV1 = match serde_json::from_value(parsed.body) {
                    Ok(v) => v,
                    Err(_) => {
                        closed = true;
                        let _ = result.send(IDENTITY);
                        continue;
                    }
                };
                let profile_ok = body.profile.language == "ibex/restricted-worker-language/1"
                    && body.profile.language_digest == arming.language_profile_digest
                    && body.profile.worker_policy == "ibex/restricted-worker-policy/1"
                    && body.profile.worker_policy_digest == arming.worker_policy_digest
                    && body.profile.broker == arming.broker_protocol
                    && body.profile.globals_digest == arming.global_inventory_digest;
                let surface_ok = valid_digest(&body.surface.envelope_digest)
                    && body
                        .surface
                        .functions
                        .windows(2)
                        .all(|rows| rows[0].id < rows[1].id)
                    && body.surface.functions.iter().all(|row| {
                        !row.id.is_empty()
                            && matches!(
                                row.kind.as_str(),
                                "query" | "mutation" | "action" | "live-query"
                            )
                            && row.alias.as_ref().is_none_or(|alias| {
                                !alias.is_empty()
                                    && alias.bytes().enumerate().all(|(index, byte)| {
                                        byte == b'_'
                                            || byte == b'$'
                                            || byte.is_ascii_alphabetic()
                                            || (index > 0 && byte.is_ascii_digit())
                                    })
                            })
                    });
                let args_ok = body.args.iter().all(|v| v.len() <= 64 * 1024);
                if parsed.schema != RESTRICTED_WORKER_BROKER_V1
                    || parsed.run_id != arming.principal.run_id
                    || parsed.sequence != 1
                    || parsed.frame_type != "start"
                    || body.source_digest != arming.principal.source_digest
                    || body.transformed_source_digest != arming.transformed_source_digest
                    || body.source_map_digest != arming.source_map_digest
                    || body.limits != limits
                    || limits_canonical.as_deref() != Some(limits_bytes.as_slice())
                    || !profile_ok
                    || !surface_ok
                    || !args_ok
                {
                    closed = true;
                    let _ = result.send(IDENTITY);
                    continue;
                }
                let engine_status = unsafe {
                    ibex_private_restricted_engine_start_v1(
                        engine,
                        source.as_ptr(),
                        source.len(),
                        frame.as_ptr(),
                        frame.len(),
                    )
                };
                if engine_status != 0 {
                    closed = true;
                    let _ = result.send(ENGINE);
                    continue;
                }
                started = true;
                expected_parent_sequence = 2;
                let _ = result.send(OK);
            }
            Command::Frame(frame) => {
                if !started || closed {
                    continue;
                }
                let parsed: FrameV1 = match strict_canonical(&frame) {
                    Ok(v) => v,
                    Err(_) => {
                        let _ = events.try_send(Event::Fault(4));
                        closed = true;
                        continue;
                    }
                };
                if parsed.schema != RESTRICTED_WORKER_BROKER_V1
                    || parsed.run_id != arming.principal.run_id
                    || parsed.sequence != expected_parent_sequence
                    || !valid_parent_frame_body(&parsed.frame_type, &parsed.body)
                {
                    let _ = events.try_send(Event::Fault(4));
                    closed = true
                } else {
                    expected_parent_sequence = match expected_parent_sequence.checked_add(1) {
                        Some(v) => v,
                        None => {
                            let _ = events.try_send(Event::Fault(4));
                            closed = true;
                            continue;
                        }
                    };
                    let _ = &parsed.frame_type;
                    if unsafe {
                        ibex_private_restricted_engine_submit_v1(
                            engine,
                            frame.as_ptr(),
                            frame.len(),
                        )
                    } != 0
                    {
                        let _ = events.try_send(Event::Fault(2));
                        closed = true;
                    }
                }
            }
            Command::Interrupt => {
                if started && !closed {
                    closed = true;
                    let _ = events.send(Event::Closed);
                }
            }
            Command::Destroy => {
                if started && !closed {
                    let _ = events.send(Event::Closed);
                }
                break;
            }
        }
    }
    engine_slot.store(ptr::null_mut(), Ordering::Release);
    unsafe { ibex_private_restricted_engine_destroy_v1(engine) }
}

unsafe fn borrowed<'a>(
    ptr: *const u8,
    len: usize,
    min: usize,
    max: usize,
) -> Result<&'a [u8], i32> {
    if ptr.is_null() || len < min {
        return Err(INVALID);
    }
    if len > max {
        return Err(CEILING);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}
unsafe fn worker<'a>(
    ptr: *mut ExactRestrictedWorkerV1,
) -> Result<&'a ExactRestrictedWorkerV1, i32> {
    if ptr.is_null() {
        Err(INVALID)
    } else {
        Ok(unsafe { &*ptr })
    }
}

#[no_mangle]
pub unsafe extern "C" fn ex_restricted_worker_create_v1(
    options: *const ExRestrictedWorkerOptionsV1,
    out_worker: *mut *mut ExactRestrictedWorkerV1,
    out_runtime_nonce: *mut u64,
) -> i32 {
    if !out_worker.is_null() {
        unsafe { *out_worker = ptr::null_mut() }
    }
    if !out_runtime_nonce.is_null() {
        unsafe { *out_runtime_nonce = 0 }
    }
    if options.is_null() || out_worker.is_null() || out_runtime_nonce.is_null() {
        return INVALID;
    }
    if !cfg!(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64")
    )) {
        return UNSUPPORTED;
    }
    let o = unsafe { &*options };
    if o.abi_version != ABI_VERSION
        || o.struct_size as usize != std::mem::size_of::<ExRestrictedWorkerOptionsV1>()
    {
        return ABI_MISMATCH;
    }
    let arming_bytes = match unsafe { borrowed(o.arming_json, o.arming_json_len, 1, MAX_ARMING) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let limits_bytes = match unsafe { borrowed(o.limits_json, o.limits_json_len, 1, MAX_LIMITS) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let arming: ArmingV1 = match strict_canonical(arming_bytes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let limits: LimitsV1 = match strict_canonical(limits_bytes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if limits.validate_effective().is_err() {
        return IDENTITY;
    }
    if let Err(e) = validate_arming(&arming, &limits) {
        return e;
    }
    let nonce = loop {
        let mut random = [0u8; 8];
        if getrandom::getrandom(&mut random).is_err() {
            return ENGINE;
        }
        let candidate = u64::from_le_bytes(random);
        if candidate == 0 {
            continue;
        }
        let mut live = match live_nonces().lock() {
            Ok(v) => v,
            Err(_) => return ENGINE,
        };
        if live.insert(candidate) {
            break candidate;
        }
    };
    let (command_tx, command_rx) = mpsc::sync_channel(8);
    let (event_tx, event_rx) = mpsc::sync_channel(8);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let engine = Arc::new(AtomicPtr::new(ptr::null_mut()));
    let command_bytes = Arc::new(AtomicUsize::new(0));
    let event_bytes = Arc::new(AtomicUsize::new(0));
    let owner_engine = engine.clone();
    let owner_command_bytes = command_bytes.clone();
    let owner_event_bytes = event_bytes.clone();
    let thread_arming = match strict_canonical(arming_bytes) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let thread_limits = limits.clone();
    let owner = match thread::Builder::new()
        .name("ibex-restricted-worker".into())
        .spawn(move || {
            owner_loop(
                command_rx,
                event_tx,
                thread_arming,
                thread_limits,
                owner_engine,
                ready_tx,
                owner_command_bytes,
                owner_event_bytes,
            )
        }) {
        Ok(v) => v,
        Err(_) => {
            if let Ok(mut live) = live_nonces().lock() {
                live.remove(&nonce);
            }
            return ENGINE;
        }
    };
    if ready_rx.recv() != Ok(true) {
        let _ = owner.join();
        if let Ok(mut live) = live_nonces().lock() {
            live.remove(&nonce);
        }
        return ENGINE;
    }
    let boxed = Box::new(ExactRestrictedWorkerV1 {
        nonce,
        coordinator: thread::current().id(),
        limits,
        limits_bytes: limits_bytes.to_vec(),
        arming,
        commands: command_tx,
        events: Mutex::new(event_rx),
        state: Mutex::new(State {
            started: false,
            closed: false,
            producer: None,
            consumer: None,
        }),
        owner: Mutex::new(Some(owner)),
        engine,
        command_bytes,
        event_bytes,
    });
    unsafe {
        *out_runtime_nonce = nonce;
        *out_worker = Box::into_raw(boxed)
    }
    OK
}

#[no_mangle]
pub unsafe extern "C" fn ex_restricted_worker_start_v1(
    ptr: *mut ExactRestrictedWorkerV1,
    source: *const u8,
    source_len: usize,
    map: *const u8,
    map_len: usize,
    frame: *const u8,
    frame_len: usize,
) -> i32 {
    let w = match unsafe { worker(ptr) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    if thread::current().id() != w.coordinator {
        return LIFECYCLE;
    }
    let source = match unsafe { borrowed(source, source_len, 1, MAX_SOURCE) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let map_bytes = if map_len == 0 {
        if !map.is_null() {
            return INVALID;
        }
        &[][..]
    } else {
        match unsafe { borrowed(map, map_len, 1, MAX_SOURCE_MAP) } {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    let frame = match unsafe { borrowed(frame, frame_len, 1, w.limits.frame_bytes as usize) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut s = match w.state.try_lock() {
        Ok(v) => v,
        Err(_) => return LIFECYCLE,
    };
    if s.started || s.closed {
        return LIFECYCLE;
    }
    if digest(source) != w.arming.transformed_source_digest
        || digest(map_bytes) != w.arming.source_map_digest
    {
        s.closed = true;
        return IDENTITY;
    }
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    if !reserve_bytes(
        &w.command_bytes,
        frame.len(),
        (w.limits.frame_bytes as usize).saturating_mul(2),
    ) {
        return QUEUE;
    }
    match w.commands.try_send(Command::Start {
        source: source.to_vec(),
        source_map: map_bytes.to_vec(),
        frame: frame.to_vec(),
        result: result_tx,
    }) {
        Ok(()) => match result_rx.recv() {
            Ok(OK) => {
                s.started = true;
                OK
            }
            Ok(status) => {
                s.closed = true;
                status
            }
            Err(_) => {
                s.closed = true;
                ENGINE
            }
        },
        Err(TrySendError::Full(_)) => {
            w.command_bytes.fetch_sub(frame.len(), Ordering::AcqRel);
            QUEUE
        }
        Err(TrySendError::Disconnected(_)) => {
            w.command_bytes.fetch_sub(frame.len(), Ordering::AcqRel);
            s.closed = true;
            ENGINE
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ex_restricted_worker_submit_frame_v1(
    ptr: *mut ExactRestrictedWorkerV1,
    frame: *const u8,
    len: usize,
) -> i32 {
    let w = match unsafe { worker(ptr) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let frame = match unsafe { borrowed(frame, len, 1, w.limits.frame_bytes as usize) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut s = match w.state.try_lock() {
        Ok(v) => v,
        Err(_) => return LIFECYCLE,
    };
    let id = thread::current().id();
    if !s.started || s.closed || s.producer.is_some_and(|v| v != id) {
        return LIFECYCLE;
    }
    s.producer = Some(id);
    if !reserve_bytes(
        &w.command_bytes,
        frame.len(),
        (w.limits.frame_bytes as usize).saturating_mul(2),
    ) {
        return QUEUE;
    }
    match w.commands.try_send(Command::Frame(frame.to_vec())) {
        Ok(()) => OK,
        Err(TrySendError::Full(_)) => {
            w.command_bytes.fetch_sub(frame.len(), Ordering::AcqRel);
            QUEUE
        }
        Err(TrySendError::Disconnected(_)) => {
            w.command_bytes.fetch_sub(frame.len(), Ordering::AcqRel);
            ENGINE
        }
    }
}

fn zero_event(event: &mut ExRestrictedWorkerEventV1) {
    *event = ExRestrictedWorkerEventV1 {
        abi_version: 0,
        struct_size: 0,
        tag: 0,
        fault: 0,
        runtime_nonce: 0,
        bytes: ptr::null_mut(),
        bytes_len: 0,
    }
}
#[no_mangle]
pub unsafe extern "C" fn ex_restricted_worker_take_event_v1(
    ptr: *mut ExactRestrictedWorkerV1,
    wait_ms: u32,
    out: *mut ExRestrictedWorkerEventV1,
) -> i32 {
    if out.is_null() {
        return INVALID;
    }
    zero_event(unsafe { &mut *out });
    if wait_ms > 300_000 {
        return INVALID;
    }
    let w = match unsafe { worker(ptr) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut s = match w.state.try_lock() {
        Ok(v) => v,
        Err(_) => return LIFECYCLE,
    };
    let id = thread::current().id();
    if s.consumer.is_some_and(|v| v != id) {
        return LIFECYCLE;
    }
    s.consumer = Some(id);
    drop(s);
    let rx = match w.events.try_lock() {
        Ok(v) => v,
        Err(_) => return LIFECYCLE,
    };
    let received = if wait_ms == 0 {
        rx.try_recv().map_err(|e| match e {
            mpsc::TryRecvError::Empty => EMPTY,
            mpsc::TryRecvError::Disconnected => ENGINE,
        })
    } else {
        rx.recv_timeout(Duration::from_millis(wait_ms as u64))
            .map_err(|e| match e {
                RecvTimeoutError::Timeout => EMPTY,
                RecvTimeoutError::Disconnected => ENGINE,
            })
    };
    let event = match received {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Event::Frame(bytes) = &event {
        w.event_bytes.fetch_sub(bytes.len(), Ordering::AcqRel);
    }
    let o = unsafe { &mut *out };
    o.abi_version = ABI_VERSION;
    o.struct_size = std::mem::size_of::<ExRestrictedWorkerEventV1>() as u32;
    o.runtime_nonce = w.nonce;
    match event {
        Event::Frame(bytes) => {
            let p = unsafe { libc::malloc(bytes.len()) as *mut u8 };
            if p.is_null() {
                zero_event(o);
                return ENGINE;
            }
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
            o.tag = 1;
            o.bytes = p;
            o.bytes_len = bytes.len();
        }
        Event::Fault(f) => {
            o.tag = if f == 1 { 2 } else { 3 };
            o.fault = f;
        }
        Event::Closed => {
            o.tag = 4;
            if let Ok(mut state) = w.state.lock() {
                state.closed = true;
            }
        }
    }
    OK
}

#[no_mangle]
pub unsafe extern "C" fn ex_restricted_worker_interrupt_v1(
    ptr: *mut ExactRestrictedWorkerV1,
    nonce: u64,
) -> i32 {
    let w = match unsafe { worker(ptr) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    if nonce == 0 || nonce != w.nonce {
        return STALE;
    }
    let engine = w.engine.load(Ordering::Acquire);
    if engine.is_null() {
        return STALE;
    }
    if unsafe { ibex_private_restricted_engine_interrupt_v1(engine) } != 0 {
        return ENGINE;
    }
    match w.commands.try_send(Command::Interrupt) {
        Ok(()) => OK,
        Err(TrySendError::Full(_)) => QUEUE,
        Err(TrySendError::Disconnected(_)) => ENGINE,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ex_restricted_worker_destroy_v1(
    ptr: *mut ExactRestrictedWorkerV1,
    nonce: u64,
) -> i32 {
    let w = match unsafe { worker(ptr) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    if thread::current().id() != w.coordinator {
        return LIFECYCLE;
    }
    if nonce == 0 || nonce != w.nonce {
        return STALE;
    }
    let _ = w.commands.send(Command::Destroy);
    let cleanup = if let Ok(mut owner) = w.owner.lock() {
        if let Some(join) = owner.take() {
            if join.join().is_err() {
                ENGINE
            } else {
                OK
            }
        } else {
            OK
        }
    } else {
        ENGINE
    };
    if let Ok(mut live) = live_nonces().lock() {
        live.remove(&nonce);
    }
    unsafe { drop(Box::from_raw(ptr)) };
    cleanup
}

#[no_mangle]
pub unsafe extern "C" fn ex_restricted_worker_event_dispose_v1(
    event: *mut ExRestrictedWorkerEventV1,
) {
    if event.is_null() {
        return;
    }
    let e = unsafe { &mut *event };
    if !e.bytes.is_null() {
        unsafe { libc::free(e.bytes.cast::<c_void>()) }
    }
    zero_event(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn canonical(value: serde_json::Value) -> Vec<u8> {
        capsec_semantics::canonical::to_jcs_bytes(&value).unwrap()
    }
    #[test]
    fn c_layout_matches_header_contract() {
        assert_eq!(std::mem::size_of::<ExRestrictedWorkerOptionsV1>(), 40);
        assert_eq!(std::mem::size_of::<ExRestrictedWorkerEventV1>(), 40);
    }
    #[test]
    fn run_id_is_lower_hex_only() {
        assert!(valid_run_id("00000000000000000000000000000000"));
        assert!(!valid_run_id("0000000000000000000000000000000A"));
    }
    #[test]
    fn native_broker_round_trip_uses_only_the_opaque_worker() {
        let run_id = "00000000000000000000000000000001";
        let emitted=format!("{{\"body\":{{\"byteLength\":0,\"chunkCount\":0,\"digest\":\"\",\"hasValue\":false}},\"runId\":\"{run_id}\",\"schema\":\"ibex/restricted-worker-broker/1\",\"sequence\":1,\"type\":\"settlementBegin\"}}");
        let source = b"(async function(api,snapback,args,signal,console,setTimeout,clearTimeout){return {present:false};})".to_vec();
        let limits = LimitsV1::defaults();
        let limits_bytes = canonical(serde_json::to_value(&limits).unwrap());
        let raw_digest = digest(b"export default 1");
        let source_digest = digest(&source);
        let map_digest = digest(&[]);
        let arming = canonical(
            serde_json::json!({"schema":RESTRICTED_WORKER_ARMING_SCHEMA_V1,"principal":{"kind":"external-script","appBindingDigest":digest(b"binding"),"sourceDigest":raw_digest,"runId":run_id},"transformedSourceDigest":source_digest,"sourceMapDigest":map_digest,"engineCompatibilityDigest":digest(b"engine"),"languageProfileDigest":digest(b"language"),"workerPolicyDigest":digest(b"policy"),"brokerProtocol":RESTRICTED_WORKER_BROKER_V1,"globalInventoryDigest":digest(b"globals"),"effectiveLimitsDigest":limits.digest().unwrap(),"dynamicCode":"disabled","moduleRegistry":"empty","capabilities":["broker:snapback-app-cli:1"]}),
        );
        let start = canonical(
            serde_json::json!({"schema":RESTRICTED_WORKER_BROKER_V1,"runId":run_id,"sequence":1,"type":"start","body":{"profile":{"language":"ibex/restricted-worker-language/1","languageDigest":digest(b"language"),"workerPolicy":"ibex/restricted-worker-policy/1","workerPolicyDigest":digest(b"policy"),"broker":RESTRICTED_WORKER_BROKER_V1,"globalsDigest":digest(b"globals")},"sourceDigest":raw_digest,"transformedSourceDigest":source_digest,"sourceMapDigest":map_digest,"args":[],"surface":{"envelopeDigest":digest(b"envelope"),"functions":[]},"limits":limits}}),
        );
        let options = ExRestrictedWorkerOptionsV1 {
            abi_version: 1,
            struct_size: std::mem::size_of::<ExRestrictedWorkerOptionsV1>() as u32,
            arming_json: arming.as_ptr(),
            arming_json_len: arming.len(),
            limits_json: limits_bytes.as_ptr(),
            limits_json_len: limits_bytes.len(),
        };
        let mut worker = ptr::null_mut();
        let mut nonce = 0;
        assert_eq!(
            unsafe { ex_restricted_worker_create_v1(&options, &mut worker, &mut nonce) },
            0
        );
        assert!(!worker.is_null());
        assert_ne!(nonce, 0);
        assert_eq!(
            unsafe {
                ex_restricted_worker_start_v1(
                    worker,
                    source.as_ptr(),
                    source.len(),
                    ptr::null(),
                    0,
                    start.as_ptr(),
                    start.len(),
                )
            },
            0
        );
        let mut event = ExRestrictedWorkerEventV1 {
            abi_version: 0,
            struct_size: 0,
            tag: 0,
            fault: 0,
            runtime_nonce: 0,
            bytes: ptr::null_mut(),
            bytes_len: 0,
        };
        assert_eq!(
            unsafe { ex_restricted_worker_take_event_v1(worker, 5_000, &mut event) },
            0
        );
        assert_eq!(event.tag, 1);
        assert_eq!(event.runtime_nonce, nonce);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(event.bytes, event.bytes_len) },
            emitted.as_bytes()
        );
        unsafe { ex_restricted_worker_event_dispose_v1(&mut event) };
        assert_eq!(
            unsafe { ex_restricted_worker_take_event_v1(worker, 5_000, &mut event) },
            0
        );
        assert_eq!(event.tag, 1);
        assert!(
            unsafe { std::slice::from_raw_parts(event.bytes, event.bytes_len) }
                .windows(b"\"type\":\"settlementEnd\"".len())
                .any(|bytes| bytes == b"\"type\":\"settlementEnd\"")
        );
        unsafe { ex_restricted_worker_event_dispose_v1(&mut event) };
        assert_eq!(
            unsafe { ex_restricted_worker_interrupt_v1(worker, nonce) },
            0
        );
        assert_eq!(
            unsafe { ex_restricted_worker_take_event_v1(worker, 5_000, &mut event) },
            0
        );
        assert_eq!(event.tag, 4);
        unsafe { ex_restricted_worker_event_dispose_v1(&mut event) };
        assert_eq!(unsafe { ex_restricted_worker_destroy_v1(worker, nonce) }, 0);
    }
}
