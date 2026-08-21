//! LLP 0514 M1 WP6: self-service production C++/Hermes seam reproduction.
//!
//! This macOS-only integration test builds the generated seam fixture with the
//! same Vite/authored-map Hermes path as the XCTest gate, then creates, calls,
//! releases, shuts down, and destroys the restricted realm on one dedicated
//! owner thread. It deliberately bypasses Swift so a C++ create regression is
//! reproducible with Cargo alone.

#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

const ABI_VERSION: u32 = 1;
const GENERATION: u64 = 73;
const STATUS_OK: i32 = 0;
const CREATE_DIAGNOSTIC_NONE: u32 = 0;
const APPEARANCE_DARK: u32 = 2;
const DIAGNOSTIC_CAPACITY: usize = 1024;
const BINDING_KIND_HOST_IMPORT: u32 = 1;
const BINDING_KIND_CAPABILITY: u32 = 2;
const OUTCOME_OK: u8 = 0;
const OUTCOME_REFUSED: u8 = 1;
const OUTCOME_THREW: u8 = 2;
const OUTCOME_PROVIDER_FAULT: u8 = 3;
const DIAGNOSTIC_TS_THROW: u16 = 15;
const DIAGNOSTIC_PROVIDER_FAULT: u16 = 16;
const DIAGNOSTIC_CAPABILITY_DENIED: u16 = 17;
const DIAGNOSTIC_CAPABILITY_OUTCOME_UNKNOWN: u16 = 18;
const EFFECT_NONE: u8 = 0;
const EFFECT_NOT_STARTED: u8 = 1;
const EFFECT_COMMITTED: u8 = 2;
const EFFECT_OUTCOME_UNKNOWN: u8 = 3;
const HOST_VALUE_BOOL_TRUE: u8 = 3;
const HOST_VALUE_OBJECT: u8 = 7;

#[repr(C)]
struct FacetHostInputsV1 {
    abi_version: u32,
    struct_size: u32,
    system_appearance: u32,
    reduced_motion: u8,
    native_control_presentation: u8,
    reserved: u16,
    viewport_width: f64,
}

type InvalidationCallback = unsafe extern "C" fn(*mut c_void, u64, u32, u64) -> i32;

#[repr(C)]
struct PlanSeamOptionsV1 {
    abi_version: u32,
    struct_size: u32,
    generation: u64,
    executor_identity: u64,
    heap_bytes: u64,
    hbc_bytes: *const u8,
    hbc_len: usize,
    expected_registry_receipt: *const u8,
    expected_registry_receipt_len: usize,
    facet_host_inputs: FacetHostInputsV1,
    invalidation_callback: Option<InvalidationCallback>,
    invalidation_context: *mut c_void,
}

#[repr(C)]
struct CreateDiagnosticV1 {
    abi_version: u32,
    struct_size: u32,
    transport_status: i32,
    code: u32,
    message_len: u32,
    reserved: u32,
    message: [u8; DIAGNOSTIC_CAPACITY],
}

impl Default for CreateDiagnosticV1 {
    fn default() -> Self {
        Self {
            abi_version: 0,
            struct_size: 0,
            transport_status: 0,
            code: 0,
            message_len: 0,
            reserved: 0,
            message: [0; DIAGNOSTIC_CAPACITY],
        }
    }
}

extern "C" {
    fn ex_hermes_plan_seam_create_v1(
        options: *const PlanSeamOptionsV1,
        out_runtime: *mut *mut c_void,
        out_diagnostic: *mut CreateDiagnosticV1,
    ) -> i32;
    fn ex_hermes_plan_seam_call_v1(
        runtime: *mut c_void,
        binding_kind: u32,
        binding_ref: u32,
        call_id: u64,
        arguments: *const u8,
        arguments_len: usize,
        out_outcome_discriminant: *mut u8,
        out_payload: *mut *const u8,
        out_payload_len: *mut usize,
        out_reactive_version: *mut u64,
        out_lease_generation: *mut u64,
        out_lease_token: *mut u64,
    ) -> i32;
    fn ex_hermes_plan_seam_read_reactive_v1(
        runtime: *mut c_void,
        host_import_ref: u32,
        out_outcome_discriminant: *mut u8,
        out_payload: *mut *const u8,
        out_payload_len: *mut usize,
        out_reactive_version: *mut u64,
        out_lease_generation: *mut u64,
        out_lease_token: *mut u64,
    ) -> i32;
    fn ex_hermes_plan_seam_release_result_v1(
        runtime: *mut c_void,
        lease_generation: u64,
        lease_token: u64,
        payload: *const u8,
        payload_len: usize,
    ) -> i32;
    fn ex_hermes_plan_seam_shutdown_v1(runtime: *mut c_void) -> i32;
    fn ex_hermes_plan_seam_destroy_v1(runtime: *mut c_void) -> i32;
}

fn ensure_runtime_linked() {
    let _ = std::hint::black_box(ibex_runtime::runtime_cache_dir as *const () as usize);
    let _ =
        std::hint::black_box(ibex_runtime::engine::ex_hermes_notify_callback as extern "C" fn());
}

fn exact_repo_root() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest.parent()?.parent()?.to_path_buf();
    candidate
        .join("packages/exact-contract/scripts/generate-plan-hermes-seam-fixture.mjs")
        .is_file()
        .then_some(candidate)
}

fn run(root: &Path, program: &str, arguments: &[&str]) -> Output {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("failed to run {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {} failed with {}\nstdout:\n{}\nstderr:\n{}",
        arguments.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn diagnostic_text(diagnostic: &CreateDiagnosticV1) -> String {
    let length = usize::try_from(diagnostic.message_len)
        .unwrap_or(DIAGNOSTIC_CAPACITY)
        .min(DIAGNOSTIC_CAPACITY);
    String::from_utf8_lossy(&diagnostic.message[..length]).into_owned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InvalidationRecord {
    generation: u64,
    host_import_ref: u32,
    hinted_version: u64,
    recorded_on_provider_stack: bool,
}

#[derive(Default)]
struct InvalidationState {
    provider_call_active: AtomicBool,
    records: Mutex<Vec<InvalidationRecord>>,
    publication_count: AtomicUsize,
}

#[derive(Debug, Eq, PartialEq)]
struct PlanHostDiagnostic {
    code: u16,
    effect_disposition: u8,
    message: String,
    stack: String,
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let end = cursor
        .checked_add(4)
        .ok_or_else(|| "diagnostic cursor overflow".to_string())?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| "diagnostic is truncated".to_string())?;
    *cursor = end;
    Ok(u32::from_le_bytes(
        value.try_into().expect("four-byte slice"),
    ))
}

fn read_utf8(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
    let length = usize::try_from(read_u32(bytes, cursor)?)
        .map_err(|_| "diagnostic string length does not fit usize".to_string())?;
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| "diagnostic string cursor overflow".to_string())?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| "diagnostic string is truncated".to_string())?;
    *cursor = end;
    String::from_utf8(value.to_vec()).map_err(|error| format!("diagnostic is not UTF-8: {error}"))
}

fn decode_plan_host_diagnostic(bytes: &[u8]) -> Result<PlanHostDiagnostic, String> {
    let header = bytes
        .get(..4)
        .ok_or_else(|| "diagnostic header is truncated".to_string())?;
    if header[3] != 0 {
        return Err("diagnostic reserved byte is nonzero".to_string());
    }
    let mut cursor = 4;
    let message = read_utf8(bytes, &mut cursor)?;
    let stack = read_utf8(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err("diagnostic has trailing bytes".to_string());
    }
    Ok(PlanHostDiagnostic {
        code: u16::from_le_bytes([header[0], header[1]]),
        effect_disposition: header[2],
        message,
        stack,
    })
}

fn diagnostic_summary(outcome: u8, payload: &[u8]) -> String {
    if outcome == OUTCOME_OK {
        return "success".to_string();
    }
    match decode_plan_host_diagnostic(payload) {
        Ok(diagnostic) => format!(
            "outcome={outcome}, code={}, effect={}, message={:?}, stack={:?}",
            diagnostic.code, diagnostic.effect_disposition, diagnostic.message, diagnostic.stack,
        ),
        Err(error) => format!("outcome={outcome}, malformed diagnostic: {error}"),
    }
}

struct NativeReply {
    outcome: u8,
    payload: *const u8,
    payload_len: usize,
    bytes: Vec<u8>,
    reactive_version: u64,
    lease_generation: u64,
    lease_token: u64,
}

impl NativeReply {
    fn summary(&self) -> String {
        diagnostic_summary(self.outcome, &self.bytes)
    }
}

unsafe fn call_reply(
    runtime: *mut c_void,
    binding_kind: u32,
    binding_ref: u32,
    call_id: u64,
    arguments: &[u8],
) -> (i32, NativeReply) {
    let mut outcome = 0u8;
    let mut payload = ptr::null();
    let mut payload_len = 0usize;
    let mut reactive_version = 0u64;
    let mut lease_generation = 0u64;
    let mut lease_token = 0u64;
    let status = ex_hermes_plan_seam_call_v1(
        runtime,
        binding_kind,
        binding_ref,
        call_id,
        arguments.as_ptr(),
        arguments.len(),
        &mut outcome,
        &mut payload,
        &mut payload_len,
        &mut reactive_version,
        &mut lease_generation,
        &mut lease_token,
    );
    let bytes = if payload.is_null() || payload_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(payload, payload_len).to_vec()
    };
    (
        status,
        NativeReply {
            outcome,
            payload,
            payload_len,
            bytes,
            reactive_version,
            lease_generation,
            lease_token,
        },
    )
}

unsafe fn read_reactive_reply(runtime: *mut c_void, host_import_ref: u32) -> (i32, NativeReply) {
    let mut outcome = 0u8;
    let mut payload = ptr::null();
    let mut payload_len = 0usize;
    let mut reactive_version = 0u64;
    let mut lease_generation = 0u64;
    let mut lease_token = 0u64;
    let status = ex_hermes_plan_seam_read_reactive_v1(
        runtime,
        host_import_ref,
        &mut outcome,
        &mut payload,
        &mut payload_len,
        &mut reactive_version,
        &mut lease_generation,
        &mut lease_token,
    );
    let bytes = if payload.is_null() || payload_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(payload, payload_len).to_vec()
    };
    (
        status,
        NativeReply {
            outcome,
            payload,
            payload_len,
            bytes,
            reactive_version,
            lease_generation,
            lease_token,
        },
    )
}

unsafe fn release_reply(runtime: *mut c_void, reply: &NativeReply) {
    assert_ne!(reply.lease_token, 0, "reply has no provider lease");
    assert_eq!(
        ex_hermes_plan_seam_release_result_v1(
            runtime,
            reply.lease_generation,
            reply.lease_token,
            reply.payload,
            reply.payload_len,
        ),
        STATUS_OK,
        "failed to release provider reply: {}",
        reply.summary(),
    );
}

unsafe extern "C" fn accept_invalidation(
    context: *mut c_void,
    generation: u64,
    host_import_ref: u32,
    hinted_version: u64,
) -> i32 {
    if context.is_null() {
        return -1;
    }
    let state = &*(context as *const InvalidationState);
    let record = InvalidationRecord {
        generation,
        host_import_ref,
        hinted_version,
        recorded_on_provider_stack: state.provider_call_active.load(Ordering::SeqCst),
    };
    match state.records.lock() {
        Ok(mut records) => {
            records.push(record);
            0
        }
        Err(_) => -1,
    }
}

#[test]
fn real_generated_hbc_creates_and_round_trips_on_its_owner_thread() {
    ensure_runtime_linked();
    let Some(root) = exact_repo_root() else {
        eprintln!("skipping Exact-only plan seam fixture outside the Exact superproject");
        return;
    };
    let scratch = tempfile::tempdir().expect("create plan seam fixture tempdir");
    let bundle_dir = scratch.path().join("bundle");
    let bundle = bundle_dir.join("plan-hermes-seam-fixture.js");
    let bundle_map = bundle_dir.join("plan-hermes-seam-fixture.js.map");
    let hbc_path = scratch.path().join("fixture.hbc");
    let arguments_path = scratch.path().join("fixture.arguments");
    let capability_arguments_path = scratch.path().join("fixture.capability-arguments");
    let expected_result_path = scratch.path().join("fixture.expected-result");
    let expected_theme_path = scratch.path().join("fixture.expected-theme");

    run(
        &root,
        "bun",
        &[
            "packages/exact-contract/scripts/generate-plan-hermes-seam-fixture.mjs",
            "--check",
        ],
    );
    let vite = Command::new("node")
        .args([
            "packages/exact-devtools/src/scripts/vite-cli.mjs",
            "build",
            "--config",
            "packages/exact-contract/vite.config.plan-hermes-seam-fixture.ts",
        ])
        .current_dir(&root)
        .env("EXACT_PLAN_SEAM_FIXTURE_BUNDLE_DIR", &bundle_dir)
        .output()
        .expect("run plan seam Vite fixture build");
    assert!(
        vite.status.success(),
        "fixture Vite build failed with {}\nstdout:\n{}\nstderr:\n{}",
        vite.status,
        String::from_utf8_lossy(&vite.stdout),
        String::from_utf8_lossy(&vite.stderr),
    );
    assert!(bundle.is_file(), "fixture bundle was not emitted");
    assert!(
        bundle_map.is_file(),
        "fixture authored source map was not emitted"
    );

    let hermesc = std::env::var_os("HERMESC")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .expect("HERMESC must name the linked Hermes profile's compiler");
    run(
        &root,
        "bun",
        &[
            "packages/exact-devtools/src/scripts/compile-hermes-with-authored-map.ts",
            "--hermesc",
            hermesc.to_str().expect("HERMESC path must be UTF-8"),
            "--input",
            bundle.to_str().expect("bundle path must be UTF-8"),
            "--input-map",
            bundle_map.to_str().expect("bundle map path must be UTF-8"),
            "--output",
            hbc_path.to_str().expect("HBC path must be UTF-8"),
            "--root",
            root.to_str().expect("repo path must be UTF-8"),
            "--flag",
            "-O",
        ],
    );
    run(
        &root,
        "bun",
        &[
            "packages/exact-contract/scripts/write-plan-hermes-seam-fixture-arguments.ts",
            arguments_path
                .to_str()
                .expect("arguments path must be UTF-8"),
            capability_arguments_path
                .to_str()
                .expect("capability arguments path must be UTF-8"),
            expected_result_path
                .to_str()
                .expect("expected result path must be UTF-8"),
            expected_theme_path
                .to_str()
                .expect("expected theme path must be UTF-8"),
        ],
    );

    let hbc = std::fs::read(hbc_path).expect("read real fixture HBC");
    let receipt = std::fs::read(
        root.join(
            "packages/exact-contract/src/__fixtures__/plan-hermes-seam-v1/registry-receipt.generated.json",
        ),
    )
    .expect("read generated fixture receipt");
    let arguments = std::fs::read(arguments_path).expect("read canonical call arguments");
    let capability_arguments =
        std::fs::read(capability_arguments_path).expect("read canonical capability arguments");
    let expected_result =
        std::fs::read(expected_result_path).expect("read canonical expected result");
    let expected_theme = std::fs::read(expected_theme_path).expect("read canonical expected theme");

    std::thread::Builder::new()
        .name("ibex-plan-seam-real-hbc-owner".to_string())
        .spawn(move || unsafe {
            let invalidations = InvalidationState::default();
            let inputs = FacetHostInputsV1 {
                abi_version: ABI_VERSION,
                struct_size: std::mem::size_of::<FacetHostInputsV1>() as u32,
                system_appearance: APPEARANCE_DARK,
                reduced_motion: 1,
                native_control_presentation: 1,
                reserved: 0,
                viewport_width: 834.0,
            };
            let options = PlanSeamOptionsV1 {
                abi_version: ABI_VERSION,
                struct_size: std::mem::size_of::<PlanSeamOptionsV1>() as u32,
                generation: GENERATION,
                executor_identity: 1,
                heap_bytes: 32 * 1024 * 1024,
                hbc_bytes: hbc.as_ptr(),
                hbc_len: hbc.len(),
                expected_registry_receipt: receipt.as_ptr(),
                expected_registry_receipt_len: receipt.len(),
                facet_host_inputs: inputs,
                invalidation_callback: Some(accept_invalidation),
                invalidation_context: (&invalidations as *const InvalidationState)
                    .cast_mut()
                    .cast(),
            };
            let mut runtime = ptr::null_mut();
            let mut diagnostic = CreateDiagnosticV1::default();
            let status = ex_hermes_plan_seam_create_v1(&options, &mut runtime, &mut diagnostic);
            assert_eq!(
                status,
                STATUS_OK,
                "real HBC create failed: status={}, diagnostic_status={}, code={}, reason={}",
                status,
                diagnostic.transport_status,
                diagnostic.code,
                diagnostic_text(&diagnostic),
            );
            assert_eq!(diagnostic.transport_status, STATUS_OK);
            assert_eq!(diagnostic.code, CREATE_DIAGNOSTIC_NONE);
            assert!(
                !runtime.is_null(),
                "successful create returned a null runtime"
            );

            let (call_status, pure) =
                call_reply(runtime, BINDING_KIND_HOST_IMPORT, 0, 0, &arguments);
            assert_eq!(
                call_status, STATUS_OK,
                "real HBC pure call transport failed"
            );
            assert_eq!(
                pure.outcome,
                OUTCOME_OK,
                "fixture pure call failed: {}",
                pure.summary()
            );
            assert_eq!(pure.reactive_version, 0);
            assert_eq!(pure.lease_generation, GENERATION);
            assert_eq!(pure.bytes, expected_result);
            release_reply(runtime, &pure);

            let (ambient_status, ambient) =
                call_reply(runtime, BINDING_KIND_HOST_IMPORT, 3, 0, &arguments);
            assert_eq!(ambient_status, STATUS_OK, "ambient call transport failed");
            assert_eq!(
                ambient.outcome,
                OUTCOME_OK,
                "restricted ambient-surface fixture failed: {}",
                ambient.summary(),
            );
            assert_eq!(
                ambient.bytes,
                [HOST_VALUE_BOOL_TRUE],
                "the evaluated HBC must observe an empty HermesInternal own-property set",
            );
            release_reply(runtime, &ambient);

            let (throw_status, hostile_throw) =
                call_reply(runtime, BINDING_KIND_HOST_IMPORT, 2, 0, &arguments);
            assert_eq!(throw_status, STATUS_OK, "hostile throw transport failed");
            let hostile_diagnostic = decode_plan_host_diagnostic(&hostile_throw.bytes)
                .expect("hostile throw must carry a valid diagnostic");
            eprintln!(
                "real HBC hostile-throw diagnostic: {}",
                hostile_throw.summary()
            );
            assert_eq!(hostile_throw.outcome, OUTCOME_THREW);
            assert_eq!(hostile_diagnostic.code, DIAGNOSTIC_TS_THROW);
            assert_eq!(hostile_diagnostic.effect_disposition, EFFECT_NONE);
            release_reply(runtime, &hostile_throw);

            // Parity with the production XCTest: the initial reactive read
            // must see the full inputs + definition/app overrides snapshot,
            // not the process defaults and not a diagnostic frame.
            let (theme_status, initial_theme) = read_reactive_reply(runtime, 1);
            assert_eq!(
                theme_status, STATUS_OK,
                "initial theme read transport failed"
            );
            if initial_theme.outcome != OUTCOME_OK {
                eprintln!(
                    "real HBC initial-theme diagnostic: {}",
                    initial_theme.summary()
                );
            }
            assert_eq!(
                initial_theme.outcome,
                OUTCOME_OK,
                "initial theme read failed: {}",
                initial_theme.summary(),
            );
            assert_eq!(initial_theme.reactive_version, 1);
            assert_eq!(
                initial_theme.bytes.first().copied(),
                Some(HOST_VALUE_OBJECT)
            );
            assert_eq!(
                initial_theme.bytes, expected_theme,
                "real HBC theme differs from fixture.expected-theme",
            );
            release_reply(runtime, &initial_theme);

            let (fault_status, provider_fault) =
                call_reply(runtime, BINDING_KIND_CAPABILITY, 1, 3, &arguments);
            assert_eq!(fault_status, STATUS_OK, "provider-fault transport failed");
            let provider_diagnostic = decode_plan_host_diagnostic(&provider_fault.bytes)
                .expect("provider-fault fixture must carry a valid diagnostic");
            eprintln!(
                "real HBC provider-fault diagnostic: {}",
                provider_fault.summary()
            );
            assert_eq!(provider_fault.outcome, OUTCOME_PROVIDER_FAULT);
            assert_eq!(provider_diagnostic.code, DIAGNOSTIC_PROVIDER_FAULT);
            assert_eq!(
                provider_diagnostic.effect_disposition,
                EFFECT_OUTCOME_UNKNOWN,
            );
            release_reply(runtime, &provider_fault);

            let (unknown_status, unknown_outcome) =
                call_reply(runtime, BINDING_KIND_CAPABILITY, 2, 4, &arguments);
            assert_eq!(
                unknown_status, STATUS_OK,
                "unknown-outcome transport failed"
            );
            let unknown_diagnostic = decode_plan_host_diagnostic(&unknown_outcome.bytes)
                .expect("unknown-outcome fixture must carry a valid diagnostic");
            eprintln!(
                "real HBC unknown-outcome diagnostic: {}",
                unknown_outcome.summary()
            );
            assert_eq!(unknown_outcome.outcome, OUTCOME_REFUSED);
            assert_eq!(
                unknown_diagnostic.code,
                DIAGNOSTIC_CAPABILITY_OUTCOME_UNKNOWN,
            );
            assert_eq!(
                unknown_diagnostic.effect_disposition,
                EFFECT_OUTCOME_UNKNOWN,
            );
            release_reply(runtime, &unknown_outcome);

            let (denied_status, denied) = call_reply(
                runtime,
                BINDING_KIND_CAPABILITY,
                99,
                2,
                &capability_arguments,
            );
            assert_eq!(
                denied_status, STATUS_OK,
                "denied-capability transport failed"
            );
            let denied_diagnostic = decode_plan_host_diagnostic(&denied.bytes)
                .expect("denied capability must carry a valid diagnostic");
            eprintln!(
                "real HBC denied-capability diagnostic: {}",
                denied.summary()
            );
            assert_eq!(denied.outcome, OUTCOME_REFUSED);
            assert_eq!(denied_diagnostic.code, DIAGNOSTIC_CAPABILITY_DENIED);
            assert_eq!(denied_diagnostic.effect_disposition, EFFECT_NOT_STARTED);
            release_reply(runtime, &denied);

            assert!(
                invalidations
                    .records
                    .lock()
                    .expect("invalidation records lock")
                    .is_empty(),
                "fixture invalidated before the real capability call",
            );
            assert_eq!(invalidations.publication_count.load(Ordering::SeqCst), 0);
            invalidations
                .provider_call_active
                .store(true, Ordering::SeqCst);
            let (capability_status, capability) = call_reply(
                runtime,
                BINDING_KIND_CAPABILITY,
                0,
                1,
                &capability_arguments,
            );
            invalidations
                .provider_call_active
                .store(false, Ordering::SeqCst);
            assert_eq!(
                capability_status, STATUS_OK,
                "theme capability transport failed"
            );
            assert_eq!(
                capability.outcome,
                OUTCOME_OK,
                "theme capability failed: {}",
                capability.summary(),
            );
            assert_eq!(
                capability.bytes,
                [EFFECT_COMMITTED, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0],
            );
            assert_eq!(invalidations.publication_count.load(Ordering::SeqCst), 0);
            let records = invalidations
                .records
                .lock()
                .expect("invalidation records lock")
                .clone();
            assert_eq!(
                records,
                [InvalidationRecord {
                    generation: GENERATION,
                    host_import_ref: 1,
                    hinted_version: 2,
                    recorded_on_provider_stack: true,
                }],
                "the capability must only enqueue one generation-fenced invalidation",
            );
            release_reply(runtime, &capability);

            // This is the native harness's explicit later top-level job: the
            // invalidation callback above only recorded a hint. A separate
            // owner turn reads the full v2 snapshot before publication.
            let (later_status, later_theme) =
                read_reactive_reply(runtime, records[0].host_import_ref);
            assert_eq!(later_status, STATUS_OK, "later theme read transport failed");
            if later_theme.outcome != OUTCOME_OK {
                eprintln!("real HBC later-theme diagnostic: {}", later_theme.summary());
            }
            assert_eq!(
                later_theme.outcome,
                OUTCOME_OK,
                "later theme read failed: {}",
                later_theme.summary(),
            );
            assert_eq!(later_theme.reactive_version, records[0].hinted_version);
            assert_eq!(later_theme.bytes.first().copied(), Some(HOST_VALUE_OBJECT));
            assert_ne!(
                later_theme.bytes, expected_theme,
                "scheme capability did not change the full reactive snapshot",
            );
            invalidations
                .publication_count
                .fetch_add(1, Ordering::SeqCst);
            release_reply(runtime, &later_theme);
            assert_eq!(invalidations.publication_count.load(Ordering::SeqCst), 1);

            assert_eq!(ex_hermes_plan_seam_shutdown_v1(runtime), STATUS_OK);
            assert_eq!(ex_hermes_plan_seam_destroy_v1(runtime), STATUS_OK);

            // The same production path must explain a deep create refusal,
            // not merely return the coarse registry transport category.
            let mut wrong_receipt = receipt.clone();
            wrong_receipt[0] ^= 1;
            let refused_options = PlanSeamOptionsV1 {
                abi_version: ABI_VERSION,
                struct_size: std::mem::size_of::<PlanSeamOptionsV1>() as u32,
                generation: GENERATION + 1,
                executor_identity: 1,
                heap_bytes: 32 * 1024 * 1024,
                hbc_bytes: hbc.as_ptr(),
                hbc_len: hbc.len(),
                expected_registry_receipt: wrong_receipt.as_ptr(),
                expected_registry_receipt_len: wrong_receipt.len(),
                facet_host_inputs: FacetHostInputsV1 {
                    abi_version: ABI_VERSION,
                    struct_size: std::mem::size_of::<FacetHostInputsV1>() as u32,
                    system_appearance: APPEARANCE_DARK,
                    reduced_motion: 1,
                    native_control_presentation: 1,
                    reserved: 0,
                    viewport_width: 834.0,
                },
                invalidation_callback: Some(accept_invalidation),
                invalidation_context: ptr::null_mut(),
            };
            let mut refused_runtime = ptr::null_mut();
            let mut refusal = CreateDiagnosticV1::default();
            let refusal_status =
                ex_hermes_plan_seam_create_v1(&refused_options, &mut refused_runtime, &mut refusal);
            assert_eq!(refusal_status, -4);
            assert!(refused_runtime.is_null());
            assert_eq!(refusal.transport_status, refusal_status);
            assert_eq!(refusal.code, 17);
            assert!(
                diagnostic_text(&refusal).contains("receipt does not match"),
                "deep create refusal lost its reason: {}",
                diagnostic_text(&refusal),
            );
        })
        .expect("spawn dedicated plan seam owner thread")
        .join()
        .expect("dedicated plan seam owner thread panicked");
}
