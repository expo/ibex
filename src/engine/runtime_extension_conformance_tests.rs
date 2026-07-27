//! Executable native runtime-extension substrate conformance.
//!
//! The fixture itself lives in `tests/native/hermes_runtime_extension_conformance.cc` and
//! is absent from ordinary Ibex artifacts. These tests deliberately drive its
//! public C construction/evaluation/lifecycle boundary instead of inspecting
//! source text.
//!
//! @ref LLP 0040#verification
//! Conformance requirements are governed by Exact LLP 0405.

use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use std::time::{Duration, Instant};

#[repr(C)]
struct DiagnosticOptionsV2 {
    struct_size: u32,
    abi_version: u32,
    extension_registry: *const c_void,
}

#[repr(C)]
struct ArmedOptionsV2 {
    struct_size: u32,
    abi_version: u32,
    armed_snapshot_digest: *const c_char,
    extension_registry: *const c_void,
}

#[repr(C)]
struct InspectionV1 {
    struct_size: u32,
    id: *const c_char,
    version: *const c_char,
    manifest_digest: *const c_char,
    generation: u64,
    lifecycle_state: u32,
    callbacks_admitted: u64,
    callbacks_rejected: u64,
}

const CREATE_OPTIONS_VERSION_V2: u32 = 2;
const STATUS_OK: i32 = 0;
const LIFECYCLE_ACTIVE: u32 = 2;

const COUNTER_INSTALL: u32 = 0;
const COUNTER_QUIESCE: u32 = 1;
const COUNTER_CLOSE: u32 = 2;
const COUNTER_ENQUEUE: u32 = 3;
const COUNTER_POST_ACCEPTED: u32 = 4;
const COUNTER_POST_REJECTED: u32 = 5;
const COUNTER_OWNER_DELIVERY_MISMATCH: u32 = 6;
const COUNTER_OWNER_CAPTURE_DESTROYED: u32 = 7;
const COUNTER_OWNER_CAPTURE_MISMATCH: u32 = 8;
const COUNTER_CLOSE_SEQUENCE: u32 = 9;
const COUNTER_TEARDOWN_SCHEDULE_REJECTED: u32 = 10;
const COUNTER_PROVIDER_VIEW_STABLE: u32 = 11;
const COUNTER_OFF_OWNER_TOKEN_RETIRED: u32 = 12;
const COUNTER_LAST_POST_RESULT: u32 = 13;
const COUNTER_OFF_OWNER_LEASE_RETIRED: u32 = 14;
const COUNTER_REGISTRY_AUTHENTICATED_INSTALL: u32 = 15;
const COUNTER_REGISTRY_UNAUTHENTICATED_INSTALL: u32 = 16;
const COUNTER_REGISTRY_AUTHENTICATED_ACTIVATION: u32 = 17;
const COUNTER_REGISTRY_UNAUTHENTICATED_ACTIVATION: u32 = 18;
const COUNTER_ACTIVATION_EFFECT: u32 = 19;
const COUNTER_ACTIVATION_SEQUENCE: u32 = 20;
const COUNTER_DUPLICATE_ACTIVATION_REGISTRATION_REJECTED: u32 = 21;
const FAULT_TOKEN_IMPL_ALLOCATION: u32 = 1 << 0;
const FAULT_POST_DISPOSITION_ALLOCATION: u32 = 1 << 1;
const FAULT_POST_CALLBACK_ALLOCATION: u32 = 1 << 2;
const COMPROMISED_PACKAGE_PRINCIPAL_ID: u64 = 1;
const SCHEDULE_ACCEPTED: u64 = 0;
const SCHEDULE_QUEUE_FULL: u64 = 13;

const REGISTRY_DUPLICATE_ID: u32 = 1;
const REGISTRY_OVERLAPPING_GLOBAL: u32 = 2;
const REGISTRY_ABI_MISMATCH: u32 = 3;
const REGISTRY_UNDECLARED_GLOBAL: u32 = 4;
const REGISTRY_UNDECLARED_EFFECT: u32 = 5;
const REGISTRY_PARTIAL_INSTALL_FAILURE: u32 = 6;
const REGISTRY_MALFORMED_DIGEST: u32 = 7;
const REGISTRY_UNSUPPORTED_FEATURE: u32 = 8;
const REGISTRY_PROVIDER_MISMATCH: u32 = 9;
const REGISTRY_SUCCESSFUL_PAIR: u32 = 10;
const REGISTRY_NESTED_MUTATION: u32 = 11;
const REGISTRY_PROTOTYPE_MUTATION: u32 = 12;
const REGISTRY_REFLECTION_REPLACEMENT: u32 = 13;
const REGISTRY_DECLARED_NESTED: u32 = 14;
const REGISTRY_UNDECLARED_BOOTSTRAP_MODULE: u32 = 15;
const REGISTRY_DECLARED_MODULE_ENTRY: u32 = 16;
const REGISTRY_UNDECLARED_MODULE_ENTRY: u32 = 17;
const REGISTRY_MALFORMED_MODULE_ENTRY: u32 = 18;
const REGISTRY_RESERVED_MODULE_SEPARATOR: u32 = 19;
const REGISTRY_INVALID_MODULE_GRAMMAR: u32 = 20;
const REGISTRY_ACTIVATION_NESTED_MUTATION: u32 = 21;

unsafe extern "C" {
    fn ibex_runtime_extension_conformance_registry_v1() -> *const c_void;
    fn ibex_runtime_extension_conformance_bound_registry_v1(
        extension_set_digest: *const c_char,
        authority_capsule_digest: *const c_char,
        executable_selection_identity: *const c_char,
    ) -> *const c_void;
    fn ibex_runtime_extension_conformance_bound_registry_descriptor_digest_mismatch_v1(
        extension_set_digest: *const c_char,
        authority_capsule_digest: *const c_char,
        executable_selection_identity: *const c_char,
    ) -> *const c_void;
    fn ibex_runtime_extension_conformance_registry_variant_v1(variant: u32) -> *const c_void;
    fn ibex_runtime_extension_conformance_counter_v1(counter: u32) -> u64;
    fn ibex_runtime_extension_conformance_reset_v1();
    fn ibex_runtime_extension_conformance_fail_next_activation_v1();
    fn ibex_runtime_extension_conformance_retire_next_subscription_off_owner_v1();
    fn ibex_runtime_extension_conformance_set_off_owner_retire_delay_v1(delay_ms: u32);
    fn ibex_runtime_extension_conformance_hold_next_accepted_post_v1();
    fn ibex_runtime_extension_conformance_accepted_post_is_held_v1() -> i32;
    fn ibex_runtime_extension_conformance_release_accepted_post_v1();
    fn ibex_runtime_extension_conformance_callback_slot_count_v1(runtime: *mut c_void) -> usize;
    fn ibex_runtime_extension_conformance_operation_lease_slot_count_v1(
        runtime: *mut c_void,
    ) -> usize;
    fn ibex_runtime_extension_conformance_hold_next_operation_lease_retirement_v1();
    fn ibex_runtime_extension_conformance_operation_lease_retirement_is_held_v1() -> i32;
    fn ibex_runtime_extension_conformance_release_operation_lease_retirement_v1();
    fn ibex_test_runtime_extension_arm_completion_fault_v1(fault_mask: u32);
    fn ibex_test_runtime_extension_arm_keyed_external_detach_fault_v1();
    fn ibex_test_runtime_extension_with_registry_lock_v1(
        body: unsafe extern "C" fn(*mut c_void),
        context: *mut c_void,
    ) -> i32;
    fn ibex_test_runtime_extension_with_callback_queue_lock_v1(
        runtime: *mut c_void,
        body: unsafe extern "C" fn(*mut c_void),
        context: *mut c_void,
    ) -> i32;
    fn ibex_test_runtime_extension_with_native_worker_lock_v1(
        runtime: *mut c_void,
        body: unsafe extern "C" fn(*mut c_void),
        context: *mut c_void,
    ) -> i32;
    fn ibex_test_runtime_extension_with_callback_slot_lock_v1(
        runtime: *mut c_void,
        body: unsafe extern "C" fn(*mut c_void),
        context: *mut c_void,
    ) -> i32;
    fn ibex_runtime_extension_conformance_create_authenticated_fixture_v1(
        options: *const ArmedOptionsV2,
    ) -> *mut c_void;
    fn ibex_runtime_extension_conformance_eval_with_principals_v1(
        runtime: *mut c_void,
        principal_ids: *const u64,
        principal_count: usize,
        source: *const u8,
        source_length: usize,
        source_url: *const c_char,
        out_value: *mut *mut c_char,
    ) -> i32;
    fn ibex_runtime_extension_conformance_armed_prerequisites_v1() -> u64;
    fn ibex_runtime_extension_supported_features_v1() -> u64;

    fn ibex_runtime_create_armed_v2(options: *const ArmedOptionsV2) -> *mut c_void;
    fn ibex_runtime_create_diagnostic_v2(options: *const DiagnosticOptionsV2) -> *mut c_void;
    fn ibex_runtime_extension_count_v1(runtime: *mut c_void) -> usize;
    fn ibex_runtime_extension_inspect_v1(
        runtime: *mut c_void,
        index: usize,
        inspection: *mut InspectionV1,
    ) -> i32;
    fn ibex_runtime_extension_report_json_v1(runtime: *mut c_void) -> *mut c_char;

    fn ex_hermes_create() -> *mut c_void;
    fn ex_hermes_destroy(runtime: *mut c_void);
    fn ex_hermes_eval(
        runtime: *mut c_void,
        data: *const u8,
        len: usize,
        source_url: *const c_char,
        is_bytecode: i32,
        out_value: *mut *mut c_char,
    ) -> i32;
    fn ex_hermes_free_string(value: *mut c_char);
    fn ex_hermes_poll(runtime: *mut c_void, now_ms: u64) -> i32;
    fn ex_hermes_now_ms() -> u64;
}

struct Runtime(*mut c_void);

impl Runtime {
    fn diagnostic(registry: *const c_void) -> Option<Self> {
        let options = DiagnosticOptionsV2 {
            struct_size: size_of::<DiagnosticOptionsV2>() as u32,
            abi_version: CREATE_OPTIONS_VERSION_V2,
            extension_registry: registry,
        };
        let raw = unsafe { ibex_runtime_create_diagnostic_v2(&options) };
        (!raw.is_null()).then_some(Self(raw))
    }

    fn eval(&self, source: &str) -> Result<String, String> {
        let source_url = CString::new("runtime-extension-conformance.js").unwrap();
        let mut output = ptr::null_mut();
        let status = unsafe {
            ex_hermes_eval(
                self.0,
                source.as_ptr(),
                source.len(),
                source_url.as_ptr(),
                0,
                &mut output,
            )
        };
        let rendered = if output.is_null() {
            String::new()
        } else {
            let value = unsafe { CStr::from_ptr(output) }
                .to_string_lossy()
                .into_owned();
            unsafe { ex_hermes_free_string(output) };
            value
        };
        if status == 0 {
            Ok(rendered)
        } else {
            Err(rendered)
        }
    }

    fn eval_with_principals(&self, principals: &[u64], source: &str) -> Result<String, String> {
        let source_url = CString::new("runtime-extension-constrained-principals.js").unwrap();
        let mut output = ptr::null_mut();
        let status = unsafe {
            ibex_runtime_extension_conformance_eval_with_principals_v1(
                self.0,
                principals.as_ptr(),
                principals.len(),
                source.as_ptr(),
                source.len(),
                source_url.as_ptr(),
                &mut output,
            )
        };
        let rendered = if output.is_null() {
            String::new()
        } else {
            let value = unsafe { CStr::from_ptr(output) }
                .to_string_lossy()
                .into_owned();
            unsafe { ex_hermes_free_string(output) };
            value
        };
        if status == 0 {
            Ok(rendered)
        } else {
            Err(rendered)
        }
    }

    fn poll(&self) -> i32 {
        unsafe { ex_hermes_poll(self.0, ex_hermes_now_ms()) }
    }

    fn extension_generation(&self) -> u64 {
        let mut inspection = InspectionV1 {
            struct_size: size_of::<InspectionV1>() as u32,
            id: ptr::null(),
            version: ptr::null(),
            manifest_digest: ptr::null(),
            generation: 0,
            lifecycle_state: 0,
            callbacks_admitted: 0,
            callbacks_rejected: 0,
        };
        assert_eq!(
            unsafe { ibex_runtime_extension_inspect_v1(self.0, 0, &mut inspection) },
            STATUS_OK
        );
        assert_ne!(inspection.generation, 0);
        inspection.generation
    }

    fn wait_for_js(&self, expression: &str, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(self.poll() >= 0, "runtime polling became fatal");
            if self.eval(expression).as_deref() == Ok(expected) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {expression} to become {expected:?}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn report(&self) -> serde_json::Value {
        let report = unsafe { ibex_runtime_extension_report_json_v1(self.0) };
        assert!(!report.is_null());
        let report_json = unsafe { CStr::from_ptr(report) }
            .to_string_lossy()
            .into_owned();
        unsafe { ex_hermes_free_string(report) };
        serde_json::from_str(&report_json).unwrap()
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { ex_hermes_destroy(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

fn counter(counter: u32) -> u64 {
    unsafe { ibex_runtime_extension_conformance_counter_v1(counter) }
}

fn reset() {
    unsafe {
        ibex_test_runtime_extension_arm_completion_fault_v1(0);
        ibex_runtime_extension_conformance_reset_v1();
    }
}

fn wait_for_counter(counter_id: u32, minimum: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while counter(counter_id) < minimum {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for conformance counter {counter_id} to reach {minimum}; \
             accepted={}, rejected={}, last-post-result={}",
            counter(COUNTER_POST_ACCEPTED),
            counter(COUNTER_POST_REJECTED),
            counter(COUNTER_LAST_POST_RESULT),
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

struct LockedProducerWait {
    post_counter: u32,
    post_minimum: u64,
    retirement_minimum: u64,
    observed: bool,
}

unsafe extern "C" fn wait_for_locked_producers(context: *mut c_void) {
    let wait = unsafe { &mut *context.cast::<LockedProducerWait>() };
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if counter(wait.post_counter) >= wait.post_minimum
            && counter(COUNTER_OFF_OWNER_TOKEN_RETIRED) >= wait.retirement_minimum
        {
            wait.observed = true;
            return;
        }
        std::thread::yield_now();
    }
}

fn arm_delayed_post_and_last_drop(runtime: &Runtime) {
    unsafe {
        ibex_runtime_extension_conformance_set_off_owner_retire_delay_v1(40);
        ibex_runtime_extension_conformance_retire_next_subscription_off_owner_v1();
    }
    assert_eq!(
        runtime
            .eval(
                r#"__ibexRuntimeExtensionFixture.completeAfter("contended", 40);
                   __ibexRuntimeExtensionFixture.subscribe(function () {});
                   "armed";"#,
            )
            .unwrap(),
        "armed"
    );
}

fn grant_package_location(grant_id: &str) {
    let request = serde_json::to_vec(&serde_json::json!({
        "grantId": grant_id,
        "principal": {
            "kind": "package",
            "name": "image-lib",
            "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
            "locator": "image-lib@2.4.1"
        },
        "authority": {
            "cap": "device:location",
            "resource": {
                "kind": "device-location",
                "usage": "foreground",
                "precision": "coarse"
            }
        }
    }))
    .unwrap();
    assert_eq!(
        unsafe {
            crate::host::abi::ex_host_typed_dynamic_grant(
                COMPROMISED_PACKAGE_PRINCIPAL_ID,
                request.as_ptr(),
                request.len(),
            )
        },
        1
    );
}

fn revoke_package_location(grant_id: &str) {
    let request = serde_json::to_vec(grant_id).unwrap();
    assert_eq!(
        unsafe {
            crate::host::abi::ex_host_typed_dynamic_revoke(
                COMPROMISED_PACKAGE_PRINCIPAL_ID,
                request.as_ptr(),
                request.len(),
            )
        },
        1
    );
}

fn diagnostic_with(registry: *const c_void) -> Option<Runtime> {
    let host = crate::host::Host::default_legacy();
    assert_ne!(crate::host::abi::install_host(host), 0);
    Runtime::diagnostic(registry)
}

fn construct_authenticated_runtime(conformance_fixture: bool) -> Option<Runtime> {
    construct_authenticated_runtime_with_host(conformance_fixture).map(|(runtime, _)| runtime)
}

fn construct_authenticated_runtime_with_host(
    conformance_fixture: bool,
) -> Option<(Runtime, crate::host::Host)> {
    let host = crate::host::runtime_extension_conformance_test_host();
    let snapshot = host
        .armed_snapshot()
        .expect("conformance Host must carry an armed snapshot");
    let capsule = snapshot
        .runtime_extension_authority()
        .expect("conformance Host must carry extension authority");
    let snapshot_digest = CString::new(snapshot.digest().as_str()).unwrap();
    let extension_set_digest = CString::new(capsule.extension_set_digest.as_str()).unwrap();
    let authority_capsule_digest = CString::new(capsule.authority_capsule_digest.as_str()).unwrap();
    let executable_selection_identity =
        CString::new(capsule.executable_selection_identity.as_str()).unwrap();
    let package: capsec_semantics::model::Principal =
        serde_json::from_value(snapshot.document()["principals"][1]["principal"].clone()).unwrap();
    assert!(package.is_package());
    assert_eq!(
        u64::from(host.module_runner_principal_id(&package).unwrap()),
        COMPROMISED_PACKAGE_PRINCIPAL_ID
    );
    let registry = unsafe {
        ibex_runtime_extension_conformance_bound_registry_v1(
            extension_set_digest.as_ptr(),
            authority_capsule_digest.as_ptr(),
            executable_selection_identity.as_ptr(),
        )
    };
    assert!(!registry.is_null(), "fixture registry binding failed");
    let contention_host = host.clone();
    assert_ne!(crate::host::abi::install_host(host), 0);
    let options = ArmedOptionsV2 {
        struct_size: size_of::<ArmedOptionsV2>() as u32,
        abi_version: CREATE_OPTIONS_VERSION_V2,
        armed_snapshot_digest: snapshot_digest.as_ptr(),
        extension_registry: registry,
    };
    let raw = unsafe {
        if conformance_fixture {
            ibex_runtime_extension_conformance_create_authenticated_fixture_v1(&options)
        } else {
            ibex_runtime_create_armed_v2(&options)
        }
    };
    (!raw.is_null()).then_some((Runtime(raw), contention_host))
}

fn authenticated_runtime() -> Runtime {
    construct_authenticated_runtime(true)
        .expect("authenticated conformance fixture runtime construction failed")
}

#[test]
fn standalone_runtime_keeps_the_canonical_empty_extension_set() {
    let _host_guard = crate::host::abi::host_test_lock();
    unsafe {
        assert!(
            ex_hermes_create().is_null(),
            "the historical unarmed constructor must remain non-executable"
        );
    }
    let runtime = diagnostic_with(ptr::null()).expect("standalone diagnostic runtime");
    assert_eq!(unsafe { ibex_runtime_extension_count_v1(runtime.0) }, 0);
    assert_eq!(
        runtime
            .eval("typeof __ibexRuntimeExtensionFixture")
            .unwrap(),
        "undefined"
    );
}

#[test]
fn production_armed_constructor_remains_fail_closed_without_required_hermes_hooks() {
    const PROMISE_REJECTION_CHECKPOINT_HOOK: u64 = 1 << 0;
    const CONSTRAINED_PRINCIPAL_JOBS: u64 = 1 << 2;
    const REQUIRED_HERMES_HOOKS: u64 =
        PROMISE_REJECTION_CHECKPOINT_HOOK | CONSTRAINED_PRINCIPAL_JOBS;
    let _host_guard = crate::host::abi::host_test_lock();
    if unsafe { ibex_runtime_extension_conformance_armed_prerequisites_v1() }
        & REQUIRED_HERMES_HOOKS
        == REQUIRED_HERMES_HOOKS
    {
        return;
    }
    reset();
    assert!(
        construct_authenticated_runtime(false).is_none(),
        "production armed construction bypassed a missing Hermes prerequisite"
    );
    assert_eq!(counter(COUNTER_INSTALL), 0);
}

#[test]
fn malformed_registries_are_refused_before_installation() {
    let _host_guard = crate::host::abi::host_test_lock();
    for (variant, name) in [
        (REGISTRY_DUPLICATE_ID, "duplicate id"),
        (REGISTRY_OVERLAPPING_GLOBAL, "overlapping global"),
        (REGISTRY_ABI_MISMATCH, "ABI mismatch"),
        (REGISTRY_MALFORMED_DIGEST, "malformed digest"),
        (REGISTRY_UNSUPPORTED_FEATURE, "unsupported feature"),
        (REGISTRY_PROVIDER_MISMATCH, "provider mismatch"),
        (REGISTRY_UNDECLARED_MODULE_ENTRY, "undeclared module entry"),
        (REGISTRY_MALFORMED_MODULE_ENTRY, "malformed module entry"),
        (
            REGISTRY_RESERVED_MODULE_SEPARATOR,
            "reserved export separator",
        ),
        (
            REGISTRY_INVALID_MODULE_GRAMMAR,
            "invalid module specifier grammar",
        ),
    ] {
        reset();
        let registry = unsafe { ibex_runtime_extension_conformance_registry_variant_v1(variant) };
        assert!(!registry.is_null(), "{name} fixture registry is absent");
        assert!(
            diagnostic_with(registry).is_none(),
            "{name} registry unexpectedly constructed a runtime"
        );
        assert_eq!(counter(COUNTER_INSTALL), 0, "{name} reached install");
    }
}

#[test]
fn declared_module_export_operation_path_constructs() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let registry = unsafe {
        ibex_runtime_extension_conformance_registry_variant_v1(REGISTRY_DECLARED_MODULE_ENTRY)
    };
    let runtime =
        diagnostic_with(registry).expect("declared module-export operation path was refused");
    let report = runtime.report();
    assert_eq!(unsafe { ibex_runtime_extension_count_v1(runtime.0) }, 1);
    assert_eq!(
        report["extensions"][0]["id"],
        "ibex.conformance.module-entry"
    );
}

#[test]
fn install_context_reports_diagnostic_registry_as_unauthenticated() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let registry = unsafe { ibex_runtime_extension_conformance_registry_v1() };
    let runtime = diagnostic_with(registry).expect("diagnostic extension runtime");
    assert_eq!(unsafe { ibex_runtime_extension_count_v1(runtime.0) }, 1);
    assert_eq!(counter(COUNTER_REGISTRY_AUTHENTICATED_INSTALL), 0);
    assert_eq!(counter(COUNTER_REGISTRY_UNAUTHENTICATED_INSTALL), 1);
    assert_eq!(counter(COUNTER_REGISTRY_AUTHENTICATED_ACTIVATION), 0);
    assert_eq!(counter(COUNTER_REGISTRY_UNAUTHENTICATED_ACTIVATION), 1);
    assert_eq!(counter(COUNTER_ACTIVATION_EFFECT), 0);
    assert_eq!(counter(COUNTER_ACTIVATION_SEQUENCE), 1);
    assert_eq!(
        counter(COUNTER_DUPLICATE_ACTIVATION_REGISTRATION_REJECTED),
        1
    );
}

#[test]
fn activation_callback_failure_rolls_back_the_complete_extension_set() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let registry = unsafe { ibex_runtime_extension_conformance_registry_v1() };
    unsafe { ibex_runtime_extension_conformance_fail_next_activation_v1() };
    assert!(
        diagnostic_with(registry).is_none(),
        "activation callback failure unexpectedly published a runtime"
    );
    assert_eq!(counter(COUNTER_INSTALL), 1);
    assert_eq!(counter(COUNTER_REGISTRY_UNAUTHENTICATED_ACTIVATION), 1);
    assert_eq!(counter(COUNTER_ACTIVATION_SEQUENCE), 1);
    assert_eq!(counter(COUNTER_QUIESCE), 1);
    assert_eq!(counter(COUNTER_CLOSE), 1);
}

#[test]
fn canonical_install_uses_reverse_quiesce_and_close_order() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let registry =
        unsafe { ibex_runtime_extension_conformance_registry_variant_v1(REGISTRY_SUCCESSFUL_PAIR) };
    let runtime = diagnostic_with(registry).expect("two-extension conformance runtime");
    assert_eq!(unsafe { ibex_runtime_extension_count_v1(runtime.0) }, 2);
    assert_eq!(counter(COUNTER_INSTALL), 2);
    assert_eq!(
        counter(COUNTER_ACTIVATION_SEQUENCE),
        12,
        "activation callbacks must run once in canonical descriptor order"
    );
    assert_eq!(
        counter(COUNTER_PROVIDER_VIEW_STABLE),
        1,
        "a second context overwrote the first provider view"
    );
    drop(runtime);
    assert_eq!(counter(COUNTER_QUIESCE), 2);
    assert_eq!(counter(COUNTER_CLOSE), 2);
    assert_eq!(
        counter(COUNTER_CLOSE_SEQUENCE),
        21,
        "extensions must close in reverse canonical installation order"
    );
}

#[test]
fn undeclared_global_and_effect_are_rejected_by_the_sdk() {
    let _host_guard = crate::host::abi::host_test_lock();
    for (variant, name) in [
        (REGISTRY_UNDECLARED_GLOBAL, "undeclared global"),
        (REGISTRY_UNDECLARED_EFFECT, "undeclared effect"),
    ] {
        reset();
        let registry = unsafe { ibex_runtime_extension_conformance_registry_variant_v1(variant) };
        assert!(!registry.is_null(), "{name} fixture registry is absent");
        assert!(
            diagnostic_with(registry).is_none(),
            "{name} unexpectedly survived construction"
        );
        assert_eq!(counter(COUNTER_INSTALL), 0);
        assert_eq!(counter(COUNTER_QUIESCE), 1);
        assert_eq!(counter(COUNTER_CLOSE), 1);
    }
}

#[test]
fn bootstrap_cannot_publish_an_undeclared_loader_module() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let registry = unsafe {
        ibex_runtime_extension_conformance_registry_variant_v1(REGISTRY_UNDECLARED_BOOTSTRAP_MODULE)
    };
    assert!(!registry.is_null());
    assert!(
        diagnostic_with(registry).is_none(),
        "authenticated bootstrap reached the construction-only module registrar"
    );
    assert_eq!(
        counter(COUNTER_INSTALL),
        0,
        "the installer ran after bootstrap module injection"
    );
}

#[test]
fn descriptor_graph_rejects_nested_prototype_and_reflection_evasions() {
    let _host_guard = crate::host::abi::host_test_lock();
    for (variant, name) in [
        (REGISTRY_NESTED_MUTATION, "nested undeclared mutation"),
        (REGISTRY_PROTOTYPE_MUTATION, "prototype mutation"),
        (
            REGISTRY_REFLECTION_REPLACEMENT,
            "Object reflection replacement",
        ),
    ] {
        reset();
        let registry = unsafe { ibex_runtime_extension_conformance_registry_variant_v1(variant) };
        assert!(!registry.is_null(), "{name} fixture registry is absent");
        assert!(
            diagnostic_with(registry).is_none(),
            "{name} unexpectedly survived descriptor-graph verification"
        );
        assert_eq!(
            counter(COUNTER_INSTALL),
            1,
            "{name} did not reach the adversarial installer"
        );
    }
}

#[test]
fn activation_cannot_mutate_the_verified_global_surface() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let registry = unsafe {
        ibex_runtime_extension_conformance_registry_variant_v1(REGISTRY_ACTIVATION_NESTED_MUTATION)
    };
    assert!(!registry.is_null());
    assert!(
        diagnostic_with(registry).is_none(),
        "activation global mutation unexpectedly survived post-callback verification"
    );
    assert_eq!(
        counter(COUNTER_INSTALL),
        1,
        "the adversarial activation installer did not run"
    );
    assert_eq!(counter(COUNTER_QUIESCE), 1);
    assert_eq!(counter(COUNTER_CLOSE), 1);
}

#[test]
fn declared_nested_global_addition_preserves_its_new_subgraph() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let registry =
        unsafe { ibex_runtime_extension_conformance_registry_variant_v1(REGISTRY_DECLARED_NESTED) };
    assert!(!registry.is_null());
    let runtime =
        diagnostic_with(registry).expect("declared nested global must survive verification");
    assert_eq!(
        runtime
            .eval("String(Object.__ibexDeclaredNestedFixture.marker)")
            .unwrap(),
        "393"
    );
    assert_eq!(counter(COUNTER_INSTALL), 1);
}

#[test]
fn authenticated_extension_set_identity_mismatch_is_refused_before_install() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let host = crate::host::runtime_extension_conformance_test_host();
    let snapshot = host.armed_snapshot().unwrap();
    let capsule = snapshot.runtime_extension_authority().unwrap();
    let snapshot_digest = CString::new(snapshot.digest().as_str()).unwrap();
    let wrong_set_digest =
        CString::new("sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE").unwrap();
    let authority_capsule_digest = CString::new(capsule.authority_capsule_digest.as_str()).unwrap();
    let executable_selection_identity =
        CString::new(capsule.executable_selection_identity.as_str()).unwrap();
    let registry = unsafe {
        ibex_runtime_extension_conformance_bound_registry_v1(
            wrong_set_digest.as_ptr(),
            authority_capsule_digest.as_ptr(),
            executable_selection_identity.as_ptr(),
        )
    };
    assert!(!registry.is_null());
    assert_ne!(crate::host::abi::install_host(host), 0);
    let options = ArmedOptionsV2 {
        struct_size: size_of::<ArmedOptionsV2>() as u32,
        abi_version: CREATE_OPTIONS_VERSION_V2,
        armed_snapshot_digest: snapshot_digest.as_ptr(),
        extension_registry: registry,
    };
    assert!(unsafe { ibex_runtime_create_armed_v2(&options) }.is_null());
    assert_eq!(counter(COUNTER_INSTALL), 0);
}

#[test]
fn descriptor_authority_capsule_digest_mismatch_is_refused_before_install() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let host = crate::host::runtime_extension_conformance_test_host();
    let snapshot = host.armed_snapshot().unwrap();
    let capsule = snapshot.runtime_extension_authority().unwrap();
    let snapshot_digest = CString::new(snapshot.digest().as_str()).unwrap();
    let extension_set_digest = CString::new(capsule.extension_set_digest.as_str()).unwrap();
    let authority_capsule_digest = CString::new(capsule.authority_capsule_digest.as_str()).unwrap();
    let executable_selection_identity =
        CString::new(capsule.executable_selection_identity.as_str()).unwrap();
    let registry = unsafe {
        ibex_runtime_extension_conformance_bound_registry_descriptor_digest_mismatch_v1(
            extension_set_digest.as_ptr(),
            authority_capsule_digest.as_ptr(),
            executable_selection_identity.as_ptr(),
        )
    };
    assert!(!registry.is_null());
    assert_ne!(crate::host::abi::install_host(host), 0);
    let options = ArmedOptionsV2 {
        struct_size: size_of::<ArmedOptionsV2>() as u32,
        abi_version: CREATE_OPTIONS_VERSION_V2,
        armed_snapshot_digest: snapshot_digest.as_ptr(),
        extension_registry: registry,
    };
    assert!(unsafe { ibex_runtime_create_armed_v2(&options) }.is_null());
    assert_eq!(counter(COUNTER_INSTALL), 0);
}

#[test]
fn failed_second_install_rolls_back_the_first_extension() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let registry = unsafe {
        ibex_runtime_extension_conformance_registry_variant_v1(REGISTRY_PARTIAL_INSTALL_FAILURE)
    };
    assert!(!registry.is_null());
    assert!(diagnostic_with(registry).is_none());
    assert_eq!(counter(COUNTER_INSTALL), 1);
    assert_eq!(counter(COUNTER_QUIESCE), 2);
    assert_eq!(counter(COUNTER_CLOSE), 2);
    assert_eq!(counter(COUNTER_CLOSE_SEQUENCE), 31);
}

#[test]
fn repeated_successful_and_failed_construction_does_not_leak_lifecycle_state() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    assert_ne!(
        crate::host::abi::install_host(crate::host::Host::default_legacy()),
        0
    );
    let valid = unsafe { ibex_runtime_extension_conformance_registry_v1() };
    let invalid =
        unsafe { ibex_runtime_extension_conformance_registry_variant_v1(REGISTRY_DUPLICATE_ID) };
    for _ in 0..12 {
        let runtime = Runtime::diagnostic(valid).expect("stress runtime construction");
        assert_eq!(unsafe { ibex_runtime_extension_count_v1(runtime.0) }, 1);
        drop(runtime);
        assert!(
            Runtime::diagnostic(invalid).is_none(),
            "failed-create stress registry unexpectedly constructed"
        );
    }
    assert_eq!(counter(COUNTER_INSTALL), 12);
    assert_eq!(counter(COUNTER_QUIESCE), 12);
    assert_eq!(counter(COUNTER_CLOSE), 12);
}

#[test]
fn native_identity_sync_enqueue_async_delivery_and_buffers_execute() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();

    assert_eq!(unsafe { ibex_runtime_extension_count_v1(runtime.0) }, 1);
    assert_eq!(counter(COUNTER_REGISTRY_AUTHENTICATED_INSTALL), 1);
    assert_eq!(counter(COUNTER_REGISTRY_UNAUTHENTICATED_INSTALL), 0);
    assert_eq!(counter(COUNTER_REGISTRY_AUTHENTICATED_ACTIVATION), 1);
    assert_eq!(counter(COUNTER_REGISTRY_UNAUTHENTICATED_ACTIVATION), 0);
    assert_eq!(
        counter(COUNTER_ACTIVATION_EFFECT),
        1,
        "activation callback did not run through the ACTIVE operation membrane"
    );
    assert_eq!(counter(COUNTER_ACTIVATION_SEQUENCE), 1);
    let mut inspection = InspectionV1 {
        struct_size: size_of::<InspectionV1>() as u32,
        id: ptr::null(),
        version: ptr::null(),
        manifest_digest: ptr::null(),
        generation: 0,
        lifecycle_state: 0,
        callbacks_admitted: 0,
        callbacks_rejected: 0,
    };
    assert_eq!(
        unsafe { ibex_runtime_extension_inspect_v1(runtime.0, 0, &mut inspection) },
        STATUS_OK
    );
    assert_eq!(inspection.lifecycle_state, LIFECYCLE_ACTIVE);
    assert_ne!(inspection.generation, 0);
    assert_eq!(
        unsafe { CStr::from_ptr(inspection.id) }.to_str().unwrap(),
        "ibex.conformance"
    );

    assert_eq!(
        runtime
            .eval(
                r#"(function () {
                  var f = __ibexRuntimeExtensionFixture;
                  var object = f.nativeObject;
                  return String(
                    require("@ibex/conformance") === f &&
                    object === f.getNativeObject() &&
                    Object.getPrototypeOf(object) === f.prototype &&
                    f.prototype.kind === "native-fixture" &&
                    object.identity > 0 &&
                    f.providerMarker === 4242
                  );
                })()"#
            )
            .unwrap(),
        "true"
    );
    assert_eq!(
        runtime
            .eval("__ibexRuntimeExtensionFixture.enqueue(41)")
            .unwrap(),
        "1"
    );
    assert_eq!(counter(COUNTER_ENQUEUE), 1);

    assert_eq!(
        runtime
            .eval(
                r#"(function () {
                  var bytes = __ibexRuntimeExtensionFixture.copyBuffer("abc");
                  return JSON.stringify([
                    bytes instanceof Uint8Array,
                    bytes.length,
                    bytes[0],
                    bytes[1],
                    bytes[2]
                  ]);
                })()"#
            )
            .unwrap(),
        "[true,3,97,98,99]"
    );

    runtime
        .eval(
            r#"globalThis.__extensionPromiseResult = "pending";
               __ibexRuntimeExtensionFixture.complete("worker-promise")
                 .then(function (value) {
                   globalThis.__extensionPromiseResult = value;
                 });
               "scheduled";"#,
        )
        .unwrap();
    assert_eq!(
        unsafe { ibex_runtime_extension_conformance_operation_lease_slot_count_v1(runtime.0) },
        1,
        "the repeating callback must retain its operation lease across producer posts"
    );
    runtime.wait_for_js(
        "String(globalThis.__extensionPromiseResult)",
        "worker-promise",
    );

    let event_posts_before = counter(COUNTER_POST_ACCEPTED);
    runtime
        .eval(
            r#"globalThis.__extensionEvents = [];
               __ibexRuntimeExtensionFixture.subscribe(function (value) {
                 globalThis.__extensionEvents.push(value);
               });
               __ibexRuntimeExtensionFixture.emit("event-one");
               "scheduled";"#,
        )
        .unwrap();
    wait_for_counter(COUNTER_POST_ACCEPTED, event_posts_before + 1);
    runtime
        .eval(r#"__ibexRuntimeExtensionFixture.emit("event-two"); "scheduled";"#)
        .unwrap();
    wait_for_counter(COUNTER_POST_ACCEPTED, event_posts_before + 2);
    runtime.wait_for_js(
        "JSON.stringify(globalThis.__extensionEvents.slice().sort())",
        r#"["event-one","event-two"]"#,
    );

    assert!(counter(COUNTER_POST_ACCEPTED) >= 3);
    assert_eq!(counter(COUNTER_OWNER_DELIVERY_MISMATCH), 0);

    let report = runtime.report();
    assert_eq!(report["schema"], "ibex.runtime-extension-report/v1");
    assert_eq!(report["mode"], "authenticated-conformance-fixture");
    assert_eq!(report["registryAuthenticated"], true);
    assert_eq!(report["extensions"][0]["id"], "ibex.conformance");
    assert_eq!(report["extensions"][0]["state"], LIFECYCLE_ACTIVE);
    assert_eq!(report["extensions"][0]["stateName"], "active");
    assert_eq!(
        report["extensions"][0]["providerAbi"]["id"],
        "ibex.conformance.provider"
    );
    assert_eq!(report["extensions"][0]["providerAbi"]["minVersion"], 1);
    assert_eq!(report["extensions"][0]["providerAbi"]["selectedVersion"], 1);
    assert_eq!(report["extensions"][0]["providerAbi"]["structSize"], 8);
    assert!(report["extensions"][0]["providerAbi"]["identityDigest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256-")));

    drop(runtime);
    assert_eq!(counter(COUNTER_QUIESCE), 1);
    assert_eq!(counter(COUNTER_CLOSE), 1);
    assert!(counter(COUNTER_OWNER_CAPTURE_DESTROYED) >= 2);
    assert_eq!(counter(COUNTER_OWNER_CAPTURE_MISMATCH), 0);
}

#[cfg(not(feature = "insecure"))]
#[test]
fn promise_carrier_reaches_the_legacy_generic_capability_gate() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let host = crate::host::Host::new(crate::host::HostConfig::default());
    assert!(
        host.check_capability("0", "network:fetch:carrier.invalid"),
        "the synchronous root control must hold legacy ambient authority"
    );
    assert!(
        !host.check_capability("1", "network:fetch:carrier.invalid"),
        "the carried package must not hold the probed legacy authority"
    );
    assert_ne!(crate::host::abi::install_host(host), 0);
    // The principal-scoped evaluator is fixture-only runtime-extension
    // conformance ABI. This gate test needs no extension installer; keeping the
    // registry empty avoids unrelated descriptor-graph traversal of lazy
    // storage globals under a no-user bootstrap frame.
    let runtime = Runtime::diagnostic(ptr::null())
        .expect("legacy-gate carrier conformance runtime construction failed");

    assert_eq!(
        runtime
            .eval(
                "__exactCapabilityCheck('network:fetch:carrier.invalid') \
                 ? 'allowed' : 'denied'"
            )
            .unwrap(),
        "allowed",
        "an ordinary synchronous root check changed semantics"
    );

    runtime
        .eval_with_principals(
            &[0, COMPROMISED_PACKAGE_PRINCIPAL_ID],
            r#"globalThis.__legacyCarrierCapabilityResult = "pending";
               Promise.resolve("carried").then(function () {
                 globalThis.__legacyCarrierCapabilityResult =
                   __exactCapabilityCheck("network:fetch:carrier.invalid")
                     ? "allowed"
                     : "denied";
               });
               "scheduled";"#,
        )
        .unwrap();
    runtime.wait_for_js(
        "String(globalThis.__legacyCarrierCapabilityResult)",
        "denied",
    );

    assert_eq!(
        runtime
            .eval(
                "__exactCapabilityCheck('network:fetch:carrier.invalid') \
                 ? 'allowed' : 'denied'"
            )
            .unwrap(),
        "allowed",
        "the completed carrier contaminated a later root-only job"
    );
}

#[test]
fn package_bearing_deputy_laundering_is_refused_on_every_continuation_path() {
    let _host_guard = crate::host::abi::host_test_lock();
    let fixture_host = crate::host::runtime_extension_conformance_test_host();
    let package: capsec_semantics::model::Principal = serde_json::from_value(
        fixture_host.armed_snapshot().unwrap().document()["principals"][1]["principal"].clone(),
    )
    .unwrap();
    assert!(
        package.is_package()
            && u64::from(fixture_host.module_runner_principal_id(&package).unwrap())
                == COMPROMISED_PACKAGE_PRINCIPAL_ID,
        "fixture principal 1 must be the authenticated compromised package"
    );
    drop(fixture_host);

    reset();
    let runtime = authenticated_runtime();
    runtime
        .eval(
            r#"globalThis.__deputyRootCleanPromise =
                 new Promise(function (resolve) { resolve("root-clean"); });
               globalThis.__deputyReturnedRootPromise =
                 new Promise(function (resolve) { resolve("returned-root"); });
               globalThis.__deputyCallableReturnedConstructorPromise =
                 new Promise(function (resolve) {
                   resolve("callable-returned-constructor");
                 });
               globalThis.__deputyCallableReturnedCatchPromise =
                 new Promise(function (resolve) {
                   resolve("callable-returned-catch");
                 });
               globalThis.__deputyCallableReturnedFinallyPromise =
                 new Promise(function (resolve) {
                   resolve("callable-returned-finally");
                 });
               globalThis.__deputyCleanConstructorSource =
                 Promise.resolve("clean-constructor-source");
               globalThis.__deputyCleanCatchSource =
                 Promise.resolve("clean-catch-source");
               globalThis.__deputyCleanFinallySource =
                 Promise.resolve("clean-finally-source");
               globalThis.__deputyRootThenCall = function (resolve) {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(14);
                   globalThis.__deputyGenericThenCallResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyGenericThenCallResult = "denied";
                 }
                 resolve("generic");
               };
               globalThis.__deputyRootThenGetter = function () {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(15);
                   globalThis.__deputyGenericThenGetterResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyGenericThenGetterResult = "denied";
                 }
                 return globalThis.__deputyRootThenCall;
               };
               globalThis.__deputyRootReturningPromise = function (executor) {
                 executor(function () {}, function () {});
                 return globalThis.__deputyReturnedRootPromise;
               };
               globalThis.__deputyRootHandledHook = function () {
                 globalThis.__deputyMutableHandledHookResult = "called";
                 __ibexRuntimeExtensionFixture.enqueue(20);
               };
               globalThis.__deputyRootRejectedHook = function () {
                 globalThis.__deputyMutableRejectedHookResult = "called";
                 __ibexRuntimeExtensionFixture.enqueue(21);
               };
               globalThis.__rootPlainObjectResult = "pending";
               Promise.resolve({ value: "plain" }).then(function () {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(16);
                   globalThis.__rootPlainObjectResult = "allowed";
                 } catch (_) {
                   globalThis.__rootPlainObjectResult = "denied";
                 }
               });
               "root-clean-promise";"#,
        )
        .unwrap();
    let compromised_stack = [0_u64, COMPROMISED_PACKAGE_PRINCIPAL_ID];
    assert_eq!(
        runtime
            .eval_with_principals(
                &compromised_stack,
                r#"(function () {
                  try {
                    __ibexRuntimeExtensionFixture.enqueue(1);
                    return "allowed";
                  } catch (_) {
                    return "denied";
                  }
                })()"#
            )
            .unwrap(),
        "denied",
        "a synchronous borrowed extension function laundered root authority"
    );

    runtime
        .eval_with_principals(
            &compromised_stack,
            r#"globalThis.__deputyMutableNoopCalled = false;
               Promise._D = function () {
                 globalThis.__deputyMutableNoopCalled = true;
               };
               Promise._B = globalThis.__deputyRootHandledHook;
               Promise._C = globalThis.__deputyRootRejectedHook;
               globalThis.__deputyBrandShell =
                 Object.create(Promise.prototype);
               globalThis.__deputyBrandArm = Promise.call.bind(
                 Promise,
                 globalThis.__deputyBrandShell,
                 function () {}
               );
               globalThis.__deputyGenericThenable = {
                 then: globalThis.__deputyRootThenCall
               };
               globalThis.__deputyGenericGetterThenable = {};
               Object.defineProperty(
                 globalThis.__deputyGenericGetterThenable,
                 "then",
                 { get: globalThis.__deputyRootThenGetter }
               );
               globalThis.__deputyReturningSource = Promise.resolve("source");
               globalThis.__deputyReturningSource.constructor =
                 globalThis.__deputyRootReturningPromise;
               globalThis.__deputyAggregateValue =
                 Promise.resolve("package-value");
               globalThis.__deputyAggregateRejection =
                 Promise.reject("package-rejection");
               globalThis.__deputyAggregatePending =
                 new Promise(function () {});
               globalThis.__deputyPackageReturningPromise =
                 function deputyPackageReturningPromise(executor) {
                   executor(function () {}, function () {});
                   return deputyPackageReturningPromise.returnedPromise;
                 };
               globalThis.__deputyPackageReturningCatchThen =
                 function deputyPackageReturningCatchThen() {
                   return deputyPackageReturningCatchThen.returnedPromise;
                 };
               globalThis.__deputyPackageReturningFinallyThen =
                 function deputyPackageReturningFinallyThen() {
                   return deputyPackageReturningFinallyThen.returnedPromise;
                 };
               "adversarial-carriers";"#,
        )
        .unwrap();
    assert_eq!(
        runtime
            .eval(
                r#"Object.defineProperty(
                     globalThis.__deputyPackageReturningPromise,
                     "returnedPromise",
                     { value: globalThis.__deputyCallableReturnedConstructorPromise }
                   );
                   Object.defineProperty(
                     globalThis.__deputyPackageReturningCatchThen,
                     "returnedPromise",
                     { value: globalThis.__deputyCallableReturnedCatchPromise }
                   );
                   Object.defineProperty(
                     globalThis.__deputyPackageReturningFinallyThen,
                     "returnedPromise",
                     { value: globalThis.__deputyCallableReturnedFinallyPromise }
                   );
                   Object.defineProperty(
                     globalThis.__deputyCleanConstructorSource,
                     "constructor",
                     { value: globalThis.__deputyPackageReturningPromise }
                   );
                   Object.defineProperty(
                     globalThis.__deputyCleanCatchSource,
                     "then",
                     { value: globalThis.__deputyPackageReturningCatchThen }
                   );
                   Object.defineProperty(
                     globalThis.__deputyCleanFinallySource,
                     "then",
                     { value: globalThis.__deputyPackageReturningFinallyThen }
                   );
                   String(
                     globalThis.__deputyCleanConstructorSource.constructor ===
                       globalThis.__deputyPackageReturningPromise &&
                     globalThis.__deputyCleanCatchSource.then ===
                       globalThis.__deputyPackageReturningCatchThen &&
                     globalThis.__deputyCleanFinallySource.then ===
                       globalThis.__deputyPackageReturningFinallyThen
                   );"#,
            )
            .unwrap(),
        "true",
        "root could not wire the package-defined Promise callables"
    );
    for callable in [
        "__deputyPackageReturningPromise",
        "__deputyPackageReturningCatchThen",
        "__deputyPackageReturningFinallyThen",
    ] {
        assert_eq!(
            runtime
                .eval(&format!(
                    "JSON.stringify(HermesInternal.\
                     captureCallableJobConstrainedPrincipals(globalThis.{callable}))"
                ))
                .unwrap(),
            "[0,1]",
            "the principal fixture did not stamp {callable} as package-defined"
        );
    }
    assert_eq!(
        runtime
            .eval(
                r#"(function () {
                  try {
                    globalThis.__deputyBrandArm();
                    return "accepted";
                  } catch (_) {
                    try {
                      globalThis.__deputyBrandShell.then(function () {});
                      return "branded";
                    } catch (_) {
                      return "rejected";
                    }
                  }
                })()"#
            )
            .unwrap(),
        "rejected",
        "Promise.call minted a private brand onto a package-retained shell"
    );
    runtime
        .eval(
            r#"globalThis.__deputyMutableNoopResult = "pending";
               globalThis.__deputyMutableHandledHookResult = "not-called";
               globalThis.__deputyMutableRejectedHookResult = "not-called";
               globalThis.__deputyGenericThenResult = "pending";
               globalThis.__deputyGenericGetterThenResult = "pending";
               globalThis.__deputyReturningConstructorResult = "pending";
               globalThis.__deputyCallableConstructorResult = "pending";
               globalThis.__deputyCallableCatchThenResult = "pending";
               globalThis.__deputyCallableFinallyThenResult = "pending";
               globalThis.__deputyMultiAllResult = "pending";
               globalThis.__deputyMultiAllSettledResult = "pending";
               globalThis.__deputyMultiAnyResult = "pending";
               globalThis.__deputyMultiRaceResult = "pending";
               Promise.resolve(21).then(function (value) {
                 globalThis.__deputyMutableNoopResult =
                   String(value) + ":" +
                   String(globalThis.__deputyMutableNoopCalled);
               });
               Promise.reject("hook-test").catch(function () {});
               Promise.resolve(globalThis.__deputyGenericThenable).then(
                 function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(17);
                     globalThis.__deputyGenericThenResult = "allowed";
                   } catch (_) {
                     globalThis.__deputyGenericThenResult = "denied";
                   }
                 }
               );
               Promise.resolve(
                 globalThis.__deputyGenericGetterThenable
               ).then(function () {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(18);
                   globalThis.__deputyGenericGetterThenResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyGenericGetterThenResult = "denied";
                 }
               });
               globalThis.__deputyReturningSource.then(function () {})
                 .then(function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(19);
                     globalThis.__deputyReturningConstructorResult = "allowed";
                   } catch (_) {
                     globalThis.__deputyReturningConstructorResult = "denied";
                   }
                 });
               globalThis.__deputyCallableConstructorPublished =
                 globalThis.__deputyCleanConstructorSource
                   .then(function () {});
               globalThis.__deputyCallableConstructorIdentity =
                 globalThis.__deputyCallableConstructorPublished ===
                   globalThis.__deputyCallableReturnedConstructorPromise;
               globalThis.__deputyCallableConstructorPublished
                 .then(function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(26);
                     globalThis.__deputyCallableConstructorResult = "allowed";
                   } catch (_) {
                     globalThis.__deputyCallableConstructorResult = "denied";
                   }
                 });
               globalThis.__deputyCallableCatchThenPublished =
                 globalThis.__deputyCleanCatchSource.catch(function () {});
               globalThis.__deputyCallableCatchThenIdentity =
                 globalThis.__deputyCallableCatchThenPublished ===
                   globalThis.__deputyCallableReturnedCatchPromise;
               globalThis.__deputyCallableCatchThenPublished.then(function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(27);
                     globalThis.__deputyCallableCatchThenResult = "allowed";
                   } catch (_) {
                     globalThis.__deputyCallableCatchThenResult = "denied";
                   }
                 });
               globalThis.__deputyCallableFinallyThenPublished =
                 globalThis.__deputyCleanFinallySource.finally(function () {});
               globalThis.__deputyCallableFinallyThenIdentity =
                 globalThis.__deputyCallableFinallyThenPublished ===
                   globalThis.__deputyCallableReturnedFinallyPromise;
               globalThis.__deputyCallableFinallyThenPublished.then(function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(28);
                     globalThis.__deputyCallableFinallyThenResult = "allowed";
                   } catch (_) {
                     globalThis.__deputyCallableFinallyThenResult = "denied";
                   }
                 });
               Promise.all([
                 globalThis.__deputyAggregateValue,
                 Promise.resolve("root-last")
               ]).then(function () {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(22);
                   globalThis.__deputyMultiAllResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyMultiAllResult = "denied";
                 }
               });
               Promise.allSettled([
                 globalThis.__deputyAggregateValue,
                 Promise.resolve("root-last")
               ]).then(function () {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(23);
                   globalThis.__deputyMultiAllSettledResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyMultiAllSettledResult = "denied";
                 }
               });
               Promise.any([
                 globalThis.__deputyAggregateRejection,
                 Promise.resolve("root-winner")
               ]).then(function () {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(24);
                   globalThis.__deputyMultiAnyResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyMultiAnyResult = "denied";
                 }
               });
               Promise.race([
                 Promise.resolve("root-winner"),
                 globalThis.__deputyAggregatePending
               ]).then(function () {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(25);
                   globalThis.__deputyMultiRaceResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyMultiRaceResult = "denied";
                 }
               });
               "adversarial-carriers-scheduled";"#,
        )
        .unwrap();
    runtime.wait_for_js(
        concat!(
            "String(globalThis.__deputyMutableNoopResult !== \"pending\" && ",
            "globalThis.__deputyGenericThenResult !== \"pending\" && ",
            "globalThis.__deputyGenericGetterThenResult !== \"pending\" && ",
            "globalThis.__deputyReturningConstructorResult !== \"pending\" && ",
            "globalThis.__deputyCallableConstructorResult !== \"pending\" && ",
            "globalThis.__deputyCallableCatchThenResult !== \"pending\" && ",
            "globalThis.__deputyCallableFinallyThenResult !== \"pending\" && ",
            "globalThis.__deputyMultiAllResult !== \"pending\" && ",
            "globalThis.__deputyMultiAllSettledResult !== \"pending\" && ",
            "globalThis.__deputyMultiAnyResult !== \"pending\" && ",
            "globalThis.__deputyMultiRaceResult !== \"pending\" && ",
            "globalThis.__rootPlainObjectResult !== \"pending\")"
        ),
        "true",
    );
    assert_eq!(
        runtime
            .eval("String(globalThis.__deputyMutableNoopResult)")
            .unwrap(),
        "21:false",
        "mutable Promise._D intercepted scalar Promise construction"
    );
    assert_eq!(
        runtime
            .eval(concat!(
                "String(globalThis.__deputyCallableConstructorIdentity + \":\" + ",
                "globalThis.__deputyCallableCatchThenIdentity + \":\" + ",
                "globalThis.__deputyCallableFinallyThenIdentity)"
            ))
            .unwrap(),
        "true:true:true",
        "the callable-provenance cases did not publish the pre-existing clean promises"
    );
    assert_eq!(
        runtime
            .eval(concat!(
                "String(globalThis.__deputyMutableHandledHookResult + \":\" + ",
                "globalThis.__deputyMutableRejectedHookResult)"
            ))
            .unwrap(),
        "not-called:not-called",
        "mutable Promise._B/_C replaced private rejection hooks"
    );
    for (expression, message) in [
        (
            "String(globalThis.__deputyGenericThenCallResult)",
            "an unbranded then method ran as a root-clean deputy",
        ),
        (
            "String(globalThis.__deputyGenericThenGetterResult)",
            "an unbranded then getter ran as a root-clean deputy",
        ),
        (
            "String(globalThis.__deputyGenericThenResult)",
            "an unbranded thenable dropped its fail-closed provenance",
        ),
        (
            "String(globalThis.__deputyGenericGetterThenResult)",
            "a getter-backed thenable dropped its fail-closed provenance",
        ),
        (
            "String(globalThis.__deputyReturningConstructorResult)",
            "a Promise constructor returned a clean Promise and erased provenance",
        ),
        (
            "String(globalThis.__deputyCallableConstructorResult)",
            "a package-defined Promise constructor erased its own provenance",
        ),
        (
            "String(globalThis.__deputyCallableCatchThenResult)",
            "a package-defined catch then method erased its own provenance",
        ),
        (
            "String(globalThis.__deputyCallableFinallyThenResult)",
            "a package-defined finally then method erased its own provenance",
        ),
        (
            "String(globalThis.__deputyMultiAllResult)",
            "Promise.all kept only its final root-clean input",
        ),
        (
            "String(globalThis.__deputyMultiAllSettledResult)",
            "Promise.allSettled kept only its final root-clean input",
        ),
        (
            "String(globalThis.__deputyMultiAnyResult)",
            "Promise.any erased an earlier constrained rejection",
        ),
        (
            "String(globalThis.__deputyMultiRaceResult)",
            "Promise.race erased a constrained observed participant",
        ),
    ] {
        assert_eq!(runtime.eval(expression).unwrap(), "denied", "{message}");
    }
    assert_eq!(
        runtime
            .eval("String(globalThis.__rootPlainObjectResult)")
            .unwrap(),
        "allowed",
        "a plain object payload was falsely treated as an unknown thenable"
    );

    runtime
        .eval_with_principals(
            &compromised_stack,
            r#"var genuineAdopter = new Promise(function (resolve) {
                 resolve(globalThis.__deputyRootCleanPromise);
               });
               globalThis.__deputyForgedAdopter = Object.assign(
                 Object.create(Promise.prototype),
                 genuineAdopter
               );
               "forged";"#,
        )
        .unwrap();
    assert_eq!(
        runtime
            .eval(
                r#"(function () {
                  try {
                    globalThis.__deputyForgedAdopter.then(function () {
                      __ibexRuntimeExtensionFixture.enqueue(11);
                    });
                    return "accepted";
                  } catch (_) {
                    return "rejected";
                  }
                })()"#
            )
            .unwrap(),
        "rejected",
        "a Promise-shaped adopter without the private context brand was accepted"
    );

    runtime
        .eval_with_principals(
            &compromised_stack,
            r#"globalThis.__deputyPromiseResult = "pending";
               globalThis.__deputyFreshScalarResult = "pending";
               globalThis.__deputyFreshScalarPromise = Promise.resolve(0);
               globalThis.__deputyOverriddenThenAllResult = "pending";
               globalThis.__deputyOverriddenThenAwaitResult = "pending";
               globalThis.__deputyOverriddenThenPromise = Promise.resolve(0);
               globalThis.__deputyOverriddenThenPromise.then =
                 globalThis.__deputyRootCleanPromise.then.bind(
                   globalThis.__deputyRootCleanPromise
                 );
               Promise.resolve().then(function () {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(2);
                   globalThis.__deputyPromiseResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyPromiseResult = "denied";
                 }
               });
               "scheduled";"#,
        )
        .unwrap();
    runtime.wait_for_js("String(globalThis.__deputyPromiseResult)", "denied");
    runtime
        .eval(
            r#"globalThis.__deputyFreshScalarPromise.then(function () {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(10);
                   globalThis.__deputyFreshScalarResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyFreshScalarResult = "denied";
                 }
               });
               "fresh-scalar-handler-attached";"#,
        )
        .unwrap();
    runtime.wait_for_js("String(globalThis.__deputyFreshScalarResult)", "denied");
    runtime
        .eval(
            r#"Promise.all([globalThis.__deputyOverriddenThenPromise]).then(
                 function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(12);
                     globalThis.__deputyOverriddenThenAllResult = "allowed";
                   } catch (_) {
                     globalThis.__deputyOverriddenThenAllResult = "denied";
                   }
                 }
               );
               (async function () {
                 await globalThis.__deputyOverriddenThenPromise;
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(13);
                   globalThis.__deputyOverriddenThenAwaitResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyOverriddenThenAwaitResult = "denied";
                 }
               })();
               "overridden-then-builtins";"#,
        )
        .unwrap();
    runtime.wait_for_js(
        concat!(
            "String(globalThis.__deputyOverriddenThenAllResult !== \"pending\" && ",
            "globalThis.__deputyOverriddenThenAwaitResult !== \"pending\")"
        ),
        "true",
    );
    assert_eq!(
        runtime
            .eval("String(globalThis.__deputyOverriddenThenAllResult)")
            .unwrap(),
        "denied",
        "Promise.all honored an authority-laundering own then override",
    );
    assert_eq!(
        runtime
            .eval("String(globalThis.__deputyOverriddenThenAwaitResult)")
            .unwrap(),
        "denied",
        "await honored an authority-laundering own then override",
    );

    runtime
        .eval_with_principals(
            &compromised_stack,
            r#"globalThis.__deputyTimerResult = "pending";
               setTimeout(function () {
                 try {
                   __ibexRuntimeExtensionFixture.enqueue(3);
                   globalThis.__deputyTimerResult = "allowed";
                 } catch (_) {
                   globalThis.__deputyTimerResult = "denied";
                 }
               }, 0);
               "scheduled";"#,
        )
        .unwrap();
    runtime.wait_for_js("String(globalThis.__deputyTimerResult)", "denied");

    let native_posts_before = counter(COUNTER_POST_ACCEPTED);
    runtime
        .eval_with_principals(
            &compromised_stack,
            r#"globalThis.__deputyNativeCompletionResult = "pending";
               globalThis.__deputyNativeCompletionChainResult = "pending";
               var compromisedCompletion =
                 __ibexRuntimeExtensionFixture.complete("native");
               compromisedCompletion.then(
                 function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(4);
                     globalThis.__deputyNativeCompletionResult = "allowed";
                   } catch (_) {
                     globalThis.__deputyNativeCompletionResult = "denied";
                   }
                 },
                 function () {
                   globalThis.__deputyNativeCompletionResult = "completion-rejected";
                 }
               );
               compromisedCompletion
                 .then(function (value) { return value; })
                 .then(
                   function () {
                     try {
                       __ibexRuntimeExtensionFixture.enqueue(5);
                       globalThis.__deputyNativeCompletionChainResult = "allowed";
                     } catch (_) {
                       globalThis.__deputyNativeCompletionChainResult = "denied";
                     }
                   },
                   function () {
                     globalThis.__deputyNativeCompletionChainResult =
                       "completion-rejected";
                   }
                 );
               "scheduled";"#,
        )
        .unwrap();
    wait_for_counter(COUNTER_POST_ACCEPTED, native_posts_before + 1);
    runtime
        .eval_with_principals(
            &compromised_stack,
            r#"globalThis.__deputyLateNativeCompletionResult = "pending";
               globalThis.__deputyLateNativeCompletion =
                 __ibexRuntimeExtensionFixture.complete("native-late");
               "scheduled";"#,
        )
        .unwrap();
    wait_for_counter(COUNTER_POST_ACCEPTED, native_posts_before + 2);
    runtime
        .eval_with_principals(
            &compromised_stack,
            r#"globalThis.__deputySettledDownstreamResult = "pending";
               globalThis.__deputySettledDownstreamSource =
                 __ibexRuntimeExtensionFixture.complete("native-downstream");
               "scheduled";"#,
        )
        .unwrap();
    wait_for_counter(COUNTER_POST_ACCEPTED, native_posts_before + 3);
    runtime
        .eval(
            r#"globalThis.__rootNativeCompletionResult = "pending";
               __ibexRuntimeExtensionFixture.complete("root").then(
                 function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(6);
                     globalThis.__rootNativeCompletionResult = "allowed";
                   } catch (_) {
                     globalThis.__rootNativeCompletionResult = "denied";
                   }
                 },
                 function () {
                   globalThis.__rootNativeCompletionResult = "completion-rejected";
                 }
               );
               "scheduled";"#,
        )
        .unwrap();
    wait_for_counter(COUNTER_POST_ACCEPTED, native_posts_before + 4);
    assert!(
        runtime.poll() >= 0,
        "native completions could not settle before delayed handlers attached"
    );
    runtime
        .eval(
            r#"globalThis.__deputyLateNativeCompletion.then(
                 function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(7);
                     globalThis.__deputyLateNativeCompletionResult = "allowed";
                   } catch (_) {
                     globalThis.__deputyLateNativeCompletionResult = "denied";
                   }
                 },
                 function () {
                   globalThis.__deputyLateNativeCompletionResult =
                     "completion-rejected";
                 }
               );
               globalThis.__deputySettledAllResult = "pending";
               Promise.all([globalThis.__deputyLateNativeCompletion]).then(
                 function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(9);
                     globalThis.__deputySettledAllResult = "allowed";
                   } catch (_) {
                     globalThis.__deputySettledAllResult = "denied";
                   }
                 },
                 function () {
                   globalThis.__deputySettledAllResult =
                     "completion-rejected";
                 }
               );
               globalThis.__deputySettledDownstream =
                 globalThis.__deputySettledDownstreamSource.then(
                   function (value) {
                     globalThis.__deputySettledDownstreamReady = "settled";
                     return globalThis.__deputyRootCleanPromise;
                   }
                 );
               "attached-after-settlement";"#,
        )
        .unwrap();
    runtime.wait_for_js(
        "String(globalThis.__deputySettledDownstreamReady)",
        "settled",
    );
    runtime
        .eval(
            r#"globalThis.__deputySettledDownstream.then(
                 function () {
                   try {
                     __ibexRuntimeExtensionFixture.enqueue(8);
                     globalThis.__deputySettledDownstreamResult = "allowed";
                   } catch (_) {
                     globalThis.__deputySettledDownstreamResult = "denied";
                   }
                 },
                 function () {
                   globalThis.__deputySettledDownstreamResult =
                     "completion-rejected";
                 }
               );
               "attached-to-settled-downstream";"#,
        )
        .unwrap();
    runtime.wait_for_js(
        concat!(
            "String(globalThis.__deputyNativeCompletionResult !== \"pending\" && ",
            "globalThis.__deputyNativeCompletionChainResult !== \"pending\" && ",
            "globalThis.__deputyLateNativeCompletionResult !== \"pending\" && ",
            "globalThis.__deputySettledAllResult !== \"pending\" && ",
            "globalThis.__deputySettledDownstreamResult !== \"pending\" && ",
            "globalThis.__rootNativeCompletionResult !== \"pending\")"
        ),
        "true",
    );
    assert_eq!(
        runtime
            .eval("String(globalThis.__deputyNativeCompletionResult)")
            .unwrap(),
        "denied",
        "a native-completion continuation laundered root authority",
    );
    assert_eq!(
        runtime
            .eval("String(globalThis.__deputyNativeCompletionChainResult)")
            .unwrap(),
        "denied",
        "a chained native-completion continuation dropped its deputy constraint",
    );
    assert_eq!(
        runtime
            .eval("String(globalThis.__rootNativeCompletionResult)")
            .unwrap(),
        "allowed",
        "a compromised completion contaminated an unrelated root job",
    );
    assert_eq!(
        runtime
            .eval("String(globalThis.__deputyLateNativeCompletionResult)")
            .unwrap(),
        "denied",
        "a handler attached after native settlement lost the deputy constraint",
    );
    assert_eq!(
        runtime
            .eval("String(globalThis.__deputySettledDownstreamResult)")
            .unwrap(),
        "denied",
        "an adopted root-clean Promise erased a downstream constraint",
    );
    assert_eq!(
        runtime
            .eval("String(globalThis.__deputySettledAllResult)")
            .unwrap(),
        "denied",
        "Promise.all synchronously unwrapped a constrained settled Promise",
    );
    assert_eq!(counter(COUNTER_ENQUEUE), 2);
    assert_eq!(
        counter(COUNTER_POST_ACCEPTED),
        native_posts_before + 4,
        "the fixture must exercise immediate, delayed, downstream, and isolated root completions"
    );
}

#[test]
fn completion_lease_rechecks_revocation_before_enqueue_and_owner_delivery() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();

    grant_package_location("runtime-extension-pre-enqueue");
    runtime
        .eval(
            r#"globalThis.__preEnqueueCompletion = "pending";
               __ibexRuntimeExtensionFixture.completeAfter("must-not-deliver", 50)
                 .then(function () {
                   globalThis.__preEnqueueCompletion = "delivered";
                 });
               "scheduled";"#,
        )
        .unwrap();
    revoke_package_location("runtime-extension-pre-enqueue");
    wait_for_counter(COUNTER_POST_REJECTED, 1);
    assert_eq!(
        runtime
            .eval("String(globalThis.__preEnqueueCompletion)")
            .unwrap(),
        "pending"
    );

    grant_package_location("runtime-extension-owner-delivery");
    let admitted_before = counter(COUNTER_POST_ACCEPTED);
    runtime
        .eval(
            r#"globalThis.__ownerDeliveryCompletion = "pending";
               __ibexRuntimeExtensionFixture.completeAfter("must-not-deliver", 2)
                 .then(function () {
                   globalThis.__ownerDeliveryCompletion = "delivered";
                 });
               "scheduled";"#,
        )
        .unwrap();
    wait_for_counter(COUNTER_POST_ACCEPTED, admitted_before + 1);
    revoke_package_location("runtime-extension-owner-delivery");
    assert!(runtime.poll() >= 0);
    assert_eq!(
        runtime
            .eval("String(globalThis.__ownerDeliveryCompletion)")
            .unwrap(),
        "pending"
    );
    assert!(
        runtime.report()["extensions"][0]["callbacksRejected"]
            .as_u64()
            .is_some_and(|rejected| rejected >= 2),
        "both stale completion paths must be counted as rejected"
    );
}

#[test]
fn schedule_is_rejected_inside_owner_thread_quiesce() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();
    runtime
        .eval(
            r#"__ibexRuntimeExtensionFixture.subscribe(function () {
                 globalThis.__teardownEventWasDelivered = true;
               });
               "subscribed";"#,
        )
        .unwrap();
    drop(runtime);
    assert_eq!(counter(COUNTER_TEARDOWN_SCHEDULE_REJECTED), 1);
    assert!(counter(COUNTER_POST_REJECTED) >= 1);
    assert_eq!(counter(COUNTER_OWNER_DELIVERY_MISMATCH), 0);
    assert_eq!(counter(COUNTER_OWNER_CAPTURE_MISMATCH), 0);
}

#[test]
fn token_construction_allocation_failure_never_publishes_its_callback_slot() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();
    unsafe {
        ibex_test_runtime_extension_arm_completion_fault_v1(FAULT_TOKEN_IMPL_ALLOCATION);
    }
    assert!(
        runtime
            .eval(
                r#"__ibexRuntimeExtensionFixture.subscribe(function () {
                     globalThis.__unreachableTokenAllocationCallback = true;
                   });
                   "unexpected";"#,
            )
            .is_err(),
        "the injected token-state allocation failure did not escape construction"
    );
    assert_eq!(
        counter(COUNTER_OWNER_CAPTURE_DESTROYED),
        1,
        "a callback slot became reachable before all token state existed"
    );
    assert_eq!(counter(COUNTER_OWNER_CAPTURE_MISMATCH), 0);

    assert_eq!(
        runtime
            .eval(
                r#"__ibexRuntimeExtensionFixture.subscribe(function () {});
                   "recovered";"#,
            )
            .unwrap(),
        "recovered",
        "the runtime did not recover after the injected allocation failure"
    );
}

#[test]
fn producer_post_and_last_drop_do_not_wait_for_runtime_or_host_locks() {
    let _host_guard = crate::host::abi::host_test_lock();
    for (case, expected_post_counter, expected_result) in [
        (
            "runtime-registry",
            COUNTER_POST_REJECTED,
            SCHEDULE_QUEUE_FULL,
        ),
        ("callback-queue", COUNTER_POST_REJECTED, SCHEDULE_QUEUE_FULL),
        ("native-worker", COUNTER_POST_ACCEPTED, SCHEDULE_ACCEPTED),
        ("callback-slot", COUNTER_POST_ACCEPTED, SCHEDULE_ACCEPTED),
        ("host-contexts", COUNTER_POST_REJECTED, SCHEDULE_QUEUE_FULL),
        (
            "typed-generation",
            COUNTER_POST_REJECTED,
            SCHEDULE_QUEUE_FULL,
        ),
    ] {
        reset();
        let (runtime, host) = construct_authenticated_runtime_with_host(true)
            .expect("authenticated contention fixture runtime");
        arm_delayed_post_and_last_drop(&runtime);
        let mut wait = LockedProducerWait {
            post_counter: expected_post_counter,
            post_minimum: 1,
            retirement_minimum: 1,
            observed: false,
        };
        let context = (&mut wait as *mut LockedProducerWait).cast();
        match case {
            "runtime-registry" => assert_eq!(
                unsafe {
                    ibex_test_runtime_extension_with_registry_lock_v1(
                        wait_for_locked_producers,
                        context,
                    )
                },
                1
            ),
            "callback-queue" => assert_eq!(
                unsafe {
                    ibex_test_runtime_extension_with_callback_queue_lock_v1(
                        runtime.0,
                        wait_for_locked_producers,
                        context,
                    )
                },
                1
            ),
            "native-worker" => assert_eq!(
                unsafe {
                    ibex_test_runtime_extension_with_native_worker_lock_v1(
                        runtime.0,
                        wait_for_locked_producers,
                        context,
                    )
                },
                1
            ),
            "callback-slot" => assert_eq!(
                unsafe {
                    ibex_test_runtime_extension_with_callback_slot_lock_v1(
                        runtime.0,
                        wait_for_locked_producers,
                        context,
                    )
                },
                1
            ),
            "host-contexts" => {
                crate::host::abi::with_runtime_extension_host_contexts_write_lock_for_test(
                    || unsafe { wait_for_locked_producers(context) },
                );
            }
            "typed-generation" => {
                host.with_runtime_extension_generation_write_lock_for_test(|| unsafe {
                    wait_for_locked_producers(context)
                });
            }
            _ => unreachable!(),
        }
        assert!(
            wait.observed,
            "{case} contention blocked producer post or last-token destruction"
        );
        assert_eq!(
            counter(COUNTER_LAST_POST_RESULT),
            expected_result,
            "{case} contention produced the wrong fail-fast disposition"
        );
        drop(runtime);
    }
}

#[test]
fn off_owner_last_operation_lease_drop_does_not_wait_for_host_context_lock() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();
    unsafe {
        ibex_runtime_extension_conformance_hold_next_operation_lease_retirement_v1();
    }
    assert_eq!(
        runtime
            .eval("__ibexRuntimeExtensionFixture.retireLeaseOffOwner(); \"armed\"")
            .unwrap(),
        "armed"
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    while unsafe { ibex_runtime_extension_conformance_operation_lease_retirement_is_held_v1() } != 1
        && Instant::now() < deadline
    {
        std::thread::yield_now();
    }
    if unsafe { ibex_runtime_extension_conformance_operation_lease_retirement_is_held_v1() } != 1 {
        unsafe {
            ibex_runtime_extension_conformance_release_operation_lease_retirement_v1();
        }
        panic!("off-owner operation-lease retirement did not reach its hold");
    }
    assert_eq!(
        unsafe { ibex_runtime_extension_conformance_operation_lease_slot_count_v1(runtime.0) },
        1,
        "the runtime owner did not retain the Host lease while its public copy was held"
    );

    let mut retired_while_locked = false;
    crate::host::abi::with_runtime_extension_host_contexts_write_lock_for_test(|| {
        unsafe {
            ibex_runtime_extension_conformance_release_operation_lease_retirement_v1();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while counter(COUNTER_OFF_OWNER_LEASE_RETIRED) == 0 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        retired_while_locked = counter(COUNTER_OFF_OWNER_LEASE_RETIRED) == 1;
    });
    assert!(
        retired_while_locked,
        "last operation-lease destruction waited for the Host context write lock"
    );

    assert!(runtime.poll() >= 0, "runtime polling became fatal");
    assert_eq!(
        unsafe { ibex_runtime_extension_conformance_operation_lease_slot_count_v1(runtime.0) },
        0,
        "the runtime owner did not revoke the retired Host lease"
    );
}

#[test]
fn operation_lease_last_copy_can_die_off_owner_after_runtime_destruction() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();
    unsafe {
        ibex_runtime_extension_conformance_hold_next_operation_lease_retirement_v1();
    }
    assert_eq!(
        runtime
            .eval("__ibexRuntimeExtensionFixture.retireLeaseOffOwner(); \"armed\"")
            .unwrap(),
        "armed"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while unsafe { ibex_runtime_extension_conformance_operation_lease_retirement_is_held_v1() } != 1
        && Instant::now() < deadline
    {
        std::thread::yield_now();
    }
    if unsafe { ibex_runtime_extension_conformance_operation_lease_retirement_is_held_v1() } != 1 {
        unsafe {
            ibex_runtime_extension_conformance_release_operation_lease_retirement_v1();
        }
        panic!("late lease retirement did not reach its hold");
    }
    assert_eq!(
        unsafe { ibex_runtime_extension_conformance_operation_lease_slot_count_v1(runtime.0) },
        1
    );

    // Teardown must revoke the owner slot even though the provider-side public
    // copy remains alive. That late copy retains only producer-safe shared
    // state after the runtime and Instance are gone.
    drop(runtime);

    let mut retired_after_destroy_while_locked = false;
    crate::host::abi::with_runtime_extension_host_contexts_write_lock_for_test(|| {
        unsafe {
            ibex_runtime_extension_conformance_release_operation_lease_retirement_v1();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while counter(COUNTER_OFF_OWNER_LEASE_RETIRED) == 0 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        retired_after_destroy_while_locked = counter(COUNTER_OFF_OWNER_LEASE_RETIRED) == 1;
    });
    assert!(
        retired_after_destroy_while_locked,
        "late lease destruction touched Host or freed runtime state"
    );
}

#[test]
fn accepted_owner_delivery_waits_for_transient_host_contention() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();
    runtime
        .eval(
            r#"globalThis.__ownerContentionValue = "pending";
               __ibexRuntimeExtensionFixture.completeAfter("delivered", 0)
                 .then(function (value) {
                   globalThis.__ownerContentionValue = value;
                 });
               "scheduled";"#,
        )
        .unwrap();
    wait_for_counter(COUNTER_POST_ACCEPTED, 1);

    let (locked_tx, locked_rx) = std::sync::mpsc::sync_channel(0);
    let lock_thread = std::thread::spawn(move || {
        crate::host::abi::with_runtime_extension_host_contexts_write_lock_for_test(|| {
            locked_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(80));
        });
    });
    locked_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("Host-context contention fixture did not acquire its write lock");

    let started = Instant::now();
    assert!(runtime.poll() >= 0, "runtime polling became fatal");
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "owner delivery treated transient Host contention as stale authority"
    );
    lock_thread.join().unwrap();
    runtime.wait_for_js("String(globalThis.__ownerContentionValue)", "delivered");
}

#[test]
fn terminal_slot_retires_when_owner_delivery_finishes_before_post_returns() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();
    unsafe {
        ibex_runtime_extension_conformance_hold_next_accepted_post_v1();
    }
    runtime
        .eval(
            r#"globalThis.__immediateOwnerDelivery = "pending";
               __ibexRuntimeExtensionFixture.completeAfter("delivered", 0)
                 .then(function (value) {
                   globalThis.__immediateOwnerDelivery = value;
                 });
               "scheduled";"#,
        )
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut producer_held = false;
    while Instant::now() < deadline {
        if unsafe { ibex_runtime_extension_conformance_accepted_post_is_held_v1() } == 1 {
            producer_held = true;
            break;
        }
        std::thread::yield_now();
    }
    if !producer_held {
        unsafe {
            ibex_runtime_extension_conformance_release_accepted_post_v1();
        }
        panic!("producer did not pause after accepted enqueue");
    }

    // recordPost runs only after CompletionTokenV1::post returns. Polling while
    // that counter is still zero deterministically exercises immediate owner
    // delivery, which the SDK permits.
    let post_still_running = counter(COUNTER_POST_ACCEPTED) == 0;
    let poll_result = runtime.poll();
    let callback_slots =
        unsafe { ibex_runtime_extension_conformance_callback_slot_count_v1(runtime.0) };
    unsafe {
        ibex_runtime_extension_conformance_release_accepted_post_v1();
    }

    assert!(
        post_still_running,
        "producer post returned before the immediate-delivery fixture polled"
    );
    assert!(poll_result >= 0, "runtime polling became fatal");
    assert_eq!(
        callback_slots, 0,
        "owner delivery settled before post returned but stranded its terminal callback slot"
    );
    wait_for_counter(COUNTER_POST_ACCEPTED, 1);
    runtime.wait_for_js("String(globalThis.__immediateOwnerDelivery)", "delivered");
}

#[test]
fn destroy_discards_accepted_completion_before_producer_post_returns() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();
    unsafe {
        ibex_runtime_extension_conformance_hold_next_accepted_post_v1();
    }
    runtime
        .eval(
            r#"__ibexRuntimeExtensionFixture.completeAfter("discarded", 0);
               "scheduled";"#,
        )
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut producer_held = false;
    while Instant::now() < deadline {
        if unsafe { ibex_runtime_extension_conformance_accepted_post_is_held_v1() } == 1 {
            producer_held = true;
            break;
        }
        std::thread::yield_now();
    }
    if !producer_held {
        unsafe {
            ibex_runtime_extension_conformance_release_accepted_post_v1();
        }
        panic!("producer did not pause after accepted enqueue");
    }
    assert_eq!(
        counter(COUNTER_POST_ACCEPTED),
        0,
        "producer post returned before the held-discard fixture destroyed the runtime"
    );

    // Destroy owns the accepted queue entry while the producer still retains
    // its post-return disposition reference. Teardown must settle and retire
    // the terminal slot on the owner before freeing Instance/JSI/Host state.
    drop(runtime);
    assert_eq!(counter(COUNTER_OWNER_CAPTURE_MISMATCH), 0);
    assert!(
        counter(COUNTER_OWNER_CAPTURE_DESTROYED) >= 1,
        "discarded completion retained its JSI-bearing owner capture"
    );

    // Releasing the producer after the runtime and extension Instance are gone
    // must be an atomics/shared-state-only action, never an Instance access.
    unsafe {
        ibex_runtime_extension_conformance_release_accepted_post_v1();
    }
    wait_for_counter(COUNTER_POST_ACCEPTED, 1);
    assert_eq!(counter(COUNTER_OWNER_CAPTURE_MISMATCH), 0);
}

#[test]
fn off_owner_last_copy_retirement_survives_post_allocation_failures() {
    let _host_guard = crate::host::abi::host_test_lock();
    for fault in [
        FAULT_POST_DISPOSITION_ALLOCATION,
        FAULT_POST_CALLBACK_ALLOCATION,
    ] {
        reset();
        let runtime = authenticated_runtime();
        unsafe {
            ibex_test_runtime_extension_arm_completion_fault_v1(fault);
            ibex_runtime_extension_conformance_retire_next_subscription_off_owner_v1();
        }
        assert_eq!(
            runtime
                .eval(
                    r#"__ibexRuntimeExtensionFixture.subscribe(function () {
                         globalThis.__retiredOffOwnerCallbackRan = true;
                       });
                       "scheduled";"#,
                )
                .unwrap(),
            "scheduled"
        );
        wait_for_counter(COUNTER_OFF_OWNER_TOKEN_RETIRED, 1);

        let deadline = Instant::now() + Duration::from_secs(5);
        while counter(COUNTER_OWNER_CAPTURE_DESTROYED) == 0 {
            assert!(runtime.poll() >= 0, "runtime polling became fatal");
            assert!(
                Instant::now() < deadline,
                "durable callback-slot retirement did not reach the owner"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            counter(COUNTER_OWNER_CAPTURE_DESTROYED),
            1,
            "the zero-pending callback slot remained orphaned"
        );
        assert_eq!(counter(COUNTER_OWNER_CAPTURE_MISMATCH), 0);
        assert_eq!(
            runtime
                .eval("String(globalThis.__retiredOffOwnerCallbackRan)")
                .unwrap(),
            "undefined"
        );
        drop(runtime);
    }
}

#[test]
fn post_allocation_failures_are_queue_full_and_recoverable() {
    let _host_guard = crate::host::abi::host_test_lock();
    for fault in [
        FAULT_POST_DISPOSITION_ALLOCATION,
        FAULT_POST_CALLBACK_ALLOCATION,
    ] {
        reset();
        let runtime = authenticated_runtime();
        unsafe {
            ibex_test_runtime_extension_arm_completion_fault_v1(fault);
        }
        assert_eq!(
            runtime
                .eval(
                    r#"__ibexRuntimeExtensionFixture.complete("faulted");
                       "scheduled";"#,
                )
                .unwrap(),
            "scheduled"
        );
        wait_for_counter(COUNTER_POST_REJECTED, 1);
        assert_eq!(
            counter(COUNTER_LAST_POST_RESULT),
            SCHEDULE_QUEUE_FULL,
            "post allocation failure did not map to bounded capacity refusal"
        );

        assert_eq!(
            runtime
                .eval(
                    r#"__ibexRuntimeExtensionFixture.complete("recovered");
                       "scheduled";"#,
                )
                .unwrap(),
            "scheduled"
        );
        wait_for_counter(COUNTER_POST_ACCEPTED, 1);
        assert_eq!(counter(COUNTER_LAST_POST_RESULT), SCHEDULE_ACCEPTED);
        assert!(runtime.poll() >= 0);
    }
}

#[test]
fn abandoned_copied_tokens_retire_without_exhausting_callback_slots() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();
    const SUBSCRIPTIONS: u64 = 4_200;
    assert_eq!(
        runtime
            .eval(
                r#"(function () {
                  globalThis.__lastRetainedSubscription = "pending";
                  for (var index = 0; index < 4200; index += 1) {
                    __ibexRuntimeExtensionFixture.subscribe(function (value) {
                      globalThis.__lastRetainedSubscription = value;
                    });
                  }
                  return "subscribed";
                })()"#
            )
            .unwrap(),
        "subscribed"
    );
    assert_eq!(
        counter(COUNTER_OWNER_CAPTURE_DESTROYED),
        SUBSCRIPTIONS - 1,
        "each replaced last token copy must retire its callback slot immediately"
    );
    assert_eq!(counter(COUNTER_OWNER_CAPTURE_MISMATCH), 0);

    runtime
        .eval(r#"__ibexRuntimeExtensionFixture.emit("retained"); "scheduled""#)
        .unwrap();
    wait_for_counter(COUNTER_POST_ACCEPTED, 1);
    assert!(runtime.poll() >= 0);
    assert_eq!(
        runtime
            .eval("String(globalThis.__lastRetainedSubscription)")
            .unwrap(),
        "retained",
        "destroying a non-last token copy must not retire the retained copy"
    );
}

#[test]
fn destroy_discards_an_accepted_unpolled_completion_on_the_owner() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();
    runtime
        .eval(
            r#"__ibexRuntimeExtensionFixture.completeAfter("discarded", 0);
               "scheduled";"#,
        )
        .unwrap();
    wait_for_counter(COUNTER_POST_ACCEPTED, 1);

    // No poll occurs between admission and destruction. Teardown must dispose
    // the queued callback and every JSI-bearing capture on the owner.
    drop(runtime);
    assert_eq!(counter(COUNTER_OWNER_DELIVERY_MISMATCH), 0);
    assert_eq!(counter(COUNTER_OWNER_CAPTURE_MISMATCH), 0);
    assert!(
        counter(COUNTER_OWNER_CAPTURE_DESTROYED) >= 1,
        "discarded completion retained its JSI-bearing owner capture"
    );
}

#[test]
fn delayed_completion_is_rejected_after_destroy_and_address_reuse_pressure() {
    let _host_guard = crate::host::abi::host_test_lock();
    reset();
    let runtime = authenticated_runtime();
    let stale_address = runtime.0 as usize;
    let stale_generation = runtime.extension_generation();
    runtime
        .eval(
            r#"globalThis.__staleCompletionObserved = false;
               __ibexRuntimeExtensionFixture.completeAfter(
                 "must-not-deliver",
                 100
               ).then(function () {
                 globalThis.__staleCompletionObserved = true;
               });
               "scheduled";"#,
        )
        .unwrap();
    drop(runtime);

    let mut reused_address = false;
    let mut previous_generation = stale_generation;
    // Physical allocator reuse is intentionally not an oracle: malloc zones
    // may quarantine a recently freed block. Repeated reconstruction still
    // pressures that path, while the monotonic generation assertion below is
    // the deterministic identity check.
    for _ in 0..8 {
        let replacement = authenticated_runtime();
        reused_address |= replacement.0 as usize == stale_address;
        let replacement_generation = replacement.extension_generation();
        assert!(
            replacement_generation > previous_generation,
            "a replacement runtime reused extension generation {replacement_generation}"
        );
        previous_generation = replacement_generation;
        assert_eq!(
            replacement
                .eval("String(globalThis.__staleCompletionObserved)")
                .unwrap(),
            "undefined"
        );
        std::thread::sleep(Duration::from_millis(15));
        assert!(replacement.poll() >= 0);
        assert_eq!(
            replacement
                .eval("String(globalThis.__staleCompletionObserved)")
                .unwrap(),
            "undefined"
        );
        drop(replacement);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while (counter(COUNTER_POST_REJECTED) == 0 || counter(COUNTER_OWNER_CAPTURE_DESTROYED) == 0)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        counter(COUNTER_POST_REJECTED) > 0,
        "stale producer completion was not rejected after teardown \
         (physical address reused: {reused_address})"
    );
    assert!(
        counter(COUNTER_OWNER_CAPTURE_DESTROYED) > 0,
        "stale producer retained its owner-thread JSI capture"
    );
    assert_eq!(counter(COUNTER_OWNER_DELIVERY_MISMATCH), 0);
    assert_eq!(counter(COUNTER_OWNER_CAPTURE_MISMATCH), 0);
}

#[test]
fn keyed_external_alias_detaches_when_the_engine_advertises_it() {
    const KEYED_EXTERNAL_FEATURE: u64 = 1 << 3;
    let _host_guard = crate::host::abi::host_test_lock();
    if unsafe { ibex_runtime_extension_supported_features_v1() } & KEYED_EXTERNAL_FEATURE == 0 {
        return;
    }
    reset();
    let runtime = authenticated_runtime();
    assert_eq!(
        runtime
            .eval(
                r#"(function () {
                  var source = new ArrayBuffer(8);
                  var sourceBytes = new Uint8Array(source);
                  sourceBytes[2] = 91;
                  var alias = __ibexRuntimeExtensionFixture.externalRange(
                    source, 2, 4, 7001
                  );
                  var aliasBytes = new Uint8Array(alias);
                  var before = aliasBytes[0];
                  sourceBytes[3] = 92;
                  var overlaps = aliasBytes[1] === 92;
                  var revoked =
                    __ibexRuntimeExtensionFixture.revokeExternal(7001);
                  return JSON.stringify([
                    before,
                    overlaps,
                    revoked,
                    alias.byteLength
                  ]);
                })()"#
            )
            .unwrap(),
        "[91,true,true,0]"
    );
}

#[test]
fn keyed_external_detach_exception_retains_alias_for_retry() {
    const KEYED_EXTERNAL_FEATURE: u64 = 1 << 3;
    let _host_guard = crate::host::abi::host_test_lock();
    if unsafe { ibex_runtime_extension_supported_features_v1() } & KEYED_EXTERNAL_FEATURE == 0 {
        return;
    }
    reset();
    let runtime = authenticated_runtime();
    unsafe { ibex_test_runtime_extension_arm_keyed_external_detach_fault_v1() };
    assert_eq!(
        runtime
            .eval(
                r#"(function () {
                  var source = new ArrayBuffer(8);
                  var alias = __ibexRuntimeExtensionFixture.externalRange(
                    source, 2, 4, 7002
                  );
                  var first = __ibexRuntimeExtensionFixture.revokeExternal(7002);
                  var retainedLength = alias.byteLength;
                  var second = __ibexRuntimeExtensionFixture.revokeExternal(7002);
                  return JSON.stringify([
                    first,
                    retainedLength,
                    second,
                    alias.byteLength
                  ]);
                })()"#
            )
            .unwrap(),
        "[false,4,true,0]"
    );
}
