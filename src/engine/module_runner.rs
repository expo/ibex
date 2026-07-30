//! Safe Rust ownership over the native Hermes module-runner capabilities.
//!
//! The only factory compilation entry accepts a verified artifact capability;
//! raw/deserialized artifacts cannot reach the C++ compiler through this API.
//! @ref LLP 0027#canonical-encoding-and-validation

use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::ffi::CString;
use std::ffi::{c_char, c_void, CStr};
use std::marker::PhantomData;
#[cfg(any(test, feature = "module-runner"))]
use std::path::Path;
use std::ptr::NonNull;
use std::rc::Rc;

use anyhow::{anyhow, bail, Context, Result};

use crate::module_loader::artifact::{ModulePayloadV1, SourceGoalV1, VerifiedModuleArtifactV1};
use crate::module_loader::carrier::{PreparedCarrierEncodingV2, VerifiedPreparedCarrierEntryV2};
#[cfg(any(test, feature = "module-runner"))]
use crate::module_loader::graph::{
    AsyncEvaluationPlan, DynamicImportBindingKey, GraphErrorCode, SynchronousGraphPlan,
};
use crate::module_loader::identity::SourceId;
#[cfg(any(test, feature = "module-runner"))]
use crate::module_loader::security::{
    AuthorizedGraphOperation, GraphAuthorityContext, GraphImportPolicy, ModuleGraphAuthorizer,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativeModuleHandle {
    opaque: [u64; 3],
}

type NativeCommonJsRequireProvider = unsafe extern "C" fn(
    context: *mut c_void,
    runtime_nonce: u64,
    graph_generation: u64,
    requester_record: NativeModuleHandle,
    requester_source_id: *const u8,
    requester_source_id_len: usize,
    specifier: *const u8,
    specifier_len: usize,
    out_target_record: *mut NativeModuleHandle,
    out_target_kind: *mut u32,
    error_buffer: *mut u8,
    error_buffer_capacity: usize,
    out_error_len: *mut usize,
) -> i32;

#[repr(C)]
#[derive(Debug, Default)]
struct NativeDynamicActivationRequest {
    runtime_nonce: u64,
    request_id: u64,
    graph_generation: u64,
    requester_record: NativeModuleHandle,
    kind: u32,
    site: u32,
    requester_source_id: *mut u8,
    requester_source_id_len: usize,
    specifier: *mut u8,
    specifier_len: usize,
}

unsafe extern "C" {
    fn ex_hermes_module_preflight_bytecode(
        bytes: *const u8,
        bytes_len: usize,
        out_error: *mut *mut c_char,
    ) -> i32;
    fn ex_hermes_module_compile_factory(
        runtime: *mut c_void,
        runtime_nonce: u64,
        source_goal: u32,
        principal_id: u32,
        graph_generation: u64,
        compartment_identity: *const u8,
        compartment_identity_len: usize,
        semantic_digest: *const u8,
        semantic_digest_len: usize,
        source_id: *const u8,
        source_id_len: usize,
        factory_source: *const u8,
        factory_source_len: usize,
        source_label: *const u8,
        source_label_len: usize,
        out_factory: *mut NativeModuleHandle,
        out_error: *mut *mut c_char,
        out_error_token: *mut u64,
    ) -> i32;
    fn ex_hermes_module_load_carrier_factory(
        runtime: *mut c_void,
        runtime_nonce: u64,
        source_goal: u32,
        principal_id: u32,
        graph_generation: u64,
        compartment_identity: *const u8,
        compartment_identity_len: usize,
        semantic_digest: *const u8,
        semantic_digest_len: usize,
        source_id: *const u8,
        source_id_len: usize,
        carrier_digest: *const u8,
        carrier_digest_len: usize,
        carrier_bytes: *const u8,
        carrier_bytes_len: usize,
        carrier_encoding: u32,
        entry_id: *const u8,
        entry_id_len: usize,
        source_label: *const u8,
        source_label_len: usize,
        out_factory: *mut NativeModuleHandle,
        out_error: *mut *mut c_char,
        out_error_token: *mut u64,
    ) -> i32;
    fn ex_hermes_module_release_handle(
        runtime: *mut c_void,
        runtime_nonce: u64,
        handle: NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_module_publish_records(
        runtime: *mut c_void,
        runtime_nonce: u64,
        handles: *const NativeModuleHandle,
        handles_len: usize,
    ) -> i32;
    fn ex_hermes_module_discard_unpublished_record(
        runtime: *mut c_void,
        runtime_nonce: u64,
        handle: NativeModuleHandle,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_module_pin_generation(
        runtime: *mut c_void,
        runtime_nonce: u64,
        graph_generation: u64,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_module_unpin_generation(
        runtime: *mut c_void,
        runtime_nonce: u64,
        graph_generation: u64,
    ) -> i32;
    fn ex_hermes_graph_context_create(
        runtime: *mut c_void,
        runtime_nonce: u64,
        graph_generation: u64,
        requesting_source_id: *const u8,
        requesting_source_id_len: usize,
        effect_owner: u32,
        schedule_owner: u32,
        constrained_principals: *const u32,
        constrained_principals_len: usize,
        out_context: *mut NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_graph_context_retain(
        runtime: *mut c_void,
        runtime_nonce: u64,
        context: NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_commonjs_create_record(
        runtime: *mut c_void,
        runtime_nonce: u64,
        factory: NativeModuleHandle,
        context: NativeModuleHandle,
        source_id: *const u8,
        source_id_len: usize,
        filename: *const u8,
        filename_len: usize,
        dirname: *const u8,
        dirname_len: usize,
        out_record: *mut NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_commonjs_record_declare_export(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        export_name: *const u8,
        export_name_len: usize,
    ) -> i32;
    fn ex_hermes_commonjs_record_link_require(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
        target_record: NativeModuleHandle,
    ) -> i32;
    #[cfg(any(test, feature = "module-runner"))]
    fn ex_hermes_commonjs_record_link_require_esm(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
        target_record: NativeModuleHandle,
        synchronous_eligible: i32,
    ) -> i32;
    fn ex_hermes_commonjs_record_defer_require(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
    ) -> i32;
    fn ex_hermes_commonjs_record_link_bootstrap_internal_require(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
    ) -> i32;
    fn ex_hermes_module_set_commonjs_require_provider(
        runtime: *mut c_void,
        runtime_nonce: u64,
        graph_generation: u64,
        provider: NativeCommonJsRequireProvider,
        provider_context: *mut c_void,
    ) -> i32;
    fn ex_hermes_module_clear_commonjs_require_provider(
        runtime: *mut c_void,
        runtime_nonce: u64,
        graph_generation: u64,
    ) -> i32;
    fn ex_hermes_commonjs_record_link_dynamic_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
        target_record: NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_commonjs_record_link_computed_dynamic_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        site: u32,
        specifier: *const u8,
        specifier_len: usize,
        target_record: NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_commonjs_record_defer_dynamic_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
    ) -> i32;
    fn ex_hermes_commonjs_record_defer_computed_dynamic_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        site: u32,
        specifier: *const u8,
        specifier_len: usize,
    ) -> i32;
    fn ex_hermes_commonjs_record_evaluate(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_evicted: *mut i32,
        out_error: *mut *mut c_char,
        out_error_token: *mut u64,
    ) -> i32;
    fn ex_hermes_commonjs_record_create_esm_adapter(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_adapter: *mut NativeModuleHandle,
        out_error: *mut *mut c_char,
        out_error_token: *mut u64,
    ) -> i32;
    fn ex_hermes_module_create_record(
        runtime: *mut c_void,
        runtime_nonce: u64,
        factory: NativeModuleHandle,
        context: NativeModuleHandle,
        source_id: *const u8,
        source_id_len: usize,
        out_record: *mut NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_module_record_declare_export(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        export_name: *const u8,
        export_name_len: usize,
    ) -> i32;
    fn ex_hermes_module_record_link_export(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        export_name: *const u8,
        export_name_len: usize,
        target_record: NativeModuleHandle,
        target_export: *const u8,
        target_export_len: usize,
    ) -> i32;
    fn ex_hermes_module_record_link_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
        imported_name: *const u8,
        imported_name_len: usize,
        target_record: NativeModuleHandle,
        target_export: *const u8,
        target_export_len: usize,
    ) -> i32;
    #[cfg(any(test, feature = "module-runner"))]
    fn ex_hermes_module_record_link_dependency(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        target_record: NativeModuleHandle,
    ) -> i32;
    #[cfg(any(test, feature = "module-runner"))]
    fn ex_hermes_module_record_link_dynamic_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
        target_record: NativeModuleHandle,
    ) -> i32;
    #[cfg(any(test, feature = "module-runner"))]
    fn ex_hermes_module_record_link_computed_dynamic_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        site: u32,
        specifier: *const u8,
        specifier_len: usize,
        target_record: NativeModuleHandle,
    ) -> i32;
    fn ex_hermes_module_record_defer_dynamic_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        specifier: *const u8,
        specifier_len: usize,
    ) -> i32;
    fn ex_hermes_module_record_defer_computed_dynamic_import(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        site: u32,
        specifier: *const u8,
        specifier_len: usize,
    ) -> i32;
    fn ex_hermes_module_take_dynamic_activation_request(
        runtime: *mut c_void,
        runtime_nonce: u64,
        graph_generation: u64,
        out_request: *mut NativeDynamicActivationRequest,
    ) -> i32;
    fn ex_hermes_module_dynamic_activation_request_dispose(
        request: *mut NativeDynamicActivationRequest,
    );
    fn ex_hermes_module_complete_dynamic_activation(
        runtime: *mut c_void,
        runtime_nonce: u64,
        request_id: u64,
        target_record: NativeModuleHandle,
        error: *const u8,
        error_len: usize,
    ) -> i32;
    fn ex_hermes_module_record_instantiate(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        meta_url: *const u8,
        meta_url_len: usize,
        virtual_path: *const u8,
        virtual_path_len: usize,
        is_main: i32,
        out_error: *mut *mut c_char,
        out_error_token: *mut u64,
    ) -> i32;
    fn ex_hermes_module_record_run_declare(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_error: *mut *mut c_char,
        out_error_token: *mut u64,
    ) -> i32;
    fn ex_hermes_module_record_run_execute(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_async: *mut i32,
        out_error: *mut *mut c_char,
        out_error_token: *mut u64,
    ) -> i32;
    fn ex_hermes_module_record_poll_evaluation(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_state: *mut i32,
        out_error: *mut *mut c_char,
        out_error_token: *mut u64,
    ) -> i32;
    fn ex_hermes_module_record_namespace_json(
        runtime: *mut c_void,
        runtime_nonce: u64,
        record: NativeModuleHandle,
        out_json: *mut *mut c_char,
        out_error: *mut *mut c_char,
        out_error_token: *mut u64,
    ) -> i32;
    fn ex_hermes_free_string(value: *mut c_char);
    #[cfg(feature = "sfe-dev-spike")]
    fn ex_hermes_create_diagnostic() -> *mut c_void;
    #[cfg(feature = "sfe-dev-spike")]
    fn ex_hermes_runtime_nonce(runtime: *mut c_void) -> u64;
    #[cfg(feature = "sfe-dev-spike")]
    fn ex_hermes_destroy(runtime: *mut c_void);
    #[cfg(feature = "sfe-dev-spike")]
    fn ex_hermes_poll(runtime: *mut c_void, now_ms: u64) -> i32;
    #[cfg(feature = "sfe-dev-spike")]
    fn ex_hermes_next_timer(runtime: *mut c_void) -> i64;
    #[cfg(feature = "sfe-dev-spike")]
    fn ex_hermes_has_pending_tasks(runtime: *mut c_void) -> i32;
    #[cfg(feature = "sfe-dev-spike")]
    fn ex_hermes_now_ms() -> u64;
    #[cfg(any(test, feature = "sfe-dev-spike"))]
    fn ex_hermes_eval(
        runtime: *mut c_void,
        data: *const u8,
        len: usize,
        source_url: *const c_char,
        is_bytecode: i32,
        out_value: *mut *mut c_char,
    ) -> i32;
}

/// Ask the exact linked Hermes decoder to sanity-check an authenticated HBC
/// carrier without evaluating it. Callers bulk-preflight all carriers before
/// creating any factory table.
pub fn preflight_hermes_bytecode(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        bail!("Hermes bytecode preflight requires non-empty bytes");
    }
    let mut error = std::ptr::null_mut();
    let status =
        unsafe { ex_hermes_module_preflight_bytecode(bytes.as_ptr(), bytes.len(), &mut error) };
    if status != 0 {
        let detail = take_error(error);
        bail!("native Hermes bytecode preflight refused ({status}): {detail}");
    }
    if !error.is_null() {
        unsafe { ex_hermes_free_string(error) };
    }
    Ok(())
}

/// Explicitly diagnostic owner used only by LLP 0029's phase-0 dynamic stub.
/// Production compiled executables must construct an advertised armed runtime.
#[cfg(feature = "sfe-dev-spike")]
pub struct DiagnosticModuleRuntime {
    raw: NonNull<c_void>,
}

#[cfg(feature = "sfe-dev-spike")]
impl DiagnosticModuleRuntime {
    pub fn new() -> Result<Self> {
        let raw = NonNull::new(unsafe { ex_hermes_create_diagnostic() })
            .ok_or_else(|| anyhow!("diagnostic Hermes runtime construction failed"))?;
        Ok(Self { raw })
    }

    pub fn borrow(&mut self) -> Result<NativeModuleRuntime<'_>> {
        let nonce = unsafe { ex_hermes_runtime_nonce(self.raw.as_ptr()) };
        // SAFETY: this owner retains the live pointer and the mutable borrow
        // prevents destruction or a second drive until the module borrow ends.
        unsafe { NativeModuleRuntime::from_raw(self.raw, nonce) }
    }

    /// Install the process identity visible to a compiled application before
    /// any authenticated module record is linked. There is no CLI parser in
    /// this path: every argument after the invoked name remains application
    /// data and `execArgv` is always empty.
    /// @ref LLP 0029#6-compiled-boot-and-process-semantics
    pub fn install_compiled_process_metadata(
        &mut self,
        exec_path: &str,
        entry_designation: &str,
        invoked_name: &str,
        application_arguments: &[String],
    ) -> Result<()> {
        let mut argv = Vec::with_capacity(application_arguments.len() + 2);
        argv.push(exec_path.to_owned());
        argv.push(entry_designation.to_owned());
        argv.extend(application_arguments.iter().cloned());
        let argv = serde_json::to_string(&argv)?;
        let exec_path = serde_json::to_string(exec_path)?;
        let invoked_name = serde_json::to_string(invoked_name)?;
        let source = format!(
            "globalThis.__exactArgv={argv};\n\
             globalThis.__exactExecArgv=[];\n\
             globalThis.__exactExecPath={exec_path};\n\
             globalThis.__exactRawArgv0={invoked_name};\n\
             if (globalThis.process && typeof globalThis.process === 'object') {{\n\
               globalThis.process.argv=globalThis.__exactArgv;\n\
               globalThis.process.execArgv=globalThis.__exactExecArgv;\n\
               globalThis.process.argv0=globalThis.__exactRawArgv0;\n\
               globalThis.process.execPath=globalThis.__exactExecPath;\n\
             }}\n\
             true;"
        );
        self.eval_text(&source, "ibex:compiled-process-metadata")?;
        Ok(())
    }

    /// Drive the compiled program's referenced work until the native event
    /// loop reaches quiescence. The timer deadline and poll timestamp come
    /// from Hermes' one monotonic clock domain; background callbacks wake the
    /// sleeping owner through the library-owned host hook.
    /// @ref LLP 0029#6-compiled-boot-and-process-semantics
    pub fn drive_compiled_event_loop_to_quiescence(&mut self) -> Result<()> {
        let _wake_hook = CompiledWakeHookGuard::install();
        loop {
            let observed_generation = compiled_wake_generation();
            let now = unsafe { ex_hermes_now_ms() };
            let executed = unsafe { ex_hermes_poll(self.raw.as_ptr(), now) };
            if executed < 0 {
                bail!("compiled Hermes task execution failed");
            }
            if executed > 0 {
                continue;
            }
            if unsafe { ex_hermes_has_pending_tasks(self.raw.as_ptr()) } == 0 {
                return Ok(());
            }

            let next_timer = unsafe { ex_hermes_next_timer(self.raw.as_ptr()) };
            let wait = if next_timer < 0 {
                std::time::Duration::from_secs(1)
            } else {
                std::time::Duration::from_millis((next_timer as u64).saturating_sub(now))
            };
            wait_for_compiled_wake(observed_generation, wait);
        }
    }

    /// Read the status selected by a root-set `process.exitCode` after the
    /// compiled event loop reaches quiescence. Invalid or absent values retain
    /// the orderly zero status; platform exit truncation remains the OS's job.
    /// @ref LLP 0025#8-exit-and-lifecycle
    pub fn compiled_process_exit_code(&mut self) -> Result<i32> {
        let value = self.eval_text(
            "(typeof globalThis.process === 'object' && globalThis.process !== null && typeof globalThis.process.exitCode === 'number') ? String(globalThis.process.exitCode) : '0'",
            "ibex:compiled-process-exit-code",
        )?;
        Ok(value.trim().parse::<i32>().unwrap_or(0))
    }

    fn eval_text(&mut self, source: &str, source_label: &str) -> Result<String> {
        let source_url = std::ffi::CString::new(source_label)?;
        let mut output = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_eval(
                self.raw.as_ptr(),
                source.as_ptr(),
                source.len(),
                source_url.as_ptr(),
                0,
                &mut output,
            )
        };
        let detail = take_error(output);
        if status != 0 {
            bail!("compiled runtime evaluation refused ({status}): {detail}");
        }
        Ok(detail)
    }
}

#[cfg(feature = "sfe-dev-spike")]
static COMPILED_EVENT_LOOP_WAKE: (std::sync::Mutex<u64>, std::sync::Condvar) =
    (std::sync::Mutex::new(0), std::sync::Condvar::new());

#[cfg(feature = "sfe-dev-spike")]
extern "C" fn wake_compiled_event_loop(_: *mut c_void) {
    let mut generation = COMPILED_EVENT_LOOP_WAKE
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *generation = generation.wrapping_add(1);
    COMPILED_EVENT_LOOP_WAKE.1.notify_one();
}

#[cfg(feature = "sfe-dev-spike")]
fn compiled_wake_generation() -> u64 {
    *COMPILED_EVENT_LOOP_WAKE
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(feature = "sfe-dev-spike")]
fn wait_for_compiled_wake(observed_generation: u64, wait: std::time::Duration) {
    let generation = COMPILED_EVENT_LOOP_WAKE
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *generation != observed_generation || wait.is_zero() {
        return;
    }
    drop(
        COMPILED_EVENT_LOOP_WAKE
            .1
            .wait_timeout(generation, wait)
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
}

#[cfg(feature = "sfe-dev-spike")]
struct CompiledWakeHookGuard;

#[cfg(feature = "sfe-dev-spike")]
impl CompiledWakeHookGuard {
    fn install() -> Self {
        crate::engine::ex_hermes_set_host_wake_hook(
            Some(wake_compiled_event_loop),
            std::ptr::null_mut(),
        );
        Self
    }
}

#[cfg(feature = "sfe-dev-spike")]
impl Drop for CompiledWakeHookGuard {
    fn drop(&mut self) {
        crate::engine::ex_hermes_set_host_wake_hook(None, std::ptr::null_mut());
    }
}

#[cfg(feature = "sfe-dev-spike")]
impl Drop for DiagnosticModuleRuntime {
    fn drop(&mut self) {
        unsafe { ex_hermes_destroy(self.raw.as_ptr()) };
    }
}

/// Exact native module-runner failure. A nonzero token names the retained raw
/// JavaScript value for this operation only; engine/protocol failures carry 0
/// and can never borrow a stale throw from another record.
#[derive(Clone, Debug)]
pub struct NativeModuleExecutionError {
    operation: String,
    status: i32,
    detail: String,
    error_token: u64,
}

impl NativeModuleExecutionError {
    pub fn error_token(&self) -> Option<std::num::NonZeroU64> {
        std::num::NonZeroU64::new(self.error_token)
    }
}

impl std::fmt::Display for NativeModuleExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native {} refused ({}): {}",
            self.operation, self.status, self.detail
        )
    }
}

impl std::error::Error for NativeModuleExecutionError {}

pub fn execution_error_token(error: &anyhow::Error) -> Option<std::num::NonZeroU64> {
    error
        .chain()
        .find_map(|source| source.downcast_ref::<NativeModuleExecutionError>())
        .and_then(NativeModuleExecutionError::error_token)
}

fn sticky_module_error(error: &anyhow::Error) -> NativeModuleExecutionError {
    error
        .chain()
        .find_map(|source| source.downcast_ref::<NativeModuleExecutionError>())
        .cloned()
        .unwrap_or_else(|| NativeModuleExecutionError {
            operation: "module graph evaluation".to_owned(),
            status: -1,
            detail: error.to_string(),
            error_token: 0,
        })
}

/// Borrowed owner-thread access to one live Hermes runtime generation.
///
/// Construction is unsafe because the embedding wrapper must prove the pointer
/// and nonce were captured together while live and that the borrow does not
/// outlive the runtime. The type is deliberately `!Send`/`!Sync`.
pub struct NativeModuleRuntime<'runtime> {
    raw: NonNull<c_void>,
    nonce: u64,
    _runtime: PhantomData<&'runtime mut c_void>,
    _owner_thread: PhantomData<Rc<()>>,
}

/// Owner-thread registration of one generation's exact synchronous
/// CommonJS-require activation provider. The context allocation is owned by
/// the caller and must outlive this token.
pub struct NativeCommonJsRequireProviderRegistration {
    raw: NonNull<c_void>,
    nonce: u64,
    graph_generation: u64,
    provider_bridge: Option<NonNull<c_void>>,
    drop_provider_bridge: unsafe fn(NonNull<c_void>),
}

// The token may be stored behind the embedding runtime's owner-thread mutex.
// Its Drop implementation never dereferences or frees the provider bridge
// after an off-owner clear refusal, preserving the callback context alongside
// an intentionally leaked thread-affine runtime.
unsafe impl Send for NativeCommonJsRequireProviderRegistration {}

struct CommonJsRequireProviderBridge<T> {
    raw: NonNull<c_void>,
    nonce: u64,
    graph_generation: u64,
    context: NonNull<T>,
    provider: fn(
        &mut T,
        &NativeModuleRuntime<'_>,
        CommonJsRequireActivationRequest,
    ) -> Result<NativeCommonJsRequireActivationTarget>,
}

unsafe fn drop_commonjs_require_provider_bridge<T>(bridge: NonNull<c_void>) {
    unsafe {
        drop(Box::from_raw(
            bridge.cast::<CommonJsRequireProviderBridge<T>>().as_ptr(),
        ));
    }
}

unsafe fn write_commonjs_require_provider_error(
    message: &str,
    error_buffer: *mut u8,
    error_buffer_capacity: usize,
    out_error_len: *mut usize,
) {
    let bytes = message.as_bytes();
    let length = bytes.len().min(error_buffer_capacity);
    if length != 0 && !error_buffer.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), error_buffer, length);
        }
    }
    if !out_error_len.is_null() {
        unsafe {
            *out_error_len = length;
        }
    }
}

unsafe extern "C" fn commonjs_require_provider_trampoline<T>(
    context: *mut c_void,
    runtime_nonce: u64,
    graph_generation: u64,
    requester_record: NativeModuleHandle,
    requester_source_id: *const u8,
    requester_source_id_len: usize,
    specifier: *const u8,
    specifier_len: usize,
    out_target_record: *mut NativeModuleHandle,
    out_target_kind: *mut u32,
    error_buffer: *mut u8,
    error_buffer_capacity: usize,
    out_error_len: *mut usize,
) -> i32 {
    if !out_target_record.is_null() {
        unsafe { *out_target_record = NativeModuleHandle::default() };
    }
    if !out_target_kind.is_null() {
        unsafe { *out_target_kind = u32::MAX };
    }
    if !out_error_len.is_null() {
        unsafe { *out_error_len = 0 };
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bridge = NonNull::new(context.cast::<CommonJsRequireProviderBridge<T>>())
            .ok_or_else(|| anyhow!("CommonJS require provider context is null"))?;
        if requester_source_id.is_null()
            || specifier.is_null()
            || out_target_record.is_null()
            || out_target_kind.is_null()
        {
            bail!("CommonJS require provider received invalid native pointers");
        }
        let bridge = unsafe { bridge.as_ptr().as_mut().expect("non-null provider bridge") };
        if runtime_nonce != bridge.nonce
            || graph_generation != bridge.graph_generation
            || requester_record.opaque[0] != runtime_nonce
            || requester_record.opaque[1] != graph_generation
        {
            bail!("CommonJS require provider token is stale");
        }
        let requester = std::str::from_utf8(unsafe {
            std::slice::from_raw_parts(requester_source_id, requester_source_id_len)
        })
        .context("CommonJS requester SourceId is not UTF-8")
        .and_then(SourceId::decode)?;
        let specifier =
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(specifier, specifier_len) })
                .context("CommonJS require spelling is not UTF-8")?
                .to_owned();
        let runtime = unsafe { NativeModuleRuntime::from_raw(bridge.raw, bridge.nonce)? };
        let request = CommonJsRequireActivationRequest {
            graph_generation,
            requester_record,
            requester,
            specifier,
        };
        let target = (bridge.provider)(unsafe { bridge.context.as_mut() }, &runtime, request)?;
        unsafe {
            *out_target_record = target.0.publication_handle();
            *out_target_kind = target.0.commonjs_require_kind();
        }
        Ok::<(), anyhow::Error>(())
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            unsafe {
                write_commonjs_require_provider_error(
                    &format!("CommonJS require activation refused: {error}"),
                    error_buffer,
                    error_buffer_capacity,
                    out_error_len,
                );
            }
            -1
        }
        Err(_) => {
            unsafe {
                write_commonjs_require_provider_error(
                    "CommonJS require activation provider panicked",
                    error_buffer,
                    error_buffer_capacity,
                    out_error_len,
                );
            }
            -1
        }
    }
}

impl<'runtime> NativeModuleRuntime<'runtime> {
    /// # Safety
    ///
    /// `raw` must name the live runtime generation identified by `nonce`, the
    /// caller must be its owner thread, and the returned borrow must not outlive
    /// that runtime. Native validation independently refuses violations.
    pub unsafe fn from_raw(raw: NonNull<c_void>, nonce: u64) -> Result<Self> {
        if nonce == 0 {
            bail!("module runtime nonce must be nonzero");
        }
        Ok(Self {
            raw,
            nonce,
            _runtime: PhantomData,
            _owner_thread: PhantomData,
        })
    }

    /// Install the exact provider invoked only for authenticated deferred
    /// `require()` spellings in this pinned graph generation.
    ///
    /// # Safety
    ///
    /// `provider_context` must remain valid until the returned token is
    /// dropped, and the provider must not evaluate JavaScript or call any ABI
    /// outside the module-mutation subset.
    pub unsafe fn install_commonjs_require_provider<T>(
        &self,
        graph_generation: u64,
        provider_context: NonNull<T>,
        provider: fn(
            &mut T,
            &NativeModuleRuntime<'_>,
            CommonJsRequireActivationRequest,
        ) -> Result<NativeCommonJsRequireActivationTarget>,
    ) -> Result<NativeCommonJsRequireProviderRegistration> {
        if graph_generation == 0 {
            bail!("CommonJS require provider generation must be nonzero");
        }
        let provider_bridge = Box::new(CommonJsRequireProviderBridge {
            raw: self.raw,
            nonce: self.nonce,
            graph_generation,
            context: provider_context,
            provider,
        });
        let provider_bridge =
            NonNull::new(Box::into_raw(provider_bridge)).expect("Box pointer is non-null");
        let erased_bridge = provider_bridge.cast::<c_void>();
        let status = unsafe {
            ex_hermes_module_set_commonjs_require_provider(
                self.raw.as_ptr(),
                self.nonce,
                graph_generation,
                commonjs_require_provider_trampoline::<T>,
                erased_bridge.as_ptr(),
            )
        };
        if status != 0 {
            unsafe { drop_commonjs_require_provider_bridge::<T>(erased_bridge) };
            bail!("native CommonJS require provider installation refused ({status})");
        }
        Ok(NativeCommonJsRequireProviderRegistration {
            raw: self.raw,
            nonce: self.nonce,
            graph_generation,
            provider_bridge: Some(erased_bridge),
            drop_provider_bridge: drop_commonjs_require_provider_bridge::<T>,
        })
    }

    /// Take one reached deferred import for this exact native graph
    /// generation. An absent request performs no resolver or carrier work.
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    pub fn take_dynamic_activation_request(
        &self,
        graph_generation: u64,
    ) -> Result<Option<DynamicModuleActivationRequest>> {
        if graph_generation == 0 {
            bail!("dynamic activation generation must be nonzero");
        }
        let mut native = NativeDynamicActivationRequest::default();
        let status = unsafe {
            ex_hermes_module_take_dynamic_activation_request(
                self.raw.as_ptr(),
                self.nonce,
                graph_generation,
                &mut native,
            )
        };
        if status != 0 {
            bail!("native dynamic activation mailbox refused ({status})");
        }
        if native.request_id == 0 {
            unsafe { ex_hermes_module_dynamic_activation_request_dispose(&mut native) };
            return Ok(None);
        }
        let runtime_nonce = native.runtime_nonce;
        let request_id = native.request_id;
        let request_generation = native.graph_generation;
        let requester_record = native.requester_record;
        let kind = native.kind;
        let site = native.site;
        let copied = (|| {
            if (native.requester_source_id_len != 0 && native.requester_source_id.is_null())
                || (native.specifier_len != 0 && native.specifier.is_null())
            {
                bail!("native dynamic activation request has a null byte carrier");
            }
            let requester = unsafe {
                std::slice::from_raw_parts(
                    native.requester_source_id,
                    native.requester_source_id_len,
                )
            }
            .to_vec();
            let specifier =
                unsafe { std::slice::from_raw_parts(native.specifier, native.specifier_len) }
                    .to_vec();
            Ok::<_, anyhow::Error>((requester, specifier))
        })();
        unsafe { ex_hermes_module_dynamic_activation_request_dispose(&mut native) };
        let (requester, specifier) = copied?;
        if runtime_nonce != self.nonce
            || request_generation != graph_generation
            || requester_record.opaque[0] != self.nonce
            || requester_record.opaque[1] != graph_generation
            || requester_record.opaque[2] == 0
        {
            bail!("native dynamic activation request identity is stale");
        }
        let requester = std::str::from_utf8(&requester)
            .context("dynamic activation requester identity is not UTF-8")
            .and_then(SourceId::decode)?;
        let specifier =
            String::from_utf8(specifier).context("dynamic activation specifier is not UTF-8")?;
        if specifier.is_empty() {
            bail!("dynamic activation specifier must not be empty");
        }
        let kind = match kind {
            0 if site == 0 => DynamicModuleActivationKind::Literal,
            1 => DynamicModuleActivationKind::Computed { site },
            _ => bail!("native dynamic activation kind is invalid"),
        };
        Ok(Some(DynamicModuleActivationRequest {
            request_id,
            graph_generation,
            requester_record: Some(requester_record),
            requester,
            kind,
            specifier,
        }))
    }

    pub fn complete_dynamic_activation(
        &self,
        request: &DynamicModuleActivationRequest,
        target: &NativeModuleRecord<'_>,
    ) -> Result<()> {
        if !std::ptr::eq(self, target.runtime) {
            bail!("dynamic activation target belongs to another runtime borrow");
        }
        self.complete_dynamic_activation_handle(request, target.live_handle()?)
    }

    fn complete_dynamic_activation_handle(
        &self,
        request: &DynamicModuleActivationRequest,
        target: NativeModuleHandle,
    ) -> Result<()> {
        let status = unsafe {
            ex_hermes_module_complete_dynamic_activation(
                self.raw.as_ptr(),
                self.nonce,
                request.request_id,
                target,
                std::ptr::null(),
                0,
            )
        };
        if status != 0 {
            bail!("native dynamic activation completion refused ({status})");
        }
        Ok(())
    }

    pub fn refuse_dynamic_activation(
        &self,
        request: &DynamicModuleActivationRequest,
        error: &str,
    ) -> Result<()> {
        if error.is_empty() {
            bail!("dynamic activation refusal must not be empty");
        }
        let status = unsafe {
            ex_hermes_module_complete_dynamic_activation(
                self.raw.as_ptr(),
                self.nonce,
                request.request_id,
                NativeModuleHandle::default(),
                error.as_ptr(),
                error.len(),
            )
        };
        if status != 0 {
            bail!("native dynamic activation refusal completion failed ({status})");
        }
        Ok(())
    }

    /// Compile one inline factory after ModuleArtifact admission. Principal and
    /// compartment are graph-owned inputs; neither is read from artifact JS.
    pub fn compile_verified_factory(
        &'runtime self,
        verified: VerifiedModuleArtifactV1<'_>,
        principal_id: u32,
        compartment_identity: Option<&str>,
        graph_generation: u64,
        source_label: &str,
    ) -> Result<CompiledModuleFactory<'runtime>> {
        self.compile_verified_factory_for_goal(
            verified,
            SourceGoalV1::Module,
            0,
            principal_id,
            compartment_identity,
            graph_generation,
            source_label,
        )
    }

    pub fn compile_verified_commonjs_factory(
        &'runtime self,
        verified: VerifiedModuleArtifactV1<'_>,
        principal_id: u32,
        compartment_identity: Option<&str>,
        graph_generation: u64,
        source_label: &str,
    ) -> Result<CompiledModuleFactory<'runtime>> {
        self.compile_verified_factory_for_goal(
            verified,
            SourceGoalV1::CommonJs,
            1,
            principal_id,
            compartment_identity,
            graph_generation,
            source_label,
        )
    }

    pub fn compile_verified_json_factory(
        &'runtime self,
        verified: VerifiedModuleArtifactV1<'_>,
        principal_id: u32,
        compartment_identity: Option<&str>,
        graph_generation: u64,
        source_label: &str,
    ) -> Result<CompiledModuleFactory<'runtime>> {
        self.compile_verified_factory_for_goal(
            verified,
            SourceGoalV1::Json,
            2,
            principal_id,
            compartment_identity,
            graph_generation,
            source_label,
        )
    }

    pub fn compile_verified_builtin_factory(
        &'runtime self,
        verified: VerifiedModuleArtifactV1<'_>,
        principal_id: u32,
        compartment_identity: Option<&str>,
        graph_generation: u64,
        source_label: &str,
    ) -> Result<CompiledModuleFactory<'runtime>> {
        self.compile_verified_factory_for_goal(
            verified,
            SourceGoalV1::Builtin,
            3,
            principal_id,
            compartment_identity,
            graph_generation,
            source_label,
        )
    }

    fn compile_verified_factory_for_goal(
        &'runtime self,
        verified: VerifiedModuleArtifactV1<'_>,
        expected_goal: SourceGoalV1,
        native_goal: u32,
        principal_id: u32,
        compartment_identity: Option<&str>,
        graph_generation: u64,
        source_label: &str,
    ) -> Result<CompiledModuleFactory<'runtime>> {
        if graph_generation == 0 {
            bail!("module graph generation must be nonzero");
        }
        let artifact = verified.artifact();
        if artifact.semantics.source_goal != expected_goal {
            bail!("factory compilation received the wrong source-goal artifact");
        }
        let source = verified.inline_factory_source().ok_or_else(|| {
            anyhow!("prepared carrier factory bytes must be loaded and verified before compilation")
        })?;
        let compartment = compartment_identity.unwrap_or("");
        let digest = artifact.semantic_digest.as_str();
        let source_id = artifact.semantics.source_id.0.encode()?;
        let mut handle = NativeModuleHandle::default();
        let mut error = std::ptr::null_mut();
        let mut error_token = 0;
        let status = unsafe {
            ex_hermes_module_compile_factory(
                self.raw.as_ptr(),
                self.nonce,
                native_goal,
                principal_id,
                graph_generation,
                compartment.as_ptr(),
                compartment.len(),
                digest.as_ptr(),
                digest.len(),
                source_id.as_ptr(),
                source_id.len(),
                source.as_ptr(),
                source.len(),
                source_label.as_ptr(),
                source_label.len(),
                &mut handle,
                &mut error,
                &mut error_token,
            )
        };
        if status != 0 {
            native_result(status, error, error_token, "module factory compile")?;
            unreachable!("nonzero factory status returned success");
        }
        if !error.is_null() {
            unsafe { ex_hermes_free_string(error) };
        }
        Ok(CompiledModuleFactory {
            runtime: self,
            handle: Some(handle),
        })
    }

    /// Load one factory from an already-admitted, per-principal prepared
    /// carrier. Both capabilities must agree on the physical carrier entry and
    /// on the original module semantics before any carrier byte is evaluated.
    pub fn load_verified_prepared_factory(
        &'runtime self,
        verified: VerifiedModuleArtifactV1<'_>,
        carrier_entry: VerifiedPreparedCarrierEntryV2<'_>,
        principal_id: u32,
        compartment_identity: Option<&str>,
        graph_generation: u64,
        source_label: &str,
    ) -> Result<CompiledModuleFactory<'runtime>> {
        if graph_generation == 0 {
            bail!("module graph generation must be nonzero");
        }
        let artifact = verified.artifact();
        let (carrier_digest, entry_id, entry_factory_digest) = match &artifact.payload {
            ModulePayloadV1::Carrier {
                carrier_digest,
                entry_id,
                entry_factory_digest,
            } => (carrier_digest, entry_id, entry_factory_digest),
            ModulePayloadV1::Inline { .. } => {
                bail!("prepared factory loading requires a carrier artifact")
            }
        };
        let manifest = carrier_entry.manifest();
        let entry = carrier_entry.entry();
        if carrier_digest != &manifest.carrier_digest
            || entry_id != &entry.entry_id
            || entry_factory_digest != &entry.semantics.factory_digest
            || artifact.semantic_digest != entry.semantic_digest
            || artifact.semantics != entry.semantics
        {
            bail!("prepared carrier entry does not match the admitted module artifact");
        }
        let native_goal = match artifact.semantics.source_goal {
            SourceGoalV1::Module => 0,
            SourceGoalV1::CommonJs => 1,
            SourceGoalV1::Json => 2,
            SourceGoalV1::Builtin => 3,
        };
        let native_encoding = match &manifest.encoding {
            PreparedCarrierEncodingV2::JavascriptFactoryTable => 0,
            PreparedCarrierEncodingV2::HermesBytecode { .. } => 1,
        };
        let compartment = compartment_identity.unwrap_or("");
        let digest = artifact.semantic_digest.as_str();
        let source_id = artifact.semantics.source_id.0.encode()?;
        let mut handle = NativeModuleHandle::default();
        let mut error = std::ptr::null_mut();
        let mut error_token = 0;
        let status = unsafe {
            ex_hermes_module_load_carrier_factory(
                self.raw.as_ptr(),
                self.nonce,
                native_goal,
                principal_id,
                graph_generation,
                compartment.as_ptr(),
                compartment.len(),
                digest.as_ptr(),
                digest.len(),
                source_id.as_ptr(),
                source_id.len(),
                manifest.carrier_digest.as_str().as_ptr(),
                manifest.carrier_digest.as_str().len(),
                carrier_entry.bytes().as_ptr(),
                carrier_entry.bytes().len(),
                native_encoding,
                entry.entry_id.as_str().as_ptr(),
                entry.entry_id.as_str().len(),
                source_label.as_ptr(),
                source_label.len(),
                &mut handle,
                &mut error,
                &mut error_token,
            )
        };
        if status != 0 {
            let operation = if status == 2 {
                "prepared Hermes bytecode load"
            } else {
                "prepared module factory load"
            };
            native_result(status, error, error_token, operation)?;
            unreachable!("nonzero prepared-factory status returned success");
        }
        if !error.is_null() {
            unsafe { ex_hermes_free_string(error) };
        }
        Ok(CompiledModuleFactory {
            runtime: self,
            handle: Some(handle),
        })
    }

    pub fn create_graph_context(
        &'runtime self,
        context: GraphEvaluationContext,
    ) -> Result<NativeGraphContext<'runtime>> {
        context.validate()?;
        let source_id = context.requesting_record.encode()?;
        let mut handle = NativeModuleHandle::default();
        let principals = context.constrained_principals;
        let status = unsafe {
            ex_hermes_graph_context_create(
                self.raw.as_ptr(),
                self.nonce,
                context.graph_generation,
                source_id.as_ptr(),
                source_id.len(),
                context.effect_owner,
                context.schedule_owner,
                principals.as_ptr(),
                principals.len(),
                &mut handle,
            )
        };
        if status != 0 {
            bail!("native graph-context creation refused ({status})");
        }
        Ok(NativeGraphContext {
            runtime: self,
            handle: Some(handle),
        })
    }
}

impl Drop for NativeCommonJsRequireProviderRegistration {
    fn drop(&mut self) {
        let status = unsafe {
            ex_hermes_module_clear_commonjs_require_provider(
                self.raw.as_ptr(),
                self.nonce,
                self.graph_generation,
            )
        };
        if matches!(status, 0 | -2 | -6) {
            if let Some(bridge) = self.provider_bridge.take() {
                unsafe { (self.drop_provider_bridge)(bridge) };
            }
        } else {
            // The native runtime remains live (most notably an off-owner
            // thread-affine runtime leak), so its callback context must remain
            // live too.
            let _ = self.provider_bridge.take();
            debug_assert_eq!(
                status, -3,
                "native CommonJS require provider clear refused ({status})"
            );
        }
    }
}

/// Complete context carried by graph operations and asynchronous continuations.
/// Principal IDs are runtime-local projections; the requesting SourceId remains
/// stable and authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEvaluationContext {
    pub requesting_record: SourceId,
    pub effect_owner: u32,
    pub schedule_owner: u32,
    pub constrained_principals: Vec<u32>,
    pub graph_generation: u64,
}

impl GraphEvaluationContext {
    pub fn new(
        requesting_record: SourceId,
        effect_owner: u32,
        schedule_owner: u32,
        constrained_principals: impl IntoIterator<Item = u32>,
        graph_generation: u64,
    ) -> Result<Self> {
        let mut constrained_principals: Vec<_> = constrained_principals.into_iter().collect();
        constrained_principals.sort_unstable();
        constrained_principals.dedup();
        let value = Self {
            requesting_record,
            effect_owner,
            schedule_owner,
            constrained_principals,
            graph_generation,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.graph_generation == 0 {
            bail!("graph evaluation context generation must be nonzero");
        }
        if self.constrained_principals.len() > 256 {
            bail!("graph evaluation context exceeds 256 constrained principals");
        }
        if self
            .constrained_principals
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            bail!("graph evaluation constrained principals must be sorted and unique");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NativeModuleRecordConfig {
    pub principal_id: u32,
    pub compartment_identity: Option<String>,
    pub evaluation_context: GraphEvaluationContext,
    pub source_label: String,
    pub meta_url: String,
    pub virtual_path: Option<String>,
}

impl NativeModuleRecordConfig {
    pub fn new(
        principal_id: u32,
        compartment_identity: Option<String>,
        evaluation_context: GraphEvaluationContext,
        source_label: impl Into<String>,
        meta_url: impl Into<String>,
    ) -> Result<Self> {
        let value = Self {
            principal_id,
            compartment_identity,
            evaluation_context,
            source_label: source_label.into(),
            meta_url: meta_url.into(),
            virtual_path: None,
        };
        if value.source_label.is_empty() {
            bail!("module source label must not be empty");
        }
        if value.meta_url.is_empty() {
            bail!("module import.meta URL must not be empty");
        }
        value.evaluation_context.validate()?;
        Ok(value)
    }

    /// Attach the Host-authenticated virtual filename used for every
    /// path-bearing module observable. The backing resolver path is never an
    /// admissible input to this projection.
    pub fn with_authenticated_virtual_path(
        mut self,
        virtual_path: impl Into<String>,
    ) -> Result<Self> {
        let virtual_path = virtual_path.into();
        if !virtual_path.starts_with("/project/") || virtual_path.contains('\0') {
            bail!("module virtual path must be a file beneath /project");
        }
        if !self.meta_url.starts_with("file:///project/") {
            bail!("file-backed module metadata requires an authenticated virtual URL");
        }
        self.virtual_path = Some(virtual_path);
        Ok(self)
    }
}

/// Owner-thread, runtime-generation-scoped callable factory capability.
pub struct CompiledModuleFactory<'runtime> {
    runtime: &'runtime NativeModuleRuntime<'runtime>,
    handle: Option<NativeModuleHandle>,
}

impl<'runtime> CompiledModuleFactory<'runtime> {
    pub fn create_record(
        &self,
        context: &NativeGraphContext<'runtime>,
        source_id: &SourceId,
    ) -> Result<NativeModuleRecord<'runtime>> {
        if !std::ptr::eq(self.runtime, context.runtime) {
            bail!("factory and graph context belong to different runtime borrows");
        }
        let factory = self
            .handle
            .ok_or_else(|| anyhow!("module factory capability was released"))?;
        let context_handle = context
            .handle
            .ok_or_else(|| anyhow!("graph context capability was released"))?;
        let source_id = source_id.encode()?;
        let mut record = NativeModuleHandle::default();
        let status = unsafe {
            ex_hermes_module_create_record(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                factory,
                context_handle,
                source_id.as_ptr(),
                source_id.len(),
                &mut record,
            )
        };
        if status != 0 {
            bail!("native ModuleRecord creation refused ({status})");
        }
        Ok(NativeModuleRecord {
            runtime: self.runtime,
            handle: Some(record),
            published: false,
        })
    }

    pub fn create_commonjs_record(
        &self,
        context: &NativeGraphContext<'runtime>,
        source_id: &SourceId,
        filename: &str,
        dirname: &str,
    ) -> Result<NativeCommonJsRecord<'runtime>> {
        if !std::ptr::eq(self.runtime, context.runtime) {
            bail!("factory and graph context belong to different runtime borrows");
        }
        if filename.is_empty() {
            bail!("CommonJS filename must not be empty");
        }
        let factory = self
            .handle
            .ok_or_else(|| anyhow!("module factory capability was released"))?;
        let context_handle = context
            .handle
            .ok_or_else(|| anyhow!("graph context capability was released"))?;
        let source_id = source_id.encode()?;
        let mut record = NativeModuleHandle::default();
        let status = unsafe {
            ex_hermes_commonjs_create_record(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                factory,
                context_handle,
                source_id.as_ptr(),
                source_id.len(),
                filename.as_ptr(),
                filename.len(),
                dirname.as_ptr(),
                dirname.len(),
                &mut record,
            )
        };
        if status != 0 {
            bail!("native CommonJS record creation refused ({status})");
        }
        Ok(NativeCommonJsRecord {
            runtime: self.runtime,
            handle: Some(record),
            published: false,
        })
    }
}

pub struct NativeGraphContext<'runtime> {
    runtime: &'runtime NativeModuleRuntime<'runtime>,
    handle: Option<NativeModuleHandle>,
}

impl Clone for NativeGraphContext<'_> {
    fn clone(&self) -> Self {
        let handle = self.handle.expect("cannot clone a released graph context");
        let status = unsafe {
            ex_hermes_graph_context_retain(self.runtime.raw.as_ptr(), self.runtime.nonce, handle)
        };
        assert_eq!(status, 0, "native graph-context retain refused");
        Self {
            runtime: self.runtime,
            handle: Some(handle),
        }
    }
}

pub struct NativeModuleRecord<'runtime> {
    runtime: &'runtime NativeModuleRuntime<'runtime>,
    handle: Option<NativeModuleHandle>,
    published: bool,
}

pub struct NativeCommonJsRecord<'runtime> {
    runtime: &'runtime NativeModuleRuntime<'runtime>,
    handle: Option<NativeModuleHandle>,
    published: bool,
}

// @ref LLP 0027#esmcommonjs-interop-matrix — native CommonJS records retain
// early-publication/eviction semantics and mint snapshot ESM adapters.
impl<'runtime> NativeCommonJsRecord<'runtime> {
    fn live_handle(&self) -> Result<NativeModuleHandle> {
        self.handle
            .ok_or_else(|| anyhow!("native CommonJS record was evicted or released"))
    }

    pub fn declare_detected_export(&mut self, export_name: &str) -> Result<()> {
        if export_name.is_empty() {
            bail!("CommonJS detected export name must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_declare_export(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                export_name.as_ptr(),
                export_name.len(),
            )
        };
        if status != 0 {
            bail!("native CommonJS export declaration refused ({status})");
        }
        Ok(())
    }

    pub fn link_require(
        &mut self,
        specifier: &str,
        target: &NativeCommonJsRecord<'_>,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime, target.runtime) {
            bail!("CommonJS records belong to different runtime borrows");
        }
        if specifier.is_empty() {
            bail!("CommonJS require specifier must not be empty");
        }
        self.link_require_handle(specifier, target.live_handle()?)
    }

    fn link_require_handle(&mut self, specifier: &str, target: NativeModuleHandle) -> Result<()> {
        if specifier.is_empty() {
            bail!("CommonJS require specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_link_require(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
                target,
            )
        };
        if status != 0 {
            bail!("native CommonJS require link refused ({status})");
        }
        Ok(())
    }

    #[cfg(any(test, feature = "module-runner"))]
    fn link_require_esm_handle(
        &mut self,
        specifier: &str,
        target: NativeModuleHandle,
        synchronous_eligible: bool,
    ) -> Result<()> {
        if specifier.is_empty() {
            bail!("CommonJS require specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_link_require_esm(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
                target,
                i32::from(synchronous_eligible),
            )
        };
        if status != 0 {
            bail!("native CommonJS require-ESM link refused ({status})");
        }
        Ok(())
    }

    fn defer_require_handle(&mut self, specifier: &str) -> Result<()> {
        if specifier.is_empty() {
            bail!("CommonJS deferred require specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_defer_require(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
            )
        };
        if status != 0 {
            bail!("native CommonJS require deferral refused ({status})");
        }
        Ok(())
    }

    fn link_bootstrap_internal_require(&mut self, specifier: &str) -> Result<()> {
        if specifier.is_empty() {
            bail!("bootstrap-internal CommonJS require specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_link_bootstrap_internal_require(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
            )
        };
        if status != 0 {
            bail!("native bootstrap-internal CommonJS require link refused ({status})");
        }
        Ok(())
    }

    pub fn link_dynamic_import(
        &mut self,
        specifier: &str,
        target: &NativeModuleRecord<'_>,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime, target.runtime) {
            bail!("CommonJS and ESM records belong to different runtime borrows");
        }
        if specifier.is_empty() {
            bail!("CommonJS dynamic-import specifier must not be empty");
        }
        self.link_dynamic_import_handle(specifier, target.live_handle()?)
    }

    fn link_dynamic_import_handle(
        &mut self,
        specifier: &str,
        target: NativeModuleHandle,
    ) -> Result<()> {
        if specifier.is_empty() {
            bail!("CommonJS dynamic-import specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_link_dynamic_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
                target,
            )
        };
        if status != 0 {
            bail!("native CommonJS dynamic-import link refused ({status})");
        }
        Ok(())
    }

    fn link_computed_dynamic_import_handle(
        &mut self,
        site: u32,
        specifier: &str,
        target: NativeModuleHandle,
    ) -> Result<()> {
        if specifier.is_empty() {
            bail!("CommonJS computed dynamic-import specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_link_computed_dynamic_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                site,
                specifier.as_ptr(),
                specifier.len(),
                target,
            )
        };
        if status != 0 {
            bail!("native CommonJS computed dynamic-import link refused ({status})");
        }
        Ok(())
    }

    fn defer_dynamic_import_handle(&mut self, specifier: &str) -> Result<()> {
        if specifier.is_empty() {
            bail!("deferred CommonJS dynamic import specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_defer_dynamic_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
            )
        };
        if status != 0 {
            bail!("native deferred CommonJS dynamic import refused ({status})");
        }
        Ok(())
    }

    fn defer_computed_dynamic_import_handle(&mut self, site: u32, specifier: &str) -> Result<()> {
        if specifier.is_empty() {
            bail!("deferred CommonJS computed import specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_commonjs_record_defer_computed_dynamic_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                site,
                specifier.as_ptr(),
                specifier.len(),
            )
        };
        if status != 0 {
            bail!("native deferred CommonJS computed import refused ({status})");
        }
        Ok(())
    }

    pub fn evaluate(&mut self) -> Result<()> {
        let handle = self.live_handle()?;
        let mut evicted = 0;
        let mut error = std::ptr::null_mut();
        let mut error_token = 0;
        let status = unsafe {
            ex_hermes_commonjs_record_evaluate(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                handle,
                &mut evicted,
                &mut error,
                &mut error_token,
            )
        };
        if evicted == 1 {
            self.handle = None;
        }
        native_result(status, error, error_token, "CommonJS record evaluation")
    }

    pub fn create_esm_adapter(&self) -> Result<NativeModuleRecord<'runtime>> {
        let mut adapter = NativeModuleHandle::default();
        let mut error = std::ptr::null_mut();
        let mut error_token = 0;
        let status = unsafe {
            ex_hermes_commonjs_record_create_esm_adapter(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                &mut adapter,
                &mut error,
                &mut error_token,
            )
        };
        native_result(status, error, error_token, "CommonJS ESM-adapter creation")?;
        Ok(NativeModuleRecord {
            runtime: self.runtime,
            handle: Some(adapter),
            published: false,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleExecutionKind {
    Synchronous,
    Asynchronous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleEvaluationState {
    Pending,
    Evaluated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DynamicModuleActivationKind {
    Literal,
    Computed { site: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicModuleActivationRequest {
    request_id: u64,
    graph_generation: u64,
    requester_record: Option<NativeModuleHandle>,
    pub requester: SourceId,
    pub kind: DynamicModuleActivationKind,
    pub specifier: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonJsRequireActivationRequest {
    graph_generation: u64,
    requester_record: NativeModuleHandle,
    pub requester: SourceId,
    pub specifier: String,
}

impl CommonJsRequireActivationRequest {
    pub fn graph_generation(&self) -> u64 {
        self.graph_generation
    }
}

impl DynamicModuleActivationRequest {
    pub fn graph_generation(&self) -> u64 {
        self.graph_generation
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        graph_generation: u64,
        requester: SourceId,
        kind: DynamicModuleActivationKind,
        specifier: impl Into<String>,
    ) -> Self {
        Self {
            request_id: 1,
            graph_generation,
            requester_record: None,
            requester,
            kind,
            specifier: specifier.into(),
        }
    }
}

impl NativeModuleRecord<'_> {
    fn live_handle(&self) -> Result<NativeModuleHandle> {
        self.handle
            .ok_or_else(|| anyhow!("native ModuleRecord capability was released"))
    }

    pub fn declare_export(&mut self, export_name: &str) -> Result<()> {
        if export_name.is_empty() {
            bail!("module export name must not be empty");
        }
        let status = unsafe {
            ex_hermes_module_record_declare_export(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                export_name.as_ptr(),
                export_name.len(),
            )
        };
        if status != 0 {
            bail!("native export-cell declaration refused ({status})");
        }
        Ok(())
    }

    pub fn link_import(
        &mut self,
        specifier: &str,
        imported_name: &str,
        target: &NativeModuleRecord<'_>,
        target_export: &str,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime, target.runtime) {
            bail!("module import records belong to different runtime borrows");
        }
        if specifier.is_empty() || imported_name.is_empty() || target_export.is_empty() {
            bail!("module import binding strings must not be empty");
        }
        self.link_import_handle(
            specifier,
            imported_name,
            target.live_handle()?,
            target_export,
        )
    }

    fn link_import_handle(
        &mut self,
        specifier: &str,
        imported_name: &str,
        target: NativeModuleHandle,
        target_export: &str,
    ) -> Result<()> {
        let status = unsafe {
            ex_hermes_module_record_link_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
                imported_name.as_ptr(),
                imported_name.len(),
                target,
                target_export.as_ptr(),
                target_export.len(),
            )
        };
        if status != 0 {
            bail!("native import binding refused ({status})");
        }
        Ok(())
    }

    #[cfg(any(test, feature = "module-runner"))]
    fn link_dependency_handle(&mut self, target: NativeModuleHandle) -> Result<()> {
        let status = unsafe {
            ex_hermes_module_record_link_dependency(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                target,
            )
        };
        if status != 0 {
            bail!("native evaluation dependency refused ({status})");
        }
        Ok(())
    }

    #[cfg(any(test, feature = "module-runner"))]
    fn link_dynamic_import_handle(
        &mut self,
        specifier: &str,
        target: NativeModuleHandle,
    ) -> Result<()> {
        if specifier.is_empty() {
            bail!("dynamic import specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_module_record_link_dynamic_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
                target,
            )
        };
        if status != 0 {
            bail!("native dynamic import binding refused ({status})");
        }
        Ok(())
    }

    #[cfg(any(test, feature = "module-runner"))]
    fn link_computed_dynamic_import_handle(
        &mut self,
        site: u32,
        specifier: &str,
        target: NativeModuleHandle,
    ) -> Result<()> {
        if specifier.is_empty() {
            bail!("computed dynamic-import specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_module_record_link_computed_dynamic_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                site,
                specifier.as_ptr(),
                specifier.len(),
                target,
            )
        };
        if status != 0 {
            bail!("native computed dynamic-import binding refused ({status})");
        }
        Ok(())
    }

    #[cfg(any(test, feature = "module-runner"))]
    fn defer_dynamic_import_handle(&mut self, specifier: &str) -> Result<()> {
        if specifier.is_empty() {
            bail!("deferred dynamic import specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_module_record_defer_dynamic_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                specifier.as_ptr(),
                specifier.len(),
            )
        };
        if status != 0 {
            bail!("native deferred dynamic import binding refused ({status})");
        }
        Ok(())
    }

    #[cfg(any(test, feature = "module-runner"))]
    fn defer_computed_dynamic_import_handle(&mut self, site: u32, specifier: &str) -> Result<()> {
        if specifier.is_empty() {
            bail!("deferred computed dynamic import specifier must not be empty");
        }
        let status = unsafe {
            ex_hermes_module_record_defer_computed_dynamic_import(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                site,
                specifier.as_ptr(),
                specifier.len(),
            )
        };
        if status != 0 {
            bail!("native deferred computed dynamic import binding refused ({status})");
        }
        Ok(())
    }

    /// Link a declared export as a live view of another record's export or
    /// namespace (`target_export == "*"`). The target must belong to the same
    /// runtime and graph generation.
    pub fn link_export(
        &mut self,
        export_name: &str,
        target: &NativeModuleRecord<'_>,
        target_export: &str,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime, target.runtime) {
            bail!("module export records belong to different runtime borrows");
        }
        if export_name.is_empty() || target_export.is_empty() {
            bail!("module export binding strings must not be empty");
        }
        self.link_export_handle(export_name, target.live_handle()?, target_export)
    }

    fn link_export_handle(
        &mut self,
        export_name: &str,
        target: NativeModuleHandle,
        target_export: &str,
    ) -> Result<()> {
        let status = unsafe {
            ex_hermes_module_record_link_export(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                export_name.as_ptr(),
                export_name.len(),
                target,
                target_export.as_ptr(),
                target_export.len(),
            )
        };
        if status != 0 {
            bail!("native export binding refused ({status})");
        }
        Ok(())
    }

    pub fn instantiate(&mut self, meta_url: &str, is_main: bool) -> Result<()> {
        self.instantiate_with_virtual_path(meta_url, None, is_main)
    }

    pub fn instantiate_with_virtual_path(
        &mut self,
        meta_url: &str,
        virtual_path: Option<&str>,
        is_main: bool,
    ) -> Result<()> {
        if meta_url.is_empty() {
            bail!("module import.meta URL must not be empty");
        }
        if virtual_path.is_some_and(|path| !path.starts_with("/project/") || path.contains('\0')) {
            bail!("module import.meta virtual path is invalid");
        }
        let virtual_path = virtual_path.unwrap_or("");
        let mut error = std::ptr::null_mut();
        let mut error_token = 0;
        let status = unsafe {
            ex_hermes_module_record_instantiate(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                meta_url.as_ptr(),
                meta_url.len(),
                virtual_path.as_ptr(),
                virtual_path.len(),
                i32::from(is_main),
                &mut error,
                &mut error_token,
            )
        };
        native_result(status, error, error_token, "ModuleRecord instantiation")
    }

    pub fn run_declare(&mut self) -> Result<()> {
        let mut error = std::ptr::null_mut();
        let mut error_token = 0;
        let status = unsafe {
            ex_hermes_module_record_run_declare(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                &mut error,
                &mut error_token,
            )
        };
        native_result(status, error, error_token, "ModuleRecord declaration")
    }

    pub fn run_execute(&mut self) -> Result<ModuleExecutionKind> {
        let mut asynchronous = 0;
        let mut error = std::ptr::null_mut();
        let mut error_token = 0;
        let status = unsafe {
            ex_hermes_module_record_run_execute(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                &mut asynchronous,
                &mut error,
                &mut error_token,
            )
        };
        native_result(status, error, error_token, "ModuleRecord execution")?;
        match asynchronous {
            0 => Ok(ModuleExecutionKind::Synchronous),
            1 => Ok(ModuleExecutionKind::Asynchronous),
            _ => bail!("native ModuleRecord returned an invalid execution kind"),
        }
    }

    /// Poll the one internal evaluation promise owned by this record. This is
    /// deliberately state-only: callers drive Hermes separately and never
    /// wait on the runtime thread.
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    pub fn poll_evaluation(&self) -> Result<ModuleEvaluationState> {
        let mut state = -1;
        let mut error = std::ptr::null_mut();
        let mut error_token = 0;
        let status = unsafe {
            ex_hermes_module_record_poll_evaluation(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                &mut state,
                &mut error,
                &mut error_token,
            )
        };
        native_result(status, error, error_token, "ModuleRecord evaluation poll")?;
        match state {
            0 => Ok(ModuleEvaluationState::Pending),
            1 => Ok(ModuleEvaluationState::Evaluated),
            _ => bail!("native ModuleRecord returned an invalid evaluation state"),
        }
    }

    pub fn namespace_json(&self) -> Result<String> {
        let mut json = std::ptr::null_mut();
        let mut error = std::ptr::null_mut();
        let mut error_token = 0;
        let status = unsafe {
            ex_hermes_module_record_namespace_json(
                self.runtime.raw.as_ptr(),
                self.runtime.nonce,
                self.live_handle()?,
                &mut json,
                &mut error,
                &mut error_token,
            )
        };
        native_result(status, error, error_token, "ModuleRecord namespace read")?;
        if json.is_null() {
            bail!("native ModuleRecord namespace read returned no JSON");
        }
        let value = unsafe { CStr::from_ptr(json) }
            .to_string_lossy()
            .into_owned();
        unsafe { ex_hermes_free_string(json) };
        Ok(value)
    }
}

/// Fully linked synchronous graph whose reachable records have all completed
/// factory instantiation and declaration before any module body may execute.
// @ref LLP 0026#5-esm-record-lifecycle — full-closure linking precedes body
// evaluation, and cycles reuse the already-created native records.
#[cfg(any(test, feature = "module-runner"))]
enum NativeLinkedRecord<'runtime> {
    Esm(NativeModuleRecord<'runtime>),
    CommonJs {
        record: NativeCommonJsRecord<'runtime>,
        adapter: NativeModuleRecord<'runtime>,
    },
}

#[cfg(any(test, feature = "module-runner"))]
impl<'runtime> NativeLinkedRecord<'runtime> {
    fn runtime(&self) -> &'runtime NativeModuleRuntime<'runtime> {
        match self {
            Self::Esm(record) => record.runtime,
            Self::CommonJs { record, .. } => record.runtime,
        }
    }

    fn publication_handle(&self) -> Result<NativeModuleHandle> {
        match self {
            Self::Esm(record) => record.live_handle(),
            Self::CommonJs { record, .. } => record.live_handle(),
        }
    }

    fn mark_published(&mut self) {
        match self {
            Self::Esm(record) => record.published = true,
            Self::CommonJs { record, adapter } => {
                record.published = true;
                adapter.published = true;
            }
        }
    }

    fn esm_link_handle(&self) -> Result<NativeModuleHandle> {
        match self {
            Self::Esm(record)
            | Self::CommonJs {
                adapter: record, ..
            } => record.live_handle(),
        }
    }

    fn esm_mut(&mut self) -> Option<&mut NativeModuleRecord<'runtime>> {
        match self {
            Self::Esm(record) => Some(record),
            Self::CommonJs { .. } => None,
        }
    }

    fn commonjs_mut(&mut self) -> Option<&mut NativeCommonJsRecord<'runtime>> {
        match self {
            Self::CommonJs { record, .. } => Some(record),
            Self::Esm(_) => None,
        }
    }

    fn namespace_json(&self) -> Result<String> {
        match self {
            Self::Esm(record)
            | Self::CommonJs {
                adapter: record, ..
            } => record.namespace_json(),
        }
    }
}

#[derive(Clone, Copy)]
enum PublishedNativeRecord {
    Esm {
        record: NativeModuleHandle,
    },
    CommonJs {
        record: NativeModuleHandle,
        adapter: NativeModuleHandle,
    },
}

impl PublishedNativeRecord {
    fn publication_handle(self) -> NativeModuleHandle {
        match self {
            Self::Esm { record } | Self::CommonJs { record, .. } => record,
        }
    }

    fn commonjs_require_kind(self) -> u32 {
        match self {
            Self::CommonJs { .. } => 0,
            Self::Esm { .. } => 1,
        }
    }
}

#[cfg(any(test, feature = "module-runner"))]
impl PublishedNativeRecord {
    fn from_linked(record: &NativeLinkedRecord<'_>) -> Result<Self> {
        Ok(match record {
            NativeLinkedRecord::Esm(record) => Self::Esm {
                record: record.live_handle()?,
            },
            NativeLinkedRecord::CommonJs { record, adapter } => Self::CommonJs {
                record: record.live_handle()?,
                adapter: adapter.live_handle()?,
            },
        })
    }

    fn esm_link_handle(self) -> NativeModuleHandle {
        match self {
            Self::Esm { record } => record,
            Self::CommonJs { adapter, .. } => adapter,
        }
    }
}

/// Opaque native target returned by a successful synchronous CommonJS
/// activation. Only the internal provider bridge can project its handle.
pub struct NativeCommonJsRequireActivationTarget(PublishedNativeRecord);

/// Runtime-independent index over records retained by a pinned native graph
/// generation. It carries no JSI owner-thread values: each late activation
/// reconstructs short-lived Rust wrappers while holding the live runtime
/// lease, then writes the expanded handle set back into this index.
// @ref LLP 0026#6-top-level-await-and-dynamic-import
#[cfg(any(test, feature = "module-runner"))]
pub struct NativePublishedGraphIndex {
    entry: SourceId,
    graph_generation: u64,
    records: BTreeMap<SourceId, PublishedNativeRecord>,
    authorization_receipts: Vec<AuthorizedGraphOperation>,
}

#[cfg(any(test, feature = "module-runner"))]
impl NativePublishedGraphIndex {
    pub fn graph_generation(&self) -> u64 {
        self.graph_generation
    }

    pub fn owns_activation(&self, request: &DynamicModuleActivationRequest) -> bool {
        if self.graph_generation != request.graph_generation {
            return false;
        }
        let Some(requester_handle) = request.requester_record else {
            return self.records.contains_key(&request.requester);
        };
        self.records
            .get(&request.requester)
            .is_some_and(|record| match record {
                PublishedNativeRecord::Esm { record }
                | PublishedNativeRecord::CommonJs { record, .. } => *record == requester_handle,
            })
    }

    fn owns_commonjs_requester(
        &self,
        requester: &SourceId,
        requester_record: NativeModuleHandle,
    ) -> bool {
        self.records.get(requester).is_some_and(|record| {
            matches!(
                record,
                PublishedNativeRecord::CommonJs { record, .. }
                    if *record == requester_record
            )
        })
    }

    /// Publish the synchronously admissible static closure selected by one
    /// exact reached literal `require()`. Async-tainted ESM closures are
    /// refused before staging or publication.
    // @ref LLP 0026#7-commonjs-interop
    pub fn publish_authorized_require_activation<'runtime, P: GraphImportPolicy>(
        &mut self,
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        request: &CommonJsRequireActivationRequest,
        target: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>>,
    ) -> Result<NativeCommonJsRequireActivationTarget> {
        if request.graph_generation != self.graph_generation
            || !self.owns_commonjs_requester(&request.requester, request.requester_record)
        {
            bail!("CommonJS activation does not belong to this published native graph");
        }
        let declarations = deferred
            .get(&request.requester)
            .ok_or_else(|| anyhow!("CommonJS requester has no deferred declarations"))?;
        if !declarations
            .commonjs_require_specifiers
            .contains(&request.specifier)
            || !plan.defers_commonjs_require_edges(&request.requester)
        {
            bail!("CommonJS activation disagrees with the authenticated requester spelling");
        }
        plan.synchronous_evaluation_order(target).map_err(|error| {
            anyhow!("ERR_REQUIRE_ASYNC_MODULE: require() target graph is asynchronous: {error}")
        })?;

        let records = self
            .records
            .iter()
            .map(|(source_id, record)| {
                let linked = match record {
                    PublishedNativeRecord::Esm { record } => {
                        NativeLinkedRecord::Esm(NativeModuleRecord {
                            runtime,
                            handle: Some(*record),
                            published: true,
                        })
                    }
                    PublishedNativeRecord::CommonJs { record, adapter } => {
                        NativeLinkedRecord::CommonJs {
                            record: NativeCommonJsRecord {
                                runtime,
                                handle: Some(*record),
                                published: true,
                            },
                            adapter: NativeModuleRecord {
                                runtime,
                                handle: Some(*adapter),
                                published: true,
                            },
                        }
                    }
                };
                (source_id.clone(), linked)
            })
            .collect();
        let mut facade = NativeSynchronousGraph {
            entry: self.entry.clone(),
            graph_generation: self.graph_generation,
            evaluation_order: Vec::new(),
            records,
            evaluation_outcome: None,
            _authorization_receipts: std::mem::take(&mut self.authorization_receipts),
        };
        let result = facade
            .publish_authorized_target(
                runtime,
                plan,
                target,
                configs,
                authorizer,
                authority_contexts,
                deferred,
                prepared_entries,
            )
            .map(NativeCommonJsRequireActivationTarget);
        self.records = published_record_index(&facade.records)
            .expect("published native graph facade retains live record handles");
        self.authorization_receipts = std::mem::take(&mut facade._authorization_receipts);
        result
    }

    pub fn publish_authorized_activation<'runtime, P: GraphImportPolicy>(
        &mut self,
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        request: &DynamicModuleActivationRequest,
        target: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>>,
    ) -> Result<()> {
        if !self.owns_activation(request) {
            bail!("dynamic activation does not belong to this published native graph");
        }
        let records = self
            .records
            .iter()
            .map(|(source_id, record)| {
                let linked = match record {
                    PublishedNativeRecord::Esm { record } => {
                        NativeLinkedRecord::Esm(NativeModuleRecord {
                            runtime,
                            handle: Some(*record),
                            published: true,
                        })
                    }
                    PublishedNativeRecord::CommonJs { record, adapter } => {
                        NativeLinkedRecord::CommonJs {
                            record: NativeCommonJsRecord {
                                runtime,
                                handle: Some(*record),
                                published: true,
                            },
                            adapter: NativeModuleRecord {
                                runtime,
                                handle: Some(*adapter),
                                published: true,
                            },
                        }
                    }
                };
                (source_id.clone(), linked)
            })
            .collect();
        let mut facade = NativeSynchronousGraph {
            entry: self.entry.clone(),
            graph_generation: self.graph_generation,
            evaluation_order: Vec::new(),
            records,
            evaluation_outcome: None,
            _authorization_receipts: std::mem::take(&mut self.authorization_receipts),
        };
        let result = facade.publish_authorized_activation(
            runtime,
            plan,
            request,
            target,
            configs,
            authorizer,
            authority_contexts,
            deferred,
            prepared_entries,
        );
        self.records = published_record_index(&facade.records)
            .expect("published native graph facade retains live record handles");
        self.authorization_receipts = std::mem::take(&mut facade._authorization_receipts);
        result
    }
}

#[cfg(any(test, feature = "module-runner"))]
fn published_record_index(
    records: &BTreeMap<SourceId, NativeLinkedRecord<'_>>,
) -> Result<BTreeMap<SourceId, PublishedNativeRecord>> {
    records
        .iter()
        .map(|(source_id, record)| {
            let published = match record {
                NativeLinkedRecord::Esm(record) => PublishedNativeRecord::Esm {
                    record: record.live_handle()?,
                },
                NativeLinkedRecord::CommonJs { record, adapter } => {
                    PublishedNativeRecord::CommonJs {
                        record: record.live_handle()?,
                        adapter: adapter.live_handle()?,
                    }
                }
            };
            Ok((source_id.clone(), published))
        })
        .collect()
}

#[cfg(any(test, feature = "module-runner"))]
fn publish_linked_records(
    runtime: &NativeModuleRuntime<'_>,
    records: &mut BTreeMap<SourceId, NativeLinkedRecord<'_>>,
) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let handles = records
        .values()
        .map(NativeLinkedRecord::publication_handle)
        .collect::<Result<Vec<_>>>()?;
    let status = unsafe {
        ex_hermes_module_publish_records(
            runtime.raw.as_ptr(),
            runtime.nonce,
            handles.as_ptr(),
            handles.len(),
        )
    };
    if status != 0 {
        bail!("native ModuleRecord publication refused ({status})");
    }
    for record in records.values_mut() {
        record.mark_published();
    }
    Ok(())
}

#[cfg(any(test, feature = "module-runner"))]
pub type ComputedDynamicImportLinks = BTreeMap<SourceId, BTreeMap<(u32, String), SourceId>>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeferredDynamicImportBindings {
    pub literal_specifiers: BTreeSet<String>,
    pub computed_candidates: BTreeSet<(u32, String)>,
    pub commonjs_require_specifiers: BTreeSet<String>,
    pub bootstrap_internal_commonjs_specifiers: BTreeSet<String>,
}

pub type DeferredDynamicImportLinks = BTreeMap<SourceId, DeferredDynamicImportBindings>;

#[cfg(any(test, feature = "module-runner"))]
fn validate_deferred_dynamic_records(
    plan: &SynchronousGraphPlan<'_>,
    source_ids: &[SourceId],
    deferred: &DeferredDynamicImportLinks,
) -> Result<()> {
    for source_id in source_ids {
        let artifact = plan.artifact(source_id)?.artifact();
        let declarations = deferred.get(source_id).cloned().unwrap_or_default();
        let expected_commonjs_requires = if artifact.semantics.source_goal
            == crate::module_loader::artifact::SourceGoalV1::Builtin
        {
            BTreeSet::new()
        } else {
            artifact
                .semantics
                .static_edges
                .iter()
                .filter_map(|edge| match edge {
                    crate::module_loader::artifact::StaticEdgeV1::CommonJsRequire { specifier } => {
                        Some(specifier.as_str().to_owned())
                    }
                    _ => None,
                })
                .collect()
        };
        let expected_bootstrap_internals = plan.bootstrap_internal_commonjs_requires(source_id);
        let expected_literals = artifact
            .semantics
            .dynamic_edges
            .iter()
            .filter_map(|edge| match edge {
                crate::module_loader::artifact::DynamicEdgeV1::Literal { specifier, .. } => {
                    Some(specifier.as_str().to_owned())
                }
                crate::module_loader::artifact::DynamicEdgeV1::Computed { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        let admitted_sites = artifact
            .semantics
            .dynamic_edges
            .iter()
            .filter_map(|edge| match edge {
                crate::module_loader::artifact::DynamicEdgeV1::Computed { site } => Some(*site),
                crate::module_loader::artifact::DynamicEdgeV1::Literal { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        if expected_literals != declarations.literal_specifiers
            || expected_commonjs_requires != declarations.commonjs_require_specifiers
            || expected_bootstrap_internals != declarations.bootstrap_internal_commonjs_specifiers
            || declarations
                .computed_candidates
                .iter()
                .any(|(site, spelling)| !admitted_sites.contains(site) || spelling.is_empty())
            || (!artifact.semantics.dynamic_edges.is_empty()
                && !plan.defers_dynamic_edges(source_id))
            || (!expected_commonjs_requires.is_empty()
                && !plan.defers_commonjs_require_edges(source_id))
        {
            bail!(
                "deferred call-time declarations disagree with authenticated artifact {source_id:?}"
            );
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "module-runner"))]
pub struct NativeSynchronousGraph<'runtime> {
    entry: SourceId,
    graph_generation: u64,
    evaluation_order: Vec<SourceId>,
    records: BTreeMap<SourceId, NativeLinkedRecord<'runtime>>,
    evaluation_outcome: Option<std::result::Result<(), NativeModuleExecutionError>>,
    _authorization_receipts: Vec<AuthorizedGraphOperation>,
}

#[cfg(any(test, feature = "module-runner"))]
impl<'runtime> NativeSynchronousGraph<'runtime> {
    /// Production graph entry: authenticate the complete reachable edge set
    /// before compiling the first factory.
    pub fn link_authorized<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
    ) -> Result<Self> {
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        let mut receipts =
            plan.authorize_reachable_operations(entry, authorizer, authority_contexts)?;
        let dynamic = plan.authorize_dynamic_candidates(entry, authorizer, authority_contexts)?;
        receipts.extend(dynamic.receipts);
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            receipts,
            Some(dynamic.allowed_bindings),
            None,
            None,
            None,
        )
    }

    /// Prepared-graph entry. Carrier capabilities were admitted atomically by
    /// the trusted loader and are matched to the same verified semantic plan.
    pub fn link_authorized_prepared<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        prepared_entries: &BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>,
    ) -> Result<Self> {
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        let mut receipts =
            plan.authorize_reachable_operations(entry, authorizer, authority_contexts)?;
        let dynamic = plan.authorize_dynamic_candidates(entry, authorizer, authority_contexts)?;
        receipts.extend(dynamic.receipts);
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            receipts,
            Some(dynamic.allowed_bindings),
            None,
            Some(prepared_entries),
            None,
        )
    }

    /// Link only the authenticated static closure and install exact dynamic
    /// site declarations that mint reached-site activation requests. No
    /// dynamic target is authorized, acquired, compiled, or linked here.
    // @ref LLP 0024#3-source-goal
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    pub fn link_authorized_deferred<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
    ) -> Result<Self> {
        Self::link_authorized_deferred_inner(
            runtime,
            plan,
            entry,
            configs,
            authorizer,
            authority_contexts,
            deferred,
            None,
        )
    }

    pub fn link_authorized_deferred_prepared<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
        prepared_entries: &BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>,
    ) -> Result<Self> {
        Self::link_authorized_deferred_inner(
            runtime,
            plan,
            entry,
            configs,
            authorizer,
            authority_contexts,
            deferred,
            Some(prepared_entries),
        )
    }

    fn link_authorized_deferred_inner<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>>,
    ) -> Result<Self> {
        let empty = BTreeMap::new();
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        let linkage_order = plan.linkage_order_for_authorized(entry, &empty)?;
        let linkage_set = linkage_order.iter().cloned().collect::<BTreeSet<_>>();
        if deferred
            .keys()
            .any(|source_id| !linkage_set.contains(source_id))
        {
            bail!("deferred dynamic declarations include a requester outside the static closure");
        }
        validate_deferred_dynamic_records(plan, &linkage_order, deferred)?;
        let receipts =
            plan.authorize_reachable_operations(entry, authorizer, authority_contexts)?;
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            receipts,
            Some(empty),
            None,
            prepared_entries,
            Some(deferred),
        )
    }

    /// Materialize and publish only the authenticated static closure selected
    /// by one reached deferred import, then resolve that invocation onto the
    /// target's stable native record. Existing records are reused by identity;
    /// every new record is fully linked and declared before one atomic native
    /// publication batch.
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    pub fn publish_authorized_activation<P: GraphImportPolicy>(
        &mut self,
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        request: &DynamicModuleActivationRequest,
        target: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>>,
    ) -> Result<()> {
        let requester_handle = self
            .records
            .get(&request.requester)
            .map(NativeLinkedRecord::publication_handle)
            .transpose()?;
        if self.graph_generation != request.graph_generation
            || requester_handle.is_none()
            || request
                .requester_record
                .is_some_and(|native| Some(native) != requester_handle)
            || self
                .records
                .values()
                .next()
                .is_some_and(|record| !std::ptr::eq(record.runtime(), runtime))
        {
            bail!("dynamic activation does not belong to this live native graph");
        }
        let requester_declarations = deferred
            .get(&request.requester)
            .ok_or_else(|| anyhow!("dynamic activation requester has no deferred declarations"))?;
        let declared = match &request.kind {
            DynamicModuleActivationKind::Literal => requester_declarations
                .literal_specifiers
                .contains(&request.specifier),
            DynamicModuleActivationKind::Computed { site } => requester_declarations
                .computed_candidates
                .contains(&(*site, request.specifier.clone())),
        };
        if !declared || !plan.defers_dynamic_edges(&request.requester) {
            bail!("dynamic activation disagrees with the authenticated requester site");
        }

        let activated = self.publish_authorized_target(
            runtime,
            plan,
            target,
            configs,
            authorizer,
            authority_contexts,
            deferred,
            prepared_entries,
        )?;
        runtime.complete_dynamic_activation_handle(request, activated.esm_link_handle())
    }

    fn publish_authorized_target<P: GraphImportPolicy>(
        &mut self,
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        target: &SourceId,
        mut configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>>,
    ) -> Result<PublishedNativeRecord> {
        let empty = BTreeMap::new();
        let linkage_order = plan.linkage_order_for_authorized(target, &empty)?;
        validate_deferred_dynamic_records(plan, &linkage_order, deferred)?;
        let receipts =
            plan.authorize_reachable_operations(target, authorizer, authority_contexts)?;
        if let Some(outside) = configs
            .keys()
            .find(|source_id| !plan.contains_record(source_id))
        {
            bail!(
                "activation configuration contains record outside the authenticated plan: {outside:?}"
            );
        }
        let new_order = linkage_order
            .iter()
            .filter(|source_id| !self.records.contains_key(*source_id))
            .cloned()
            .collect::<Vec<_>>();
        if new_order.is_empty() {
            let target_record = self
                .records
                .get(target)
                .ok_or_else(|| anyhow!("activation target is absent from the live graph"))?;
            self._authorization_receipts.extend(receipts);
            return PublishedNativeRecord::from_linked(target_record);
        }

        let mut pending = BTreeMap::new();
        let mut module_metadata = BTreeMap::new();
        for source_id in &new_order {
            let config = configs.remove(source_id).ok_or_else(|| {
                anyhow!("new activation record {source_id:?} has no native configuration")
            })?;
            if config.evaluation_context.requesting_record != *source_id
                || config.evaluation_context.graph_generation != self.graph_generation
            {
                bail!("activation ModuleRecord context is stale or belongs to another record");
            }
            let context = runtime.create_graph_context(config.evaluation_context)?;
            let verified = plan.artifact(source_id)?;
            let factory = match prepared_entries.and_then(|entries| entries.get(source_id)) {
                Some(prepared) => runtime.load_verified_prepared_factory(
                    verified,
                    *prepared,
                    config.principal_id,
                    config.compartment_identity.as_deref(),
                    self.graph_generation,
                    &config.source_label,
                )?,
                None => match plan.source_goal(source_id)? {
                    SourceGoalV1::Module => runtime.compile_verified_factory(
                        verified,
                        config.principal_id,
                        config.compartment_identity.as_deref(),
                        self.graph_generation,
                        &config.source_label,
                    )?,
                    SourceGoalV1::CommonJs => runtime.compile_verified_commonjs_factory(
                        verified,
                        config.principal_id,
                        config.compartment_identity.as_deref(),
                        self.graph_generation,
                        &config.source_label,
                    )?,
                    SourceGoalV1::Json => runtime.compile_verified_json_factory(
                        verified,
                        config.principal_id,
                        config.compartment_identity.as_deref(),
                        self.graph_generation,
                        &config.source_label,
                    )?,
                    SourceGoalV1::Builtin => runtime.compile_verified_builtin_factory(
                        verified,
                        config.principal_id,
                        config.compartment_identity.as_deref(),
                        self.graph_generation,
                        &config.source_label,
                    )?,
                },
            };
            let record = match plan.source_goal(source_id)? {
                SourceGoalV1::Module | SourceGoalV1::Json => {
                    NativeLinkedRecord::Esm(factory.create_record(&context, source_id)?)
                }
                SourceGoalV1::CommonJs | SourceGoalV1::Builtin => {
                    let filename = config
                        .virtual_path
                        .as_deref()
                        .unwrap_or(&config.source_label);
                    let dirname = Path::new(filename)
                        .parent()
                        .and_then(Path::to_str)
                        .unwrap_or("");
                    let mut record =
                        factory.create_commonjs_record(&context, source_id, filename, dirname)?;
                    for export_name in plan.namespace(source_id)?.keys() {
                        if export_name != "default" && export_name != "module.exports" {
                            record.declare_detected_export(export_name)?;
                        }
                    }
                    let adapter = record.create_esm_adapter()?;
                    NativeLinkedRecord::CommonJs { record, adapter }
                }
            };
            pending.insert(source_id.clone(), record);
            module_metadata.insert(source_id.clone(), (config.meta_url, config.virtual_path));
        }

        for source_id in &new_order {
            let namespace = plan.namespace(source_id)?;
            let Some(record) = pending
                .get_mut(source_id)
                .expect("every new activation record was created")
                .esm_mut()
            else {
                continue;
            };
            for export_name in namespace.keys() {
                record.declare_export(export_name)?;
            }
        }

        for source_id in &new_order {
            for (export_name, export_target) in plan.namespace(source_id)? {
                if export_target.record == *source_id && export_target.binding == export_name {
                    continue;
                }
                let target_handle = pending
                    .get(&export_target.record)
                    .or_else(|| self.records.get(&export_target.record))
                    .ok_or_else(|| anyhow!("activation export target is outside static closure"))?
                    .esm_link_handle()?;
                let Some(record) = pending
                    .get_mut(source_id)
                    .expect("every new activation record was created")
                    .esm_mut()
                else {
                    continue;
                };
                record.link_export_handle(&export_name, target_handle, &export_target.binding)?;
            }
            for binding in plan.import_bindings(source_id)? {
                let target_handle = pending
                    .get(&binding.target.record)
                    .or_else(|| self.records.get(&binding.target.record))
                    .ok_or_else(|| anyhow!("activation import target is outside static closure"))?
                    .esm_link_handle()?;
                let Some(record) = pending
                    .get_mut(source_id)
                    .expect("every new activation record was created")
                    .esm_mut()
                else {
                    continue;
                };
                record.link_import_handle(
                    &binding.specifier,
                    &binding.imported,
                    target_handle,
                    &binding.target.binding,
                )?;
            }
            for (specifier, require_target) in plan.commonjs_require_bindings(source_id)? {
                let target_record = pending
                    .get(&require_target)
                    .or_else(|| self.records.get(&require_target))
                    .ok_or_else(|| {
                        anyhow!("activation require target is outside static closure")
                    })?;
                let (target_handle, target_is_esm) = match target_record {
                    NativeLinkedRecord::CommonJs { record, .. } => (record.live_handle()?, false),
                    NativeLinkedRecord::Esm(record) => (record.live_handle()?, true),
                };
                let record = pending
                    .get_mut(source_id)
                    .and_then(NativeLinkedRecord::commonjs_mut)
                    .ok_or_else(|| {
                        anyhow!("activation CommonJS require belongs to a non-CommonJS record")
                    })?;
                if target_is_esm {
                    let synchronous_eligible =
                        match plan.synchronous_evaluation_order(&require_target) {
                            Ok(_) => true,
                            Err(error) if error.code == GraphErrorCode::RequireAsyncModule => false,
                            Err(error) => return Err(error.into()),
                        };
                    record.link_require_esm_handle(
                        &specifier,
                        target_handle,
                        synchronous_eligible,
                    )?;
                } else {
                    record.link_require_handle(&specifier, target_handle)?;
                }
            }

            let mut dependencies = BTreeSet::new();
            for edge in &plan.artifact(source_id)?.artifact().semantics.static_edges {
                let specifier = match edge {
                    crate::module_loader::artifact::StaticEdgeV1::CommonJsRequire { .. } => {
                        continue
                    }
                    crate::module_loader::artifact::StaticEdgeV1::SideEffect {
                        specifier, ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::Default { specifier, .. }
                    | crate::module_loader::artifact::StaticEdgeV1::Namespace {
                        specifier, ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::Named { specifier, .. }
                    | crate::module_loader::artifact::StaticEdgeV1::ReExportNamed {
                        specifier,
                        ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::ReExportStar {
                        specifier,
                        ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::ReExportNamespace {
                        specifier,
                        ..
                    } => specifier.as_str(),
                };
                let dependency = plan.literal_static_target(source_id, specifier)?.clone();
                if dependencies.insert(dependency.clone()) {
                    let target_handle = pending
                        .get(&dependency)
                        .or_else(|| self.records.get(&dependency))
                        .ok_or_else(|| anyhow!("activation dependency is outside static closure"))?
                        .esm_link_handle()?;
                    let Some(record) = pending
                        .get_mut(source_id)
                        .expect("every new activation record was created")
                        .esm_mut()
                    else {
                        bail!("activation ESM dependency belongs to a non-ESM record");
                    };
                    record.link_dependency_handle(target_handle)?;
                }
            }
            if let Some(bindings) = deferred.get(source_id) {
                for specifier in &bindings.bootstrap_internal_commonjs_specifiers {
                    pending
                        .get_mut(source_id)
                        .and_then(NativeLinkedRecord::commonjs_mut)
                        .ok_or_else(|| {
                            anyhow!(
                                "bootstrap-internal CommonJS require belongs to a non-CommonJS record"
                            )
                        })?
                        .link_bootstrap_internal_require(specifier)?;
                }
                for specifier in &bindings.commonjs_require_specifiers {
                    pending
                        .get_mut(source_id)
                        .and_then(NativeLinkedRecord::commonjs_mut)
                        .ok_or_else(|| {
                            anyhow!("deferred CommonJS require belongs to a non-CommonJS record")
                        })?
                        .defer_require_handle(specifier)?;
                }
                for specifier in &bindings.literal_specifiers {
                    match pending
                        .get_mut(source_id)
                        .expect("every new activation record was created")
                    {
                        NativeLinkedRecord::Esm(record) => {
                            record.defer_dynamic_import_handle(specifier)?
                        }
                        NativeLinkedRecord::CommonJs { record, .. } => {
                            record.defer_dynamic_import_handle(specifier)?
                        }
                    }
                }
                for (site, specifier) in &bindings.computed_candidates {
                    match pending
                        .get_mut(source_id)
                        .expect("every new activation record was created")
                    {
                        NativeLinkedRecord::Esm(record) => {
                            record.defer_computed_dynamic_import_handle(*site, specifier)?
                        }
                        NativeLinkedRecord::CommonJs { record, .. } => {
                            record.defer_computed_dynamic_import_handle(*site, specifier)?
                        }
                    }
                }
            }
        }

        for source_id in &new_order {
            let (meta_url, virtual_path) = module_metadata
                .get(source_id)
                .expect("every new activation record has native metadata");
            let Some(record) = pending
                .get_mut(source_id)
                .expect("every new activation record was created")
                .esm_mut()
            else {
                continue;
            };
            record.instantiate_with_virtual_path(meta_url, virtual_path.as_deref(), false)?;
        }
        for source_id in &new_order {
            let Some(record) = pending
                .get_mut(source_id)
                .expect("every new activation record was created")
                .esm_mut()
            else {
                continue;
            };
            record.run_declare()?;
        }
        publish_linked_records(runtime, &mut pending)?;
        let target_record = pending
            .get(target)
            .or_else(|| self.records.get(target))
            .ok_or_else(|| anyhow!("published activation omitted its target"))?;
        let activated = PublishedNativeRecord::from_linked(target_record)?;
        self.records.append(&mut pending);
        self._authorization_receipts.extend(receipts);
        Ok(activated)
    }

    pub fn published_activation_index(&self) -> Result<NativePublishedGraphIndex> {
        Ok(NativePublishedGraphIndex {
            entry: self.entry.clone(),
            graph_generation: self.graph_generation,
            records: published_record_index(&self.records)?,
            authorization_receipts: self._authorization_receipts.clone(),
        })
    }

    /// Diagnostic-only bypass for native ABI unit fixtures. Advertised builds
    /// have no unauthenticated graph-link entry.
    #[cfg(test)]
    pub fn link(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
    ) -> Result<Self> {
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            Vec::new(),
            None,
            None,
            None,
            None,
        )
    }

    #[cfg(test)]
    pub fn link_with_computed_candidates(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        computed_candidates: &ComputedDynamicImportLinks,
    ) -> Result<Self> {
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            Vec::new(),
            None,
            Some(computed_candidates),
            None,
            None,
        )
    }

    #[cfg(any(test, feature = "sfe-dev-spike"))]
    pub fn link_prepared(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        prepared_entries: &BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>,
    ) -> Result<Self> {
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            Vec::new(),
            None,
            None,
            Some(prepared_entries),
            None,
        )
    }

    #[cfg(any(test, feature = "sfe-dev-spike"))]
    pub fn link_prepared_with_computed_candidates(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        prepared_entries: &BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>,
        computed_candidates: &ComputedDynamicImportLinks,
    ) -> Result<Self> {
        let evaluation_order = plan.synchronous_evaluation_order(entry)?;
        Self::link_inner(
            runtime,
            plan,
            entry,
            evaluation_order,
            configs,
            Vec::new(),
            None,
            Some(computed_candidates),
            Some(prepared_entries),
            None,
        )
    }

    fn link_inner(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        evaluation_order: Vec<SourceId>,
        mut configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorization_receipts: Vec<AuthorizedGraphOperation>,
        allowed_dynamic_bindings: Option<BTreeMap<SourceId, BTreeSet<DynamicImportBindingKey>>>,
        computed_candidates: Option<&ComputedDynamicImportLinks>,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>>,
        deferred_dynamic: Option<&DeferredDynamicImportLinks>,
    ) -> Result<Self> {
        let linkage_order = match &allowed_dynamic_bindings {
            Some(allowed) => plan.linkage_order_for_authorized(entry, allowed)?,
            None => plan.linkage_order(entry)?,
        };
        if let Some(outside) = configs
            .keys()
            .find(|source_id| !plan.contains_record(source_id))
        {
            bail!(
                "native configuration contains record outside the authenticated plan: {outside:?}"
            );
        }
        let generation = configs
            .get(entry)
            .ok_or_else(|| anyhow!("entry ModuleRecord has no native configuration"))?
            .evaluation_context
            .graph_generation;
        let mut records = BTreeMap::new();
        let mut module_metadata = BTreeMap::new();

        // Create every reachable record before publishing cells or links. The
        // native record retains its context and callable factory handles.
        for source_id in &linkage_order {
            let config = configs.remove(source_id).ok_or_else(|| {
                anyhow!("reachable ModuleRecord {source_id:?} has no native configuration")
            })?;
            if config.evaluation_context.requesting_record != *source_id {
                bail!("ModuleRecord context requester does not match {source_id:?}");
            }
            if config.evaluation_context.graph_generation != generation {
                bail!("synchronous graph mixes execution generations");
            }
            let context = runtime.create_graph_context(config.evaluation_context)?;
            let verified = plan.artifact(source_id)?;
            let factory = match prepared_entries {
                Some(entries) => runtime.load_verified_prepared_factory(
                    verified,
                    *entries.get(source_id).ok_or_else(|| {
                        anyhow!("prepared graph has no admitted carrier entry for {source_id:?}")
                    })?,
                    config.principal_id,
                    config.compartment_identity.as_deref(),
                    generation,
                    &config.source_label,
                )?,
                None => match plan.source_goal(source_id)? {
                    SourceGoalV1::Module => runtime.compile_verified_factory(
                        verified,
                        config.principal_id,
                        config.compartment_identity.as_deref(),
                        generation,
                        &config.source_label,
                    )?,
                    SourceGoalV1::CommonJs => runtime.compile_verified_commonjs_factory(
                        verified,
                        config.principal_id,
                        config.compartment_identity.as_deref(),
                        generation,
                        &config.source_label,
                    )?,
                    SourceGoalV1::Json => runtime.compile_verified_json_factory(
                        verified,
                        config.principal_id,
                        config.compartment_identity.as_deref(),
                        generation,
                        &config.source_label,
                    )?,
                    SourceGoalV1::Builtin => runtime.compile_verified_builtin_factory(
                        verified,
                        config.principal_id,
                        config.compartment_identity.as_deref(),
                        generation,
                        &config.source_label,
                    )?,
                },
            };
            let record = match plan.source_goal(source_id)? {
                SourceGoalV1::Module | SourceGoalV1::Json => {
                    NativeLinkedRecord::Esm(factory.create_record(&context, source_id)?)
                }
                SourceGoalV1::CommonJs | SourceGoalV1::Builtin => {
                    let filename = config
                        .virtual_path
                        .as_deref()
                        .unwrap_or(&config.source_label);
                    let dirname = Path::new(filename)
                        .parent()
                        .and_then(Path::to_str)
                        .unwrap_or("");
                    let mut record =
                        factory.create_commonjs_record(&context, source_id, filename, dirname)?;
                    for export_name in plan.namespace(source_id)?.keys() {
                        if export_name != "default" && export_name != "module.exports" {
                            record.declare_detected_export(export_name)?;
                        }
                    }
                    let adapter = record.create_esm_adapter()?;
                    NativeLinkedRecord::CommonJs { record, adapter }
                }
            };
            records.insert(source_id.clone(), record);
            module_metadata.insert(source_id.clone(), (config.meta_url, config.virtual_path));
        }
        // Configurations for denied or unselected dynamic candidates remain
        // inert: no native record, factory compilation, or call-time table
        // entry is created for them.

        // Materialize every namespace shape before linking any aliases. This
        // is the cycle boundary: every record identity and cell already exists.
        for source_id in &linkage_order {
            let namespace = plan.namespace(source_id)?;
            let Some(record) = records
                .get_mut(source_id)
                .expect("evaluation order was used to create every record")
                .esm_mut()
            else {
                continue;
            };
            for export_name in namespace.keys() {
                record.declare_export(export_name)?;
            }
        }

        for source_id in &linkage_order {
            for (export_name, target) in plan.namespace(source_id)? {
                if target.record == *source_id && target.binding == export_name {
                    continue;
                }
                let target_handle = records
                    .get(&target.record)
                    .ok_or_else(|| anyhow!("export target is outside the entry closure"))?
                    .esm_link_handle()?;
                let Some(record) = records
                    .get_mut(source_id)
                    .expect("evaluation order was used to create every record")
                    .esm_mut()
                else {
                    continue;
                };
                record.link_export_handle(&export_name, target_handle, &target.binding)?;
            }
            for binding in plan.import_bindings(source_id)? {
                let target_handle = records
                    .get(&binding.target.record)
                    .ok_or_else(|| anyhow!("import target is outside the entry closure"))?
                    .esm_link_handle()?;
                let Some(record) = records
                    .get_mut(source_id)
                    .expect("evaluation order was used to create every record")
                    .esm_mut()
                else {
                    continue;
                };
                record.link_import_handle(
                    &binding.specifier,
                    &binding.imported,
                    target_handle,
                    &binding.target.binding,
                )?;
            }
            for (specifier, target) in plan.commonjs_require_bindings(source_id)? {
                let (target_handle, target_is_esm) = match records
                    .get(&target)
                    .ok_or_else(|| anyhow!("CommonJS require target is outside linkage closure"))?
                {
                    NativeLinkedRecord::CommonJs { record, .. } => (record.live_handle()?, false),
                    NativeLinkedRecord::Esm(record) => (record.live_handle()?, true),
                };
                let record = records
                    .get_mut(source_id)
                    .and_then(NativeLinkedRecord::commonjs_mut)
                    .ok_or_else(|| {
                        anyhow!("CommonJS require edge belongs to a non-CommonJS record")
                    })?;
                if target_is_esm {
                    let synchronous_eligible = match plan.synchronous_evaluation_order(&target) {
                        Ok(_) => true,
                        Err(error) if error.code == GraphErrorCode::RequireAsyncModule => false,
                        Err(error) => return Err(error.into()),
                    };
                    record.link_require_esm_handle(
                        &specifier,
                        target_handle,
                        synchronous_eligible,
                    )?;
                } else {
                    record.link_require_handle(&specifier, target_handle)?;
                }
            }

            let mut dependencies = BTreeSet::new();
            for edge in &plan.artifact(source_id)?.artifact().semantics.static_edges {
                let specifier = match edge {
                    crate::module_loader::artifact::StaticEdgeV1::CommonJsRequire { .. } => {
                        continue
                    }
                    crate::module_loader::artifact::StaticEdgeV1::SideEffect {
                        specifier, ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::Default { specifier, .. }
                    | crate::module_loader::artifact::StaticEdgeV1::Namespace {
                        specifier, ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::Named { specifier, .. }
                    | crate::module_loader::artifact::StaticEdgeV1::ReExportNamed {
                        specifier,
                        ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::ReExportStar {
                        specifier,
                        ..
                    }
                    | crate::module_loader::artifact::StaticEdgeV1::ReExportNamespace {
                        specifier,
                        ..
                    } => specifier.as_str(),
                };
                let target = plan.literal_static_target(source_id, specifier)?.clone();
                if dependencies.insert(target.clone()) {
                    let target_handle = records
                        .get(&target)
                        .ok_or_else(|| anyhow!("evaluation dependency is outside linkage closure"))?
                        .esm_link_handle()?;
                    let Some(record) = records
                        .get_mut(source_id)
                        .expect("linkage order was used to create every record")
                        .esm_mut()
                    else {
                        bail!("ESM static edge belongs to a non-ESM record");
                    };
                    record.link_dependency_handle(target_handle)?;
                }
            }
            if let Some(deferred) = deferred_dynamic {
                if let Some(bindings) = deferred.get(source_id) {
                    for specifier in &bindings.bootstrap_internal_commonjs_specifiers {
                        records
                            .get_mut(source_id)
                            .and_then(NativeLinkedRecord::commonjs_mut)
                            .ok_or_else(|| {
                                anyhow!(
                                    "bootstrap-internal CommonJS require belongs to a non-CommonJS record"
                                )
                            })?
                            .link_bootstrap_internal_require(specifier)?;
                    }
                    for specifier in &bindings.commonjs_require_specifiers {
                        records
                            .get_mut(source_id)
                            .and_then(NativeLinkedRecord::commonjs_mut)
                            .ok_or_else(|| {
                                anyhow!(
                                    "deferred CommonJS require belongs to a non-CommonJS record"
                                )
                            })?
                            .defer_require_handle(specifier)?;
                    }
                    for specifier in &bindings.literal_specifiers {
                        match records
                            .get_mut(source_id)
                            .expect("linkage order was used to create every record")
                        {
                            NativeLinkedRecord::Esm(record) => {
                                record.defer_dynamic_import_handle(specifier)?
                            }
                            NativeLinkedRecord::CommonJs { record, .. } => {
                                record.defer_dynamic_import_handle(specifier)?
                            }
                        }
                    }
                    for (site, specifier) in &bindings.computed_candidates {
                        match records
                            .get_mut(source_id)
                            .expect("linkage order was used to create every record")
                        {
                            NativeLinkedRecord::Esm(record) => {
                                record.defer_computed_dynamic_import_handle(*site, specifier)?
                            }
                            NativeLinkedRecord::CommonJs { record, .. } => {
                                record.defer_computed_dynamic_import_handle(*site, specifier)?
                            }
                        }
                    }
                }
                continue;
            }
            for binding in plan.dynamic_import_bindings(source_id)? {
                if binding.site.is_some() {
                    continue;
                }
                let binding_key = DynamicImportBindingKey {
                    site: None,
                    specifier: binding.specifier.clone(),
                };
                let specifier = binding.specifier;
                let target = binding.target;
                if allowed_dynamic_bindings.as_ref().is_some_and(|allowed| {
                    !allowed
                        .get(source_id)
                        .is_some_and(|bindings| bindings.contains(&binding_key))
                }) {
                    continue;
                }
                let target_handle = records
                    .get(&target)
                    .ok_or_else(|| anyhow!("dynamic import target is outside linkage closure"))?
                    .esm_link_handle()?;
                match records
                    .get_mut(source_id)
                    .expect("linkage order was used to create every record")
                {
                    NativeLinkedRecord::Esm(record) => {
                        record.link_dynamic_import_handle(&specifier, target_handle)?
                    }
                    NativeLinkedRecord::CommonJs { record, .. } => {
                        record.link_dynamic_import_handle(&specifier, target_handle)?;
                    }
                }
            }
            let site_rows = match computed_candidates.and_then(|rows| rows.get(source_id)) {
                Some(rows) => rows
                    .iter()
                    .map(|((site, specifier), target)| (*site, specifier.clone(), target.clone()))
                    .collect::<Vec<_>>(),
                None => plan
                    .computed_candidate_sites()
                    .get(source_id)
                    .into_iter()
                    .flat_map(|rows| rows.iter())
                    .map(|((site, specifier), binding)| {
                        (*site, specifier.clone(), binding.target.clone())
                    })
                    .collect::<Vec<_>>(),
            };
            if !site_rows.is_empty() {
                let admitted_sites = plan
                    .artifact(source_id)?
                    .artifact()
                    .semantics
                    .dynamic_edges
                    .iter()
                    .filter_map(|edge| match edge {
                        crate::module_loader::artifact::DynamicEdgeV1::Computed { site } => {
                            Some(*site)
                        }
                        crate::module_loader::artifact::DynamicEdgeV1::Literal { .. } => None,
                    })
                    .collect::<BTreeSet<_>>();
                let authenticated = plan.computed_candidate_sites().get(source_id);
                for (site, specifier, target) in site_rows {
                    let binding_key = DynamicImportBindingKey {
                        site: Some(site),
                        specifier: specifier.clone(),
                    };
                    if allowed_dynamic_bindings.as_ref().is_some_and(|allowed| {
                        !allowed
                            .get(source_id)
                            .is_some_and(|bindings| bindings.contains(&binding_key))
                    }) {
                        continue;
                    }
                    if !admitted_sites.contains(&site) {
                        bail!(
                            "computed candidate site {site} is absent from the authenticated artifact"
                        );
                    }
                    if !authenticated.is_some_and(|rows| {
                        rows.get(&(site, specifier.clone()))
                            .is_some_and(|binding| binding.target == target)
                    }) {
                        bail!(
                            "computed candidate site {site} spelling {specifier:?} is absent from the authenticated plan"
                        );
                    }
                    let target_handle = records
                        .get(&target)
                        .ok_or_else(|| {
                            anyhow!("computed dynamic-import target is outside linkage closure")
                        })?
                        .esm_link_handle()?;
                    match records
                        .get_mut(source_id)
                        .expect("linkage order was used to create every record")
                    {
                        NativeLinkedRecord::Esm(record) => record
                            .link_computed_dynamic_import_handle(site, &specifier, target_handle)?,
                        NativeLinkedRecord::CommonJs { record, .. } => record
                            .link_computed_dynamic_import_handle(site, &specifier, target_handle)?,
                    }
                }
            }
        }

        // Complete graph-wide instantiation and declaration before the first
        // body executes. Dependency-first order also matches the synchronous
        // DFS evaluation order for cycles and acyclic graphs.
        for source_id in &linkage_order {
            let (meta_url, virtual_path) = module_metadata
                .get(source_id)
                .expect("every configured record has an import.meta URL");
            let Some(record) = records
                .get_mut(source_id)
                .expect("evaluation order was used to create every record")
                .esm_mut()
            else {
                continue;
            };
            record.instantiate_with_virtual_path(
                meta_url,
                virtual_path.as_deref(),
                source_id == entry,
            )?;
        }
        for source_id in &linkage_order {
            let Some(record) = records
                .get_mut(source_id)
                .expect("evaluation order was used to create every record")
                .esm_mut()
            else {
                continue;
            };
            record.run_declare()?;
        }
        publish_linked_records(runtime, &mut records)?;

        Ok(Self {
            entry: entry.clone(),
            graph_generation: generation,
            evaluation_order,
            records,
            evaluation_outcome: None,
            _authorization_receipts: authorization_receipts,
        })
    }

    pub fn evaluate(&mut self) -> Result<()> {
        if let Some(outcome) = &self.evaluation_outcome {
            return outcome.clone().map_err(anyhow::Error::new);
        }
        let outcome = (|| {
            for source_id in &self.evaluation_order {
                let kind = match self
                    .records
                    .get_mut(source_id)
                    .expect("linked graph retains every reachable record")
                {
                    NativeLinkedRecord::Esm(record) => record.run_execute()?,
                    NativeLinkedRecord::CommonJs { record, .. } => {
                        record.evaluate()?;
                        ModuleExecutionKind::Synchronous
                    }
                };
                if kind == ModuleExecutionKind::Asynchronous {
                    bail!(
                        "ERR_REQUIRE_ASYNC_MODULE: synchronous artifact returned a promise in {source_id:?}"
                    );
                }
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => {
                self.evaluation_outcome = Some(Ok(()));
                Ok(())
            }
            Err(error) => {
                let sticky = sticky_module_error(&error);
                self.evaluation_outcome = Some(Err(sticky.clone()));
                Err(anyhow::Error::new(sticky))
            }
        }
    }

    pub fn entry(&self) -> &SourceId {
        &self.entry
    }

    pub fn namespace_json(&self, source_id: &SourceId) -> Result<String> {
        self.records
            .get(source_id)
            .ok_or_else(|| anyhow!("namespace requested outside the linked entry closure"))?
            .namespace_json()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncGraphPoll {
    Suspended,
    Evaluated,
}

/// A linked ESM graph whose dependency-first progress is driven by polling.
/// The graph owns every internal record promise until terminal settlement;
/// callers drive the Hermes microtask/event loop between `poll` calls and no
/// runtime thread is ever blocked.
// @ref LLP 0024#7-the-session-record
// @ref LLP 0025#6-interruption-and-cancellation
#[cfg(any(test, feature = "module-runner"))]
pub struct NativeAsynchronousGraph<'runtime> {
    entry: SourceId,
    graph_generation: u64,
    schedule: AsyncEvaluationPlan,
    records: BTreeMap<SourceId, NativeLinkedRecord<'runtime>>,
    next_scc: usize,
    suspended_records: Vec<SourceId>,
    evaluation_outcome: Option<std::result::Result<(), NativeModuleExecutionError>>,
    _authorization_receipts: Vec<AuthorizedGraphOperation>,
}

#[cfg(any(test, feature = "module-runner"))]
impl<'runtime> NativeAsynchronousGraph<'runtime> {
    pub fn link_authorized<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
    ) -> Result<Self> {
        let schedule = plan.asynchronous_evaluation_plan(entry)?;
        let mut receipts =
            plan.authorize_reachable_operations(entry, authorizer, authority_contexts)?;
        let dynamic = plan.authorize_dynamic_candidates(entry, authorizer, authority_contexts)?;
        receipts.extend(dynamic.receipts);
        Self::link_inner(
            runtime,
            plan,
            entry,
            schedule,
            configs,
            receipts,
            Some(dynamic.allowed_bindings),
            None,
        )
    }

    pub fn link_authorized_prepared<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        prepared_entries: &BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>,
    ) -> Result<Self> {
        let schedule = plan.asynchronous_evaluation_plan(entry)?;
        let mut receipts =
            plan.authorize_reachable_operations(entry, authorizer, authority_contexts)?;
        let dynamic = plan.authorize_dynamic_candidates(entry, authorizer, authority_contexts)?;
        receipts.extend(dynamic.receipts);
        Self::link_inner(
            runtime,
            plan,
            entry,
            schedule,
            configs,
            receipts,
            Some(dynamic.allowed_bindings),
            Some(prepared_entries),
        )
    }

    pub fn link_authorized_deferred<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
    ) -> Result<Self> {
        Self::link_authorized_deferred_inner(
            runtime,
            plan,
            entry,
            configs,
            authorizer,
            authority_contexts,
            deferred,
            None,
        )
    }

    pub fn link_authorized_deferred_prepared<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
        prepared_entries: &BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>,
    ) -> Result<Self> {
        Self::link_authorized_deferred_inner(
            runtime,
            plan,
            entry,
            configs,
            authorizer,
            authority_contexts,
            deferred,
            Some(prepared_entries),
        )
    }

    fn link_authorized_deferred_inner<P: GraphImportPolicy>(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>>,
    ) -> Result<Self> {
        let empty = BTreeMap::new();
        let linkage_order = plan.linkage_order_for_authorized(entry, &empty)?;
        let linkage_set = linkage_order.iter().cloned().collect::<BTreeSet<_>>();
        if deferred
            .keys()
            .any(|source_id| !linkage_set.contains(source_id))
        {
            bail!("deferred dynamic declarations include a requester outside the static closure");
        }
        validate_deferred_dynamic_records(plan, &linkage_order, deferred)?;
        let schedule = plan.asynchronous_evaluation_plan(entry)?;
        let receipts =
            plan.authorize_reachable_operations(entry, authorizer, authority_contexts)?;
        let linked = NativeSynchronousGraph::link_inner(
            runtime,
            plan,
            entry,
            schedule.evaluation_order.clone(),
            configs,
            receipts,
            Some(empty),
            None,
            prepared_entries,
            Some(deferred),
        )?;
        Self::from_synchronous(linked, schedule)
    }

    #[cfg(test)]
    pub fn link(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
    ) -> Result<Self> {
        let schedule = plan.asynchronous_evaluation_plan(entry)?;
        Self::link_inner(
            runtime,
            plan,
            entry,
            schedule,
            configs,
            Vec::new(),
            None,
            None,
        )
    }

    fn link_inner(
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        entry: &SourceId,
        schedule: AsyncEvaluationPlan,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorization_receipts: Vec<AuthorizedGraphOperation>,
        allowed_dynamic_bindings: Option<BTreeMap<SourceId, BTreeSet<DynamicImportBindingKey>>>,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>>,
    ) -> Result<Self> {
        let linked = NativeSynchronousGraph::link_inner(
            runtime,
            plan,
            entry,
            schedule.evaluation_order.clone(),
            configs,
            authorization_receipts,
            allowed_dynamic_bindings,
            None,
            prepared_entries,
            None,
        )?;
        Self::from_synchronous(linked, schedule)
    }

    fn from_synchronous(
        linked: NativeSynchronousGraph<'runtime>,
        schedule: AsyncEvaluationPlan,
    ) -> Result<Self> {
        let NativeSynchronousGraph {
            entry,
            graph_generation,
            records,
            _authorization_receipts,
            ..
        } = linked;
        Ok(Self {
            entry,
            graph_generation,
            schedule,
            records,
            next_scc: 0,
            suspended_records: Vec::new(),
            evaluation_outcome: None,
            _authorization_receipts,
        })
    }

    pub fn publish_authorized_activation<P: GraphImportPolicy>(
        &mut self,
        runtime: &'runtime NativeModuleRuntime<'runtime>,
        plan: &SynchronousGraphPlan<'_>,
        request: &DynamicModuleActivationRequest,
        target: &SourceId,
        configs: BTreeMap<SourceId, NativeModuleRecordConfig>,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        authority_contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
        deferred: &DeferredDynamicImportLinks,
        prepared_entries: Option<&BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>>,
    ) -> Result<()> {
        let mut facade = NativeSynchronousGraph {
            entry: self.entry.clone(),
            graph_generation: self.graph_generation,
            evaluation_order: Vec::new(),
            records: std::mem::take(&mut self.records),
            evaluation_outcome: None,
            _authorization_receipts: std::mem::take(&mut self._authorization_receipts),
        };
        let result = facade.publish_authorized_activation(
            runtime,
            plan,
            request,
            target,
            configs,
            authorizer,
            authority_contexts,
            deferred,
            prepared_entries,
        );
        self.records = facade.records;
        self._authorization_receipts = facade._authorization_receipts;
        result
    }

    pub fn published_activation_index(&self) -> Result<NativePublishedGraphIndex> {
        Ok(NativePublishedGraphIndex {
            entry: self.entry.clone(),
            graph_generation: self.graph_generation,
            records: published_record_index(&self.records)?,
            authorization_receipts: self._authorization_receipts.clone(),
        })
    }

    /// Make deterministic progress until the next TLA suspension or terminal
    /// outcome. A native rejection becomes the graph's sticky error and every
    /// later poll reports the same diagnostic.
    pub fn poll(&mut self) -> Result<AsyncGraphPoll> {
        if let Some(outcome) = &self.evaluation_outcome {
            return outcome
                .clone()
                .map(|()| AsyncGraphPoll::Evaluated)
                .map_err(anyhow::Error::new);
        }
        let outcome: Result<AsyncGraphPoll> = (|| {
            if !self.suspended_records.is_empty() {
                let mut pending = Vec::new();
                for source_id in self.suspended_records.drain(..) {
                    match self
                        .records
                        .get_mut(&source_id)
                        .expect("suspended record remains owned by its graph")
                        .esm_mut()
                        .ok_or_else(|| anyhow!("CommonJS record cannot suspend asynchronously"))?
                        .poll_evaluation()?
                    {
                        ModuleEvaluationState::Pending => pending.push(source_id),
                        ModuleEvaluationState::Evaluated => {}
                    }
                }
                self.suspended_records = pending;
                if !self.suspended_records.is_empty() {
                    return Ok(AsyncGraphPoll::Suspended);
                }
                self.next_scc += 1;
            }

            while self.next_scc < self.schedule.sccs.len() {
                // All records in one SCC must be allowed to start before the
                // component waits. Otherwise one TLA record can suspend ahead
                // of a cyclic peer whose body is required to settle it.
                // @ref LLP 0026#6-top-level-await-and-dynamic-import
                for source_id in self.schedule.sccs[self.next_scc].records.clone() {
                    let kind = match self
                        .records
                        .get_mut(&source_id)
                        .expect("async schedule retains every reachable record")
                    {
                        NativeLinkedRecord::Esm(record) => record.run_execute()?,
                        NativeLinkedRecord::CommonJs { record, .. } => {
                            record.evaluate()?;
                            ModuleExecutionKind::Synchronous
                        }
                    };
                    if kind == ModuleExecutionKind::Asynchronous {
                        self.suspended_records.push(source_id);
                    }
                }
                if !self.suspended_records.is_empty() {
                    return Ok(AsyncGraphPoll::Suspended);
                }
                self.next_scc += 1;
            }
            Ok(AsyncGraphPoll::Evaluated)
        })();
        match outcome {
            Ok(AsyncGraphPoll::Evaluated) => {
                self.evaluation_outcome = Some(Ok(()));
                Ok(AsyncGraphPoll::Evaluated)
            }
            Ok(AsyncGraphPoll::Suspended) => Ok(AsyncGraphPoll::Suspended),
            Err(error) => {
                let sticky = sticky_module_error(&error);
                self.evaluation_outcome = Some(Err(sticky.clone()));
                Err(anyhow::Error::new(sticky))
            }
        }
    }

    pub fn is_suspended(&self) -> bool {
        !self.suspended_records.is_empty()
    }

    pub fn entry(&self) -> &SourceId {
        &self.entry
    }

    pub fn schedule(&self) -> &AsyncEvaluationPlan {
        &self.schedule
    }

    pub fn namespace_json(&self, source_id: &SourceId) -> Result<String> {
        self.records
            .get(source_id)
            .ok_or_else(|| anyhow!("namespace requested outside the linked entry closure"))?
            .namespace_json()
    }
}

fn release(runtime: &NativeModuleRuntime<'_>, handle: &mut Option<NativeModuleHandle>) {
    let Some(handle) = handle.take() else {
        return;
    };
    let status =
        unsafe { ex_hermes_module_release_handle(runtime.raw.as_ptr(), runtime.nonce, handle) };
    debug_assert!(
        status == 0 || status == -2,
        "native module-runner handle release refused ({status})"
    );
}

fn release_record(
    runtime: &NativeModuleRuntime<'_>,
    handle: &mut Option<NativeModuleHandle>,
    published: bool,
) {
    let Some(value) = *handle else {
        return;
    };
    if !published {
        let status = unsafe {
            ex_hermes_module_discard_unpublished_record(runtime.raw.as_ptr(), runtime.nonce, value)
        };
        if status == 0 || status == -2 {
            *handle = None;
            return;
        }
        debug_assert_eq!(
            status, -1,
            "native unpublished record discard refused ({status})"
        );
    }
    release(runtime, handle);
}

impl Drop for CompiledModuleFactory<'_> {
    fn drop(&mut self) {
        release(self.runtime, &mut self.handle);
    }
}

impl Drop for NativeGraphContext<'_> {
    fn drop(&mut self) {
        release(self.runtime, &mut self.handle);
    }
}

impl Drop for NativeModuleRecord<'_> {
    fn drop(&mut self) {
        release_record(self.runtime, &mut self.handle, self.published);
    }
}

impl Drop for NativeCommonJsRecord<'_> {
    fn drop(&mut self) {
        release_record(self.runtime, &mut self.handle, self.published);
    }
}

fn take_error(error: *mut c_char) -> String {
    if error.is_null() {
        return "no native diagnostic".into();
    }
    let detail = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    unsafe { ex_hermes_free_string(error) };
    detail
}

fn native_result(status: i32, error: *mut c_char, error_token: u64, operation: &str) -> Result<()> {
    if status != 0 {
        let detail = take_error(error);
        return Err(NativeModuleExecutionError {
            operation: operation.to_owned(),
            status,
            detail,
            error_token,
        }
        .into());
    }
    if !error.is_null() {
        unsafe { ex_hermes_free_string(error) };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_loader::artifact::{
        digest_bytes, ArtifactAdmissionV1, CanonicalSourceId, CommonJsExportsV1, DynamicEdgeV1,
        ExportDescriptorV1, ModuleArtifactV1, ModuleSemanticsV1, ProducerIdentityV1,
        SourceDialectV1, SourceGoalV1, SourceMapV1, StaticEdgeV1, TransformFingerprintV1,
        MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
    };
    use crate::module_loader::carrier::{
        AdmittedPreparedCarrierV2, HermesBytecodeMetadataV1, PreparedCarrierAdmissionV2,
        PreparedCarrierEngineBindingV2, PreparedModuleCarrierV2,
    };
    use crate::module_loader::graph::{ComputedCandidateBinding, GraphEdgeKey};
    use crate::module_loader::identity::{ImportAttributes, ResolutionKind};
    use crate::module_loader::producer_spike::{
        produce_commonjs_artifact_with_sites_v1, produce_module_artifact_v1,
    };
    use capsec_semantics::model::{Digest, NonEmptyString, PathComponent, Principal};

    #[allow(clashing_extern_declarations)]
    unsafe extern "C" {
        fn ex_hermes_create_diagnostic() -> *mut c_void;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ex_hermes_create_armed(armed_snapshot_digest: *const c_char) -> *mut c_void;
        fn ex_hermes_runtime_nonce(runtime: *mut c_void) -> u64;
        fn ex_hermes_poll(runtime: *mut c_void, now_ms: u64) -> i32;
        fn ex_hermes_destroy(runtime: *mut c_void);
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_install_capsec_context_observer(
            runtime: *mut c_void,
            global_name: *const c_char,
            compartment_identity: *const c_char,
        ) -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_begin_structured_module_error_capture(runtime: *mut c_void) -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_end_structured_module_error_capture(runtime: *mut c_void) -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_structured_module_error_token_matches_utf8(
            runtime: *mut c_void,
            error_token: u64,
            expected: *const u8,
            expected_length: usize,
        ) -> i32;
        #[cfg(feature = "capsec-conformance-observer")]
        fn ibex_test_structured_module_error_token_for_utf8(
            runtime: *mut c_void,
            expected: *const u8,
            expected_length: usize,
        ) -> u64;
    }

    fn digest(label: &str) -> Digest {
        digest_bytes("module-runner-test", label.as_bytes()).unwrap()
    }

    fn test_artifact_with_factory(
        source_id: SourceId,
        factory: &str,
        exports: &[&str],
    ) -> ModuleArtifactV1 {
        test_graph_artifact(
            source_id,
            factory,
            Vec::new(),
            exports
                .iter()
                .map(|name| ExportDescriptorV1::Local {
                    exported: NonEmptyString::new(*name).unwrap(),
                    local: NonEmptyString::new(*name).unwrap(),
                })
                .collect(),
        )
    }

    fn test_graph_artifact(
        source_id: SourceId,
        factory: &str,
        static_edges: Vec<StaticEdgeV1>,
        export_descriptors: Vec<ExportDescriptorV1>,
    ) -> ModuleArtifactV1 {
        test_artifact_for_goal(
            source_id,
            factory,
            SourceGoalV1::Module,
            static_edges,
            export_descriptors,
            None,
        )
    }

    fn test_commonjs_artifact(
        source_id: SourceId,
        factory: &str,
        detected_names: &[&str],
    ) -> ModuleArtifactV1 {
        test_artifact_for_goal(
            source_id,
            factory,
            SourceGoalV1::CommonJs,
            Vec::new(),
            Vec::new(),
            Some(CommonJsExportsV1 {
                detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                detector_version: NonEmptyString::new("2.1.0").unwrap(),
                names: detected_names
                    .iter()
                    .map(|name| NonEmptyString::new(*name).unwrap())
                    .collect(),
                reexports: Vec::new(),
            }),
        )
    }

    fn test_builtin_artifact(
        source_id: SourceId,
        factory: &str,
        detected_names: &[&str],
    ) -> ModuleArtifactV1 {
        test_artifact_for_goal(
            source_id,
            factory,
            SourceGoalV1::Builtin,
            Vec::new(),
            Vec::new(),
            Some(CommonJsExportsV1 {
                detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                detector_version: NonEmptyString::new("2.1.0").unwrap(),
                names: detected_names
                    .iter()
                    .map(|name| NonEmptyString::new(*name).unwrap())
                    .collect(),
                reexports: Vec::new(),
            }),
        )
    }

    fn test_artifact_for_goal(
        source_id: SourceId,
        factory: &str,
        source_goal: SourceGoalV1,
        static_edges: Vec<StaticEdgeV1>,
        export_descriptors: Vec<ExportDescriptorV1>,
        commonjs_exports: Option<CommonJsExportsV1>,
    ) -> ModuleArtifactV1 {
        let fingerprint = TransformFingerprintV1 {
            producer: NonEmptyString::new("test-producer").unwrap(),
            parser_version: NonEmptyString::new("oxc-test").unwrap(),
            transform_version: NonEmptyString::new("transform-test").unwrap(),
            hermes_target: NonEmptyString::new("hermes-test").unwrap(),
            typescript_jsx_options_digest: digest("ts-jsx"),
            module_runner_abi: NonEmptyString::new("ibex-module-runner-1").unwrap(),
            hermes_compat_version: NonEmptyString::new("compat-test").unwrap(),
            commonjs_detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
            commonjs_detector_version: NonEmptyString::new("2.1.0").unwrap(),
            output_options_digest: digest("output"),
        };
        ModuleArtifactV1::new_inline(
            ModuleSemanticsV1 {
                source_id: CanonicalSourceId(source_id.clone()),
                source_goal,
                dialect: Some(SourceDialectV1::Js),
                source_integrity: digest("source"),
                transform_fingerprint: fingerprint,
                static_edges,
                dynamic_edges: Vec::new(),
                export_descriptors,
                commonjs_exports,
                has_top_level_await: false,
                factory_digest: digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory.as_bytes())
                    .unwrap(),
                source_map: SourceMapV1 {
                    version: 3,
                    source_ids: vec![CanonicalSourceId(source_id)],
                    names: Vec::new(),
                    mappings: String::new(),
                },
            },
            factory.into(),
            ProducerIdentityV1::InProcess {
                producer_id: NonEmptyString::new("test-runtime").unwrap(),
                producer_binary_digest: digest("producer"),
            },
        )
        .unwrap()
    }

    fn test_artifact(source_id: SourceId) -> ModuleArtifactV1 {
        test_artifact_with_factory(
            source_id,
            "function ($export) { return { declare: function () {}, execute: function () { $export('value', 42); } }; }",
            &["value"],
        )
    }

    #[cfg(feature = "sfe-dev-spike")]
    #[test]
    fn compiled_process_metadata_keeps_reserved_words_as_application_data() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        let mut owner = DiagnosticModuleRuntime::new().unwrap();
        owner
            .install_compiled_process_metadata(
                "/tmp/app",
                "/app/entry.mjs",
                "custom-argv0",
                &["--inspect".into(), "compile".into()],
            )
            .unwrap();
        let source = b"JSON.stringify([globalThis.__exactArgv,globalThis.__exactExecArgv,globalThis.__exactRawArgv0,globalThis.__exactExecPath])";
        let source_url = CString::new("compiled-process-metadata-test.js").unwrap();
        let mut output = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_eval(
                owner.raw.as_ptr(),
                source.as_ptr(),
                source.len(),
                source_url.as_ptr(),
                0,
                &mut output,
            )
        };
        assert_eq!(status, 0);
        assert_eq!(
            take_error(output),
            r#"[["/tmp/app","/app/entry.mjs","--inspect","compile"],[],"custom-argv0","/tmp/app"]"#
        );
    }

    #[cfg(feature = "sfe-dev-spike")]
    #[test]
    fn compiled_runtime_drains_referenced_work_and_reads_exit_code() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        let mut owner = DiagnosticModuleRuntime::new().unwrap();
        owner
            .eval_text(
                "globalThis.__compiledTimerRan=false; setTimeout(function(){ globalThis.__compiledTimerRan=true; process.exitCode=7; }, 5); 'scheduled'",
                "compiled-lifecycle-test.js",
            )
            .unwrap();

        owner.drive_compiled_event_loop_to_quiescence().unwrap();

        assert_eq!(owner.compiled_process_exit_code().unwrap(), 7);
        assert_eq!(
            owner
                .eval_text(
                    "String(globalThis.__compiledTimerRan)",
                    "compiled-lifecycle-result.js",
                )
                .unwrap(),
            "true"
        );
    }

    /// Separate from SWC/Oxc parse equivalence: this proves that JavaScript
    /// emitted by the exact pinned Oxc producer is accepted and executed by the
    /// Hermes library actually loaded on each advertised native tuple.
    /// @ref LLP 0028#3-the-llp-0024-gates-revise-the-seam-then-build-on-oxc
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn oxc_javascript_goal_output_is_accepted_by_loaded_hermes() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        let source_id = SourceId::synthetic("oxc-hermes-acceptance", "entry.mjs").unwrap();
        let producer_digest = digest("oxc-hermes-acceptance-producer");
        let artifact = produce_module_artifact_v1(
            source_id.clone(),
            "entry.mjs",
            std::path::Path::new("entry.mjs"),
            "const state = { value: 40 }; export const answer = (state?.value ?? 0) + 2;",
            producer_digest.clone(),
        )
        .unwrap();
        let verified = artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: source_id.clone(),
                expected_source_integrity: artifact.semantics.source_integrity.clone(),
                expected_producer_id: NonEmptyString::new("ibex-runtime-oxc").unwrap(),
                producer_binary_digest: producer_digest,
                transform_fingerprint_digest: artifact
                    .semantics
                    .transform_fingerprint
                    .digest()
                    .unwrap(),
            })
            .unwrap();

        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let factory = runtime
                .compile_verified_factory(verified, 0, None, 1, "entry.mjs")
                .unwrap();
            let mut record = factory.create_record(&context, &source_id).unwrap();
            record.declare_export("answer").unwrap();
            record
                .instantiate("synthetic:oxc-hermes-acceptance/entry.mjs", true)
                .unwrap();
            record.run_declare().unwrap();
            assert_eq!(
                record.run_execute().unwrap(),
                ModuleExecutionKind::Synchronous
            );
            assert_eq!(record.namespace_json().unwrap(), r#"{"answer":42}"#);
            drop(record);
            drop(factory);
            drop(context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    /// Exercise the Rust/Oxc LLP 0019 mirror on the loaded Hermes engine, not
    /// merely through producer-shape assertions. The fixture combines the
    /// canonical rewrite, recursive rewrite, and leave-raw branches.
    /// @ref LLP 0019#tier-3-the-rustoxc-module-artifact-producer
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn tier3_for_of_canonical_parity_executes_on_loaded_hermes() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        let source_id = SourceId::synthetic("tier3-for-of-parity", "entry.mjs").unwrap();
        let producer_digest = digest("tier3-for-of-parity-producer");
        let source = r#"
const captures = [];
for (const { value } of [{ value: "a" }, { value: "b" }]) {
  for (const suffix of ["!"]) captures.push(() => value + suffix);
}
class Counter {
  constructor() { this.total = 0; }
  add(values) {
    for (const value of values) this.total += value;
    return this.total;
  }
}
let assigned = 0;
for (assigned of [4, 5]) {}
const varCaptures = [];
for (var shared of ["x", "y"]) varCaptures.push(() => shared);
const control = [];
for (const value of [-1, 1, 2, 9]) {
  if (value < 0) continue;
  if (value > 3) break;
  control.push(value);
}
let closed = false;
function* values() {
  try { yield 1; }
  finally { closed = true; }
}
try {
  for (const value of values()) { throw new Error(String(value)); }
} catch (_) {}
export const result = JSON.stringify({
  captures: captures.map((read) => read()),
  total: new Counter().add([1, 2, 3]),
  assigned,
  vars: varCaptures.map((read) => read()),
  control,
  closed,
});
"#;
        let artifact = produce_module_artifact_v1(
            source_id.clone(),
            "entry.mjs",
            std::path::Path::new("entry.mjs"),
            source,
            producer_digest.clone(),
        )
        .unwrap();
        let verified = artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: source_id.clone(),
                expected_source_integrity: artifact.semantics.source_integrity.clone(),
                expected_producer_id: NonEmptyString::new("ibex-runtime-oxc").unwrap(),
                producer_binary_digest: producer_digest,
                transform_fingerprint_digest: artifact
                    .semantics
                    .transform_fingerprint
                    .digest()
                    .unwrap(),
            })
            .unwrap();

        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let factory = runtime
                .compile_verified_factory(verified, 0, None, 1, "entry.mjs")
                .unwrap();
            let mut record = factory.create_record(&context, &source_id).unwrap();
            record.declare_export("result").unwrap();
            record
                .instantiate("synthetic:tier3-for-of-parity/entry.mjs", true)
                .unwrap();
            record.run_declare().unwrap();
            assert_eq!(
                record.run_execute().unwrap(),
                ModuleExecutionKind::Synchronous
            );
            assert_eq!(
                record.namespace_json().unwrap(),
                r#"{"result":"{\"captures\":[\"a!\",\"b!\"],\"total\":6,\"assigned\":5,\"vars\":[\"y\",\"y\"],\"control\":[1,2],\"closed\":true}"}"#
            );
            drop(record);
            drop(factory);
            drop(context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    fn asynchronous_artifact(
        artifact: ModuleArtifactV1,
        dynamic_edges: Vec<DynamicEdgeV1>,
    ) -> ModuleArtifactV1 {
        let factory_source = match artifact.payload {
            crate::module_loader::artifact::ModulePayloadV1::Inline { factory_source, .. } => {
                factory_source
            }
            crate::module_loader::artifact::ModulePayloadV1::Carrier { .. } => {
                panic!("test artifacts are inline")
            }
        };
        let mut semantics = artifact.semantics;
        semantics.has_top_level_await = true;
        semantics.dynamic_edges = dynamic_edges;
        ModuleArtifactV1::new_inline(semantics, factory_source, artifact.producer).unwrap()
    }

    fn with_dynamic_edges(
        artifact: ModuleArtifactV1,
        dynamic_edges: Vec<DynamicEdgeV1>,
    ) -> ModuleArtifactV1 {
        let factory_source = match artifact.payload {
            crate::module_loader::artifact::ModulePayloadV1::Inline { factory_source, .. } => {
                factory_source
            }
            crate::module_loader::artifact::ModulePayloadV1::Carrier { .. } => {
                panic!("test artifacts are inline")
            }
        };
        let mut semantics = artifact.semantics;
        semantics.dynamic_edges = dynamic_edges;
        ModuleArtifactV1::new_inline(semantics, factory_source, artifact.producer).unwrap()
    }

    fn verify_test_artifact(artifact: &ModuleArtifactV1) -> VerifiedModuleArtifactV1<'_> {
        artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: artifact.semantics.source_id.0.clone(),
                expected_source_integrity: digest("source"),
                expected_producer_id: NonEmptyString::new("test-runtime").unwrap(),
                producer_binary_digest: digest("producer"),
                transform_fingerprint_digest: artifact
                    .semantics
                    .transform_fingerprint
                    .digest()
                    .unwrap(),
            })
            .unwrap()
    }

    struct PanicGraphPolicy;

    impl GraphImportPolicy for PanicGraphPolicy {
        fn snapshot_digest(&self) -> &Digest {
            panic!("call-time edge guard ran after policy authorization")
        }

        fn snapshot_generations(&self) -> capsec_semantics::arming::SnapshotGenerations {
            panic!("call-time edge guard ran after policy authorization")
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
            panic!("call-time edge guard ran after policy authorization")
        }
    }

    struct AllowGraphPolicy {
        digest: Digest,
        generations: capsec_semantics::arming::SnapshotGenerations,
    }

    impl AllowGraphPolicy {
        fn new() -> Self {
            let generation = capsec_semantics::model::SafeUint::new(1).unwrap();
            Self {
                digest: digest("allow-graph-policy"),
                generations: capsec_semantics::arming::SnapshotGenerations {
                    policy: generation,
                    negative: generation,
                    dynamic: generation,
                    handle: generation,
                },
            }
        }
    }

    impl GraphImportPolicy for AllowGraphPolicy {
        fn snapshot_digest(&self) -> &Digest {
            &self.digest
        }

        fn snapshot_generations(&self) -> capsec_semantics::arming::SnapshotGenerations {
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
            true
        }
    }

    enum RequireProviderTestTarget {
        CommonJs {
            factory: NativeModuleHandle,
            context: NativeModuleHandle,
            source_id: Vec<u8>,
        },
        Esm {
            record: NativeModuleHandle,
        },
    }

    struct RequireProviderTestContext {
        raw: *mut c_void,
        expected_generation: u64,
        expected_requester: Vec<u8>,
        expected_specifier: Vec<u8>,
        target: RequireProviderTestTarget,
        invocations: usize,
        reentrant_eval_status: i32,
    }

    fn test_commonjs_require_provider(
        state: &mut RequireProviderTestContext,
        _runtime: &NativeModuleRuntime<'_>,
        request: CommonJsRequireActivationRequest,
    ) -> Result<NativeCommonJsRequireActivationTarget> {
        if request.requester.encode()?.as_bytes() != state.expected_requester
            || request.specifier.as_bytes() != state.expected_specifier
            || request.graph_generation() != state.expected_generation
        {
            bail!("provider received the wrong requester token");
        }
        state.invocations += 1;
        let source = b"1";
        let source_url = b"require-provider-reentry.js\0";
        let mut reentrant_output = std::ptr::null_mut();
        state.reentrant_eval_status = unsafe {
            ex_hermes_eval(
                state.raw,
                source.as_ptr(),
                source.len(),
                source_url.as_ptr().cast(),
                0,
                &mut reentrant_output,
            )
        };
        if !reentrant_output.is_null() {
            unsafe { ex_hermes_free_string(reentrant_output) };
        }

        let (factory, context, source_id) = match &state.target {
            RequireProviderTestTarget::CommonJs {
                factory,
                context,
                source_id,
            } => (factory, context, source_id),
            RequireProviderTestTarget::Esm { record } => {
                return Ok(NativeCommonJsRequireActivationTarget(
                    PublishedNativeRecord::Esm { record: *record },
                ));
            }
        };
        let filename = b"/project/activated-target.cjs";
        let dirname = b"/project";
        let mut target = NativeModuleHandle::default();
        let create_status = unsafe {
            ex_hermes_commonjs_create_record(
                state.raw,
                request.requester_record.opaque[0],
                *factory,
                *context,
                source_id.as_ptr(),
                source_id.len(),
                filename.as_ptr(),
                filename.len(),
                dirname.as_ptr(),
                dirname.len(),
                &mut target,
            )
        };
        if create_status != 0 {
            bail!("provider could not create target ({create_status})");
        }
        let mut adapter = NativeModuleHandle::default();
        let mut adapter_error = std::ptr::null_mut();
        let mut adapter_error_token = 0;
        let adapter_status = unsafe {
            ex_hermes_commonjs_record_create_esm_adapter(
                state.raw,
                request.requester_record.opaque[0],
                target,
                &mut adapter,
                &mut adapter_error,
                &mut adapter_error_token,
            )
        };
        if !adapter_error.is_null() {
            unsafe { ex_hermes_free_string(adapter_error) };
        }
        if adapter_status != 0 {
            unsafe {
                ex_hermes_module_discard_unpublished_record(
                    state.raw,
                    request.requester_record.opaque[0],
                    target,
                );
            }
            bail!("provider could not create target adapter ({adapter_status})");
        }
        let publish_status = unsafe {
            ex_hermes_module_publish_records(
                state.raw,
                request.requester_record.opaque[0],
                &target,
                1,
            )
        };
        if publish_status != 0 {
            unsafe {
                ex_hermes_module_discard_unpublished_record(
                    state.raw,
                    request.requester_record.opaque[0],
                    target,
                );
            }
            bail!("provider could not publish target ({publish_status})");
        }
        Ok(NativeCommonJsRequireActivationTarget(
            PublishedNativeRecord::CommonJs {
                record: target,
                adapter,
            },
        ))
    }

    #[test]
    fn every_authenticated_linker_refuses_call_time_edges_before_authorization() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "guarded-entry").unwrap();
            let target_id = SourceId::synthetic("module-runner-test", "guarded-target").unwrap();
            let entry_artifact = asynchronous_artifact(
                test_artifact(entry_id.clone()),
                vec![DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./target.mjs").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
            );
            let target_artifact = test_artifact(target_id.clone());
            let plan = SynchronousGraphPlan::new_typed([
                (
                    verify_test_artifact(&entry_artifact),
                    BTreeMap::from([(
                        GraphEdgeKey::new("./target.mjs", ResolutionKind::DynamicImport),
                        target_id.clone(),
                    )]),
                ),
                (verify_test_artifact(&target_artifact), BTreeMap::new()),
            ])
            .unwrap();
            let policy = PanicGraphPolicy;
            let authorizer = ModuleGraphAuthorizer::new(&policy);
            let prepared_entries = BTreeMap::new();

            let errors = [
                NativeSynchronousGraph::link_authorized(
                    &runtime,
                    &plan,
                    &entry_id,
                    BTreeMap::new(),
                    &authorizer,
                    &BTreeMap::new(),
                )
                .err()
                .expect("synchronous linker accepted an authored dynamic edge"),
                NativeSynchronousGraph::link_authorized_prepared(
                    &runtime,
                    &plan,
                    &entry_id,
                    BTreeMap::new(),
                    &authorizer,
                    &BTreeMap::new(),
                    &prepared_entries,
                )
                .err()
                .expect("prepared synchronous linker accepted an authored dynamic edge"),
                NativeAsynchronousGraph::link_authorized(
                    &runtime,
                    &plan,
                    &entry_id,
                    BTreeMap::new(),
                    &authorizer,
                    &BTreeMap::new(),
                )
                .err()
                .expect("asynchronous linker accepted an authored dynamic edge"),
                NativeAsynchronousGraph::link_authorized_prepared(
                    &runtime,
                    &plan,
                    &entry_id,
                    BTreeMap::new(),
                    &authorizer,
                    &BTreeMap::new(),
                    &prepared_entries,
                )
                .err()
                .expect("prepared asynchronous linker accepted an authored dynamic edge"),
            ];
            for error in errors {
                assert!(
                    error.to_string().contains("dynamic-import activation"),
                    "unexpected authenticated-linker refusal: {error:#}"
                );
            }

            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    fn prepared_admission(
        owner: Principal,
        manifest: &PreparedModuleCarrierV2,
    ) -> PreparedCarrierAdmissionV2 {
        PreparedCarrierAdmissionV2 {
            expected_principal: owner,
            expected_producer_id: NonEmptyString::new("prepared-test").unwrap(),
            producer_binary_digest: digest("prepared-producer"),
            deployment_graph_digest: digest("prepared-graph"),
            authorized_semantic_digests: manifest
                .entries
                .iter()
                .map(|entry| entry.semantic_digest.clone())
                .collect(),
            expected_engine_binding: None,
            expected_bytecode_version: None,
        }
    }

    fn verify_prepared_artifact<'a>(
        artifact: &'a ModuleArtifactV1,
        manifest: &PreparedModuleCarrierV2,
    ) -> VerifiedModuleArtifactV1<'a> {
        artifact
            .verify_for_admission(&ArtifactAdmissionV1::DigestBoundPrepared {
                expected_source_id: artifact.semantics.source_id.0.clone(),
                expected_source_integrity: digest("source"),
                expected_producer_id: NonEmptyString::new("prepared-test").unwrap(),
                producer_binary_digest: digest("prepared-producer"),
                deployment_graph_digest: digest("prepared-graph"),
                expected_carrier_digest: manifest.carrier_digest.clone(),
                expected_entry_id: NonEmptyString::new("entry").unwrap(),
                authorized_semantic_digests: [artifact.semantic_digest.clone()].into(),
                transform_fingerprint_digest: artifact
                    .semantics
                    .transform_fingerprint
                    .digest()
                    .unwrap(),
            })
            .unwrap()
    }

    #[test]
    fn native_handle_has_no_pointer_or_javascript_identity() {
        assert_eq!(std::mem::size_of::<NativeModuleHandle>(), 24);
        assert_eq!(NativeModuleHandle::default().opaque, [0, 0, 0]);
        assert!(!std::mem::needs_drop::<NativeModuleHandle>());
    }

    #[test]
    fn runtime_nonce_rejects_cross_runtime_and_destroy_recreate_handles() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw_a = ex_hermes_create_diagnostic();
            let raw_b = ex_hermes_create_diagnostic();
            assert!(!raw_a.is_null());
            assert!(!raw_b.is_null());
            let nonce_a = ex_hermes_runtime_nonce(raw_a);
            let nonce_b = ex_hermes_runtime_nonce(raw_b);
            assert_ne!(nonce_a, nonce_b);
            let runtime_a =
                NativeModuleRuntime::from_raw(NonNull::new(raw_a).unwrap(), nonce_a).unwrap();
            let source_id = SourceId::synthetic("module-runner-runtime-a", "entry").unwrap();
            let artifact = test_artifact(source_id);
            let factory = runtime_a
                .compile_verified_factory(
                    verify_test_artifact(&artifact),
                    0,
                    None,
                    1,
                    "cross-runtime.mjs",
                )
                .unwrap();
            let stale = factory.handle.expect("compiled factory handle");

            assert_ne!(
                ex_hermes_module_release_handle(raw_b, nonce_b, stale),
                0,
                "a live second runtime must reject the first runtime's handle"
            );

            std::mem::forget(factory);
            drop(runtime_a);
            ex_hermes_destroy(raw_a);

            let raw_replacement = ex_hermes_create_diagnostic();
            assert!(!raw_replacement.is_null());
            let replacement_nonce = ex_hermes_runtime_nonce(raw_replacement);
            assert_ne!(replacement_nonce, nonce_a);
            assert_ne!(
                ex_hermes_module_release_handle(raw_replacement, replacement_nonce, stale),
                0,
                "a replacement runtime must reject a destroyed generation's handle"
            );

            let replacement = NativeModuleRuntime::from_raw(
                NonNull::new(raw_replacement).unwrap(),
                replacement_nonce,
            )
            .unwrap();
            let replacement_source =
                SourceId::synthetic("module-runner-runtime-replacement", "entry").unwrap();
            let replacement_artifact = test_artifact(replacement_source);
            let replacement_factory = replacement
                .compile_verified_factory(
                    verify_test_artifact(&replacement_artifact),
                    0,
                    None,
                    1,
                    "replacement.mjs",
                )
                .unwrap();
            drop(replacement_factory);
            drop(replacement);
            ex_hermes_destroy(raw_replacement);
            ex_hermes_destroy(raw_b);
        }
    }

    #[test]
    fn graph_context_canonicalizes_the_constrained_principal_set() {
        let source_id = SourceId::file(
            Principal::Root {
                identity: NonEmptyString::new("project").unwrap(),
            },
            vec![PathComponent::utf8("entry.mjs").unwrap()],
        )
        .unwrap();
        let context = GraphEvaluationContext::new(source_id, 4, 3, [9, 3, 9, 4], 7).unwrap();
        assert_eq!(context.constrained_principals, vec![3, 4, 9]);
        assert_eq!(context.graph_generation, 7);
    }

    #[test]
    fn prepared_source_and_hbc_carriers_execute_the_same_original_module() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        let owner = Principal::Root {
            identity: NonEmptyString::new("prepared-project").unwrap(),
        };
        let source_id = SourceId::file(
            owner.clone(),
            vec![PathComponent::utf8("entry.mjs").unwrap()],
        )
        .unwrap();
        let source_artifact = test_artifact(source_id.clone());
        let (source_manifest, source_bytes) = PreparedModuleCarrierV2::from_inline_artifacts(
            owner.clone(),
            NonEmptyString::new("prepared-test").unwrap(),
            digest("prepared-producer"),
            digest("prepared-graph"),
            [(
                NonEmptyString::new("entry").unwrap(),
                verify_test_artifact(&source_artifact),
            )],
        )
        .unwrap();

        let hermesc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tools/hermes")
            .join(if cfg!(target_os = "windows") {
                "hermesc.exe"
            } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
                "hermesc-macos-arm64"
            } else if cfg!(target_os = "macos") {
                "hermesc-macos-x64"
            } else if cfg!(target_arch = "aarch64") {
                "hermesc-linux-arm64"
            } else {
                "hermesc-linux-x64"
            });
        if !hermesc.is_file() {
            eprintln!(
                "skipping prepared HBC equivalence: {} is absent",
                hermesc.display()
            );
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("carrier.js");
        let hbc_path = temp.path().join("carrier.hbc");
        std::fs::write(&source_path, &source_bytes).unwrap();
        let status = std::process::Command::new(&hermesc)
            .args(["-O", "-emit-binary", "-out"])
            .arg(&hbc_path)
            .arg(&source_path)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "matching hermesc must compile the carrier"
        );
        let hbc_bytes = std::fs::read(hbc_path).unwrap();
        preflight_hermes_bytecode(&hbc_bytes).unwrap();
        let mut corrupted_hbc = hbc_bytes.clone();
        corrupted_hbc.pop();
        assert!(preflight_hermes_bytecode(&corrupted_hbc).is_err());
        let engine_binding = PreparedCarrierEngineBindingV2::LoadedFile {
            binary_digest: Digest::new(crate::engine::loaded_engine_binary_digest().unwrap())
                .unwrap(),
        };
        let bytecode_version = HermesBytecodeMetadataV1::inspect(&hbc_bytes)
            .unwrap()
            .bytecode_version;
        let hbc_manifest = source_manifest
            .bind_hermes_bytecode(&hbc_bytes, engine_binding.clone())
            .unwrap();

        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            for (manifest, bytes, is_hbc) in [
                (&source_manifest, source_bytes.as_slice(), false),
                (&hbc_manifest, hbc_bytes.as_slice(), true),
            ] {
                let mut admission = prepared_admission(owner.clone(), manifest);
                if is_hbc {
                    admission.expected_engine_binding = Some(engine_binding.clone());
                    admission.expected_bytecode_version = Some(bytecode_version);
                }
                let carrier = AdmittedPreparedCarrierV2::decode_and_admit(
                    &manifest.encode_canonical().unwrap(),
                    bytes,
                    &admission,
                )
                .unwrap();
                let prepared_artifact = manifest.prepared_artifact("entry").unwrap();
                let verified = verify_prepared_artifact(&prepared_artifact, manifest);
                let context = runtime
                    .create_graph_context(
                        GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                    )
                    .unwrap();
                let factory = runtime
                    .load_verified_prepared_factory(
                        verified,
                        carrier.entry("entry").unwrap(),
                        0,
                        None,
                        1,
                        if is_hbc { "carrier.hbc" } else { "carrier.js" },
                    )
                    .unwrap();
                let mut record = factory.create_record(&context, &source_id).unwrap();
                record.declare_export("value").unwrap();
                record
                    .instantiate("file:prepared-project/entry.mjs", true)
                    .unwrap();
                record.run_declare().unwrap();
                assert_eq!(
                    record.run_execute().unwrap(),
                    ModuleExecutionKind::Synchronous
                );
                assert_eq!(record.namespace_json().unwrap(), r#"{"value":42}"#);
            }
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    /// The ordinary equivalence test above proves carrier identity and output;
    /// this observer-enabled test separately proves the non-root frame stamp
    /// for every source/cache carrier mode required by ENG-25060.
    // @ref LLP 0026#4-native-graph-owner-and-hermes-runner — cold, warm, prepared, and HBC factories retain package attribution
    #[cfg(all(feature = "capsec-conformance-observer", not(target_os = "windows")))]
    #[test]
    fn source_prepared_and_hbc_factories_have_frame_principal_attribution() {
        const PRINCIPAL_ID: u32 = 7;
        const OBSERVER: &str = "__ibexCapsecContextObserver_eng25060";

        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::module_runner_attribution_test_host();
        let armed_digest = CString::new(host.armed_snapshot().unwrap().digest().as_str()).unwrap();
        crate::host::abi::install_host(host);
        let owner = Principal::Root {
            identity: NonEmptyString::new("attributed-project").unwrap(),
        };
        let source_id = SourceId::file(
            owner.clone(),
            vec![PathComponent::utf8("entry.mjs").unwrap()],
        )
        .unwrap();
        let artifact = test_artifact_with_factory(
            source_id.clone(),
            "function ($export) { return { declare: function () {}, execute: function () { var observe = globalThis.__ibexCapsecContextObserver_eng25060; delete globalThis.__ibexCapsecContextObserver_eng25060; var principal = observe().principalId; globalThis.__ibexCapsecObservedPrincipal_eng25060 = principal; $export('principal', principal); } }; }",
            &["principal"],
        );
        let (source_manifest, source_bytes) = PreparedModuleCarrierV2::from_inline_artifacts(
            owner.clone(),
            NonEmptyString::new("prepared-test").unwrap(),
            digest("prepared-producer"),
            digest("prepared-graph"),
            [(
                NonEmptyString::new("entry").unwrap(),
                verify_test_artifact(&artifact),
            )],
        )
        .unwrap();

        let hermesc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tools/hermes")
            .join(
                if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
                    "hermesc-macos-arm64"
                } else if cfg!(target_os = "macos") {
                    "hermesc-macos-x64"
                } else if cfg!(target_arch = "aarch64") {
                    "hermesc-linux-arm64"
                } else {
                    "hermesc-linux-x64"
                },
            );
        assert!(
            hermesc.is_file(),
            "advertised target is missing matching hermesc at {}",
            hermesc.display()
        );
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("attributed-carrier.js");
        let hbc_path = temp.path().join("attributed-carrier.hbc");
        std::fs::write(&source_path, &source_bytes).unwrap();
        assert!(
            std::process::Command::new(&hermesc)
                .args(["-O", "-emit-binary", "-out"])
                .arg(&hbc_path)
                .arg(&source_path)
                .status()
                .unwrap()
                .success(),
            "matching hermesc must compile the attributed carrier"
        );
        let hbc_bytes = std::fs::read(hbc_path).unwrap();
        let engine_binding = PreparedCarrierEngineBindingV2::LoadedFile {
            binary_digest: Digest::new(crate::engine::loaded_engine_binary_digest().unwrap())
                .unwrap(),
        };
        let bytecode_version = HermesBytecodeMetadataV1::inspect(&hbc_bytes)
            .unwrap()
            .bytecode_version;
        let hbc_manifest = source_manifest
            .bind_hermes_bytecode(&hbc_bytes, engine_binding.clone())
            .unwrap();

        unsafe {
            let raw = ex_hermes_create_armed(armed_digest.as_ptr());
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let observer = CString::new(OBSERVER).unwrap();
            let compartment = CString::new("package:attributed-project").unwrap();
            let run_factory = |factory: CompiledModuleFactory<'_>, generation: u64| {
                let context = runtime
                    .create_graph_context(
                        GraphEvaluationContext::new(
                            source_id.clone(),
                            PRINCIPAL_ID,
                            PRINCIPAL_ID,
                            [PRINCIPAL_ID],
                            generation,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                let mut record = factory.create_record(&context, &source_id).unwrap();
                record.declare_export("principal").unwrap();
                record
                    .instantiate("file:attributed-project/entry.mjs", true)
                    .unwrap();
                record.run_declare().unwrap();
                assert_eq!(
                    record.run_execute().unwrap(),
                    ModuleExecutionKind::Synchronous
                );
                let source = "(function () { var compartment = __compartments['package:attributed-project']; var principal = String(compartment.__ibexCapsecObservedPrincipal_eng25060); delete compartment.__ibexCapsecObservedPrincipal_eng25060; return principal; })()";
                let source_url = CString::new("module-runner-attribution-observation.js").unwrap();
                let mut output = std::ptr::null_mut();
                assert_eq!(
                    ex_hermes_eval(
                        raw,
                        source.as_ptr(),
                        source.len(),
                        source_url.as_ptr(),
                        0,
                        &mut output,
                    ),
                    0
                );
                assert!(!output.is_null());
                assert_eq!(CStr::from_ptr(output).to_string_lossy(), "u64:7");
                ex_hermes_free_string(output);
            };

            for generation in [1, 2] {
                assert_eq!(
                    ibex_test_install_capsec_context_observer(
                        raw,
                        observer.as_ptr(),
                        compartment.as_ptr(),
                    ),
                    1
                );
                let factory = runtime
                    .compile_verified_factory(
                        verify_test_artifact(&artifact),
                        PRINCIPAL_ID,
                        Some("package:attributed-project"),
                        generation,
                        if generation == 1 {
                            "cold-source.mjs"
                        } else {
                            "warm-source.mjs"
                        },
                    )
                    .unwrap();
                run_factory(factory, generation);
            }

            for (generation, manifest, bytes, is_hbc) in [
                (3, &source_manifest, source_bytes.as_slice(), false),
                (4, &hbc_manifest, hbc_bytes.as_slice(), true),
            ] {
                let mut admission = prepared_admission(owner.clone(), manifest);
                if is_hbc {
                    admission.expected_engine_binding = Some(engine_binding.clone());
                    admission.expected_bytecode_version = Some(bytecode_version);
                }
                let carrier = AdmittedPreparedCarrierV2::decode_and_admit(
                    &manifest.encode_canonical().unwrap(),
                    bytes,
                    &admission,
                )
                .unwrap();
                let prepared_artifact = manifest.prepared_artifact("entry").unwrap();
                assert_eq!(
                    ibex_test_install_capsec_context_observer(
                        raw,
                        observer.as_ptr(),
                        compartment.as_ptr(),
                    ),
                    1
                );
                let factory = runtime
                    .load_verified_prepared_factory(
                        verify_prepared_artifact(&prepared_artifact, manifest),
                        carrier.entry("entry").unwrap(),
                        PRINCIPAL_ID,
                        Some("package:attributed-project"),
                        generation,
                        if is_hbc {
                            "attributed-carrier.hbc"
                        } else {
                            "attributed-carrier.js"
                        },
                    )
                    .unwrap();
                run_factory(factory, generation);
            }

            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn prepared_carrier_enters_the_full_graph_linker() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        let owner = Principal::Root {
            identity: NonEmptyString::new("prepared-graph-project").unwrap(),
        };
        let source_id = SourceId::file(
            owner.clone(),
            vec![PathComponent::utf8("entry.mjs").unwrap()],
        )
        .unwrap();
        let inline = test_artifact(source_id.clone());
        let (manifest, bytes) = PreparedModuleCarrierV2::from_inline_artifacts(
            owner.clone(),
            NonEmptyString::new("prepared-test").unwrap(),
            digest("prepared-producer"),
            digest("prepared-graph"),
            [(
                NonEmptyString::new("entry").unwrap(),
                verify_test_artifact(&inline),
            )],
        )
        .unwrap();
        let carrier = AdmittedPreparedCarrierV2::decode_and_admit(
            &manifest.encode_canonical().unwrap(),
            &bytes,
            &prepared_admission(owner, &manifest),
        )
        .unwrap();
        let artifact = manifest.prepared_artifact("entry").unwrap();
        let plan = SynchronousGraphPlan::new([(
            verify_prepared_artifact(&artifact, &manifest),
            BTreeMap::new(),
        )])
        .unwrap();
        let entries = BTreeMap::from([(source_id.clone(), carrier.entry("entry").unwrap())]);
        let configs = BTreeMap::from([(
            source_id.clone(),
            NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                "prepared-entry.mjs",
                "file:prepared-graph-project/entry.mjs",
            )
            .unwrap(),
        )]);

        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let mut graph = NativeSynchronousGraph::link_prepared(
                &runtime, &plan, &source_id, configs, &entries,
            )
            .unwrap();
            graph.evaluate().unwrap();
            assert_eq!(graph.namespace_json(&source_id).unwrap(), r#"{"value":42}"#);
            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn per_module_hbc_carriers_enter_the_full_graph_linker() {
        let hermesc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tools/hermes")
            .join(if cfg!(target_os = "windows") {
                "hermesc.exe"
            } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
                "hermesc-macos-arm64"
            } else if cfg!(target_os = "macos") {
                "hermesc-macos-x64"
            } else if cfg!(target_arch = "aarch64") {
                "hermesc-linux-arm64"
            } else {
                "hermesc-linux-x64"
            });
        if !hermesc.is_file() {
            eprintln!(
                "skipping prepared HBC graph execution: {} is absent",
                hermesc.display()
            );
            return;
        }

        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        let owner = Principal::Root {
            identity: NonEmptyString::new("prepared-hbc-graph-project").unwrap(),
        };
        let target_id = SourceId::file(
            owner.clone(),
            vec![PathComponent::utf8("target.mjs").unwrap()],
        )
        .unwrap();
        let entry_id = SourceId::file(
            owner.clone(),
            vec![PathComponent::utf8("entry.mjs").unwrap()],
        )
        .unwrap();
        let target_inline = test_artifact_with_factory(
            target_id.clone(),
            "function ($export) { return { declare: function () {}, execute: function () { $export('value', 41); } }; }",
            &["value"],
        );
        let entry_inline = test_graph_artifact(
            entry_id.clone(),
            "function ($export, context) { return { declare: function () {}, execute: function () { $export('answer', context.importValue('./target', 'value') + 1); } }; }",
            vec![StaticEdgeV1::Named {
                specifier: NonEmptyString::new("./target").unwrap(),
                imported: NonEmptyString::new("value").unwrap(),
                local: NonEmptyString::new("value").unwrap(),
                attributes: ImportAttributes::default(),
            }],
            vec![ExportDescriptorV1::Local {
                exported: NonEmptyString::new("answer").unwrap(),
                local: NonEmptyString::new("answer").unwrap(),
            }],
        );
        let source_carrier = |artifact: &ModuleArtifactV1| {
            PreparedModuleCarrierV2::from_inline_artifacts(
                owner.clone(),
                NonEmptyString::new("prepared-test").unwrap(),
                digest("prepared-producer"),
                digest("prepared-graph"),
                [(
                    NonEmptyString::new("entry").unwrap(),
                    verify_test_artifact(artifact),
                )],
            )
            .unwrap()
        };
        let (target_source_manifest, target_source) = source_carrier(&target_inline);
        let (entry_source_manifest, entry_source) = source_carrier(&entry_inline);
        let temp = tempfile::tempdir().unwrap();
        let compile = |name: &str, source: &[u8]| {
            let source_path = temp.path().join(format!("{name}.js"));
            let hbc_path = temp.path().join(format!("{name}.hbc"));
            std::fs::write(&source_path, source).unwrap();
            assert!(
                std::process::Command::new(&hermesc)
                    .args(["-O", "-emit-binary", "-out"])
                    .arg(&hbc_path)
                    .arg(&source_path)
                    .status()
                    .unwrap()
                    .success(),
                "matching hermesc must compile {name}"
            );
            std::fs::read(hbc_path).unwrap()
        };
        let target_hbc = compile("target", &target_source);
        let entry_hbc = compile("entry", &entry_source);
        let engine_binding = PreparedCarrierEngineBindingV2::LoadedFile {
            binary_digest: Digest::new(crate::engine::loaded_engine_binary_digest().unwrap())
                .unwrap(),
        };
        let bytecode_version = HermesBytecodeMetadataV1::inspect(&target_hbc)
            .unwrap()
            .bytecode_version;
        assert_eq!(
            HermesBytecodeMetadataV1::inspect(&entry_hbc)
                .unwrap()
                .bytecode_version,
            bytecode_version
        );
        let target_manifest = target_source_manifest
            .bind_hermes_bytecode(&target_hbc, engine_binding.clone())
            .unwrap();
        let entry_manifest = entry_source_manifest
            .bind_hermes_bytecode(&entry_hbc, engine_binding.clone())
            .unwrap();
        let admit = |manifest: &PreparedModuleCarrierV2, bytes: &[u8]| {
            let mut admission = prepared_admission(owner.clone(), manifest);
            admission.expected_engine_binding = Some(engine_binding.clone());
            admission.expected_bytecode_version = Some(bytecode_version);
            AdmittedPreparedCarrierV2::decode_and_admit(
                &manifest.encode_canonical().unwrap(),
                bytes,
                &admission,
            )
            .unwrap()
        };
        let target_carrier = admit(&target_manifest, &target_hbc);
        let entry_carrier = admit(&entry_manifest, &entry_hbc);
        let target_artifact = target_manifest.prepared_artifact("entry").unwrap();
        let entry_artifact = entry_manifest.prepared_artifact("entry").unwrap();
        let plan = SynchronousGraphPlan::new([
            (
                verify_prepared_artifact(&target_artifact, &target_manifest),
                BTreeMap::new(),
            ),
            (
                verify_prepared_artifact(&entry_artifact, &entry_manifest),
                BTreeMap::from([("./target".into(), target_id.clone())]),
            ),
        ])
        .unwrap();
        let entries = BTreeMap::from([
            (target_id.clone(), target_carrier.entry("entry").unwrap()),
            (entry_id.clone(), entry_carrier.entry("entry").unwrap()),
        ]);
        let config = |source_id: SourceId, label: &str| {
            NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                label,
                format!("file:prepared-hbc-graph-project/{label}"),
            )
            .unwrap()
        };
        let configs = BTreeMap::from([
            (target_id.clone(), config(target_id.clone(), "target.mjs")),
            (entry_id.clone(), config(entry_id.clone(), "entry.mjs")),
        ]);

        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let mut graph = NativeSynchronousGraph::link_prepared(
                &runtime, &plan, &entry_id, configs, &entries,
            )
            .unwrap();
            graph.evaluate().unwrap();
            assert_eq!(graph.namespace_json(&entry_id).unwrap(), r#"{"answer":42}"#);
            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn verified_factory_context_and_record_are_generation_scoped() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let source_id = SourceId::synthetic("module-runner-test", "entry").unwrap();
            let artifact = test_artifact(source_id.clone());
            let verified = verify_test_artifact(&artifact);
            let context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let retained_context = context.clone();
            let factory = runtime
                .compile_verified_factory(verified, 0, None, 1, "entry.mjs")
                .unwrap();
            let mut record = factory.create_record(&context, &source_id).unwrap();
            record.declare_export("value").unwrap();
            record
                .instantiate("synthetic:module-runner-test/entry", true)
                .unwrap();
            record.run_declare().unwrap();
            let tdz = record.namespace_json().unwrap_err().to_string();
            assert!(
                tdz.contains("module namespace serialization threw"),
                "namespace getter must preserve the opaque throw boundary: {tdz}"
            );
            assert_eq!(
                record.run_execute().unwrap(),
                ModuleExecutionKind::Synchronous
            );
            assert_eq!(record.namespace_json().unwrap(), r#"{"value":42}"#);
            drop(record);
            drop(factory);
            drop(retained_context);
            drop(context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn authenticated_virtual_path_populates_import_meta_without_a_host_path() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let source_id = SourceId::synthetic("module-runner-test", "virtual-meta").unwrap();
            let artifact = test_artifact_with_factory(
                source_id.clone(),
                "function ($export, context) { return { declare: function () {}, execute: function () { $export('url', context.meta.url); $export('path', context.meta.path); $export('filename', context.meta.filename); $export('dirname', context.meta.dirname); $export('dir', context.meta.dir); $export('file', context.meta.file); $export('main', context.meta.main); try { context.meta.resolve('./unbound.mjs'); } catch (error) { $export('resolveError', String(error && error.message)); } } }; }",
                &["url", "path", "filename", "dirname", "dir", "file", "main", "resolveError"],
            );
            let plan =
                SynchronousGraphPlan::new([(verify_test_artifact(&artifact), BTreeMap::new())])
                    .unwrap();
            let config = NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                "file:///project/src/entry%20point.mjs",
                "file:///project/src/entry%20point.mjs",
            )
            .unwrap()
            .with_authenticated_virtual_path("/project/src/entry point.mjs")
            .unwrap();
            let mut graph = NativeSynchronousGraph::link(
                &runtime,
                &plan,
                &source_id,
                BTreeMap::from([(source_id.clone(), config)]),
            )
            .unwrap();
            graph.evaluate().unwrap();
            let observed: serde_json::Value =
                serde_json::from_str(&graph.namespace_json(&source_id).unwrap()).unwrap();
            assert_eq!(
                observed,
                serde_json::json!({
                    "url": "file:///project/src/entry%20point.mjs",
                    "path": "/project/src/entry point.mjs",
                    "filename": "/project/src/entry point.mjs",
                    "dirname": "/project/src",
                    "dir": "/project/src",
                    "file": "entry point.mjs",
                    "main": true,
                    "resolveError": "ERR_IMPORT_META_RESOLVE_UNAVAILABLE: native resolution-only gate is unavailable",
                })
            );
            assert!(!graph
                .namespace_json(&source_id)
                .unwrap()
                .contains("/Users/"));
            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn synchronous_graph_links_every_record_before_dependency_first_evaluation() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let target_id = SourceId::synthetic("module-runner-test", "driver-target").unwrap();
            let reexport_id = SourceId::synthetic("module-runner-test", "driver-reexport").unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "driver-entry").unwrap();
            let target = test_artifact_with_factory(
                target_id.clone(),
                "function ($export) { return { declare: function () {}, execute: function () { $export('value', 42); } }; }",
                &["value"],
            );
            let reexport = test_graph_artifact(
                reexport_id.clone(),
                "function () { return { declare: function () {}, execute: function () {} }; }",
                vec![StaticEdgeV1::ReExportNamed {
                    specifier: NonEmptyString::new("./target").unwrap(),
                    imported: NonEmptyString::new("value").unwrap(),
                    exported: NonEmptyString::new("answer").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                vec![ExportDescriptorV1::Indirect {
                    exported: NonEmptyString::new("answer").unwrap(),
                    specifier: NonEmptyString::new("./target").unwrap(),
                    imported: NonEmptyString::new("value").unwrap(),
                }],
            );
            let entry = test_graph_artifact(
                entry_id.clone(),
                "function ($export, context) { return { declare: function () {}, execute: function () { $export('observed', context.importValue('./reexport', 'answer')); } }; }",
                vec![StaticEdgeV1::Named {
                    specifier: NonEmptyString::new("./reexport").unwrap(),
                    imported: NonEmptyString::new("answer").unwrap(),
                    local: NonEmptyString::new("answer").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                vec![ExportDescriptorV1::Local {
                    exported: NonEmptyString::new("observed").unwrap(),
                    local: NonEmptyString::new("observed").unwrap(),
                }],
            );
            let plan = SynchronousGraphPlan::new([
                (verify_test_artifact(&target), BTreeMap::new()),
                (
                    verify_test_artifact(&reexport),
                    BTreeMap::from([("./target".into(), target_id.clone())]),
                ),
                (
                    verify_test_artifact(&entry),
                    BTreeMap::from([("./reexport".into(), reexport_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeSynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (
                        target_id.clone(),
                        config(target_id.clone(), "driver-target"),
                    ),
                    (
                        reexport_id.clone(),
                        config(reexport_id.clone(), "driver-reexport"),
                    ),
                    (entry_id.clone(), config(entry_id.clone(), "driver-entry")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.entry(), &entry_id);
            assert!(graph
                .namespace_json(&entry_id)
                .unwrap_err()
                .to_string()
                .contains("module namespace serialization threw"));
            graph.evaluate().unwrap();
            graph.evaluate().unwrap();
            assert_eq!(
                graph.namespace_json(&reexport_id).unwrap(),
                r#"{"answer":42}"#
            );
            assert_eq!(
                graph.namespace_json(&entry_id).unwrap(),
                r#"{"observed":42}"#
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn synchronous_graph_links_esm_imports_to_commonjs_with_length_bearing_export_names() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let cjs_id = SourceId::synthetic("module-runner-test", "mixed-cjs").unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "mixed-entry").unwrap();
            let cjs = test_artifact_for_goal(
                cjs_id.clone(),
                "function (require, module, exports) { exports.answer = 41; exports['nul\\u0000named'] = 2; }",
                SourceGoalV1::CommonJs,
                Vec::new(),
                Vec::new(),
                Some(CommonJsExportsV1 {
                    detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                    detector_version: NonEmptyString::new("2.1.0").unwrap(),
                    names: vec![
                        NonEmptyString::new("answer").unwrap(),
                        NonEmptyString::new("nul\0named").unwrap(),
                    ],
                    reexports: Vec::new(),
                }),
            );
            let entry = test_graph_artifact(
                entry_id.clone(),
                "function ($export, context) { return { declare: function () {}, execute: function () { var named = context.importValue('./legacy', 'answer'); var nulNamed = context.importValue('./legacy', 'nul\\u0000named'); var value = context.importValue('./legacy', 'default'); $export('observed', String(named) + ':' + String(nulNamed) + ':' + String(value.answer === named)); } }; }",
                vec![
                    StaticEdgeV1::Named {
                        specifier: NonEmptyString::new("./legacy").unwrap(),
                        imported: NonEmptyString::new("answer").unwrap(),
                        local: NonEmptyString::new("answer").unwrap(),
                        attributes: ImportAttributes::default(),
                    },
                    StaticEdgeV1::Named {
                        specifier: NonEmptyString::new("./legacy").unwrap(),
                        imported: NonEmptyString::new("nul\0named").unwrap(),
                        local: NonEmptyString::new("nulNamed").unwrap(),
                        attributes: ImportAttributes::default(),
                    },
                    StaticEdgeV1::Default {
                        specifier: NonEmptyString::new("./legacy").unwrap(),
                        local: NonEmptyString::new("legacy").unwrap(),
                        attributes: ImportAttributes::default(),
                    },
                ],
                vec![ExportDescriptorV1::Local {
                    exported: NonEmptyString::new("observed").unwrap(),
                    local: NonEmptyString::new("observed").unwrap(),
                }],
            );
            let plan = SynchronousGraphPlan::new([
                (verify_test_artifact(&cjs), BTreeMap::new()),
                (
                    verify_test_artifact(&entry),
                    BTreeMap::from([("./legacy".into(), cjs_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    label,
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeSynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (cjs_id.clone(), config(cjs_id.clone(), "/pkg/legacy.cjs")),
                    (entry_id.clone(), config(entry_id.clone(), "/pkg/entry.mjs")),
                ]),
            )
            .unwrap();
            graph.namespace_json(&cjs_id).unwrap_err();
            graph.evaluate().unwrap();
            assert_eq!(
                graph.namespace_json(&entry_id).unwrap(),
                r#"{"observed":"41:2:true"}"#
            );
            assert_eq!(
                graph.namespace_json(&cjs_id).unwrap(),
                r#"{"answer":41,"default":{"answer":41,"nul\u0000named":2},"module.exports":{"answer":41,"nul\u0000named":2},"nul\u0000named":2}"#
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn synchronous_graph_links_commonjs_require_of_esm_with_length_bearing_export_names() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let esm_id = SourceId::synthetic("module-runner-test", "required-esm").unwrap();
            let cjs_id = SourceId::synthetic("module-runner-test", "requiring-cjs").unwrap();
            let esm = test_artifact_with_factory(
                esm_id.clone(),
                "function ($export) { return { declare: function () {}, execute: function () { $export('default', 9); $export('named', 4); $export('nul\\u0000named', 5); } }; }",
                &["default", "named", "nul\0named"],
            );
            let cjs = test_artifact_for_goal(
                cjs_id.clone(),
                "function (require, module, exports) { var namespace = require('./esm'); exports.observed = String(namespace.default + namespace.named + namespace['nul\\u0000named']) + ':' + String(namespace.__esModule === true); }",
                SourceGoalV1::CommonJs,
                vec![StaticEdgeV1::CommonJsRequire {
                    specifier: NonEmptyString::new("./esm").unwrap(),
                }],
                Vec::new(),
                Some(CommonJsExportsV1 {
                    detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                    detector_version: NonEmptyString::new("2.1.0").unwrap(),
                    names: vec![NonEmptyString::new("observed").unwrap()],
                    reexports: Vec::new(),
                }),
            );
            let plan = SynchronousGraphPlan::new([
                (verify_test_artifact(&esm), BTreeMap::new()),
                (
                    verify_test_artifact(&cjs),
                    BTreeMap::from([("./esm".into(), esm_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    label,
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeSynchronousGraph::link(
                &runtime,
                &plan,
                &cjs_id,
                BTreeMap::from([
                    (esm_id.clone(), config(esm_id.clone(), "/pkg/esm.mjs")),
                    (cjs_id.clone(), config(cjs_id.clone(), "/pkg/cjs.cjs")),
                ]),
            )
            .unwrap();
            graph.evaluate().unwrap();
            assert_eq!(
                graph.namespace_json(&cjs_id).unwrap(),
                r#"{"default":{"observed":"18:true"},"module.exports":{"observed":"18:true"},"observed":"18:true"}"#
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn commonjs_require_is_invocation_only_across_dead_tla_and_cycles() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let a_id = SourceId::synthetic("module-runner-test", "lazy-require-a").unwrap();
            let b_id = SourceId::synthetic("module-runner-test", "lazy-require-b").unwrap();
            let dead_id = SourceId::synthetic("module-runner-test", "lazy-require-dead").unwrap();

            let a = test_artifact_for_goal(
                a_id.clone(),
                "function (require, module, exports) { globalThis.__lazyRequireOrder = 'A-start>'; globalThis.__lazyRequireDead = false; exports.phase = 'started'; if (false) require('./dead'); var b = require('./b'); globalThis.__lazyRequireOrder += 'A-end'; exports.order = globalThis.__lazyRequireOrder; exports.sawA = b.sawA; exports.dead = globalThis.__lazyRequireDead; }",
                SourceGoalV1::CommonJs,
                vec![
                    StaticEdgeV1::CommonJsRequire {
                        specifier: NonEmptyString::new("./dead").unwrap(),
                    },
                    StaticEdgeV1::CommonJsRequire {
                        specifier: NonEmptyString::new("./b").unwrap(),
                    },
                ],
                Vec::new(),
                Some(CommonJsExportsV1 {
                    detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                    detector_version: NonEmptyString::new("2.1.0").unwrap(),
                    names: ["dead", "order", "phase", "sawA"]
                        .into_iter()
                        .map(|name| NonEmptyString::new(name).unwrap())
                        .collect(),
                    reexports: Vec::new(),
                }),
            );
            let b = test_artifact_for_goal(
                b_id.clone(),
                "function (require, module, exports) { globalThis.__lazyRequireOrder += 'B-start>'; var a = require('./a'); exports.sawA = a.phase; globalThis.__lazyRequireOrder += 'B-end>'; }",
                SourceGoalV1::CommonJs,
                vec![StaticEdgeV1::CommonJsRequire {
                    specifier: NonEmptyString::new("./a").unwrap(),
                }],
                Vec::new(),
                Some(CommonJsExportsV1 {
                    detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                    detector_version: NonEmptyString::new("2.1.0").unwrap(),
                    names: vec![NonEmptyString::new("sawA").unwrap()],
                    reexports: Vec::new(),
                }),
            );
            let dead = asynchronous_artifact(
                test_artifact_with_factory(
                    dead_id.clone(),
                    "function ($export) { return { declare: function () {}, execute: function () { globalThis.__lazyRequireDead = true; return Promise.resolve().then(function () { $export('value', 99); }); } }; }",
                    &["value"],
                ),
                Vec::new(),
            );
            let plan = SynchronousGraphPlan::new([
                (
                    verify_test_artifact(&a),
                    BTreeMap::from([
                        ("./dead".into(), dead_id.clone()),
                        ("./b".into(), b_id.clone()),
                    ]),
                ),
                (
                    verify_test_artifact(&b),
                    BTreeMap::from([("./a".into(), a_id.clone())]),
                ),
                (verify_test_artifact(&dead), BTreeMap::new()),
            ])
            .unwrap();
            assert_eq!(
                plan.synchronous_evaluation_order(&a_id).unwrap(),
                [a_id.clone()]
            );
            assert!(plan.linkage_order(&a_id).unwrap().contains(&dead_id));

            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.cjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeSynchronousGraph::link(
                &runtime,
                &plan,
                &a_id,
                BTreeMap::from([
                    (a_id.clone(), config(a_id.clone(), "lazy-require-a")),
                    (b_id.clone(), config(b_id.clone(), "lazy-require-b")),
                    (
                        dead_id.clone(),
                        config(dead_id.clone(), "lazy-require-dead"),
                    ),
                ]),
            )
            .unwrap();
            graph.evaluate().unwrap();
            let namespace: serde_json::Value =
                serde_json::from_str(&graph.namespace_json(&a_id).unwrap()).unwrap();
            assert_eq!(namespace["order"], "A-start>B-start>B-end>A-end");
            assert_eq!(namespace["sawA"], "started");
            assert_eq!(namespace["dead"], false);

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn reached_commonjs_require_refuses_tla_before_target_execution() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let entry_id =
                SourceId::synthetic("module-runner-test", "reached-tla-require").unwrap();
            let target_id =
                SourceId::synthetic("module-runner-test", "reached-tla-target").unwrap();
            let entry = test_artifact_for_goal(
                entry_id.clone(),
                "function (require, module, exports) { globalThis.__reachedTlaExecuted = false; try { require('./async'); } catch (error) { exports.refused = String(error.message).indexOf('ERR_REQUIRE_ASYNC_MODULE') >= 0; } exports.executed = globalThis.__reachedTlaExecuted; }",
                SourceGoalV1::CommonJs,
                vec![StaticEdgeV1::CommonJsRequire {
                    specifier: NonEmptyString::new("./async").unwrap(),
                }],
                Vec::new(),
                Some(CommonJsExportsV1 {
                    detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                    detector_version: NonEmptyString::new("2.1.0").unwrap(),
                    names: ["executed", "refused"]
                        .into_iter()
                        .map(|name| NonEmptyString::new(name).unwrap())
                        .collect(),
                    reexports: Vec::new(),
                }),
            );
            let target = asynchronous_artifact(
                test_artifact_with_factory(
                    target_id.clone(),
                    "function ($export) { return { declare: function () {}, execute: function () { globalThis.__reachedTlaExecuted = true; return Promise.resolve().then(function () { $export('value', 1); }); } }; }",
                    &["value"],
                ),
                Vec::new(),
            );
            let plan = SynchronousGraphPlan::new([
                (
                    verify_test_artifact(&entry),
                    BTreeMap::from([("./async".into(), target_id.clone())]),
                ),
                (verify_test_artifact(&target), BTreeMap::new()),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    label,
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeSynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (
                        entry_id.clone(),
                        config(entry_id.clone(), "/pkg/reached-tla-require.cjs"),
                    ),
                    (
                        target_id.clone(),
                        config(target_id.clone(), "/pkg/reached-tla-target.mjs"),
                    ),
                ]),
            )
            .unwrap();
            graph.evaluate().unwrap();
            let namespace: serde_json::Value =
                serde_json::from_str(&graph.namespace_json(&entry_id).unwrap()).unwrap();
            assert_eq!(namespace["refused"], true);
            assert_eq!(namespace["executed"], false);

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn deferred_commonjs_require_provider_can_publish_exact_target_during_drive() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            assert_eq!(ex_hermes_module_pin_generation(raw, nonce, 23), 0);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let owner = Principal::Root {
                identity: NonEmptyString::new("deferred-require-root").unwrap(),
            };
            let requester_id = SourceId::file(
                owner.clone(),
                vec![PathComponent::utf8("requester.cjs").unwrap()],
            )
            .unwrap();
            let target_id = SourceId::file(
                owner,
                vec![PathComponent::utf8("activated-target.cjs").unwrap()],
            )
            .unwrap();
            let requester = test_artifact_for_goal(
                requester_id.clone(),
                "function (require, module, exports) { var first = require('./target'); var second = require('./target'); exports.observed = first.value + second.value; }",
                SourceGoalV1::CommonJs,
                vec![StaticEdgeV1::CommonJsRequire {
                    specifier: NonEmptyString::new("./target").unwrap(),
                }],
                Vec::new(),
                Some(CommonJsExportsV1 {
                    detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                    detector_version: NonEmptyString::new("2.1.0").unwrap(),
                    names: vec![NonEmptyString::new("observed").unwrap()],
                    reexports: Vec::new(),
                }),
            );
            let target = test_commonjs_artifact(
                target_id.clone(),
                "function (require, module, exports) { globalThis.requireActivationTargetRuns = (globalThis.requireActivationTargetRuns || 0) + 1; exports.value = 42; }",
                &["value"],
            );
            let plan = SynchronousGraphPlan::new_typed_with_call_time_deferred_edges(
                [(verify_test_artifact(&requester), BTreeMap::new())],
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::from([requester_id.clone()]),
            )
            .unwrap();
            let target_factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&target),
                    0,
                    None,
                    23,
                    "/project/activated-target.cjs",
                )
                .unwrap();
            let target_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(target_id.clone(), 0, 0, [0], 23).unwrap(),
                )
                .unwrap();
            let mut provider_context = Box::new(RequireProviderTestContext {
                raw,
                expected_generation: 23,
                expected_requester: requester_id.encode().unwrap().into_bytes(),
                expected_specifier: b"./target".to_vec(),
                target: RequireProviderTestTarget::CommonJs {
                    factory: target_factory.handle.unwrap(),
                    context: target_context.handle.unwrap(),
                    source_id: target_id.encode().unwrap().into_bytes(),
                },
                invocations: 0,
                reentrant_eval_status: 0,
            });
            let provider_context_pointer = NonNull::from(provider_context.as_mut());
            let provider = runtime
                .install_commonjs_require_provider(
                    23,
                    provider_context_pointer,
                    test_commonjs_require_provider,
                )
                .unwrap();
            let policy = AllowGraphPolicy::new();
            let authority =
                GraphAuthorityContext::initialization(requester_id.clone(), 23).unwrap();
            let config = NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(requester_id.clone(), 0, 0, [0], 23).unwrap(),
                "/project/requester.cjs",
                "file:///project/requester.cjs",
            )
            .unwrap();
            let deferred = BTreeMap::from([(
                requester_id.clone(),
                DeferredDynamicImportBindings {
                    literal_specifiers: BTreeSet::new(),
                    computed_candidates: BTreeSet::new(),
                    commonjs_require_specifiers: BTreeSet::from(["./target".to_owned()]),
                    bootstrap_internal_commonjs_specifiers: BTreeSet::new(),
                },
            )]);
            let mut graph = NativeSynchronousGraph::link_authorized_deferred(
                &runtime,
                &plan,
                &requester_id,
                BTreeMap::from([(requester_id.clone(), config)]),
                &ModuleGraphAuthorizer::new(&policy),
                &BTreeMap::from([(requester_id.clone(), authority)]),
                &deferred,
            )
            .unwrap();
            graph.evaluate().unwrap();
            assert_eq!(
                graph.namespace_json(&requester_id).unwrap(),
                r#"{"default":{"observed":84},"module.exports":{"observed":84},"observed":84}"#
            );
            assert_eq!(provider_context.invocations, 1);
            assert_eq!(
                provider_context.reentrant_eval_status, -4,
                "the provider callback opened general runtime reentrancy"
            );

            drop(graph);
            drop(provider);
            let replacement_provider = runtime
                .install_commonjs_require_provider(
                    23,
                    provider_context_pointer,
                    test_commonjs_require_provider,
                )
                .expect("dropping the first registration did not clear its native provider");
            drop(replacement_provider);
            drop(target_context);
            drop(target_factory);
            assert_eq!(ex_hermes_module_unpin_generation(raw, nonce, 23), 0);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn deferred_commonjs_require_provider_preserves_synchronous_esm_admission() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            assert_eq!(ex_hermes_module_pin_generation(raw, nonce, 24), 0);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let owner = Principal::Root {
                identity: NonEmptyString::new("deferred-require-esm-root").unwrap(),
            };
            let requester_id = SourceId::file(
                owner.clone(),
                vec![PathComponent::utf8("requester.cjs").unwrap()],
            )
            .unwrap();
            let target_id = SourceId::file(
                owner,
                vec![PathComponent::utf8("activated-target.mjs").unwrap()],
            )
            .unwrap();
            let requester = test_artifact_for_goal(
                requester_id.clone(),
                "function (require, module, exports) { var target = require('./target'); exports.observed = target.value; }",
                SourceGoalV1::CommonJs,
                vec![StaticEdgeV1::CommonJsRequire {
                    specifier: NonEmptyString::new("./target").unwrap(),
                }],
                Vec::new(),
                Some(CommonJsExportsV1 {
                    detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                    detector_version: NonEmptyString::new("2.1.0").unwrap(),
                    names: vec![NonEmptyString::new("observed").unwrap()],
                    reexports: Vec::new(),
                }),
            );
            let target = test_artifact_with_factory(
                target_id.clone(),
                "function ($export) { return { declare: function () {}, execute: function () { $export('value', 42); } }; }",
                &["value"],
            );
            let plan = SynchronousGraphPlan::new_typed_with_call_time_deferred_edges(
                [(verify_test_artifact(&requester), BTreeMap::new())],
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::from([requester_id.clone()]),
            )
            .unwrap();

            let target_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(target_id.clone(), 0, 0, [0], 24).unwrap(),
                )
                .unwrap();
            let target_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&target),
                    0,
                    None,
                    24,
                    "/project/activated-target.mjs",
                )
                .unwrap();
            let mut target_record = target_factory
                .create_record(&target_context, &target_id)
                .unwrap();
            target_record.declare_export("value").unwrap();
            target_record
                .instantiate("file:///project/activated-target.mjs", false)
                .unwrap();
            target_record.run_declare().unwrap();
            let target_handle = target_record.live_handle().unwrap();
            assert_eq!(
                ex_hermes_module_publish_records(raw, nonce, &target_handle, 1),
                0
            );
            target_record.published = true;

            let mut provider_context = Box::new(RequireProviderTestContext {
                raw,
                expected_generation: 24,
                expected_requester: requester_id.encode().unwrap().into_bytes(),
                expected_specifier: b"./target".to_vec(),
                target: RequireProviderTestTarget::Esm {
                    record: target_handle,
                },
                invocations: 0,
                reentrant_eval_status: 0,
            });
            let provider_context_pointer = NonNull::from(provider_context.as_mut());
            let provider = runtime
                .install_commonjs_require_provider(
                    24,
                    provider_context_pointer,
                    test_commonjs_require_provider,
                )
                .unwrap();
            let policy = AllowGraphPolicy::new();
            let authority =
                GraphAuthorityContext::initialization(requester_id.clone(), 24).unwrap();
            let config = NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(requester_id.clone(), 0, 0, [0], 24).unwrap(),
                "/project/requester.cjs",
                "file:///project/requester.cjs",
            )
            .unwrap();
            let deferred = BTreeMap::from([(
                requester_id.clone(),
                DeferredDynamicImportBindings {
                    literal_specifiers: BTreeSet::new(),
                    computed_candidates: BTreeSet::new(),
                    commonjs_require_specifiers: BTreeSet::from(["./target".to_owned()]),
                    bootstrap_internal_commonjs_specifiers: BTreeSet::new(),
                },
            )]);
            let mut graph = NativeSynchronousGraph::link_authorized_deferred(
                &runtime,
                &plan,
                &requester_id,
                BTreeMap::from([(requester_id.clone(), config)]),
                &ModuleGraphAuthorizer::new(&policy),
                &BTreeMap::from([(requester_id.clone(), authority)]),
                &deferred,
            )
            .unwrap();
            graph.evaluate().unwrap();
            assert_eq!(
                graph.namespace_json(&requester_id).unwrap(),
                r#"{"default":{"observed":42},"module.exports":{"observed":42},"observed":42}"#
            );
            assert_eq!(provider_context.invocations, 1);
            assert_eq!(provider_context.reentrant_eval_status, -4);

            drop(graph);
            drop(provider);
            drop(target_record);
            drop(target_factory);
            drop(target_context);
            assert_eq!(ex_hermes_module_unpin_generation(raw, nonce, 24), 0);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn asynchronous_graph_evaluates_commonjs_before_tla_esm_importer() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let cjs_id = SourceId::synthetic("module-runner-test", "async-mixed-cjs").unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "async-mixed-entry").unwrap();
            let cjs = test_commonjs_artifact(
                cjs_id.clone(),
                "function (require, module, exports) { exports.answer = 41; }",
                &["answer"],
            );
            let entry = asynchronous_artifact(
                test_graph_artifact(
                    entry_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { var answer = context.importValue('./legacy', 'answer'); return Promise.resolve().then(function () { $export('observed', answer + 1); }); } }; }",
                    vec![StaticEdgeV1::Named {
                        specifier: NonEmptyString::new("./legacy").unwrap(),
                        imported: NonEmptyString::new("answer").unwrap(),
                        local: NonEmptyString::new("answer").unwrap(),
                        attributes: ImportAttributes::default(),
                    }],
                    vec![ExportDescriptorV1::Local {
                        exported: NonEmptyString::new("observed").unwrap(),
                        local: NonEmptyString::new("observed").unwrap(),
                    }],
                ),
                Vec::new(),
            );
            let plan = SynchronousGraphPlan::new([
                (verify_test_artifact(&cjs), BTreeMap::new()),
                (
                    verify_test_artifact(&entry),
                    BTreeMap::from([("./legacy".into(), cjs_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    label,
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeAsynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (cjs_id.clone(), config(cjs_id.clone(), "/pkg/legacy.cjs")),
                    (entry_id.clone(), config(entry_id.clone(), "/pkg/entry.mjs")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert_ne!(ex_hermes_poll(raw, 0), -1);
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Evaluated);
            assert_eq!(
                graph.namespace_json(&entry_id).unwrap(),
                r#"{"observed":42}"#
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn asynchronous_graph_suspends_dependencies_and_makes_rejection_sticky() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let dependency_id =
                SourceId::synthetic("module-runner-test", "async-dependency").unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "async-entry").unwrap();
            let dependency = asynchronous_artifact(
                test_artifact_with_factory(
                    dependency_id.clone(),
                    "function ($export) { return { declare: function () {}, execute: function () { return Promise.resolve(42).then(function (value) { $export('value', value); }); } }; }",
                    &["value"],
                ),
                Vec::new(),
            );
            let entry = test_graph_artifact(
                entry_id.clone(),
                "function ($export, context) { return { declare: function () {}, execute: function () { $export('observed', context.importValue('./dependency', 'value')); } }; }",
                vec![StaticEdgeV1::Named {
                    specifier: NonEmptyString::new("./dependency").unwrap(),
                    imported: NonEmptyString::new("value").unwrap(),
                    local: NonEmptyString::new("value").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                vec![ExportDescriptorV1::Local {
                    exported: NonEmptyString::new("observed").unwrap(),
                    local: NonEmptyString::new("observed").unwrap(),
                }],
            );
            let plan = SynchronousGraphPlan::new([
                (verify_test_artifact(&dependency), BTreeMap::new()),
                (
                    verify_test_artifact(&entry),
                    BTreeMap::from([("./dependency".into(), dependency_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeAsynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (
                        dependency_id.clone(),
                        config(dependency_id.clone(), "async-dependency"),
                    ),
                    (entry_id.clone(), config(entry_id.clone(), "async-entry")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert!(graph.is_suspended());
            assert_ne!(ex_hermes_poll(raw, 0), -1);
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Evaluated);
            assert_eq!(
                graph.namespace_json(&entry_id).unwrap(),
                r#"{"observed":42}"#
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);

            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let rejection_id = SourceId::synthetic("module-runner-test", "async-reject").unwrap();
            let rejection = asynchronous_artifact(
                test_artifact_with_factory(
                    rejection_id.clone(),
                    "function () { return { declare: function () {}, execute: function () { var hostile = { toString: function () { throw new Error('rejection toString was called'); } }; hostile[Symbol.toPrimitive] = function () { throw new Error('rejection Symbol.toPrimitive was called'); }; return Promise.reject(hostile); } }; }",
                    &[],
                ),
                Vec::new(),
            );
            let rejection_plan =
                SynchronousGraphPlan::new([(verify_test_artifact(&rejection), BTreeMap::new())])
                    .unwrap();
            let mut rejection_graph = NativeAsynchronousGraph::link(
                &runtime,
                &rejection_plan,
                &rejection_id,
                BTreeMap::from([(
                    rejection_id.clone(),
                    config(rejection_id.clone(), "async-reject"),
                )]),
            )
            .unwrap();
            assert_eq!(rejection_graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert_ne!(ex_hermes_poll(raw, 0), -1);
            let first = rejection_graph.poll().unwrap_err().to_string();
            let second = rejection_graph.poll().unwrap_err().to_string();
            assert!(
                first.contains("module evaluation promise rejected"),
                "unexpected rejection: {first}"
            );
            assert!(
                !first.contains("was called"),
                "hostile coercion ran: {first}"
            );
            assert_eq!(second, first);

            drop(rejection_graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn asynchronous_record_errors_keep_exact_tokens_under_reverse_polling() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            assert_eq!(ibex_test_begin_structured_module_error_capture(raw), 1);
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let a_id = SourceId::synthetic("module-runner-test", "token-a").unwrap();
            let b_id = SourceId::synthetic("module-runner-test", "token-b").unwrap();
            let rejection = |source_id: SourceId, sentinel: &str| {
                asynchronous_artifact(
                    test_artifact_with_factory(
                        source_id,
                        &format!(
                            "function () {{ return {{ declare: function () {{}}, execute: function () {{ return Promise.reject({sentinel:?}); }} }}; }}"
                        ),
                        &[],
                    ),
                    Vec::new(),
                )
            };
            let a = rejection(a_id.clone(), "sentinel-a");
            let b = rejection(b_id.clone(), "sentinel-b");
            let a_plan =
                SynchronousGraphPlan::new([(verify_test_artifact(&a), BTreeMap::new())]).unwrap();
            let b_plan =
                SynchronousGraphPlan::new([(verify_test_artifact(&b), BTreeMap::new())]).unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph_a = NativeAsynchronousGraph::link(
                &runtime,
                &a_plan,
                &a_id,
                BTreeMap::from([(a_id.clone(), config(a_id.clone(), "token-a"))]),
            )
            .unwrap();
            let mut graph_b = NativeAsynchronousGraph::link(
                &runtime,
                &b_plan,
                &b_id,
                BTreeMap::from([(b_id.clone(), config(b_id.clone(), "token-b"))]),
            )
            .unwrap();

            assert_eq!(graph_a.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert_eq!(graph_b.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert_ne!(ex_hermes_poll(raw, 0), -1);

            // Poll in the opposite order from execution. Each sticky Rust
            // error must retain the token for its own raw rejection value.
            let error_b = graph_b.poll().unwrap_err();
            let token_b = execution_error_token(&error_b)
                .expect("record B rejection omitted its raw-value token");
            let error_a = graph_a.poll().unwrap_err();
            let token_a = execution_error_token(&error_a)
                .expect("record A rejection omitted its raw-value token");
            assert_ne!(token_a, token_b, "distinct rejections shared one token");
            assert_eq!(
                ibex_test_structured_module_error_token_matches_utf8(
                    raw,
                    token_a.get(),
                    b"sentinel-a".as_ptr(),
                    b"sentinel-a".len(),
                ),
                1
            );
            assert_eq!(
                ibex_test_structured_module_error_token_matches_utf8(
                    raw,
                    token_b.get(),
                    b"sentinel-b".as_ptr(),
                    b"sentinel-b".len(),
                ),
                1
            );
            assert_eq!(
                execution_error_token(&graph_a.poll().unwrap_err()),
                Some(token_a),
                "record A did not keep its first error token sticky"
            );
            assert_eq!(
                execution_error_token(&graph_b.poll().unwrap_err()),
                Some(token_b),
                "record B did not keep its first error token sticky"
            );

            // A dynamic target rejection is handled by its importing entry,
            // so the graph succeeds while the target's raw value remains in
            // the graph-local token table.
            let handled_target_id =
                SourceId::synthetic("module-runner-test", "token-handled-target").unwrap();
            let handled_entry_id =
                SourceId::synthetic("module-runner-test", "token-handled-entry").unwrap();
            let handled_target = rejection(handled_target_id.clone(), "handled-dynamic");
            let handled_entry = asynchronous_artifact(
                test_artifact_with_factory(
                    handled_entry_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { return context.dynamicImport('./target').then(function () { throw new Error('dynamic rejection was not observed'); }, function () { $export('handled', true); }); } }; }",
                    &["handled"],
                ),
                vec![DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./target").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
            );
            let handled_plan = SynchronousGraphPlan::new([
                (verify_test_artifact(&handled_target), BTreeMap::new()),
                (
                    verify_test_artifact(&handled_entry),
                    BTreeMap::from([("./target".into(), handled_target_id.clone())]),
                ),
            ])
            .unwrap();
            let mut handled_graph = NativeAsynchronousGraph::link(
                &runtime,
                &handled_plan,
                &handled_entry_id,
                BTreeMap::from([
                    (
                        handled_target_id.clone(),
                        config(handled_target_id.clone(), "token-handled-target"),
                    ),
                    (
                        handled_entry_id.clone(),
                        config(handled_entry_id.clone(), "token-handled-entry"),
                    ),
                ]),
            )
            .unwrap();
            assert_eq!(handled_graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            let mut handled_settled = false;
            for tick in 1..=8 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
                match handled_graph.poll().unwrap() {
                    AsyncGraphPoll::Evaluated => {
                        handled_settled = true;
                        break;
                    }
                    AsyncGraphPoll::Suspended => {}
                }
            }
            assert!(handled_settled, "handled dynamic rejection did not settle");
            assert_eq!(
                handled_graph.namespace_json(&handled_entry_id).unwrap(),
                r#"{"handled":true}"#
            );
            assert_ne!(
                ibex_test_structured_module_error_token_for_utf8(
                    raw,
                    b"handled-dynamic".as_ptr(),
                    b"handled-dynamic".len(),
                ),
                0,
                "handled dynamic rejection was not retained under its own token"
            );

            // A later native protocol failure occurs while both raw values
            // and the handled dynamic rejection remain retained. It must carry
            // token 0 instead of borrowing any prior rejection.
            let protocol_id = SourceId::synthetic("module-runner-test", "token-protocol").unwrap();
            let protocol_artifact = test_artifact(protocol_id.clone());
            let factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&protocol_artifact),
                    0,
                    None,
                    1,
                    "token-protocol.mjs",
                )
                .unwrap();
            let context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(protocol_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let mut record = factory.create_record(&context, &protocol_id).unwrap();
            let protocol_error = record
                .run_declare()
                .expect_err("declaring an uninstantiated record must fail");
            assert_eq!(
                execution_error_token(&protocol_error),
                None,
                "a protocol failure borrowed an unrelated raw rejection"
            );

            assert_eq!(ibex_test_end_structured_module_error_capture(raw), 1);
            drop(record);
            drop(context);
            drop(factory);
            drop(handled_graph);
            drop(graph_b);
            drop(graph_a);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn asynchronous_scc_starts_every_peer_before_waiting() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let a_id = SourceId::synthetic("module-runner-test", "async-scc-a").unwrap();
            let b_id = SourceId::synthetic("module-runner-test", "async-scc-b").unwrap();
            let a = test_graph_artifact(
                a_id.clone(),
                "function () { return { declare: function () {}, execute: function () { globalThis.finishAsyncSccB(); } }; }",
                vec![StaticEdgeV1::SideEffect {
                    specifier: NonEmptyString::new("./b").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                Vec::new(),
            );
            let b = asynchronous_artifact(
                test_graph_artifact(
                    b_id.clone(),
                    "function ($export) { return { declare: function () {}, execute: function () { return new Promise(function (resolve) { globalThis.finishAsyncSccB = resolve; }).then(function () { $export('settled', true); }); } }; }",
                    vec![StaticEdgeV1::SideEffect {
                        specifier: NonEmptyString::new("./a").unwrap(),
                        attributes: ImportAttributes::default(),
                    }],
                    vec![ExportDescriptorV1::Local {
                        exported: NonEmptyString::new("settled").unwrap(),
                        local: NonEmptyString::new("settled").unwrap(),
                    }],
                ),
                Vec::new(),
            );
            let plan = SynchronousGraphPlan::new([
                (
                    verify_test_artifact(&a),
                    BTreeMap::from([("./b".into(), b_id.clone())]),
                ),
                (
                    verify_test_artifact(&b),
                    BTreeMap::from([("./a".into(), a_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeAsynchronousGraph::link(
                &runtime,
                &plan,
                &a_id,
                BTreeMap::from([
                    (a_id.clone(), config(a_id.clone(), "async-scc-a")),
                    (b_id.clone(), config(b_id.clone(), "async-scc-b")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.schedule().sccs.len(), 1);
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert_ne!(ex_hermes_poll(raw, 0), -1);
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Evaluated);
            assert_eq!(graph.namespace_json(&b_id).unwrap(), r#"{"settled":true}"#);

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn deferred_dynamic_activation_mailbox_is_reached_exact_and_generation_bound() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let entry_id =
                SourceId::synthetic("module-runner-test", "deferred-activation-entry").unwrap();
            let target_id =
                SourceId::synthetic("module-runner-test", "deferred-activation-target").unwrap();
            let entry = with_dynamic_edges(
                test_artifact_with_factory(
                    entry_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { if (false) context.dynamicImport('./dead'); context.dynamicImport(7, './missing').then(function () { throw new Error('computed miss resolved'); }, function () { $export('missDenied', true); }); var first = context.dynamicImport('./target'); var second = context.dynamicImport('./target'); $export('fresh', first !== second); Promise.all([first, second]).then(function (namespaces) { $export('settled', namespaces[0].value + namespaces[1].value); }); context.dynamicImport('./denied').then(function () { throw new Error('denied activation resolved'); }, function () { $export('activationDenied', true); }); } }; }",
                    &["activationDenied", "fresh", "missDenied", "settled"],
                ),
                vec![
                    DynamicEdgeV1::Literal {
                        specifier: NonEmptyString::new("./dead").unwrap(),
                        attributes: ImportAttributes::default(),
                    },
                    DynamicEdgeV1::Literal {
                        specifier: NonEmptyString::new("./target").unwrap(),
                        attributes: ImportAttributes::default(),
                    },
                    DynamicEdgeV1::Literal {
                        specifier: NonEmptyString::new("./denied").unwrap(),
                        attributes: ImportAttributes::default(),
                    },
                    DynamicEdgeV1::Computed { site: 7 },
                ],
            );
            let target = test_artifact(target_id.clone());

            let entry_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(entry_id.clone(), 0, 0, [0], 11).unwrap(),
                )
                .unwrap();
            let entry_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&entry),
                    0,
                    None,
                    11,
                    "deferred-entry.mjs",
                )
                .unwrap();
            let mut entry_record = entry_factory
                .create_record(&entry_context, &entry_id)
                .unwrap();
            entry_record.declare_export("activationDenied").unwrap();
            entry_record.declare_export("fresh").unwrap();
            entry_record.declare_export("missDenied").unwrap();
            entry_record.declare_export("settled").unwrap();
            entry_record.defer_dynamic_import_handle("./dead").unwrap();
            entry_record
                .defer_dynamic_import_handle("./target")
                .unwrap();
            entry_record
                .defer_dynamic_import_handle("./denied")
                .unwrap();
            entry_record
                .defer_computed_dynamic_import_handle(7, "./allowed")
                .unwrap();
            entry_record
                .instantiate("synthetic:module-runner-test/deferred-entry", true)
                .unwrap();
            entry_record.run_declare().unwrap();
            assert_eq!(
                entry_record.run_execute().unwrap(),
                ModuleExecutionKind::Synchronous
            );

            assert!(
                runtime
                    .take_dynamic_activation_request(12)
                    .unwrap()
                    .is_none(),
                "another generation consumed a reached activation"
            );
            let first_request = runtime
                .take_dynamic_activation_request(11)
                .unwrap()
                .expect("reached literal import did not mint an activation");
            let second_request = runtime
                .take_dynamic_activation_request(11)
                .unwrap()
                .expect("second invocation did not mint its own activation");
            let denied_request = runtime
                .take_dynamic_activation_request(11)
                .unwrap()
                .expect("reached denied import did not mint an activation");
            for request in [&first_request, &second_request] {
                assert_eq!(request.graph_generation(), 11);
                assert_eq!(request.requester, entry_id);
                assert_eq!(request.kind, DynamicModuleActivationKind::Literal);
                assert_eq!(request.specifier, "./target");
            }
            assert_eq!(denied_request.specifier, "./denied");
            assert!(
                runtime
                    .take_dynamic_activation_request(11)
                    .unwrap()
                    .is_none(),
                "dead or absent candidate spelling reached the activation mailbox"
            );

            let target_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(target_id.clone(), 0, 0, [0], 11).unwrap(),
                )
                .unwrap();
            let target_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&target),
                    0,
                    None,
                    11,
                    "deferred-target.mjs",
                )
                .unwrap();
            let mut target_record = target_factory
                .create_record(&target_context, &target_id)
                .unwrap();
            target_record.declare_export("value").unwrap();
            target_record
                .instantiate("synthetic:module-runner-test/deferred-target", false)
                .unwrap();
            target_record.run_declare().unwrap();

            runtime
                .complete_dynamic_activation(&first_request, &target_record)
                .unwrap();
            runtime
                .complete_dynamic_activation(&second_request, &target_record)
                .unwrap();
            runtime
                .refuse_dynamic_activation(&denied_request, "test policy denied reached activation")
                .unwrap();
            let repeated = runtime
                .complete_dynamic_activation(&first_request, &target_record)
                .unwrap_err()
                .to_string();
            assert!(
                repeated.contains("(-2)"),
                "one activation request completed more than once: {repeated}"
            );
            for tick in 0..8 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
            }
            assert_eq!(
                entry_record.namespace_json().unwrap(),
                r#"{"activationDenied":true,"fresh":true,"missDenied":true,"settled":84}"#
            );

            drop(target_record);
            drop(target_factory);
            drop(target_context);
            drop(entry_record);
            drop(entry_factory);
            drop(entry_context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn generation_teardown_discards_pending_activation_and_refuses_late_completion() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            assert_eq!(ex_hermes_module_pin_generation(raw, nonce, 41), 0);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let entry_id =
                SourceId::synthetic("module-runner-test", "teardown-activation-entry").unwrap();
            let target_id =
                SourceId::synthetic("module-runner-test", "teardown-activation-target").unwrap();
            let entry = with_dynamic_edges(
                test_artifact_with_factory(
                    entry_id.clone(),
                    "function (_, context) { return { declare: function () {}, execute: function () { context.dynamicImport('./target'); } }; }",
                    &[],
                ),
                vec![DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./target").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
            );
            let target = test_artifact(target_id.clone());
            let create_record = |artifact: &ModuleArtifactV1,
                                 source_id: &SourceId,
                                 label: &str,
                                 deferred: Option<&str>| {
                let context = runtime
                    .create_graph_context(
                        GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 41).unwrap(),
                    )
                    .unwrap();
                let factory = runtime
                    .compile_verified_factory(verify_test_artifact(artifact), 0, None, 41, label)
                    .unwrap();
                let mut record = factory.create_record(&context, source_id).unwrap();
                if let Some(specifier) = deferred {
                    record.defer_dynamic_import_handle(specifier).unwrap();
                }
                record
                    .instantiate(
                        &format!("synthetic:module-runner-test/{label}"),
                        source_id == &entry_id,
                    )
                    .unwrap();
                record.run_declare().unwrap();
                record
            };
            let mut entry_record =
                create_record(&entry, &entry_id, "teardown-entry.mjs", Some("./target"));
            assert_eq!(
                entry_record.run_execute().unwrap(),
                ModuleExecutionKind::Synchronous
            );
            let target_record = create_record(&target, &target_id, "teardown-target.mjs", None);
            let request = runtime
                .take_dynamic_activation_request(41)
                .unwrap()
                .expect("reached import did not mint a teardown request");

            assert_eq!(ex_hermes_module_unpin_generation(raw, nonce, 41), 0);
            assert!(
                runtime
                    .take_dynamic_activation_request(41)
                    .unwrap()
                    .is_none(),
                "generation teardown left a request in the activation mailbox"
            );
            let completion = runtime
                .complete_dynamic_activation(&request, &target_record)
                .unwrap_err()
                .to_string();
            assert!(
                completion.contains("(-2)"),
                "late completion crossed generation teardown: {completion}"
            );
            let refusal = runtime
                .refuse_dynamic_activation(&request, "late teardown refusal")
                .unwrap_err()
                .to_string();
            assert!(
                refusal.contains("(-2)"),
                "late refusal crossed generation teardown: {refusal}"
            );
            assert!(
                entry_record.namespace_json().is_err(),
                "teardown left the requester record addressable"
            );

            drop(target_record);
            drop(entry_record);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn authenticated_deferred_link_never_materializes_an_unreached_target() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let owner = Principal::Root {
                identity: NonEmptyString::new("deferred-link-root").unwrap(),
            };
            let entry_id = SourceId::file(
                owner.clone(),
                vec![PathComponent::utf8("deferred-entry.mjs").unwrap()],
            )
            .unwrap();
            let target_id = SourceId::file(
                owner,
                vec![PathComponent::utf8("deferred-target.mjs").unwrap()],
            )
            .unwrap();
            let entry = with_dynamic_edges(
                test_artifact_with_factory(
                    entry_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { context.dynamicImport('./target.mjs').then(function (namespace) { $export('value', namespace.value); }); } }; }",
                    &["value"],
                ),
                vec![DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./target.mjs").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
            );
            let target = test_artifact(target_id.clone());
            let plan = SynchronousGraphPlan::new_typed_with_call_time_deferred(
                [(verify_test_artifact(&entry), BTreeMap::new())],
                BTreeMap::new(),
                BTreeSet::from([entry_id.clone()]),
            )
            .unwrap();
            let panic_policy = PanicGraphPolicy;
            let mismatch = NativeSynchronousGraph::link_authorized_deferred(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::new(),
                &ModuleGraphAuthorizer::new(&panic_policy),
                &BTreeMap::new(),
                &BTreeMap::new(),
            )
            .err()
            .expect("missing deferred declaration reached policy authorization");
            assert!(
                mismatch
                    .to_string()
                    .contains("deferred call-time declarations disagree"),
                "unexpected declaration mismatch: {mismatch:#}"
            );

            let policy = AllowGraphPolicy::new();
            let context = GraphAuthorityContext::initialization(entry_id.clone(), 17).unwrap();
            let config = NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(entry_id.clone(), 0, 0, [0], 17).unwrap(),
                "deferred-entry.mjs",
                "file:///project/deferred-entry.mjs",
            )
            .unwrap();
            let deferred = BTreeMap::from([(
                entry_id.clone(),
                DeferredDynamicImportBindings {
                    literal_specifiers: BTreeSet::from(["./target.mjs".to_owned()]),
                    computed_candidates: BTreeSet::new(),
                    commonjs_require_specifiers: BTreeSet::new(),
                    bootstrap_internal_commonjs_specifiers: BTreeSet::new(),
                },
            )]);
            let mut graph = NativeSynchronousGraph::link_authorized_deferred(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([(entry_id.clone(), config)]),
                &ModuleGraphAuthorizer::new(&policy),
                &BTreeMap::from([(entry_id.clone(), context.clone())]),
                &deferred,
            )
            .unwrap();
            graph.evaluate().unwrap();
            let request = runtime
                .take_dynamic_activation_request(17)
                .unwrap()
                .expect("reached deferred import did not mint an activation");
            assert_eq!(request.requester, entry_id);
            assert_eq!(request.kind, DynamicModuleActivationKind::Literal);
            assert_eq!(request.specifier, "./target.mjs");
            let published_index = graph.published_activation_index().unwrap();
            assert!(published_index.owns_activation(&request));
            let mut foreign_requester = request.clone();
            foreign_requester
                .requester_record
                .as_mut()
                .expect("native mailbox request carries an exact requester handle")
                .opaque[2] += 1;
            assert!(
                !published_index.owns_activation(&foreign_requester),
                "source identity alone routed a request from another native record"
            );
            assert!(
                runtime
                    .take_dynamic_activation_request(17)
                    .unwrap()
                    .is_none(),
                "authenticated deferred link materialized more than the reached request"
            );
            let expanded_plan = SynchronousGraphPlan::new_typed_with_call_time_deferred(
                [
                    (verify_test_artifact(&entry), BTreeMap::new()),
                    (verify_test_artifact(&target), BTreeMap::new()),
                ],
                BTreeMap::new(),
                BTreeSet::from([entry_id.clone()]),
            )
            .unwrap();
            let target_context =
                GraphAuthorityContext::initialization(target_id.clone(), 17).unwrap();
            let target_config = NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(target_id.clone(), 0, 0, [0], 17).unwrap(),
                "deferred-target.mjs",
                "file:///project/deferred-target.mjs",
            )
            .unwrap();
            graph
                .publish_authorized_activation(
                    &runtime,
                    &expanded_plan,
                    &request,
                    &target_id,
                    BTreeMap::from([(target_id.clone(), target_config)]),
                    &ModuleGraphAuthorizer::new(&policy),
                    &BTreeMap::from([
                        (entry_id.clone(), context),
                        (target_id.clone(), target_context),
                    ]),
                    &deferred,
                    None,
                )
                .unwrap();
            for tick in 0..4 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
            }
            assert_eq!(graph.namespace_json(&entry_id).unwrap(), r#"{"value":42}"#);

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn asynchronous_deferred_graph_resumes_after_incremental_target_publication() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let owner = Principal::Root {
                identity: NonEmptyString::new("async-deferred-link-root").unwrap(),
            };
            let entry_id = SourceId::file(
                owner.clone(),
                vec![PathComponent::utf8("async-entry.mjs").unwrap()],
            )
            .unwrap();
            let target_id = SourceId::file(
                owner,
                vec![PathComponent::utf8("async-target.mjs").unwrap()],
            )
            .unwrap();
            let entry = asynchronous_artifact(
                test_artifact_with_factory(
                    entry_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { return context.dynamicImport('./target.mjs').then(function (namespace) { $export('value', namespace.value); }); } }; }",
                    &["value"],
                ),
                vec![DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./target.mjs").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
            );
            let target = test_artifact(target_id.clone());
            let initial_plan = SynchronousGraphPlan::new_typed_with_call_time_deferred(
                [(verify_test_artifact(&entry), BTreeMap::new())],
                BTreeMap::new(),
                BTreeSet::from([entry_id.clone()]),
            )
            .unwrap();
            let policy = AllowGraphPolicy::new();
            let entry_context =
                GraphAuthorityContext::initialization(entry_id.clone(), 29).unwrap();
            let entry_config = NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(entry_id.clone(), 0, 0, [0], 29).unwrap(),
                "async-entry.mjs",
                "file:///project/async-entry.mjs",
            )
            .unwrap();
            let deferred = BTreeMap::from([(
                entry_id.clone(),
                DeferredDynamicImportBindings {
                    literal_specifiers: BTreeSet::from(["./target.mjs".to_owned()]),
                    computed_candidates: BTreeSet::new(),
                    commonjs_require_specifiers: BTreeSet::new(),
                    bootstrap_internal_commonjs_specifiers: BTreeSet::new(),
                },
            )]);
            let mut graph = NativeAsynchronousGraph::link_authorized_deferred(
                &runtime,
                &initial_plan,
                &entry_id,
                BTreeMap::from([(entry_id.clone(), entry_config)]),
                &ModuleGraphAuthorizer::new(&policy),
                &BTreeMap::from([(entry_id.clone(), entry_context.clone())]),
                &deferred,
            )
            .unwrap();
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            let request = runtime
                .take_dynamic_activation_request(29)
                .unwrap()
                .expect("awaited dynamic import did not mint an activation");
            let expanded_plan = SynchronousGraphPlan::new_typed_with_call_time_deferred(
                [
                    (verify_test_artifact(&entry), BTreeMap::new()),
                    (verify_test_artifact(&target), BTreeMap::new()),
                ],
                BTreeMap::new(),
                BTreeSet::from([entry_id.clone()]),
            )
            .unwrap();
            let target_context =
                GraphAuthorityContext::initialization(target_id.clone(), 29).unwrap();
            let target_config = NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(target_id.clone(), 0, 0, [0], 29).unwrap(),
                "async-target.mjs",
                "file:///project/async-target.mjs",
            )
            .unwrap();
            graph
                .publish_authorized_activation(
                    &runtime,
                    &expanded_plan,
                    &request,
                    &target_id,
                    BTreeMap::from([(target_id.clone(), target_config)]),
                    &ModuleGraphAuthorizer::new(&policy),
                    &BTreeMap::from([
                        (entry_id.clone(), entry_context),
                        (target_id.clone(), target_context),
                    ]),
                    &deferred,
                    None,
                )
                .unwrap();
            let mut evaluated = false;
            for tick in 0..8 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
                if graph.poll().unwrap() == AsyncGraphPoll::Evaluated {
                    evaluated = true;
                    break;
                }
            }
            assert!(evaluated, "async deferred graph did not resume");
            assert_eq!(graph.namespace_json(&entry_id).unwrap(), r#"{"value":42}"#);

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn dynamic_import_returns_fresh_promises_over_one_async_record() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let target_id = SourceId::synthetic("module-runner-test", "dynamic-target").unwrap();
            let peer_id = SourceId::synthetic("module-runner-test", "dynamic-peer").unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "dynamic-entry").unwrap();
            let target = test_graph_artifact(
                target_id.clone(),
                "function ($export) { return { declare: function () {}, execute: function () { globalThis.finishDynamicSccPeer(); $export('value', 7); } }; }",
                vec![StaticEdgeV1::SideEffect {
                    specifier: NonEmptyString::new("./peer").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                vec![ExportDescriptorV1::Local {
                    exported: NonEmptyString::new("value").unwrap(),
                    local: NonEmptyString::new("value").unwrap(),
                }],
            );
            let peer = asynchronous_artifact(
                test_graph_artifact(
                    peer_id.clone(),
                    "function () { return { declare: function () {}, execute: function () { return new Promise(function (resolve) { globalThis.finishDynamicSccPeer = resolve; }); } }; }",
                    vec![StaticEdgeV1::SideEffect {
                        specifier: NonEmptyString::new("./target").unwrap(),
                        attributes: ImportAttributes::default(),
                    }],
                    Vec::new(),
                ),
                Vec::new(),
            );
            let entry = asynchronous_artifact(
                test_artifact_with_factory(
                    entry_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { var first = context.dynamicImport('./target'); var second = context.dynamicImport('./target'); $export('fresh', first !== second); return Promise.all([first, second]).then(function (namespaces) { $export('sum', namespaces[0].value + namespaces[1].value); }); } }; }",
                    &["fresh", "sum"],
                ),
                vec![DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./target").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
            );
            let plan = SynchronousGraphPlan::new([
                (
                    verify_test_artifact(&target),
                    BTreeMap::from([("./peer".into(), peer_id.clone())]),
                ),
                (
                    verify_test_artifact(&peer),
                    BTreeMap::from([("./target".into(), target_id.clone())]),
                ),
                (
                    verify_test_artifact(&entry),
                    BTreeMap::from([("./target".into(), target_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeAsynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (
                        target_id.clone(),
                        config(target_id.clone(), "dynamic-target"),
                    ),
                    (peer_id.clone(), config(peer_id.clone(), "dynamic-peer")),
                    (entry_id.clone(), config(entry_id.clone(), "dynamic-entry")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            for tick in 0..4 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
            }
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Evaluated);
            assert_eq!(
                graph.namespace_json(&entry_id).unwrap(),
                r#"{"fresh":true,"sum":14}"#
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn computed_dynamic_import_candidates_are_site_specific() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "computed-entry").unwrap();
            let left_id = SourceId::synthetic("module-runner-test", "computed-left").unwrap();
            let right_id = SourceId::synthetic("module-runner-test", "computed-right").unwrap();
            let entry = with_dynamic_edges(
                test_artifact_with_factory(
                    entry_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { $export('leftAllowed', false); $export('rightAllowed', false); $export('crossSiteDenied', false); $export('denialMessage', ''); $export('optionsRejected', false); context.dynamicImport(0, 40, 55, 0, './left').then(function () { $export('leftAllowed', true); }, function () {}); context.dynamicImport(1, 60, 75, 0, './right').then(function () { $export('rightAllowed', true); }, function () {}); context.dynamicImport(0, 40, 55, 0, './right').then(function () {}, function (error) { $export('crossSiteDenied', true); $export('denialMessage', error.message); }); context.dynamicImport(0, 100, 120, 1, './left', { with: { mystery: 'x' } }).then(function () {}, function () { $export('optionsRejected', true); }); } }; }",
                    &[
                        "leftAllowed",
                        "rightAllowed",
                        "crossSiteDenied",
                        "denialMessage",
                        "optionsRejected",
                    ],
                ),
                vec![
                    DynamicEdgeV1::Literal {
                        specifier: NonEmptyString::new("./left").unwrap(),
                        attributes: ImportAttributes::default(),
                    },
                    DynamicEdgeV1::Computed { site: 0 },
                    DynamicEdgeV1::Computed { site: 1 },
                ],
            );
            let left = test_artifact_with_factory(
                left_id.clone(),
                "function ($export) { return { declare: function () {}, execute: function () { $export('value', 'left'); } }; }",
                &["value"],
            );
            let right = test_artifact_with_factory(
                right_id.clone(),
                "function ($export) { return { declare: function () {}, execute: function () { $export('value', 'right'); } }; }",
                &["value"],
            );
            let plan = SynchronousGraphPlan::new_typed_with_computed_candidates(
                [
                    (
                        verify_test_artifact(&entry),
                        BTreeMap::from([(
                            GraphEdgeKey::new("./left", ResolutionKind::DynamicImport),
                            left_id.clone(),
                        )]),
                    ),
                    (verify_test_artifact(&left), BTreeMap::new()),
                    (verify_test_artifact(&right), BTreeMap::new()),
                ],
                BTreeMap::from([(
                    entry_id.clone(),
                    BTreeMap::from([
                        (
                            (0, "./left".into()),
                            ComputedCandidateBinding {
                                target: left_id.clone(),
                                attributes: ImportAttributes::default(),
                            },
                        ),
                        (
                            (1, "./right".into()),
                            ComputedCandidateBinding {
                                target: right_id.clone(),
                                attributes: ImportAttributes::default(),
                            },
                        ),
                    ]),
                )]),
            )
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let links = ComputedDynamicImportLinks::from([(
                entry_id.clone(),
                BTreeMap::from([
                    ((0, "./left".into()), left_id.clone()),
                    ((1, "./right".into()), right_id.clone()),
                ]),
            )]);
            let mut graph = NativeSynchronousGraph::link_with_computed_candidates(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (entry_id.clone(), config(entry_id.clone(), "computed-entry")),
                    (left_id.clone(), config(left_id.clone(), "computed-left")),
                    (right_id.clone(), config(right_id.clone(), "computed-right")),
                ]),
                &links,
            )
            .unwrap();
            graph.evaluate().unwrap();
            for tick in 0..8 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
            }
            let namespace: serde_json::Value =
                serde_json::from_str(&graph.namespace_json(&entry_id).unwrap()).unwrap();
            assert_eq!(namespace["leftAllowed"], true);
            assert_eq!(namespace["rightAllowed"], true);
            assert_eq!(namespace["crossSiteDenied"], true);
            assert_eq!(namespace["optionsRejected"], true);
            let denial = namespace["denialMessage"].as_str().unwrap();
            assert!(denial.contains("original-source bytes 40..55"));
            assert!(denial.contains("ibex-source-id-v1:"));
            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn pinned_generation_keeps_fire_and_forget_dynamic_target_live() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            assert_eq!(ex_hermes_module_pin_generation(raw, nonce, 1), 0);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let target_id = SourceId::synthetic("module-runner-test", "pinned-target").unwrap();
            let entry_id = SourceId::synthetic("module-runner-test", "pinned-entry").unwrap();
            let target = asynchronous_artifact(
                test_artifact_with_factory(
                    target_id.clone(),
                    "function ($export) { return { declare: function () {}, execute: function () { return Promise.resolve().then(function () { $export('value', 73); }); } }; }",
                    &["value"],
                ),
                Vec::new(),
            );
            let entry = {
                let artifact = test_artifact_with_factory(
                    entry_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { context.dynamicImport('./target').then(function (namespace) { globalThis.pinnedDynamicValue = namespace.value; }); } }; }",
                    &[],
                );
                let crate::module_loader::artifact::ModulePayloadV1::Inline {
                    factory_source, ..
                } = artifact.payload
                else {
                    unreachable!()
                };
                let mut semantics = artifact.semantics;
                semantics.dynamic_edges = vec![DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./target").unwrap(),
                    attributes: ImportAttributes::default(),
                }];
                ModuleArtifactV1::new_inline(semantics, factory_source, artifact.producer).unwrap()
            };
            let plan = SynchronousGraphPlan::new([
                (verify_test_artifact(&target), BTreeMap::new()),
                (
                    verify_test_artifact(&entry),
                    BTreeMap::from([("./target".into(), target_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeSynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (target_id.clone(), config(target_id, "pinned-target")),
                    (entry_id.clone(), config(entry_id.clone(), "pinned-entry")),
                ]),
            )
            .unwrap();
            graph.evaluate().unwrap();
            drop(graph);
            for tick in 0..8 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
            }
            let source = "String(globalThis.pinnedDynamicValue)";
            let source_url = CString::new("pinned-dynamic-observation.js").unwrap();
            let mut output = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_eval(
                    raw,
                    source.as_ptr(),
                    source.len(),
                    source_url.as_ptr(),
                    0,
                    &mut output,
                ),
                0
            );
            assert_eq!(take_error(output), "73");
            assert_eq!(ex_hermes_module_unpin_generation(raw, nonce, 1), 0);

            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn mixed_dynamic_static_reentry_rejects_instead_of_deadlocking() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let a_id = SourceId::synthetic("module-runner-test", "async-cycle-a").unwrap();
            let b_id = SourceId::synthetic("module-runner-test", "async-cycle-b").unwrap();
            let a = asynchronous_artifact(
                test_artifact_with_factory(
                    a_id.clone(),
                    "function ($export, context) { return { declare: function () {}, execute: function () { return context.dynamicImport('./b'); } }; }",
                    &[],
                ),
                vec![DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new("./b").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
            );
            let b = test_graph_artifact(
                b_id.clone(),
                "function () { return { declare: function () {}, execute: function () {} }; }",
                vec![StaticEdgeV1::SideEffect {
                    specifier: NonEmptyString::new("./a").unwrap(),
                    attributes: ImportAttributes::default(),
                }],
                Vec::new(),
            );
            let plan = SynchronousGraphPlan::new([
                (
                    verify_test_artifact(&a),
                    BTreeMap::from([("./b".into(), b_id.clone())]),
                ),
                (
                    verify_test_artifact(&b),
                    BTreeMap::from([("./a".into(), a_id.clone())]),
                ),
            ])
            .unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    format!("{label}.mjs"),
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeAsynchronousGraph::link(
                &runtime,
                &plan,
                &a_id,
                BTreeMap::from([
                    (a_id.clone(), config(a_id.clone(), "async-cycle-a")),
                    (b_id.clone(), config(b_id.clone(), "async-cycle-b")),
                ]),
            )
            .unwrap();
            assert_eq!(graph.poll().unwrap(), AsyncGraphPoll::Suspended);
            assert_ne!(ex_hermes_poll(raw, 0), -1);
            let error = graph.poll().unwrap_err().to_string();
            assert!(
                error.contains("module evaluation promise rejected"),
                "unexpected async cycle error: {error}"
            );

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn producer_commonjs_site_bearing_dynamic_imports_reach_linked_targets() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());

        let entry_id = SourceId::synthetic("module-runner-test", "producer-cjs-dynamic").unwrap();
        let literal_id = SourceId::synthetic("module-runner-test", "producer-cjs-literal").unwrap();
        let computed_id =
            SourceId::synthetic("module-runner-test", "producer-cjs-computed").unwrap();
        let producer_digest = digest("producer-cjs-dynamic-producer");
        let source = "globalThis.__producerCjsTopLevelThis = this === module.exports; import('./literal.mjs').then(function (namespace) { globalThis.__producerCjsLiteral = namespace.value; }); const name = './computed.mjs'; import(name, { with: { 'ibex:site': 'routes' } }).then(function (namespace) { globalThis.__producerCjsComputed = namespace.value; });";
        let produced = produce_commonjs_artifact_with_sites_v1(
            entry_id.clone(),
            "producer-cjs-dynamic.cjs",
            Path::new("producer-cjs-dynamic.cjs"),
            source,
            producer_digest.clone(),
        )
        .unwrap();
        assert_eq!(produced.dynamic_import_sites.len(), 1);
        let computed_site = &produced.dynamic_import_sites[0];
        assert_eq!(
            computed_site.label.as_ref().map(|label| label.as_str()),
            Some("routes")
        );
        let entry = produced
            .artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: entry_id.clone(),
                expected_source_integrity: produced.artifact.semantics.source_integrity.clone(),
                expected_producer_id: NonEmptyString::new("ibex-runtime-oxc").unwrap(),
                producer_binary_digest: producer_digest,
                transform_fingerprint_digest: produced
                    .artifact
                    .semantics
                    .transform_fingerprint
                    .digest()
                    .unwrap(),
            })
            .unwrap();
        let literal = test_artifact_with_factory(
            literal_id.clone(),
            "function ($export) { return { declare: function () {}, execute: function () { $export('value', 11); } }; }",
            &["value"],
        );
        let computed = test_artifact_with_factory(
            computed_id.clone(),
            "function ($export) { return { declare: function () {}, execute: function () { $export('value', 22); } }; }",
            &["value"],
        );
        let plan = SynchronousGraphPlan::new_typed_with_computed_candidates(
            [
                (
                    entry,
                    BTreeMap::from([(
                        GraphEdgeKey::new("./literal.mjs", ResolutionKind::DynamicImport),
                        literal_id.clone(),
                    )]),
                ),
                (verify_test_artifact(&literal), BTreeMap::new()),
                (verify_test_artifact(&computed), BTreeMap::new()),
            ],
            BTreeMap::from([(
                entry_id.clone(),
                BTreeMap::from([(
                    (computed_site.site, "./computed.mjs".to_owned()),
                    ComputedCandidateBinding {
                        target: computed_id.clone(),
                        attributes: computed_site.attributes.clone(),
                    },
                )]),
            )]),
        )
        .unwrap();

        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let config = |source_id: SourceId, label: &str| {
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    label,
                    format!("synthetic:module-runner-test/{label}"),
                )
                .unwrap()
            };
            let mut graph = NativeSynchronousGraph::link(
                &runtime,
                &plan,
                &entry_id,
                BTreeMap::from([
                    (
                        entry_id.clone(),
                        config(entry_id.clone(), "/pkg/producer-cjs-dynamic.cjs"),
                    ),
                    (
                        literal_id.clone(),
                        config(literal_id.clone(), "/pkg/literal.mjs"),
                    ),
                    (
                        computed_id.clone(),
                        config(computed_id.clone(), "/pkg/computed.mjs"),
                    ),
                ]),
            )
            .unwrap();
            graph.evaluate().unwrap();
            for tick in 0..8 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
            }

            let observation =
                "String(globalThis.__producerCjsLiteral) + ':' + String(globalThis.__producerCjsComputed) + ':' + String(globalThis.__producerCjsTopLevelThis)";
            let source_url = CString::new("producer-cjs-dynamic-observation.js").unwrap();
            let mut output = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_eval(
                    raw,
                    observation.as_ptr(),
                    observation.len(),
                    source_url.as_ptr(),
                    0,
                    &mut output,
                ),
                0
            );
            assert!(!output.is_null());
            assert_eq!(CStr::from_ptr(output).to_string_lossy(), "11:22:true");
            ex_hermes_free_string(output);

            drop(graph);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn commonjs_dynamic_import_returns_an_esm_namespace_promise() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let esm_id = SourceId::synthetic("module-runner-test", "cjs-dynamic-esm").unwrap();
            let cjs_id = SourceId::synthetic("module-runner-test", "cjs-dynamic-owner").unwrap();
            let esm_artifact = asynchronous_artifact(
                test_artifact_with_factory(
                    esm_id.clone(),
                    "function ($export) { return { declare: function () {}, execute: function () { return Promise.resolve().then(function () { $export('value', 31); }); } }; }",
                    &["value"],
                ),
                Vec::new(),
            );
            let esm_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(esm_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let esm_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&esm_artifact),
                    0,
                    None,
                    1,
                    "cjs-dynamic-esm.mjs",
                )
                .unwrap();
            let mut esm = esm_factory.create_record(&esm_context, &esm_id).unwrap();
            esm.declare_export("value").unwrap();
            esm.instantiate("synthetic:module-runner-test/cjs-dynamic-esm", false)
                .unwrap();
            esm.run_declare().unwrap();

            let cjs_artifact = test_commonjs_artifact(
                cjs_id.clone(),
                "function (require, module, exports, __filename, __dirname, dynamicImport) { dynamicImport('./esm').then(function (namespace) { globalThis.cjsDynamicValue = namespace.value; }); }",
                &[],
            );
            let cjs_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(cjs_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let cjs_factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&cjs_artifact),
                    0,
                    None,
                    1,
                    "cjs-dynamic-owner.cjs",
                )
                .unwrap();
            let mut cjs = cjs_factory
                .create_commonjs_record(&cjs_context, &cjs_id, "/pkg/owner.cjs", "/pkg")
                .unwrap();
            cjs.link_dynamic_import("./esm", &esm).unwrap();
            cjs.evaluate().unwrap();
            for tick in 0..6 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
            }
            let source = "String(globalThis.cjsDynamicValue)";
            let source_url = CString::new("cjs-dynamic-observation.js").unwrap();
            let mut output = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_eval(
                    raw,
                    source.as_ptr(),
                    source.len(),
                    source_url.as_ptr(),
                    0,
                    &mut output,
                ),
                0
            );
            assert!(!output.is_null());
            assert_eq!(CStr::from_ptr(output).to_string_lossy(), "31");
            ex_hermes_free_string(output);

            drop(cjs);
            drop(esm);
            drop(cjs_factory);
            drop(cjs_context);
            drop(esm_factory);
            drop(esm_context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn commonjs_deferred_dynamic_import_uses_the_same_reached_site_mailbox() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let cjs_id = SourceId::synthetic("module-runner-test", "cjs-deferred-owner").unwrap();
            let artifact = with_dynamic_edges(
                test_commonjs_artifact(
                    cjs_id.clone(),
                    "function (require, module, exports, __filename, __dirname, dynamicImport) { if (false) dynamicImport('./dead'); dynamicImport('./later').then(function () { throw new Error('deferred CommonJS target resolved early'); }, function () { globalThis.cjsDeferredDenied = true; }); }",
                    &[],
                ),
                vec![
                    DynamicEdgeV1::Literal {
                        specifier: NonEmptyString::new("./dead").unwrap(),
                        attributes: ImportAttributes::default(),
                    },
                    DynamicEdgeV1::Literal {
                        specifier: NonEmptyString::new("./later").unwrap(),
                        attributes: ImportAttributes::default(),
                    },
                ],
            );
            let context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(cjs_id.clone(), 0, 0, [0], 23).unwrap(),
                )
                .unwrap();
            let factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&artifact),
                    0,
                    None,
                    23,
                    "cjs-deferred-owner.cjs",
                )
                .unwrap();
            let mut record = factory
                .create_commonjs_record(&context, &cjs_id, "/pkg/owner.cjs", "/pkg")
                .unwrap();
            record.defer_dynamic_import_handle("./dead").unwrap();
            record.defer_dynamic_import_handle("./later").unwrap();
            record.evaluate().unwrap();

            let request = runtime
                .take_dynamic_activation_request(23)
                .unwrap()
                .expect("reached CommonJS import did not mint an activation");
            assert_eq!(request.requester, cjs_id);
            assert_eq!(request.kind, DynamicModuleActivationKind::Literal);
            assert_eq!(request.specifier, "./later");
            assert!(
                runtime
                    .take_dynamic_activation_request(23)
                    .unwrap()
                    .is_none(),
                "dead CommonJS import minted an activation"
            );
            runtime
                .refuse_dynamic_activation(&request, "test CommonJS target intentionally absent")
                .unwrap();
            for tick in 0..4 {
                assert_ne!(ex_hermes_poll(raw, tick), -1);
            }
            let source = "String(globalThis.cjsDeferredDenied)";
            let source_url = CString::new("cjs-deferred-observation.js").unwrap();
            let mut output = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_eval(
                    raw,
                    source.as_ptr(),
                    source.len(),
                    source_url.as_ptr(),
                    0,
                    &mut output,
                ),
                0
            );
            assert!(!output.is_null());
            assert_eq!(CStr::from_ptr(output).to_string_lossy(), "true");
            ex_hermes_free_string(output);

            drop(record);
            drop(factory);
            drop(context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn manifest_builtin_require_cannot_escape_synchronous_initialization() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let dependency_id =
                SourceId::builtin("ibex-runtime", "builtin-private-dependency").unwrap();
            let owner_id = SourceId::builtin("ibex-runtime", "builtin-private-owner").unwrap();
            let ordinary_id =
                SourceId::synthetic("module-runner-test", "ordinary-cjs-target").unwrap();
            let dynamic_id =
                SourceId::synthetic("module-runner-test", "ordinary-dynamic-target").unwrap();
            let dependency_artifact = test_builtin_artifact(
                dependency_id.clone(),
                "function (require, module) { module.exports = { value: 41 }; }",
                &[],
            );
            let owner_artifact = test_builtin_artifact(
                owner_id.clone(),
                "function (require) { globalThis.__builtinInitValue = require('./dep').value; globalThis.__leakedBuiltinRequire = require; }",
                &[],
            );
            let ordinary_artifact = test_commonjs_artifact(
                ordinary_id.clone(),
                "function (require, module) { module.exports = {}; }",
                &[],
            );
            let dynamic_artifact = test_artifact(dynamic_id.clone());
            let dependency_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(dependency_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let owner_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(owner_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let ordinary_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(ordinary_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let dynamic_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(dynamic_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let dependency_factory = runtime
                .compile_verified_builtin_factory(
                    verify_test_artifact(&dependency_artifact),
                    0,
                    None,
                    1,
                    "builtin-private-dependency.js",
                )
                .unwrap();
            let owner_factory = runtime
                .compile_verified_builtin_factory(
                    verify_test_artifact(&owner_artifact),
                    0,
                    None,
                    1,
                    "builtin-private-owner.js",
                )
                .unwrap();
            let ordinary_factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&ordinary_artifact),
                    0,
                    None,
                    1,
                    "ordinary-cjs-target.cjs",
                )
                .unwrap();
            let dynamic_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&dynamic_artifact),
                    0,
                    None,
                    1,
                    "ordinary-dynamic-target.mjs",
                )
                .unwrap();
            let dependency = dependency_factory
                .create_commonjs_record(
                    &dependency_context,
                    &dependency_id,
                    "builtin:private-dependency",
                    "builtin:",
                )
                .unwrap();
            let mut owner = owner_factory
                .create_commonjs_record(
                    &owner_context,
                    &owner_id,
                    "builtin:private-owner",
                    "builtin:",
                )
                .unwrap();
            let ordinary = ordinary_factory
                .create_commonjs_record(
                    &ordinary_context,
                    &ordinary_id,
                    "/project/ordinary.cjs",
                    "/project",
                )
                .unwrap();
            let dynamic = dynamic_factory
                .create_record(&dynamic_context, &dynamic_id)
                .unwrap();
            assert!(
                owner.link_require("./ordinary", &ordinary).is_err(),
                "manifest-builtin private linkage accepted a non-builtin target"
            );
            assert!(
                owner.link_dynamic_import("./dynamic", &dynamic).is_err(),
                "manifest-builtin private linkage accepted a dynamic target"
            );
            owner.link_require("./dep", &dependency).unwrap();
            owner.evaluate().unwrap();

            let source = "String(globalThis.__builtinInitValue) + ':' + (function () { try { globalThis.__leakedBuiltinRequire('./dep'); return 'allowed'; } catch (error) { return String(error && error.message); } })()";
            let source_url = CString::new("builtin-require-scope-observation.js").unwrap();
            let mut output = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_eval(
                    raw,
                    source.as_ptr(),
                    source.len(),
                    source_url.as_ptr(),
                    0,
                    &mut output,
                ),
                0
            );
            assert!(!output.is_null());
            assert_eq!(
                CStr::from_ptr(output).to_string_lossy(),
                "41:manifest builtin require is unavailable outside synchronous initialization"
            );
            ex_hermes_free_string(output);

            drop(dynamic);
            drop(ordinary);
            drop(owner);
            drop(dependency);
            drop(dynamic_factory);
            drop(ordinary_factory);
            drop(owner_factory);
            drop(dependency_factory);
            drop(dynamic_context);
            drop(ordinary_context);
            drop(owner_context);
            drop(dependency_context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn manifest_builtin_require_cannot_reenter_through_another_active_record() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            assert_eq!(ibex_test_begin_structured_module_error_capture(raw), 1);
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let a_id = SourceId::builtin("ibex-runtime", "builtin-owner-a").unwrap();
            let b_id = SourceId::builtin("ibex-runtime", "builtin-owner-b").unwrap();
            let dep_id = SourceId::builtin("ibex-runtime", "builtin-owner-dep").unwrap();
            let a_artifact = test_builtin_artifact(
                a_id.clone(),
                "function (require, module, exports) { exports.leaked = require; require('./b'); }",
                &[],
            );
            let b_artifact = test_builtin_artifact(
                b_id.clone(),
                "function (require) { var owner = require('./a'); try { owner.leaked('./dep'); } catch (error) { throw String(error && error.message); } }",
                &[],
            );
            let dep_artifact = test_builtin_artifact(
                dep_id.clone(),
                "function (require, module) { module.exports = { value: 1 }; }",
                &[],
            );
            let context = |source_id: SourceId| {
                runtime
                    .create_graph_context(
                        GraphEvaluationContext::new(source_id, 0, 0, [0], 1).unwrap(),
                    )
                    .unwrap()
            };
            let a_context = context(a_id.clone());
            let b_context = context(b_id.clone());
            let dep_context = context(dep_id.clone());
            let compile = |artifact: &ModuleArtifactV1, label: &str| {
                runtime
                    .compile_verified_builtin_factory(
                        verify_test_artifact(artifact),
                        0,
                        None,
                        1,
                        label,
                    )
                    .unwrap()
            };
            let a_factory = compile(&a_artifact, "builtin-owner-a.js");
            let b_factory = compile(&b_artifact, "builtin-owner-b.js");
            let dep_factory = compile(&dep_artifact, "builtin-owner-dep.js");
            let mut a = a_factory
                .create_commonjs_record(&a_context, &a_id, "builtin:a", "builtin:")
                .unwrap();
            let mut b = b_factory
                .create_commonjs_record(&b_context, &b_id, "builtin:b", "builtin:")
                .unwrap();
            let dep = dep_factory
                .create_commonjs_record(&dep_context, &dep_id, "builtin:dep", "builtin:")
                .unwrap();
            a.link_require("./b", &b).unwrap();
            a.link_require("./dep", &dep).unwrap();
            b.link_require("./a", &a).unwrap();

            let error = a
                .evaluate()
                .expect_err("another active builtin record reused a leaked require closure");
            let token = execution_error_token(&error)
                .expect("the reentrant builtin refusal omitted its raw throw token");
            let expected =
                b"manifest builtin require is unavailable outside synchronous initialization";
            assert_eq!(
                ibex_test_structured_module_error_token_matches_utf8(
                    raw,
                    token.get(),
                    expected.as_ptr(),
                    expected.len(),
                ),
                1
            );
            assert_eq!(ibex_test_end_structured_module_error_capture(raw), 1);

            drop(dep);
            drop(b);
            drop(a);
            drop(dep_factory);
            drop(b_factory);
            drop(a_factory);
            drop(dep_context);
            drop(b_context);
            drop(a_context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn commonjs_cycles_publish_early_exports_and_build_snapshot_adapters() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let a_id = SourceId::synthetic("module-runner-test", "commonjs-a").unwrap();
            let b_id = SourceId::synthetic("module-runner-test", "commonjs-b").unwrap();
            let a_artifact = test_commonjs_artifact(
                a_id.clone(),
                "function (require, module, exports) { module.exports = { ready: false }; const b = require('./b'); module.exports.fromB = b.sawA; module.exports.ready = true; }",
                &["fromB", "ready"],
            );
            let b_artifact = test_commonjs_artifact(
                b_id.clone(),
                "function (require, module, exports) { exports.sawA = require('./a').ready; }",
                &["sawA"],
            );
            let a_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(a_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let b_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(b_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let a_factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&a_artifact),
                    0,
                    None,
                    1,
                    "commonjs-a.cjs",
                )
                .unwrap();
            let b_factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&b_artifact),
                    0,
                    None,
                    1,
                    "commonjs-b.cjs",
                )
                .unwrap();
            let mut a = a_factory
                .create_commonjs_record(&a_context, &a_id, "/pkg/a.cjs", "/pkg")
                .unwrap();
            let mut b = b_factory
                .create_commonjs_record(&b_context, &b_id, "/pkg/b.cjs", "/pkg")
                .unwrap();
            a.declare_detected_export("fromB").unwrap();
            a.declare_detected_export("ready").unwrap();
            b.declare_detected_export("sawA").unwrap();
            a.link_require("./b", &b).unwrap();
            b.link_require("./a", &a).unwrap();

            a.evaluate().unwrap();
            b.evaluate().unwrap();
            let a_adapter = a.create_esm_adapter().unwrap();
            let b_adapter = b.create_esm_adapter().unwrap();
            assert_eq!(
                a_adapter.namespace_json().unwrap(),
                r#"{"default":{"ready":true,"fromB":false},"fromB":false,"module.exports":{"ready":true,"fromB":false},"ready":true}"#
            );
            assert_eq!(
                b_adapter.namespace_json().unwrap(),
                r#"{"default":{"sawA":false},"module.exports":{"sawA":false},"sawA":false}"#
            );

            drop(b_adapter);
            drop(a_adapter);
            drop(b);
            drop(a);
            drop(b_factory);
            drop(a_factory);
            drop(b_context);
            drop(a_context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn throwing_commonjs_record_is_evicted_and_can_be_recreated() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let source_id = SourceId::synthetic("module-runner-test", "commonjs-throw").unwrap();
            let artifact = test_commonjs_artifact(
                source_id.clone(),
                "function () { throw new Error('cjs boom'); }",
                &["never"],
            );
            let context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let factory = runtime
                .compile_verified_commonjs_factory(
                    verify_test_artifact(&artifact),
                    0,
                    None,
                    1,
                    "commonjs-throw.cjs",
                )
                .unwrap();
            for _ in 0..2 {
                let mut record = factory
                    .create_commonjs_record(&context, &source_id, "/pkg/throw.cjs", "/pkg")
                    .unwrap();
                let error = record.evaluate().unwrap_err().to_string();
                assert!(
                    error.contains("CommonJS record evaluation threw"),
                    "unexpected error: {error}"
                );
                assert!(record.create_esm_adapter().is_err());
            }

            drop(factory);
            drop(context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    #[test]
    fn linked_records_observe_live_binding_updates() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());
        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let target_id = SourceId::synthetic("module-runner-test", "target").unwrap();
            let importer_id = SourceId::synthetic("module-runner-test", "importer").unwrap();
            let reexport_id = SourceId::synthetic("module-runner-test", "reexport").unwrap();
            let target_artifact = test_artifact_with_factory(
                target_id.clone(),
                "function ($export) { let count; function increment() { $export('count', ++count); } return { declare: function () { $export('increment', increment); }, execute: function () { count = 0; $export('count', count); } }; }",
                &["count", "increment"],
            );
            let importer_artifact = test_artifact_with_factory(
                importer_id.clone(),
                "function ($export, context) { return { declare: function () {}, execute: function () { const before = context.importValue('./target', 'count'); context.importValue('./target', 'increment')(); $export('observed', before + ':' + context.importValue('./target', 'count')); } }; }",
                &["observed"],
            );
            let reexport_artifact = test_artifact_with_factory(
                reexport_id.clone(),
                "function () { return { declare: function () {}, execute: function () {} }; }",
                &["count", "target"],
            );
            let target_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(target_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let importer_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(importer_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let reexport_context = runtime
                .create_graph_context(
                    GraphEvaluationContext::new(reexport_id.clone(), 0, 0, [0], 1).unwrap(),
                )
                .unwrap();
            let target_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&target_artifact),
                    0,
                    None,
                    1,
                    "target.mjs",
                )
                .unwrap();
            let importer_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&importer_artifact),
                    0,
                    None,
                    1,
                    "importer.mjs",
                )
                .unwrap();
            let reexport_factory = runtime
                .compile_verified_factory(
                    verify_test_artifact(&reexport_artifact),
                    0,
                    None,
                    1,
                    "reexport.mjs",
                )
                .unwrap();
            let mut target = target_factory
                .create_record(&target_context, &target_id)
                .unwrap();
            target.declare_export("count").unwrap();
            target.declare_export("increment").unwrap();
            let mut importer = importer_factory
                .create_record(&importer_context, &importer_id)
                .unwrap();
            importer.declare_export("observed").unwrap();
            importer
                .link_import("./target", "count", &target, "count")
                .unwrap();
            importer
                .link_import("./target", "increment", &target, "increment")
                .unwrap();
            let mut reexport = reexport_factory
                .create_record(&reexport_context, &reexport_id)
                .unwrap();
            reexport.declare_export("count").unwrap();
            reexport.declare_export("target").unwrap();
            reexport.link_export("count", &target, "count").unwrap();
            reexport.link_export("target", &target, "*").unwrap();

            target
                .instantiate("synthetic:module-runner-test/target", false)
                .unwrap();
            importer
                .instantiate("synthetic:module-runner-test/importer", true)
                .unwrap();
            reexport
                .instantiate("synthetic:module-runner-test/reexport", false)
                .unwrap();
            target.run_declare().unwrap();
            importer.run_declare().unwrap();
            reexport.run_declare().unwrap();
            assert_eq!(
                target.run_execute().unwrap(),
                ModuleExecutionKind::Synchronous
            );
            assert_eq!(
                importer.run_execute().unwrap(),
                ModuleExecutionKind::Synchronous
            );
            assert_eq!(target.namespace_json().unwrap(), r#"{"count":1}"#);
            assert_eq!(importer.namespace_json().unwrap(), r#"{"observed":"0:1"}"#);
            assert_eq!(
                reexport.namespace_json().unwrap(),
                r#"{"count":1,"target":{"count":1}}"#
            );

            drop(reexport);
            drop(importer);
            drop(target);
            drop(reexport_factory);
            drop(importer_factory);
            drop(target_factory);
            drop(reexport_context);
            drop(importer_context);
            drop(target_context);
            drop(runtime);
            ex_hermes_destroy(raw);
        }
    }

    /// Hosted micro-evidence for the two performance questions that a whole
    /// application startup profile cannot isolate: checked binding operations
    /// after linking and the true cold CommonJS `require(ESM)` drive.
    // @ref LLP 0026#performance-and-platform-gates — measure checked cells against plain properties and cold require(ESM)
    #[test]
    #[ignore = "hosted module-runner micro-performance evidence"]
    fn module_runner_cell_and_require_performance_baseline() {
        use std::time::Instant;

        const ITERATIONS: usize = 20_000;
        const REQUIRE_DEPENDENCY_MODULES: usize = 40;

        let output = std::env::var_os("IBEX_MODULE_RUNNER_MICRO_PERF_OUTPUT")
            .map(std::path::PathBuf::from)
            .expect("IBEX_MODULE_RUNNER_MICRO_PERF_OUTPUT is required");
        let samples = std::env::var("IBEX_MODULE_RUNNER_PERF_SAMPLES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value >= 3)
            .unwrap_or(5);
        let summarize = |values: &[f64]| {
            let mut sorted = values.to_vec();
            sorted.sort_by(f64::total_cmp);
            serde_json::json!({
                "samples": values.len(),
                "minMs": sorted[0],
                "medianMs": sorted[sorted.len() / 2],
                "meanMs": values.iter().sum::<f64>() / values.len() as f64,
                "maxMs": sorted[sorted.len() - 1],
            })
        };
        let config = |source_id: SourceId, generation: u64, label: &str| {
            NativeModuleRecordConfig::new(
                0,
                None,
                GraphEvaluationContext::new(source_id, 0, 0, [0], generation).unwrap(),
                label,
                format!("synthetic:module-runner-performance/{label}"),
            )
            .unwrap()
        };

        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());

        let cell_target_id =
            SourceId::synthetic("module-runner-performance", "cell-target").unwrap();
        let cell_entry_id = SourceId::synthetic("module-runner-performance", "cell-entry").unwrap();
        let plain_entry_id =
            SourceId::synthetic("module-runner-performance", "plain-entry").unwrap();
        let cell_target = test_artifact_with_factory(
            cell_target_id.clone(),
            "function ($export) { var count; function increment() { count += 1; $export('count', count); } return { declare: function () { $export('increment', increment); }, execute: function () { count = 0; $export('count', count); } }; }",
            &["count", "increment"],
        );
        let cell_entry = test_graph_artifact(
            cell_entry_id.clone(),
            &format!(
                "function ($export, context) {{ return {{ declare: function () {{}}, execute: function () {{ var ns = context.importValue('./target', '*'); var sum = 0; for (var i = 0; i < {ITERATIONS}; i += 1) {{ context.importValue('./target', 'increment')(); sum += context.importValue('./target', 'count') + ns.count; }} $export('result', sum); }} }}; }}"
            ),
            vec![
                StaticEdgeV1::Namespace {
                    specifier: NonEmptyString::new("./target").unwrap(),
                    local: NonEmptyString::new("ns").unwrap(),
                    attributes: ImportAttributes::default(),
                },
                StaticEdgeV1::Named {
                    specifier: NonEmptyString::new("./target").unwrap(),
                    imported: NonEmptyString::new("increment").unwrap(),
                    local: NonEmptyString::new("increment").unwrap(),
                    attributes: ImportAttributes::default(),
                },
                StaticEdgeV1::Named {
                    specifier: NonEmptyString::new("./target").unwrap(),
                    imported: NonEmptyString::new("count").unwrap(),
                    local: NonEmptyString::new("count").unwrap(),
                    attributes: ImportAttributes::default(),
                },
            ],
            vec![ExportDescriptorV1::Local {
                exported: NonEmptyString::new("result").unwrap(),
                local: NonEmptyString::new("result").unwrap(),
            }],
        );
        let plain_entry = test_artifact_with_factory(
            plain_entry_id.clone(),
            &format!(
                "function ($export) {{ return {{ declare: function () {{}}, execute: function () {{ var box = {{ count: 0 }}; function increment() {{ box.count += 1; }} var sum = 0; for (var i = 0; i < {ITERATIONS}; i += 1) {{ increment(); sum += box.count + box.count; }} $export('result', sum); }} }}; }}"
            ),
            &["result"],
        );
        let cell_plan = SynchronousGraphPlan::new([
            (verify_test_artifact(&cell_target), BTreeMap::new()),
            (
                verify_test_artifact(&cell_entry),
                BTreeMap::from([("./target".into(), cell_target_id.clone())]),
            ),
        ])
        .unwrap();
        let plain_plan =
            SynchronousGraphPlan::new([(verify_test_artifact(&plain_entry), BTreeMap::new())])
                .unwrap();
        let expected_sum = ITERATIONS * (ITERATIONS + 1);

        let mut require_artifacts = Vec::with_capacity(REQUIRE_DEPENDENCY_MODULES + 1);
        let mut require_edges = Vec::with_capacity(REQUIRE_DEPENDENCY_MODULES + 1);
        let require_ids = (0..REQUIRE_DEPENDENCY_MODULES)
            .map(|index| {
                SourceId::synthetic("module-runner-performance", format!("require-m{index}"))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for index in 0..REQUIRE_DEPENDENCY_MODULES {
            if index + 1 < REQUIRE_DEPENDENCY_MODULES {
                let specifier = format!("./m{}", index + 1);
                require_artifacts.push(test_graph_artifact(
                    require_ids[index].clone(),
                    &format!(
                        "function ($export, context) {{ return {{ declare: function () {{}}, execute: function () {{ $export('value', context.importValue('{specifier}', 'value') + 1); }} }}; }}"
                    ),
                    vec![StaticEdgeV1::Named {
                        specifier: NonEmptyString::new(specifier.clone()).unwrap(),
                        imported: NonEmptyString::new("value").unwrap(),
                        local: NonEmptyString::new("next").unwrap(),
                        attributes: ImportAttributes::default(),
                    }],
                    vec![ExportDescriptorV1::Local {
                        exported: NonEmptyString::new("value").unwrap(),
                        local: NonEmptyString::new("value").unwrap(),
                    }],
                ));
                require_edges.push(BTreeMap::from([(
                    specifier,
                    require_ids[index + 1].clone(),
                )]));
            } else {
                require_artifacts.push(test_artifact_with_factory(
                    require_ids[index].clone(),
                    "function ($export) { return { declare: function () {}, execute: function () { $export('value', 1); } }; }",
                    &["value"],
                ));
                require_edges.push(BTreeMap::new());
            }
        }
        let require_entry_id =
            SourceId::synthetic("module-runner-performance", "require-entry").unwrap();
        require_artifacts.push(test_artifact_for_goal(
            require_entry_id.clone(),
            "function (require, module, exports) { exports.result = require('./m0').value; }",
            SourceGoalV1::CommonJs,
            vec![StaticEdgeV1::CommonJsRequire {
                specifier: NonEmptyString::new("./m0").unwrap(),
            }],
            Vec::new(),
            Some(CommonJsExportsV1 {
                detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
                detector_version: NonEmptyString::new("2.1.0").unwrap(),
                names: vec![NonEmptyString::new("result").unwrap()],
                reexports: Vec::new(),
            }),
        ));
        require_edges.push(BTreeMap::from([("./m0".into(), require_ids[0].clone())]));

        unsafe {
            let raw = ex_hermes_create_diagnostic();
            assert!(!raw.is_null());
            let nonce = ex_hermes_runtime_nonce(raw);
            let runtime = NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
            let mut cell_ms = Vec::with_capacity(samples);
            let mut plain_ms = Vec::with_capacity(samples);

            for sample in 0..(samples + 2) {
                let generation = sample as u64 + 1;
                let mut cell_graph = NativeSynchronousGraph::link(
                    &runtime,
                    &cell_plan,
                    &cell_entry_id,
                    BTreeMap::from([
                        (
                            cell_target_id.clone(),
                            config(cell_target_id.clone(), generation, "cell-target.mjs"),
                        ),
                        (
                            cell_entry_id.clone(),
                            config(cell_entry_id.clone(), generation, "cell-entry.mjs"),
                        ),
                    ]),
                )
                .unwrap();
                let started = Instant::now();
                cell_graph.evaluate().unwrap();
                let elapsed = started.elapsed().as_secs_f64() * 1000.0;
                assert_eq!(
                    cell_graph.namespace_json(&cell_entry_id).unwrap(),
                    format!(r#"{{"result":{expected_sum}}}"#)
                );
                if sample >= 2 {
                    cell_ms.push(elapsed);
                }

                let plain_generation = generation + (samples + 2) as u64;
                let mut plain_graph = NativeSynchronousGraph::link(
                    &runtime,
                    &plain_plan,
                    &plain_entry_id,
                    BTreeMap::from([(
                        plain_entry_id.clone(),
                        config(plain_entry_id.clone(), plain_generation, "plain-entry.mjs"),
                    )]),
                )
                .unwrap();
                let started = Instant::now();
                plain_graph.evaluate().unwrap();
                let elapsed = started.elapsed().as_secs_f64() * 1000.0;
                assert_eq!(
                    plain_graph.namespace_json(&plain_entry_id).unwrap(),
                    format!(r#"{{"result":{expected_sum}}}"#)
                );
                if sample >= 2 {
                    plain_ms.push(elapsed);
                }
            }
            drop(runtime);
            ex_hermes_destroy(raw);

            let mut cold_require_ms = Vec::with_capacity(samples);
            for sample in 0..samples {
                let started = Instant::now();
                let plan = SynchronousGraphPlan::new(
                    require_artifacts
                        .iter()
                        .zip(require_edges.iter())
                        .map(|(artifact, edges)| (verify_test_artifact(artifact), edges.clone())),
                )
                .unwrap();
                plan.synchronous_evaluation_order(&require_entry_id)
                    .unwrap();
                let raw = ex_hermes_create_diagnostic();
                assert!(!raw.is_null());
                let nonce = ex_hermes_runtime_nonce(raw);
                let runtime =
                    NativeModuleRuntime::from_raw(NonNull::new(raw).unwrap(), nonce).unwrap();
                let generation = sample as u64 + 1;
                let mut configs = BTreeMap::new();
                for (index, source_id) in require_ids.iter().enumerate() {
                    configs.insert(
                        source_id.clone(),
                        config(source_id.clone(), generation, &format!("m{index}.mjs")),
                    );
                }
                configs.insert(
                    require_entry_id.clone(),
                    config(require_entry_id.clone(), generation, "entry.cjs"),
                );
                let mut graph =
                    NativeSynchronousGraph::link(&runtime, &plan, &require_entry_id, configs)
                        .unwrap();
                graph.evaluate().unwrap();
                assert_eq!(
                    graph.namespace_json(&require_entry_id).unwrap(),
                    r#"{"default":{"result":40},"module.exports":{"result":40},"result":40}"#
                );
                cold_require_ms.push(started.elapsed().as_secs_f64() * 1000.0);
                drop(graph);
                drop(runtime);
                ex_hermes_destroy(raw);
            }

            let report = serde_json::json!({
                "schema": "ibex/module-runner-micro-performance-baseline/1",
                "platform": { "os": std::env::consts::OS, "arch": std::env::consts::ARCH },
                "measurementConditions": {
                    "iterations": ITERATIONS,
                    "requireDependencyModules": REQUIRE_DEPENDENCY_MODULES,
                    "warmupSamplesExcluded": 2,
                    "cellWorkload": "one checked function import read, one export update observed through a checked value import and namespace getter, per iteration",
                    "plainWorkload": "one ordinary function call and two ordinary object property reads per iteration"
                },
                "profiles": {
                    "checkedCellSetterNamespace": summarize(&cell_ms),
                    "plainProperty": summarize(&plain_ms),
                    "coldRequireEsm": summarize(&cold_require_ms),
                },
            });
            std::fs::write(
                output,
                format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
            )
            .unwrap();
        }
    }
}
