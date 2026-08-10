//! Safe Rust ownership around Hermes' versioned structured-evaluation ABI.
//!
//! The public seam accepts only opaque authenticated Rust values. Native
//! session-token and request-binding bytes are assembled and consumed inside
//! this module; the binary crate never receives credential material or the C
//! layout that carries it.
//! @ref LLP 0024#6-evaluation-outcomes-and-the-abi — native outcomes remain
//! typed, length-bearing, runtime-scoped, and free of JavaScript coercion.

use std::ffi::c_void;
use std::mem::size_of;
use std::num::NonZeroU64;
use std::ptr;
use std::sync::Arc;

use super::evaluation::{
    ArmedSessionToken, CapabilityStratum, EngineFault, EntryKind, EvaluationOutcome,
    EvaluationResult, EvaluatorCapabilities, ModuleKind, NativeErrorClass, SourceRequest,
    StructuredEngineFault, ThrowMetadata, ValueHandle, WorkKind, WorkTarget,
    STRUCTURED_EVALUATION_VERSION,
};
use super::session_lowering::{
    lower_program, LoweredDeclarationKind, LoweredStaticImportBindingKind,
    SESSION_LOWERING_PROTOCOL_VERSION,
};

const ABI_VERSION: u32 = 2;
const IMPORT_PLAN_ABI_VERSION: u32 = 4;
const STRUCTURED_SOURCE_SESSION: u32 = 1;
const STRUCTURED_SOURCE_COMMONJS_ENTRY: u32 = 2;
const STRUCTURED_SOURCE_GENERATED_COMMONJS_ENTRY: u32 = 3;

const OUTCOME_EMPTY: u32 = 1;
const OUTCOME_VALUE: u32 = 2;
const OUTCOME_THROW: u32 = 3;
const OUTCOME_CANCELLED: u32 = 4;
const OUTCOME_LIFECYCLE: u32 = 5;
const OUTCOME_ENGINE_FAULT: u32 = 6;
const CONTINUATION_SUSPENDED: u32 = 7;

const FAULT_NONE: u32 = 0;

const CAPABILITY_BASE: u32 = 1 << 0;
const CAPABILITY_SAFE_THROW: u32 = 1 << 1;
const CAPABILITY_SOURCE_POSITIONS: u32 = 1 << 2;
const CAPABILITY_RICH_INSPECTION: u32 = 1 << 3;
const CAPABILITY_KNOWN: u32 = CAPABILITY_BASE
    | CAPABILITY_SAFE_THROW
    | CAPABILITY_SOURCE_POSITIONS
    | CAPABILITY_RICH_INSPECTION;

const THROW_METADATA_UNAVAILABLE: u32 = 0;
const THROW_METADATA_CAPTURED: u32 = 1;
const THROW_FIELD_MESSAGE: u32 = 1 << 0;
const THROW_FIELD_STACK: u32 = 1 << 1;
const THROW_FIELD_POSITIONS: u32 = 1 << 2;
const THROW_FIELD_MESSAGE_TRUNCATED: u32 = 1 << 3;
const THROW_FIELD_STACK_TRUNCATED: u32 = 1 << 4;
const THROW_FIELDS_KNOWN: u32 = THROW_FIELD_MESSAGE
    | THROW_FIELD_STACK
    | THROW_FIELD_POSITIONS
    | THROW_FIELD_MESSAGE_TRUNCATED
    | THROW_FIELD_STACK_TRUNCATED;
pub const SAFE_TEXT_MAX_BYTES: usize = 16 * 1024;
pub const SAFE_TEXT_TRUNCATION_MARKER: &str = "...[truncated]";

const ERROR_CLASS_UNCLASSIFIED: u32 = 0;
const ERROR_CLASS_ERROR: u32 = 1;
const ERROR_CLASS_AGGREGATE_ERROR: u32 = 2;
const ERROR_CLASS_EVAL_ERROR: u32 = 3;
const ERROR_CLASS_RANGE_ERROR: u32 = 4;
const ERROR_CLASS_REFERENCE_ERROR: u32 = 5;
const ERROR_CLASS_SYNTAX_ERROR: u32 = 6;
const ERROR_CLASS_TYPE_ERROR: u32 = 7;
const ERROR_CLASS_URI_ERROR: u32 = 8;
const ERROR_CLASS_TIMEOUT_ERROR: u32 = 9;
const ERROR_CLASS_QUIT_ERROR: u32 = 10;

const VALUE_INVALID: u32 = 0;
const VALUE_UNDEFINED: u32 = 1;
const VALUE_NULL: u32 = 2;
const VALUE_BOOLEAN: u32 = 3;
const VALUE_NUMBER: u32 = 4;
const VALUE_STRING: u32 = 5;
const VALUE_SYMBOL: u32 = 6;
const VALUE_BIGINT: u32 = 7;
const VALUE_FUNCTION: u32 = 8;
const VALUE_OBJECT: u32 = 9;
const VALUE_ARRAY: u32 = 10;

#[repr(C)]
struct HermesRuntimeOpaque {
    _private: [u8; 0],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
struct NativeValueHandle {
    runtime_nonce: u64,
    handle_id: u64,
}

impl NativeValueHandle {
    const EMPTY: Self = Self {
        runtime_nonce: 0,
        handle_id: 0,
    };
}

#[derive(Clone, Copy)]
#[repr(C)]
struct NativeOwnedBytes {
    data: *mut u8,
    length: usize,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct NativeSourcePosition {
    source_label: NativeOwnedBytes,
    line: u32,
    column: u32,
}

impl NativeOwnedBytes {
    const EMPTY: Self = Self {
        data: ptr::null_mut(),
        length: 0,
    };
}

#[repr(C)]
struct NativeSessionCredential {
    abi_version: u32,
    struct_size: u32,
    session_token: [u8; 32],
    request_binding: [u8; 32],
    ordinal: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct NativeSessionDeclaration {
    name: *const u8,
    name_length: usize,
    kind: u32,
    reserved: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct NativeSessionStaticImport {
    abi_version: u32,
    struct_size: u32,
    specifier: *const u8,
    specifier_length: usize,
    first_binding: usize,
    binding_count: usize,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct NativeSessionImportBinding {
    abi_version: u32,
    struct_size: u32,
    local_name: *const u8,
    local_name_length: usize,
    imported_name: *const u8,
    imported_name_length: usize,
    kind: u32,
    reserved: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct NativeUtf8Slice {
    data: *const u8,
    length: usize,
}

#[repr(C)]
struct NativeSessionImportPlan {
    abi_version: u32,
    struct_size: u32,
    logical_referrer: *const u8,
    logical_referrer_length: usize,
    imports: *const NativeSessionStaticImport,
    import_count: usize,
    bindings: *const NativeSessionImportBinding,
    binding_count: usize,
    file_arguments: *const NativeUtf8Slice,
    file_argument_count: usize,
    source_id: *const u8,
    source_id_length: usize,
    generated_entry_record: *const u8,
    generated_entry_record_length: usize,
    source_kind: u32,
    reserved: u32,
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

impl NativeEvaluationResult {
    const fn empty() -> Self {
        Self {
            abi_version: ABI_VERSION,
            struct_size: size_of::<Self>() as u32,
            outcome_tag: 0,
            fault: FAULT_NONE,
            work_target_id: 0,
            value: NativeValueHandle::EMPTY,
            throw_metadata_status: THROW_METADATA_UNAVAILABLE,
            throw_metadata_fields: 0,
            throw_error_class: ERROR_CLASS_UNCLASSIFIED,
            lifecycle_exit_code: 0,
            capability_flags: 0,
            message: NativeOwnedBytes::EMPTY,
            stack: NativeOwnedBytes::EMPTY,
            positions: ptr::null_mut(),
            position_count: 0,
        }
    }
}

const _: () = assert!(size_of::<NativeSessionCredential>() <= u32::MAX as usize);
const _: () = assert!(size_of::<NativeSessionDeclaration>() <= u32::MAX as usize);
const _: () = assert!(size_of::<NativeSessionStaticImport>() <= u32::MAX as usize);
const _: () = assert!(size_of::<NativeSessionImportBinding>() <= u32::MAX as usize);
const _: () = assert!(size_of::<NativeUtf8Slice>() <= u32::MAX as usize);
const _: () = assert!(size_of::<NativeSessionImportPlan>() <= u32::MAX as usize);
const _: () = assert!(size_of::<NativeEvaluationResult>() <= u32::MAX as usize);
const _: () = assert!(size_of::<NativeSourcePosition>() <= u32::MAX as usize);
const _: () = assert!(STRUCTURED_EVALUATION_VERSION as u32 == ABI_VERSION);
const _: () = assert!(SESSION_LOWERING_PROTOCOL_VERSION == 2);

extern "C" {
    fn ex_hermes_runtime_nonce(runtime: *mut c_void) -> u64;
    fn ex_hermes_structured_session_bind(
        runtime: *mut HermesRuntimeOpaque,
        session_token: *const u8,
        session_token_length: usize,
    ) -> u32;
    fn ex_hermes_structured_submission_admit(
        runtime: *mut HermesRuntimeOpaque,
        credential: *const NativeSessionCredential,
        out_work_target_id: *mut u64,
    ) -> u32;
    fn ex_hermes_structured_submission_settle(
        runtime: *mut HermesRuntimeOpaque,
        credential: *const NativeSessionCredential,
    ) -> u32;
    fn ex_hermes_structured_module_graph_begin(
        runtime: *mut HermesRuntimeOpaque,
        credential: *const NativeSessionCredential,
        file_arguments: *const NativeUtf8Slice,
        file_argument_count: usize,
    ) -> u32;
    fn ex_hermes_structured_module_graph_suspend(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
    ) -> u32;
    fn ex_hermes_structured_module_graph_resume(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
    ) -> u32;
    fn ex_hermes_structured_module_graph_finish(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
        execution_outcome: u32,
        error_token: u64,
        result: *mut NativeEvaluationResult,
    ) -> i32;
    fn ex_hermes_evaluation_result_init(result: *mut NativeEvaluationResult);
    fn ex_hermes_evaluation_result_dispose(result: *mut NativeEvaluationResult);
    fn ex_hermes_eval_lowered_session(
        runtime: *mut HermesRuntimeOpaque,
        credential: *const NativeSessionCredential,
        lowering_protocol_version: u32,
        lowered_source: *const u8,
        lowered_source_length: usize,
        lowered_source_map: *const u8,
        lowered_source_map_length: usize,
        source_label: *const u8,
        source_label_length: usize,
        declarations: *const NativeSessionDeclaration,
        declaration_count: usize,
        import_plan: *const NativeSessionImportPlan,
        asynchronous: bool,
        result: *mut NativeEvaluationResult,
    ) -> i32;
    #[cfg(feature = "capsec-conformance-observer")]
    fn ibex_private_test_eval_lowered_session_with_principals(
        runtime: *mut HermesRuntimeOpaque,
        principal_ids: *const u64,
        principal_count: usize,
        credential: *const NativeSessionCredential,
        lowering_protocol_version: u32,
        lowered_source: *const u8,
        lowered_source_length: usize,
        lowered_source_map: *const u8,
        lowered_source_map_length: usize,
        source_label: *const u8,
        source_label_length: usize,
        declarations: *const NativeSessionDeclaration,
        declaration_count: usize,
        import_plan: *const NativeSessionImportPlan,
        asynchronous: bool,
        result: *mut NativeEvaluationResult,
    ) -> i32;
    fn ex_hermes_resume_structured_session(
        runtime: *mut HermesRuntimeOpaque,
        work_target_id: u64,
        result: *mut NativeEvaluationResult,
    ) -> i32;
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
    fn ex_hermes_value_release(runtime: *mut HermesRuntimeOpaque, handle: NativeValueHandle)
        -> u32;
    fn ex_hermes_free_string(value: *mut std::ffi::c_char);
}

/// One structured native evaluation, including information which is meaningful
/// even when the native outcome is an engine fault.
#[derive(Debug)]
pub struct StructuredEvaluation {
    pub work_target: Option<WorkTarget>,
    pub capabilities: EvaluatorCapabilities,
    pub result: EvaluationResult,
}

/// Linear owner-thread receipt for a top-level-await unit which has not yet
/// settled. It is a progress state rather than a public evaluation outcome;
/// only the native continuation adapter can consume it.
#[derive(Debug, Eq, PartialEq)]
pub struct StructuredSuspension {
    runtime_nonce: NonZeroU64,
    work_target_id: NonZeroU64,
    owner_thread: std::thread::ThreadId,
}

#[derive(Debug)]
pub enum StructuredEvaluationProgress {
    Settled(StructuredEvaluation),
    Suspended(StructuredSuspension),
}

/// Trap-free top-level kind of a rooted JavaScript value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueKind {
    Undefined,
    Null,
    Boolean,
    Number,
    String,
    Symbol,
    BigInt,
    Function,
    Object,
    Array,
}

/// Stage-1 display materialized without calling JavaScript, reading object
/// properties, or invoking user coercion. Strings are JSON-quoted and object
/// categories use closed tags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stage1Display {
    pub kind: ValueKind,
    pub text: Arc<str>,
    pub truncated: bool,
}

/// Linear acknowledgement receipt for the exact rooted value and work target
/// whose Stage-1 text was materialized. Fields are private so callers can only
/// return a receipt obtained from an authenticated evaluation.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "display receipts must be settled as displayed, fallback, or write-failed"]
pub struct Stage1DisplayReceipt {
    runtime_nonce: NonZeroU64,
    work_target_id: NonZeroU64,
    handle_id: NonZeroU64,
    owner_thread: std::thread::ThreadId,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Stage1EvaluationOutcome {
    Empty,
    Value {
        display: Stage1Display,
        receipt: Stage1DisplayReceipt,
    },
    Throw {
        value: Stage1Display,
        metadata: ThrowMetadata,
    },
    Cancelled,
    Lifecycle {
        exit_code: i32,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub struct Stage1Evaluation {
    pub work_target: Option<WorkTarget>,
    pub capabilities: EvaluatorCapabilities,
    pub outcome: Stage1EvaluationOutcome,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Stage1EvaluationProgress {
    Settled(Stage1Evaluation),
    Suspended(StructuredSuspension),
}

/// Terminal classification supplied by the Rust graph owner after the native
/// linker/evaluator has returned. JavaScript throws are materialized from the
/// raw value retained by the Hermes bridge; an engine fault never borrows that
/// value or turns a diagnostic string into a user exception.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleGraphExecutionOutcome {
    Completed,
    JavaScriptThrow(NonZeroU64),
    EngineFault,
    CooperativeCancellation,
    UnresolvedTopLevelAwait,
}

impl ModuleGraphExecutionOutcome {
    const fn abi_value(self) -> u32 {
        match self {
            Self::Completed => 0,
            Self::JavaScriptThrow(_) => 1,
            Self::EngineFault => 2,
            Self::CooperativeCancellation => 3,
            Self::UnresolvedTopLevelAwait => 4,
        }
    }

    const fn error_token(self) -> u64 {
        match self {
            Self::JavaScriptThrow(token) => token.get(),
            Self::Completed
            | Self::EngineFault
            | Self::CooperativeCancellation
            | Self::UnresolvedTopLevelAwait => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleGraphSuspension {
    Suspended,
    CancellationPending,
}

/// Synchronous post-admission route selected by an authenticated direct-file
/// graph preparer. `Native` carries only Rust-owned, request-bound preparation;
/// `LegacyRequired` continues the original raw request through the ordinary
/// structured evaluator without admitting a second submission ordinal.
pub enum AuthenticatedModuleGraphPreparation<T> {
    Native(T),
    LegacyRequired,
}

/// Result of admitting one authenticated direct-file request before invoking
/// its synchronous graph preparer.
pub enum AuthenticatedModuleGraphAdmission<T> {
    Native {
        preparation: T,
        evaluation: AuthenticatedModuleGraphEvaluation,
    },
    Legacy(StructuredEvaluationProgress),
}

/// Linear owner-thread guard for one admitted native module graph. It keeps the
/// exact structured work target active across Rust-owned linking, evaluation,
/// and TLA polling, then converts the native terminal record through the same
/// Stage-1 adapter used by ordinary authenticated evaluation.
pub struct AuthenticatedModuleGraphEvaluation {
    runtime: *mut HermesRuntimeOpaque,
    runtime_nonce: NonZeroU64,
    work_target_id: NonZeroU64,
    owner_thread: std::thread::ThreadId,
    pending: bool,
    suspended: bool,
}

impl AuthenticatedModuleGraphEvaluation {
    pub fn work_target_id(&self) -> NonZeroU64 {
        self.work_target_id
    }

    /// Publish a foreground TLA gap so callbacks and timers driven by the host
    /// become independently named work units.
    pub unsafe fn suspend(&mut self) -> Result<ModuleGraphSuspension, EngineFault> {
        if !self.pending || self.suspended {
            return Err(protocol(
                "native module graph cannot suspend from this state",
            ));
        }
        match unsafe {
            ex_hermes_structured_module_graph_suspend(self.runtime, self.work_target_id.get())
        } {
            0 => {
                self.suspended = true;
                Ok(ModuleGraphSuspension::Suspended)
            }
            1 => Ok(ModuleGraphSuspension::CancellationPending),
            _ => Err(protocol("native module graph suspension transition failed")),
        }
    }

    /// Re-enter the same exact foreground target immediately before advancing
    /// the native graph poll state.
    pub unsafe fn resume(&mut self) -> Result<(), EngineFault> {
        if !self.pending || !self.suspended {
            return Err(protocol(
                "native module graph cannot resume from this state",
            ));
        }
        let status = unsafe {
            ex_hermes_structured_module_graph_resume(self.runtime, self.work_target_id.get())
        };
        if status != 0 {
            return Err(protocol("native module graph resume transition failed"));
        }
        self.suspended = false;
        Ok(())
    }

    /// Finish the exact graph evaluation and materialize its structured result.
    ///
    /// # Safety
    ///
    /// The runtime passed to [`begin_authenticated_module_graph_stage1`] must
    /// still be live, unmoved, and owned by the current thread.
    pub unsafe fn finish(
        &mut self,
        outcome: ModuleGraphExecutionOutcome,
    ) -> Result<Stage1Evaluation, EngineFault> {
        if !self.pending {
            return Err(protocol("native module graph was already settled"));
        }
        if self.owner_thread != std::thread::current().id() {
            return Err(EngineFault::Structured(StructuredEngineFault::WrongThread));
        }
        let (runtime, runtime_nonce) = unsafe { live_runtime(self.runtime.cast())? };
        if runtime_nonce != self.runtime_nonce {
            return Err(EngineFault::Structured(StructuredEngineFault::StaleHandle));
        }
        let mut native_result = unsafe { NativeResultGuard::new(runtime, runtime_nonce)? };
        let status = unsafe {
            ex_hermes_structured_module_graph_finish(
                runtime,
                self.work_target_id.get(),
                outcome.abi_value(),
                outcome.error_token(),
                native_result.raw_mut(),
            )
        };
        if status == -1 {
            return Err(protocol(
                "native module graph evaluator rejected the result ABI layout",
            ));
        }
        if status != 0 {
            return Err(protocol(format!(
                "native module graph evaluator returned unknown status {status}"
            )));
        }

        // A successful native call has irreversibly retired the exact target,
        // even if the returned record later fails Rust-side validation. Clear
        // the Drop fallback only at this boundary; every preflight/ABI refusal
        // above leaves it armed for owner-thread cleanup.
        self.pending = false;
        if native_result.raw().work_target_id != self.work_target_id.get() {
            return Err(protocol(format!(
                "native module graph returned work target {}, expected {}",
                native_result.raw().work_target_id,
                self.work_target_id
            )));
        }
        let converted = unsafe { convert_result(native_result.raw(), runtime_nonce)? };
        if converted.transferred_handle {
            native_result.mark_handle_transferred();
        }
        unsafe { materialize_stage1(runtime.cast(), converted.evaluation) }
    }
}

impl Drop for AuthenticatedModuleGraphEvaluation {
    fn drop(&mut self) {
        if !self.pending
            || self.owner_thread != std::thread::current().id()
            || NonZeroU64::new(unsafe { ex_hermes_runtime_nonce(self.runtime.cast()) })
                != Some(self.runtime_nonce)
        {
            return;
        }
        if let Ok(mut result) = unsafe { NativeResultGuard::new(self.runtime, self.runtime_nonce) }
        {
            let _ = unsafe {
                ex_hermes_structured_module_graph_finish(
                    self.runtime,
                    self.work_target_id.get(),
                    ModuleGraphExecutionOutcome::EngineFault.abi_value(),
                    0,
                    result.raw_mut(),
                )
            };
        }
        self.pending = false;
    }
}

/// Admit one authenticated direct-file request, then synchronously select its
/// native or ordinary structured route. The preparer runs only after native
/// admission has consumed the request ordinal. A typed legacy decision keeps
/// that same admission and original request; a preparation refusal explicitly
/// settles the consumed ordinal before it is returned.
///
/// # Safety
///
/// `runtime` must satisfy the same lifetime and owner-thread requirements as
/// [`evaluate_authenticated_stage1`].
pub unsafe fn admit_prepare_authenticated_module_graph<T, F>(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    mut request: SourceRequest,
    prepare: F,
) -> Result<AuthenticatedModuleGraphAdmission<T>, EngineFault>
where
    F: FnOnce(&SourceRequest) -> Result<AuthenticatedModuleGraphPreparation<T>, EngineFault>,
{
    let valid_file_entry = matches!(
        &request,
        SourceRequest::Program(program) if program.is_main()
    ) && matches!(request.entry_kind(), EntryKind::File)
        && request.source_id().is_some();
    let file_arguments = request
        .file_arguments()
        .filter(|arguments| arguments.len() >= 2)
        .ok_or_else(|| {
            EngineFault::Rejected(Arc::from(
                "native module graph requires authenticated file arguments",
            ))
        })?
        .iter()
        .map(|argument| NativeUtf8Slice {
            data: argument.as_bytes().as_ptr(),
            length: argument.len(),
        })
        .collect::<Vec<_>>();
    if !valid_file_entry {
        return Err(EngineFault::Rejected(Arc::from(
            "native module graph requires an authenticated direct-file main entry",
        )));
    }

    let mut admission = unsafe { admit_authenticated_submission(runtime, session, &mut request)? };
    let preparation = match prepare(&request) {
        Ok(preparation) => preparation,
        Err(error) => {
            unsafe { admission.settle()? };
            let refusal = match error {
                EngineFault::Rejected(message) => EngineFault::Rejected(message),
                _ => EngineFault::Rejected(Arc::from(
                    "authenticated native module graph preparation was refused",
                )),
            };
            return Err(refusal);
        }
    };

    match preparation {
        AuthenticatedModuleGraphPreparation::Native(preparation) => {
            let fault = unsafe {
                ex_hermes_structured_module_graph_begin(
                    admission.runtime,
                    &admission.credential.native,
                    file_arguments.as_ptr(),
                    file_arguments.len(),
                )
            };
            if let Some(fault) = decode_fault(fault)? {
                return Err(EngineFault::Structured(fault));
            }
            admission.mark_continued();
            Ok(AuthenticatedModuleGraphAdmission::Native {
                preparation,
                evaluation: AuthenticatedModuleGraphEvaluation {
                    runtime: admission.runtime,
                    runtime_nonce: admission.runtime_nonce,
                    work_target_id: admission.work_target_id,
                    owner_thread: std::thread::current().id(),
                    pending: true,
                    suspended: false,
                },
            })
        }
        AuthenticatedModuleGraphPreparation::LegacyRequired => unsafe {
            evaluate_authenticated_inner_with_admission(request, None, None, admission)
                .map(AuthenticatedModuleGraphAdmission::Legacy)
        },
    }
}

/// Consume one authenticated direct-file request and enter the structured
/// native module-graph work unit before any graph factory executes.
///
/// # Safety
///
/// `runtime` must satisfy the same lifetime and owner-thread requirements as
/// [`evaluate_authenticated_stage1`].
pub unsafe fn begin_authenticated_module_graph_stage1(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    request: SourceRequest,
) -> Result<AuthenticatedModuleGraphEvaluation, EngineFault> {
    match unsafe {
        admit_prepare_authenticated_module_graph(runtime, session, request, |_| {
            Ok(AuthenticatedModuleGraphPreparation::Native(()))
        })?
    } {
        AuthenticatedModuleGraphAdmission::Native { evaluation, .. } => Ok(evaluation),
        AuthenticatedModuleGraphAdmission::Legacy(_) => Err(protocol(
            "native module graph unexpectedly selected legacy evaluation",
        )),
    }
}

/// Bind and admit the exact authenticated request before any parser or
/// lowering pass observes its text. Shape, immutable bytes, UTF-8, digest, and
/// credential validation have all completed at this point; a later syntax
/// failure is therefore a submitted evaluation and must consume its ordinal.
unsafe fn admit_authenticated_submission(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    request: &mut SourceRequest,
) -> Result<NativeAdmission, EngineFault> {
    let source_label = request.source_label().as_str();
    if source_label.is_empty() || source_label.as_bytes().contains(&0) {
        return Err(protocol("authenticated source label invariant failed"));
    }
    let credential = {
        let credential_view = request.native_credential_for(session).ok_or_else(|| {
            EngineFault::Rejected(Arc::from(
                "source request failed authenticated credential validation",
            ))
        })?;
        CredentialGuard::new(
            *credential_view.session_nonce(),
            *credential_view.request_binding(),
            credential_view.ordinal().get(),
        )
    };
    let (runtime, runtime_nonce) = unsafe { live_runtime(runtime)? };
    let bind_fault = unsafe {
        ex_hermes_structured_session_bind(
            runtime,
            credential.native.session_token.as_ptr(),
            credential.native.session_token.len(),
        )
    };
    if let Some(fault) = decode_fault(bind_fault)? {
        return Err(EngineFault::Structured(fault));
    }

    let mut work_target_id = 0;
    let admit_fault = unsafe {
        ex_hermes_structured_submission_admit(runtime, &credential.native, &mut work_target_id)
    };
    if let Some(fault) = decode_fault(admit_fault)? {
        return Err(EngineFault::Structured(fault));
    }
    let work_target_id = match NonZeroU64::new(work_target_id) {
        Some(work_target_id) => work_target_id,
        None => {
            let _ = unsafe { ex_hermes_structured_submission_settle(runtime, &credential.native) };
            return Err(protocol(
                "native submission admission omitted its work target",
            ));
        }
    };

    if let Err(error) = request.mark_native_accepted() {
        let settle_fault =
            unsafe { ex_hermes_structured_submission_settle(runtime, &credential.native) };
        let settle_detail = match decode_fault(settle_fault) {
            Ok(None) => String::new(),
            Ok(Some(fault)) => format!("; native settlement also failed: {fault}"),
            Err(fault) => format!("; native settlement also failed: {fault}"),
        };
        return Err(protocol(format!(
            "native accepted a source request which was not pending: {error}{settle_detail}"
        )));
    }

    Ok(NativeAdmission {
        runtime,
        runtime_nonce,
        credential,
        work_target_id,
        pending: true,
    })
}

/// Reauthenticate, bind, and consume one armed-session source request.
///
/// Together with [`consume_authenticated_json`], this is the only public
/// session-binding adapter: callers cannot obtain token bytes or bind a token
/// independently of a closed, authenticated [`SourceRequest`].
///
/// # Safety
///
/// `runtime` must point to a live `ExactHermesRuntime`, must remain live and
/// at the same address for the complete call, and this function must run on
/// that runtime's owner thread. The adapter validates the registry nonce and
/// native owner-thread refusal, but it cannot establish raw-pointer lifetime.
pub unsafe fn evaluate_authenticated(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    request: SourceRequest,
) -> Result<StructuredEvaluationProgress, EngineFault> {
    unsafe { evaluate_authenticated_inner(runtime, session, request, None, None) }
}

/// Evaluate one authenticated request under an exact additional principal
/// intersection. This exists only in conformance-observer builds and preserves
/// the ordinary authenticated admission and ordinal path.
///
/// # Safety
///
/// The runtime requirements are identical to [`evaluate_authenticated`].
#[cfg(feature = "capsec-conformance-observer")]
pub unsafe fn evaluate_authenticated_with_constrained_principals(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    request: SourceRequest,
    constrained_principals: &[u64],
) -> Result<StructuredEvaluationProgress, EngineFault> {
    if constrained_principals.is_empty()
        || constrained_principals.len() > 256
        || !constrained_principals
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(EngineFault::Rejected(Arc::from(
            "conformance principal constraints must be a nonempty canonical set",
        )));
    }
    unsafe {
        evaluate_authenticated_inner(
            runtime,
            session,
            request,
            None,
            Some(constrained_principals),
        )
    }
}

/// Evaluate one native-verified, single-original CommonJS representation while
/// consuming the credential bound to its authenticated raw file. Generated
/// bytes and metadata never replace the request's SourceId or principal.
///
/// # Safety
///
/// The runtime requirements are identical to [`evaluate_authenticated`].
pub unsafe fn evaluate_authenticated_generated(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    request: SourceRequest,
    generated_source: &[u8],
    generated_record: &[u8],
) -> Result<StructuredEvaluationProgress, EngineFault> {
    let parsed_record = serde_json::from_slice::<serde_json::Value>(generated_record).ok();
    let record = parsed_record
        .as_ref()
        .and_then(serde_json::Value::as_object);
    let request_source_id = request.source_id();
    let request_arguments = request.file_arguments().unwrap_or_default();
    let provenance_digest_valid = record
        .and_then(|record| record.get("provenanceDigest"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    let record_valid = record.is_some_and(|record| {
        record.len() == 6
            && record.get("schema").and_then(serde_json::Value::as_str)
                == Some("ibex/generated-single-commonjs-entry/1")
            && provenance_digest_valid
            && record
                .get("sourceId")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|candidate| {
                    request_source_id
                        .is_some_and(|source_id| source_id.authenticates_cache_key(candidate))
                })
            && record
                .get("sourceLabel")
                .and_then(serde_json::Value::as_str)
                == Some(request.source_label().as_str())
            && record
                .get("virtualPath")
                .and_then(serde_json::Value::as_str)
                == request_arguments.get(1).map(|argument| argument.as_ref())
            && record.get("definingPrincipal")
                == request_source_id
                    .and_then(crate::vfs::SourceId::defining_principal)
                    .and_then(|principal| serde_json::to_value(principal).ok())
                    .as_ref()
    });
    if std::str::from_utf8(generated_source).is_err()
        || generated_record.is_empty()
        || generated_record.len() > 1024 * 1024
        || !record_valid
    {
        return Err(EngineFault::Rejected(Arc::from(
            "generated CommonJS representation is malformed",
        )));
    }
    unsafe {
        evaluate_authenticated_inner(
            runtime,
            session,
            request,
            Some((generated_source, generated_record)),
            None,
        )
    }
}

unsafe fn evaluate_authenticated_inner(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    mut request: SourceRequest,
    generated: Option<(&[u8], &[u8])>,
    constrained_principals: Option<&[u64]>,
) -> Result<StructuredEvaluationProgress, EngineFault> {
    if matches!(&request, SourceRequest::JsonData(_)) {
        return Err(EngineFault::Rejected(Arc::from(
            "JSON-data source requests are parsed, not evaluated",
        )));
    }
    let common_js_entry = matches!(
        &request,
        SourceRequest::Program(program)
            if program.module_kind() == Some(ModuleKind::CommonJs)
    );
    if generated.is_some() && !common_js_entry {
        return Err(EngineFault::Rejected(Arc::from(
            "generated source requires an authenticated CommonJS file entry",
        )));
    }
    if common_js_entry
        && (!matches!(request.entry_kind(), EntryKind::File)
            || request.source_id().is_none()
            || !matches!(&request, SourceRequest::Program(program) if program.is_main()))
    {
        return Err(EngineFault::Rejected(Arc::from(
            "CommonJS source requires an authenticated direct-file main entry",
        )));
    }
    let admission = unsafe { admit_authenticated_submission(runtime, session, &mut request)? };
    unsafe {
        evaluate_authenticated_inner_with_admission(
            request,
            generated,
            constrained_principals,
            admission,
        )
    }
}

/// Continue an already-consumed native admission through the ordinary
/// authenticated evaluator. This is private so no caller can detach an
/// admission from its original request or manufacture a second ordinal.
unsafe fn evaluate_authenticated_inner_with_admission(
    request: SourceRequest,
    generated: Option<(&[u8], &[u8])>,
    constrained_principals: Option<&[u64]>,
    mut admission: NativeAdmission,
) -> Result<StructuredEvaluationProgress, EngineFault> {
    let common_js_entry = matches!(
        &request,
        SourceRequest::Program(program)
            if program.module_kind() == Some(ModuleKind::CommonJs)
    );
    let source_label = request.source_label().as_str().as_bytes();
    let logical_referrer = capsec_semantics::canonical::to_jcs_bytes(
        &serde_json::to_value(request.virtual_referrer())
            .map_err(|error| protocol(format!("cannot serialize logical referrer: {error}")))?,
    )
    .map_err(|error| protocol(format!("cannot canonicalize logical referrer: {error}")))?;
    let lowered = if common_js_entry {
        None
    } else {
        let lowered = match &request {
            SourceRequest::Program(program) => lower_program(
                program,
                request.text().as_str(),
                request.source_label().as_str(),
            )
            .map_err(|error| EngineFault::Rejected(Arc::from(error.to_string()))),
            SourceRequest::JsonData(_) => unreachable!("JSON requests returned above"),
        };
        match lowered {
            Ok(lowered) => Some(lowered),
            Err(error) => {
                unsafe { admission.settle()? };
                return Err(error);
            }
        }
    };
    let declarations = lowered.as_ref().map_or_else(Vec::new, |lowered| {
        lowered
            .declarations()
            .iter()
            .map(|declaration| NativeSessionDeclaration {
                name: declaration.name.as_bytes().as_ptr(),
                name_length: declaration.name.len(),
                kind: match declaration.kind {
                    LoweredDeclarationKind::Var => 1,
                    LoweredDeclarationKind::Function => 2,
                    LoweredDeclarationKind::Let => 3,
                    LoweredDeclarationKind::Const => 4,
                    LoweredDeclarationKind::Class => 5,
                    LoweredDeclarationKind::Import => 6,
                },
                reserved: 0,
            })
            .collect::<Vec<_>>()
    });
    let mut import_bindings = Vec::new();
    let mut static_imports = Vec::with_capacity(
        lowered
            .as_ref()
            .map_or(0, |lowered| lowered.static_imports().len()),
    );
    if let Some(lowered) = lowered.as_ref() {
        for import in lowered.static_imports() {
            let first_binding = import_bindings.len();
            import_bindings.extend(import.bindings.iter().map(|binding| {
                let (local_name, local_name_length) =
                    binding.local.as_ref().map_or((ptr::null(), 0), |name| {
                        (name.as_bytes().as_ptr(), name.len())
                    });
                let (imported_name, imported_name_length) =
                    binding.imported.as_ref().map_or((ptr::null(), 0), |name| {
                        (name.as_bytes().as_ptr(), name.len())
                    });
                NativeSessionImportBinding {
                    abi_version: IMPORT_PLAN_ABI_VERSION,
                    struct_size: size_of::<NativeSessionImportBinding>() as u32,
                    local_name,
                    local_name_length,
                    imported_name,
                    imported_name_length,
                    kind: match binding.kind {
                        LoweredStaticImportBindingKind::Default => 1,
                        LoweredStaticImportBindingKind::Named => 2,
                        LoweredStaticImportBindingKind::Namespace => 3,
                    },
                    reserved: 0,
                }
            }));
            static_imports.push(NativeSessionStaticImport {
                abi_version: IMPORT_PLAN_ABI_VERSION,
                struct_size: size_of::<NativeSessionStaticImport>() as u32,
                specifier: import.specifier.as_bytes().as_ptr(),
                specifier_length: import.specifier.len(),
                first_binding,
                binding_count: import.bindings.len(),
            });
        }
    }
    let file_arguments = request
        .file_arguments()
        .unwrap_or_default()
        .iter()
        .map(|argument| NativeUtf8Slice {
            data: argument.as_bytes().as_ptr(),
            length: argument.len(),
        })
        .collect::<Vec<_>>();
    let source_id = request.source_id().map(crate::vfs::SourceId::cache_key);
    let import_plan = NativeSessionImportPlan {
        abi_version: IMPORT_PLAN_ABI_VERSION,
        struct_size: size_of::<NativeSessionImportPlan>() as u32,
        logical_referrer: logical_referrer.as_ptr(),
        logical_referrer_length: logical_referrer.len(),
        imports: if static_imports.is_empty() {
            ptr::null()
        } else {
            static_imports.as_ptr()
        },
        import_count: static_imports.len(),
        bindings: if import_bindings.is_empty() {
            ptr::null()
        } else {
            import_bindings.as_ptr()
        },
        binding_count: import_bindings.len(),
        file_arguments: if file_arguments.is_empty() {
            ptr::null()
        } else {
            file_arguments.as_ptr()
        },
        file_argument_count: file_arguments.len(),
        source_id: source_id
            .as_ref()
            .map_or(ptr::null(), |source_id| source_id.as_bytes().as_ptr()),
        source_id_length: source_id.as_ref().map_or(0, String::len),
        generated_entry_record: generated.map_or(ptr::null(), |(_, record)| record.as_ptr()),
        generated_entry_record_length: generated.map_or(0, |(_, record)| record.len()),
        source_kind: if generated.is_some() {
            STRUCTURED_SOURCE_GENERATED_COMMONJS_ENTRY
        } else if common_js_entry {
            STRUCTURED_SOURCE_COMMONJS_ENTRY
        } else {
            STRUCTURED_SOURCE_SESSION
        },
        reserved: 0,
    };

    let mut native_result =
        unsafe { NativeResultGuard::new(admission.runtime, admission.runtime_nonce)? };
    let (native_source, native_source_map, asynchronous) = if let Some((source, _)) = generated {
        (source, &[][..], false)
    } else if let Some(lowered) = lowered.as_ref() {
        (
            lowered.source().as_bytes(),
            lowered.source_map(),
            lowered.is_asynchronous(),
        )
    } else {
        (request.text().as_bytes(), &[][..], false)
    };
    let status = unsafe {
        #[cfg(feature = "capsec-conformance-observer")]
        let evaluate = constrained_principals.map(|principals| {
            ibex_private_test_eval_lowered_session_with_principals(
                admission.runtime,
                principals.as_ptr(),
                principals.len(),
                &admission.credential.native,
                SESSION_LOWERING_PROTOCOL_VERSION,
                native_source.as_ptr(),
                native_source.len(),
                native_source_map.as_ptr(),
                native_source_map.len(),
                source_label.as_ptr(),
                source_label.len(),
                declarations.as_ptr(),
                declarations.len(),
                &import_plan,
                asynchronous,
                native_result.raw_mut(),
            )
        });
        #[cfg(not(feature = "capsec-conformance-observer"))]
        let evaluate: Option<i32> = {
            debug_assert!(constrained_principals.is_none());
            None
        };
        evaluate.unwrap_or_else(|| {
            ex_hermes_eval_lowered_session(
                admission.runtime,
                &admission.credential.native,
                SESSION_LOWERING_PROTOCOL_VERSION,
                native_source.as_ptr(),
                native_source.len(),
                native_source_map.as_ptr(),
                native_source_map.len(),
                source_label.as_ptr(),
                source_label.len(),
                declarations.as_ptr(),
                declarations.len(),
                &import_plan,
                asynchronous,
                native_result.raw_mut(),
            )
        })
    };
    if status == -1 {
        return Err(protocol(
            "native structured evaluator rejected the result ABI layout",
        ));
    }
    if status != 0 {
        return Err(protocol(format!(
            "native structured evaluator returned unknown status {status}"
        )));
    }

    if native_result.raw().work_target_id != admission.work_target_id.get() {
        return Err(protocol(format!(
            "native lowered continuation returned work target {}, expected {}",
            native_result.raw().work_target_id,
            admission.work_target_id
        )));
    }
    admission.mark_continued();

    let nonce_after = NonZeroU64::new(unsafe { ex_hermes_runtime_nonce(admission.runtime.cast()) })
        .ok_or_else(|| protocol("Hermes runtime stopped during structured evaluation"))?;
    if nonce_after != admission.runtime_nonce {
        return Err(protocol(
            "Hermes runtime identity changed during structured evaluation",
        ));
    }

    let converted = unsafe { convert_progress(native_result.raw(), admission.runtime_nonce)? };
    if converted.transferred_handle {
        native_result.mark_handle_transferred();
    }
    Ok(converted.progress)
}

/// Poll the nonblocking native settlement state for one exact suspended
/// top-level-await unit. The host is responsible for driving ready engine work
/// between calls; this adapter only authenticates the linear receipt and
/// converts the resulting progress/terminal record.
///
/// # Safety
///
/// The runtime requirements are identical to [`evaluate_authenticated`].
pub unsafe fn resume_authenticated(
    runtime: *mut c_void,
    suspension: StructuredSuspension,
) -> Result<StructuredEvaluationProgress, EngineFault> {
    if suspension.owner_thread != std::thread::current().id() {
        return Err(EngineFault::Structured(StructuredEngineFault::WrongThread));
    }
    let (runtime, runtime_nonce) = unsafe { live_runtime(runtime)? };
    if runtime_nonce != suspension.runtime_nonce {
        return Err(EngineFault::Structured(StructuredEngineFault::StaleHandle));
    }

    let mut native_result = unsafe { NativeResultGuard::new(runtime, runtime_nonce)? };
    let status = unsafe {
        ex_hermes_resume_structured_session(
            runtime,
            suspension.work_target_id.get(),
            native_result.raw_mut(),
        )
    };
    if status == -1 {
        return Err(protocol(
            "native structured continuation rejected the result ABI layout",
        ));
    }
    if status != 0 {
        return Err(protocol(format!(
            "native structured continuation returned unknown status {status}"
        )));
    }
    if native_result.raw().work_target_id != suspension.work_target_id.get() {
        return Err(protocol(format!(
            "native structured continuation returned work target {}, expected {}",
            native_result.raw().work_target_id,
            suspension.work_target_id
        )));
    }

    let converted = unsafe { convert_progress(native_result.raw(), runtime_nonce)? };
    if converted.transferred_handle {
        native_result.mark_handle_transferred();
    }
    Ok(converted.progress)
}

/// Evaluate and fully materialize the Stage-1 result while the runtime and its
/// rooted handles remain on the owner thread. Throw handles are released
/// immediately; a successful value returns a linear receipt which the broker
/// must settle after choosing Displayed, fallback, or write-failed.
///
/// # Safety
///
/// The runtime requirements are identical to [`evaluate_authenticated`].
pub unsafe fn evaluate_authenticated_stage1(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    request: SourceRequest,
) -> Result<Stage1EvaluationProgress, EngineFault> {
    match unsafe { evaluate_authenticated(runtime, session, request)? } {
        StructuredEvaluationProgress::Settled(evaluation) => unsafe {
            materialize_stage1(runtime, evaluation).map(Stage1EvaluationProgress::Settled)
        },
        StructuredEvaluationProgress::Suspended(suspension) => {
            Ok(Stage1EvaluationProgress::Suspended(suspension))
        }
    }
}

/// Stage-1 form of
/// [`evaluate_authenticated_with_constrained_principals`].
///
/// # Safety
///
/// The runtime requirements are identical to [`evaluate_authenticated`].
#[cfg(feature = "capsec-conformance-observer")]
pub unsafe fn evaluate_authenticated_stage1_with_constrained_principals(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    request: SourceRequest,
    constrained_principals: &[u64],
) -> Result<Stage1EvaluationProgress, EngineFault> {
    match unsafe {
        evaluate_authenticated_with_constrained_principals(
            runtime,
            session,
            request,
            constrained_principals,
        )?
    } {
        StructuredEvaluationProgress::Settled(evaluation) => unsafe {
            materialize_stage1(runtime, evaluation).map(Stage1EvaluationProgress::Settled)
        },
        StructuredEvaluationProgress::Suspended(suspension) => {
            Ok(Stage1EvaluationProgress::Suspended(suspension))
        }
    }
}

/// Materialize an already-admitted structured progress record into Stage 1.
/// This is used by the module-graph admission seam when a typed preparation
/// decision continues through the bounded legacy evaluator on the same native
/// admission and ordinal.
///
/// # Safety
///
/// The runtime requirements are identical to [`evaluate_authenticated`].
pub unsafe fn materialize_authenticated_progress_stage1(
    runtime: *mut c_void,
    progress: StructuredEvaluationProgress,
) -> Result<Stage1EvaluationProgress, EngineFault> {
    match progress {
        StructuredEvaluationProgress::Settled(evaluation) => unsafe {
            materialize_stage1(runtime, evaluation).map(Stage1EvaluationProgress::Settled)
        },
        StructuredEvaluationProgress::Suspended(suspension) => {
            Ok(Stage1EvaluationProgress::Suspended(suspension))
        }
    }
}

/// Stage-1 adapter for a verified single-original generated CommonJS entry.
///
/// # Safety
///
/// The runtime requirements are identical to [`evaluate_authenticated`].
pub unsafe fn evaluate_authenticated_generated_stage1(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    request: SourceRequest,
    generated_source: &[u8],
    generated_record: &[u8],
) -> Result<Stage1EvaluationProgress, EngineFault> {
    match unsafe {
        evaluate_authenticated_generated(
            runtime,
            session,
            request,
            generated_source,
            generated_record,
        )?
    } {
        StructuredEvaluationProgress::Settled(evaluation) => unsafe {
            materialize_stage1(runtime, evaluation).map(Stage1EvaluationProgress::Settled)
        },
        StructuredEvaluationProgress::Suspended(suspension) => {
            Ok(Stage1EvaluationProgress::Suspended(suspension))
        }
    }
}

/// Resume one suspended top-level-await unit and materialize Stage 1 only once
/// it has a terminal result.
///
/// # Safety
///
/// The runtime requirements are identical to [`evaluate_authenticated`].
pub unsafe fn resume_authenticated_stage1(
    runtime: *mut c_void,
    suspension: StructuredSuspension,
) -> Result<Stage1EvaluationProgress, EngineFault> {
    match unsafe { resume_authenticated(runtime, suspension)? } {
        StructuredEvaluationProgress::Settled(evaluation) => unsafe {
            materialize_stage1(runtime, evaluation).map(Stage1EvaluationProgress::Settled)
        },
        StructuredEvaluationProgress::Suspended(suspension) => {
            Ok(Stage1EvaluationProgress::Suspended(suspension))
        }
    }
}

unsafe fn materialize_stage1(
    runtime: *mut c_void,
    evaluation: StructuredEvaluation,
) -> Result<Stage1Evaluation, EngineFault> {
    let work_target = evaluation.work_target;
    let outcome = match evaluation.result? {
        EvaluationOutcome::Empty => Stage1EvaluationOutcome::Empty,
        EvaluationOutcome::Value(handle) => {
            let work_target = work_target
                .ok_or_else(|| protocol("value outcome omitted its display work target"))?;
            let display = unsafe { render_value_stage1(runtime, &handle) };
            match display {
                Ok(display) => Stage1EvaluationOutcome::Value {
                    display,
                    receipt: Stage1DisplayReceipt {
                        runtime_nonce: handle.runtime_nonce(),
                        work_target_id: work_target.id,
                        handle_id: handle.handle_id(),
                        owner_thread: std::thread::current().id(),
                    },
                },
                Err(error) => {
                    let native_runtime = unsafe { runtime_for_handle(runtime, &handle)? };
                    let _ = unsafe {
                        ex_hermes_session_display_ack(
                            native_runtime,
                            work_target.id.get(),
                            native_handle(&handle),
                            false,
                        )
                    };
                    return Err(error);
                }
            }
        }
        EvaluationOutcome::Throw { value, metadata } => Stage1EvaluationOutcome::Throw {
            value: unsafe { render_and_release(runtime, value)? },
            metadata,
        },
        EvaluationOutcome::Cancelled => Stage1EvaluationOutcome::Cancelled,
        EvaluationOutcome::Lifecycle { exit_code } => {
            Stage1EvaluationOutcome::Lifecycle { exit_code }
        }
    };
    Ok(Stage1Evaluation {
        work_target,
        capabilities: evaluation.capabilities,
        outcome,
    })
}

/// Parse one authenticated JSON-data request entirely in Rust after native
/// admission. Admission precedes JSON parsing, so invalid JSON consumes the
/// submitted ordinal while remaining non-executable.
///
/// # Safety
///
/// The runtime requirements are identical to [`evaluate_authenticated`].
pub unsafe fn consume_authenticated_json(
    runtime: *mut c_void,
    session: &ArmedSessionToken,
    mut request: SourceRequest,
) -> Result<Arc<str>, EngineFault> {
    if !matches!(&request, SourceRequest::JsonData(_)) {
        return Err(EngineFault::Rejected(Arc::from(
            "program source cannot enter the Rust JSON-data consumer",
        )));
    }
    let mut admission = unsafe { admit_authenticated_submission(runtime, session, &mut request)? };
    let value: serde_json::Value = match serde_json::from_str(request.text().as_str()) {
        Ok(value) => value,
        Err(error) => {
            unsafe { admission.settle()? };
            return Err(EngineFault::Rejected(Arc::from(format!(
                "invalid JSON data: {error}"
            ))));
        }
    };
    let rendered = match serde_json::to_string_pretty(&value) {
        Ok(rendered) => rendered,
        Err(error) => {
            unsafe { admission.settle()? };
            return Err(protocol(format!(
                "failed to render parsed JSON data: {error}"
            )));
        }
    };
    unsafe { admission.settle()? };
    Ok(Arc::from(rendered))
}

/// Return the top-level kind of a rooted value without invoking JavaScript.
///
/// # Safety
///
/// `runtime` must be the live owner-thread runtime which minted `handle`, and
/// must remain live for the complete call.
pub unsafe fn value_kind(
    runtime: *mut c_void,
    handle: &ValueHandle,
) -> Result<ValueKind, EngineFault> {
    let runtime = unsafe { runtime_for_handle(runtime, handle)? };
    let native = native_handle(handle);
    match unsafe { ex_hermes_value_kind(runtime, native) } {
        VALUE_UNDEFINED => Ok(ValueKind::Undefined),
        VALUE_NULL => Ok(ValueKind::Null),
        VALUE_BOOLEAN => Ok(ValueKind::Boolean),
        VALUE_NUMBER => Ok(ValueKind::Number),
        VALUE_STRING => Ok(ValueKind::String),
        VALUE_SYMBOL => Ok(ValueKind::Symbol),
        VALUE_BIGINT => Ok(ValueKind::BigInt),
        VALUE_FUNCTION => Ok(ValueKind::Function),
        VALUE_OBJECT => Ok(ValueKind::Object),
        VALUE_ARRAY => Ok(ValueKind::Array),
        VALUE_INVALID => Err(EngineFault::Structured(StructuredEngineFault::StaleHandle)),
        other => Err(protocol(format!(
            "native value-kind query returned unknown kind {other}"
        ))),
    }
}

/// Render one rooted value at Stage 1 without releasing it.
///
/// # Safety
///
/// `runtime` must be the live owner runtime for `handle`.
pub unsafe fn render_value_stage1(
    runtime: *mut c_void,
    handle: &ValueHandle,
) -> Result<Stage1Display, EngineFault> {
    let kind = unsafe { value_kind(runtime, handle)? };
    let (text, truncated) = match kind {
        ValueKind::Function => (Arc::from("[Function]"), false),
        ValueKind::Array => (Arc::from("[Array]"), false),
        ValueKind::Object => (Arc::from("[Object]"), false),
        _ => {
            let native_runtime = unsafe { runtime_for_handle(runtime, handle)? };
            let mut data = ptr::null_mut();
            let mut length = 0usize;
            let mut truncated = 0u32;
            let fault = unsafe {
                ex_hermes_value_stage1_text(
                    native_runtime,
                    native_handle(handle),
                    &mut data,
                    &mut length,
                    &mut truncated,
                )
            };
            if let Some(fault) = decode_fault(fault)? {
                return Err(EngineFault::Structured(fault));
            }
            let truncated = match truncated {
                0 => false,
                1 => true,
                other => {
                    unsafe { ex_hermes_free_string(data.cast()) };
                    return Err(protocol(format!(
                        "native Stage-1 renderer returned invalid truncation flag {other}"
                    )));
                }
            };
            if data.is_null() {
                return Err(protocol(
                    "native primitive Stage-1 renderer omitted its byte payload",
                ));
            }
            if length > SAFE_TEXT_MAX_BYTES {
                unsafe { ex_hermes_free_string(data.cast()) };
                return Err(protocol(format!(
                    "native Stage-1 renderer exceeded the {SAFE_TEXT_MAX_BYTES}-byte bound"
                )));
            }
            let bytes = unsafe { std::slice::from_raw_parts(data, length) };
            let decoded = std::str::from_utf8(bytes)
                .map(str::to_owned)
                .map_err(|_| protocol("native Stage-1 renderer returned invalid UTF-8"));
            unsafe { ex_hermes_free_string(data.cast()) };
            let mut decoded = decoded?;
            if truncated {
                let Some(prefix) = decoded.strip_suffix(SAFE_TEXT_TRUNCATION_MARKER) else {
                    return Err(protocol(
                        "truncated native Stage-1 text omitted its trusted marker",
                    ));
                };
                decoded.truncate(prefix.len());
            }
            if kind == ValueKind::String {
                decoded = serde_json::to_string(&decoded)
                    .map_err(|error| protocol(format!("failed to quote string: {error}")))?;
            } else if kind == ValueKind::BigInt {
                if decoded.is_empty() && truncated {
                    decoded.push_str("[BigInt]");
                } else {
                    decoded.push('n');
                }
            }
            (Arc::from(decoded), truncated)
        }
    };
    Ok(Stage1Display {
        kind,
        text,
        truncated,
    })
}

/// Settle one exact Stage-1 receipt. `displayed=true` is the only disposition
/// which updates native `$_`; every disposition releases the rooted handle.
///
/// # Safety
///
/// `runtime` must still be the live owner runtime which produced `receipt`.
pub unsafe fn acknowledge_stage1_display(
    runtime: *mut c_void,
    receipt: Stage1DisplayReceipt,
    displayed: bool,
) -> Result<(), EngineFault> {
    if receipt.owner_thread != std::thread::current().id() {
        return Err(EngineFault::Structured(StructuredEngineFault::WrongThread));
    }
    let (native_runtime, runtime_nonce) = unsafe { live_runtime(runtime)? };
    if runtime_nonce != receipt.runtime_nonce {
        return Err(EngineFault::Structured(StructuredEngineFault::StaleHandle));
    }
    let fault = unsafe {
        ex_hermes_session_display_ack(
            native_runtime,
            receipt.work_target_id.get(),
            NativeValueHandle {
                runtime_nonce: receipt.runtime_nonce.get(),
                handle_id: receipt.handle_id.get(),
            },
            displayed,
        )
    };
    match decode_fault(fault)? {
        None => Ok(()),
        Some(fault) => Err(EngineFault::Structured(fault)),
    }
}

unsafe fn render_and_release(
    runtime: *mut c_void,
    handle: ValueHandle,
) -> Result<Stage1Display, EngineFault> {
    let rendered = unsafe { render_value_stage1(runtime, &handle) };
    let released = unsafe { release_value(runtime, handle) };
    match (rendered, released) {
        (Ok(rendered), Ok(())) => Ok(rendered),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

/// Materialize and release a native async-failure value handle while the
/// caller owns the live runtime thread. The raw numeric pair is accepted only
/// at this private ABI bridge; it is immediately reconstituted as the same
/// linear `ValueHandle` used by structured evaluation and never crosses IPC.
/// @ref LLP 0024#9-asynchronous-failures
///
/// # Safety
///
/// `runtime` must be the live owner-thread runtime that minted the handle.
#[doc(hidden)]
pub unsafe fn render_and_release_async_failure_value(
    runtime: *mut c_void,
    runtime_nonce: u64,
    handle_id: u64,
) -> Result<(Stage1Display, ThrowMetadata), EngineFault> {
    let (native_runtime, live_nonce) = unsafe { live_runtime(runtime)? };
    let handle = decode_handle(
        NativeValueHandle {
            runtime_nonce,
            handle_id,
        },
        live_nonce,
    )?;
    let mut metadata_fields = 0u32;
    let mut error_class = ERROR_CLASS_UNCLASSIFIED;
    let mut message = NativeOwnedBytes::EMPTY;
    let mut stack = NativeOwnedBytes::EMPTY;
    let metadata_fault = unsafe {
        ex_hermes_value_safe_throw_metadata(
            native_runtime,
            native_handle(&handle),
            &mut metadata_fields,
            &mut error_class,
            &mut message,
            &mut stack,
        )
    };
    let metadata = match decode_fault(metadata_fault) {
        Ok(None) => {
            let decoded = (|| unsafe {
                validate_throw_metadata_fields(metadata_fields)?;
                let message_truncated = metadata_fields & THROW_FIELD_MESSAGE_TRUNCATED != 0;
                let stack_truncated = metadata_fields & THROW_FIELD_STACK_TRUNCATED != 0;
                Ok(ThrowMetadata::Captured {
                    error_class: decode_error_class(error_class)?,
                    message: decode_optional_utf8(
                        message,
                        metadata_fields & THROW_FIELD_MESSAGE != 0,
                        message_truncated,
                        "message",
                        SAFE_TEXT_MAX_BYTES,
                    )?,
                    message_truncated,
                    stack: decode_optional_utf8(
                        stack,
                        metadata_fields & THROW_FIELD_STACK != 0,
                        stack_truncated,
                        "stack",
                        SAFE_TEXT_MAX_BYTES,
                    )?,
                    stack_truncated,
                    positions: Vec::new(),
                })
            })();
            unsafe {
                ex_hermes_free_string(message.data.cast());
                ex_hermes_free_string(stack.data.cast());
            }
            decoded
        }
        Ok(Some(fault)) => Err(EngineFault::Structured(fault)),
        Err(error) => Err(error),
    };
    let rendered = unsafe { render_and_release(runtime, handle) };
    match (rendered, metadata) {
        (Ok(display), Ok(metadata)) => Ok((display, metadata)),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

/// Release a rooted native value on its owner runtime and thread.
///
/// Consuming the Rust handle prevents a successful release from being repeated
/// through this safe type. Native stale/wrong-thread refusals remain exact.
///
/// # Safety
///
/// `runtime` must be the live owner-thread runtime which minted `handle`, and
/// must remain live for the complete call.
pub unsafe fn release_value(runtime: *mut c_void, handle: ValueHandle) -> Result<(), EngineFault> {
    let runtime = unsafe { runtime_for_handle(runtime, &handle)? };
    let code = unsafe { ex_hermes_value_release(runtime, native_handle(&handle)) };
    match decode_fault(code)? {
        None => Ok(()),
        Some(fault) => Err(EngineFault::Structured(fault)),
    }
}

struct CredentialGuard {
    native: NativeSessionCredential,
}

impl CredentialGuard {
    fn new(session_token: [u8; 32], request_binding: [u8; 32], ordinal: u64) -> Self {
        Self {
            native: NativeSessionCredential {
                abi_version: ABI_VERSION,
                struct_size: size_of::<NativeSessionCredential>() as u32,
                session_token,
                request_binding,
                ordinal,
            },
        }
    }
}

impl Drop for CredentialGuard {
    fn drop(&mut self) {
        for byte in self
            .native
            .session_token
            .iter_mut()
            .chain(self.native.request_binding.iter_mut())
        {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        unsafe { ptr::write_volatile(&mut self.native.ordinal, 0) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Owner-thread guard for the exact native admission ticket. Until the
/// lowered evaluator consumes it, every early Rust return explicitly settles
/// the native pending state without rolling back the already-consumed ordinal.
struct NativeAdmission {
    runtime: *mut HermesRuntimeOpaque,
    runtime_nonce: NonZeroU64,
    credential: CredentialGuard,
    work_target_id: NonZeroU64,
    pending: bool,
}

impl NativeAdmission {
    unsafe fn settle(&mut self) -> Result<(), EngineFault> {
        if !self.pending {
            return Err(protocol("native submission admission was already settled"));
        }
        let fault = unsafe {
            ex_hermes_structured_submission_settle(self.runtime, &self.credential.native)
        };
        match decode_fault(fault)? {
            None => {
                self.pending = false;
                Ok(())
            }
            Some(fault) => Err(EngineFault::Structured(fault)),
        }
    }

    fn mark_continued(&mut self) {
        self.pending = false;
    }
}

impl Drop for NativeAdmission {
    fn drop(&mut self) {
        if self.pending
            && NonZeroU64::new(unsafe { ex_hermes_runtime_nonce(self.runtime.cast()) })
                == Some(self.runtime_nonce)
        {
            let _ = unsafe {
                ex_hermes_structured_submission_settle(self.runtime, &self.credential.native)
            };
        }
    }
}

struct NativeResultGuard {
    runtime: *mut HermesRuntimeOpaque,
    runtime_nonce: NonZeroU64,
    raw: NativeEvaluationResult,
    handle_transferred: bool,
}

impl NativeResultGuard {
    unsafe fn new(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: NonZeroU64,
    ) -> Result<Self, EngineFault> {
        let mut guard = Self {
            runtime,
            runtime_nonce,
            raw: NativeEvaluationResult::empty(),
            handle_transferred: false,
        };
        unsafe { ex_hermes_evaluation_result_init(&mut guard.raw) };
        validate_result_layout(&guard.raw)?;
        Ok(guard)
    }

    fn raw(&self) -> &NativeEvaluationResult {
        &self.raw
    }

    fn raw_mut(&mut self) -> *mut NativeEvaluationResult {
        &mut self.raw
    }

    fn mark_handle_transferred(&mut self) {
        self.handle_transferred = true;
    }
}

impl Drop for NativeResultGuard {
    fn drop(&mut self) {
        if !self.handle_transferred
            && self.raw.value.runtime_nonce != 0
            && self.raw.value.handle_id != 0
            && NonZeroU64::new(unsafe { ex_hermes_runtime_nonce(self.runtime.cast()) })
                == Some(self.runtime_nonce)
        {
            let _ = unsafe { ex_hermes_value_release(self.runtime, self.raw.value) };
        }
        unsafe { ex_hermes_evaluation_result_dispose(&mut self.raw) };
    }
}

struct ConvertedEvaluation {
    evaluation: StructuredEvaluation,
    transferred_handle: bool,
}

struct ConvertedProgress {
    progress: StructuredEvaluationProgress,
    transferred_handle: bool,
}

unsafe fn convert_progress(
    raw: &NativeEvaluationResult,
    runtime_nonce: NonZeroU64,
) -> Result<ConvertedProgress, EngineFault> {
    if raw.outcome_tag == CONTINUATION_SUSPENDED {
        validate_result_layout(raw)?;
        if raw.fault != FAULT_NONE {
            return Err(protocol(
                "suspended structured continuation carried a native fault",
            ));
        }
        validate_handle_absent(raw)?;
        validate_metadata_absent(raw)?;
        validate_lifecycle_absent(raw)?;
        let capabilities = decode_capabilities(raw.capability_flags)?;
        if !capabilities.base {
            return Err(protocol(
                "suspended armed continuation omitted the required Base capability",
            ));
        }
        let work_target_id = NonZeroU64::new(raw.work_target_id)
            .ok_or_else(|| protocol("suspended continuation omitted its work target"))?;
        return Ok(ConvertedProgress {
            progress: StructuredEvaluationProgress::Suspended(StructuredSuspension {
                runtime_nonce,
                work_target_id,
                owner_thread: std::thread::current().id(),
            }),
            transferred_handle: false,
        });
    }

    let converted = unsafe { convert_result(raw, runtime_nonce)? };
    Ok(ConvertedProgress {
        progress: StructuredEvaluationProgress::Settled(converted.evaluation),
        transferred_handle: converted.transferred_handle,
    })
}

unsafe fn convert_result(
    raw: &NativeEvaluationResult,
    runtime_nonce: NonZeroU64,
) -> Result<ConvertedEvaluation, EngineFault> {
    validate_result_layout(raw)?;
    let capabilities = decode_capabilities(raw.capability_flags)?;
    let work_target = NonZeroU64::new(raw.work_target_id).map(|id| WorkTarget {
        id,
        kind: WorkKind::Evaluation,
    });

    if raw.outcome_tag == OUTCOME_ENGINE_FAULT {
        validate_engine_fault_shape(raw, &capabilities)?;
        let fault = decode_fault(raw.fault)?
            .ok_or_else(|| protocol("engine-fault outcome carried the no-fault code"))?;
        return Ok(ConvertedEvaluation {
            evaluation: StructuredEvaluation {
                work_target,
                capabilities,
                result: Err(EngineFault::Structured(fault)),
            },
            transferred_handle: false,
        });
    }

    if raw.fault != FAULT_NONE {
        return Err(protocol(
            "successful structured outcome carried a native fault code",
        ));
    }
    if work_target.is_none() {
        return Err(protocol(
            "successful structured outcome omitted its evaluation work target",
        ));
    }
    if !capabilities.base {
        return Err(protocol(
            "successful armed-session outcome omitted the required Base capability",
        ));
    }

    let (outcome, transferred_handle) = match raw.outcome_tag {
        OUTCOME_EMPTY => {
            validate_handle_absent(raw)?;
            validate_metadata_absent(raw)?;
            validate_lifecycle_absent(raw)?;
            (EvaluationOutcome::Empty, false)
        }
        OUTCOME_VALUE => {
            validate_metadata_absent(raw)?;
            validate_lifecycle_absent(raw)?;
            (
                EvaluationOutcome::Value(decode_handle(raw.value, runtime_nonce)?),
                true,
            )
        }
        OUTCOME_THROW => {
            validate_lifecycle_absent(raw)?;
            let value = decode_handle(raw.value, runtime_nonce)?;
            let metadata = unsafe { decode_throw_metadata(raw)? };
            if capabilities.safe_throw != matches!(&metadata, ThrowMetadata::Captured { .. }) {
                return Err(protocol(
                    "throw metadata status disagreed with the advertised SafeThrow capability",
                ));
            }
            if !capabilities.source_positions
                && matches!(
                    &metadata,
                    ThrowMetadata::Captured { positions, .. } if !positions.is_empty()
                )
            {
                return Err(protocol(
                    "throw carried source positions without advertising SourcePositions",
                ));
            }
            (EvaluationOutcome::Throw { value, metadata }, true)
        }
        OUTCOME_CANCELLED => {
            validate_handle_absent(raw)?;
            validate_metadata_absent(raw)?;
            validate_lifecycle_absent(raw)?;
            (EvaluationOutcome::Cancelled, false)
        }
        OUTCOME_LIFECYCLE => {
            validate_handle_absent(raw)?;
            validate_metadata_absent(raw)?;
            (
                EvaluationOutcome::Lifecycle {
                    exit_code: raw.lifecycle_exit_code,
                },
                false,
            )
        }
        other => {
            return Err(protocol(format!(
                "native evaluator returned unknown outcome tag {other}"
            )))
        }
    };

    Ok(ConvertedEvaluation {
        evaluation: StructuredEvaluation {
            work_target,
            capabilities,
            result: Ok(outcome),
        },
        transferred_handle,
    })
}

fn validate_result_layout(raw: &NativeEvaluationResult) -> Result<(), EngineFault> {
    if raw.abi_version != ABI_VERSION {
        return Err(protocol(format!(
            "native result ABI version {} does not match {ABI_VERSION}",
            raw.abi_version
        )));
    }
    if raw.struct_size as usize != size_of::<NativeEvaluationResult>() {
        return Err(protocol(format!(
            "native result size {} does not match {}",
            raw.struct_size,
            size_of::<NativeEvaluationResult>()
        )));
    }
    Ok(())
}

fn decode_capabilities(flags: u32) -> Result<EvaluatorCapabilities, EngineFault> {
    if flags & !CAPABILITY_KNOWN != 0 {
        return Err(protocol(format!(
            "native evaluator advertised unknown capability bits 0x{:x}",
            flags & !CAPABILITY_KNOWN
        )));
    }
    let capabilities = EvaluatorCapabilities {
        protocol_version: STRUCTURED_EVALUATION_VERSION,
        base: flags & CAPABILITY_BASE != 0,
        safe_throw: flags & CAPABILITY_SAFE_THROW != 0,
        source_positions: flags & CAPABILITY_SOURCE_POSITIONS != 0,
        rich_inspection: flags & CAPABILITY_RICH_INSPECTION != 0,
    };
    capabilities
        .validate()
        .map_err(|error| protocol(error.to_string()))?;
    Ok(capabilities)
}

fn validate_engine_fault_shape(
    raw: &NativeEvaluationResult,
    capabilities: &EvaluatorCapabilities,
) -> Result<(), EngineFault> {
    validate_handle_absent(raw)?;
    validate_metadata_absent(raw)?;
    validate_lifecycle_absent(raw)?;
    if capabilities.base
        || capabilities.safe_throw
        || capabilities.source_positions
        || capabilities.rich_inspection
    {
        return Err(protocol(
            "native engine-fault outcome advertised evaluation capabilities",
        ));
    }
    Ok(())
}

fn validate_handle_absent(raw: &NativeEvaluationResult) -> Result<(), EngineFault> {
    if raw.value != NativeValueHandle::EMPTY {
        return Err(protocol("outcome unexpectedly carried a value handle"));
    }
    Ok(())
}

fn validate_lifecycle_absent(raw: &NativeEvaluationResult) -> Result<(), EngineFault> {
    if raw.lifecycle_exit_code != 0 {
        return Err(protocol(
            "non-lifecycle outcome carried a lifecycle exit code",
        ));
    }
    Ok(())
}

fn validate_metadata_absent(raw: &NativeEvaluationResult) -> Result<(), EngineFault> {
    if raw.throw_metadata_status != THROW_METADATA_UNAVAILABLE
        || raw.throw_metadata_fields != 0
        || raw.throw_error_class != ERROR_CLASS_UNCLASSIFIED
        || !owned_bytes_are_absent(raw.message)
        || !owned_bytes_are_absent(raw.stack)
        || !raw.positions.is_null()
        || raw.position_count != 0
    {
        return Err(protocol(
            "non-throw or unavailable-metadata outcome carried throw metadata",
        ));
    }
    Ok(())
}

fn decode_error_class(raw: u32) -> Result<NativeErrorClass, EngineFault> {
    match raw {
        ERROR_CLASS_UNCLASSIFIED => Ok(NativeErrorClass::Unclassified),
        ERROR_CLASS_ERROR => Ok(NativeErrorClass::Error),
        ERROR_CLASS_AGGREGATE_ERROR => Ok(NativeErrorClass::AggregateError),
        ERROR_CLASS_EVAL_ERROR => Ok(NativeErrorClass::EvalError),
        ERROR_CLASS_RANGE_ERROR => Ok(NativeErrorClass::RangeError),
        ERROR_CLASS_REFERENCE_ERROR => Ok(NativeErrorClass::ReferenceError),
        ERROR_CLASS_SYNTAX_ERROR => Ok(NativeErrorClass::SyntaxError),
        ERROR_CLASS_TYPE_ERROR => Ok(NativeErrorClass::TypeError),
        ERROR_CLASS_URI_ERROR => Ok(NativeErrorClass::UriError),
        ERROR_CLASS_TIMEOUT_ERROR => Ok(NativeErrorClass::TimeoutError),
        ERROR_CLASS_QUIT_ERROR => Ok(NativeErrorClass::QuitError),
        other => Err(protocol(format!(
            "throw carried unknown native error class {other}"
        ))),
    }
}

unsafe fn decode_throw_metadata(
    raw: &NativeEvaluationResult,
) -> Result<ThrowMetadata, EngineFault> {
    validate_throw_metadata_fields(raw.throw_metadata_fields)?;
    match raw.throw_metadata_status {
        THROW_METADATA_UNAVAILABLE => {
            validate_metadata_absent(raw)?;
            Ok(ThrowMetadata::Unavailable {
                required_stratum: CapabilityStratum::SafeThrow,
            })
        }
        THROW_METADATA_CAPTURED => {
            let message_truncated = raw.throw_metadata_fields & THROW_FIELD_MESSAGE_TRUNCATED != 0;
            let stack_truncated = raw.throw_metadata_fields & THROW_FIELD_STACK_TRUNCATED != 0;
            let message = unsafe {
                decode_optional_utf8(
                    raw.message,
                    raw.throw_metadata_fields & THROW_FIELD_MESSAGE != 0,
                    message_truncated,
                    "message",
                    SAFE_TEXT_MAX_BYTES,
                )?
            };
            let stack = unsafe {
                decode_optional_utf8(
                    raw.stack,
                    raw.throw_metadata_fields & THROW_FIELD_STACK != 0,
                    stack_truncated,
                    "stack",
                    SAFE_TEXT_MAX_BYTES,
                )?
            };
            let positions = unsafe {
                decode_source_positions(
                    raw.positions,
                    raw.position_count,
                    raw.throw_metadata_fields & THROW_FIELD_POSITIONS != 0,
                )?
            };
            Ok(ThrowMetadata::Captured {
                error_class: decode_error_class(raw.throw_error_class)?,
                message,
                message_truncated,
                stack,
                stack_truncated,
                positions,
            })
        }
        other => Err(protocol(format!(
            "throw carried unknown metadata status {other}"
        ))),
    }
}

fn validate_throw_metadata_fields(fields: u32) -> Result<(), EngineFault> {
    if fields & !THROW_FIELDS_KNOWN != 0 {
        return Err(protocol(format!(
            "throw metadata carried unknown field bits 0x{:x}",
            fields & !THROW_FIELDS_KNOWN
        )));
    }
    if fields & THROW_FIELD_MESSAGE_TRUNCATED != 0 && fields & THROW_FIELD_MESSAGE == 0 {
        return Err(protocol(
            "throw message truncation bit was present without the message field bit",
        ));
    }
    if fields & THROW_FIELD_STACK_TRUNCATED != 0 && fields & THROW_FIELD_STACK == 0 {
        return Err(protocol(
            "throw stack truncation bit was present without the stack field bit",
        ));
    }
    Ok(())
}

unsafe fn decode_source_positions(
    positions: *mut NativeSourcePosition,
    count: usize,
    present: bool,
) -> Result<Vec<super::evaluation::SourcePosition>, EngineFault> {
    if !present {
        if !positions.is_null() || count != 0 {
            return Err(protocol(
                "throw source positions were present without the field bit",
            ));
        }
        return Ok(Vec::new());
    }
    if positions.is_null() || count == 0 {
        return Err(protocol(
            "throw source-position field bit requires a nonempty position array",
        ));
    }
    if !(positions as usize).is_multiple_of(std::mem::align_of::<NativeSourcePosition>()) {
        return Err(protocol("throw source-position array is misaligned"));
    }
    if count > isize::MAX as usize / size_of::<NativeSourcePosition>() {
        return Err(protocol(
            "throw source-position count exceeds the addressable range",
        ));
    }

    let native = unsafe { std::slice::from_raw_parts(positions.cast_const(), count) };
    native
        .iter()
        .enumerate()
        .map(|(index, position)| {
            if position.line == 0 || position.column == 0 {
                return Err(protocol(format!(
                    "throw source position {index} is not one-based"
                )));
            }
            let Some(label) = (unsafe {
                decode_optional_utf8(
                    position.source_label,
                    true,
                    false,
                    "source label",
                    isize::MAX as usize,
                )?
            }) else {
                return Err(protocol(format!(
                    "throw source position {index} omitted its required label"
                )));
            };
            let source_label =
                super::evaluation::SourceLabel::from_native(label).map_err(|_| {
                    protocol(format!(
                        "throw source position {index} has an invalid label"
                    ))
                })?;
            Ok(super::evaluation::SourcePosition {
                source_label,
                line: position.line,
                column: position.column,
            })
        })
        .collect()
}

unsafe fn decode_optional_utf8(
    bytes: NativeOwnedBytes,
    present: bool,
    truncated: bool,
    name: &str,
    maximum_bytes: usize,
) -> Result<Option<Arc<str>>, EngineFault> {
    if !present {
        if !owned_bytes_are_absent(bytes) {
            return Err(protocol(format!(
                "throw {name} bytes were present without the field bit"
            )));
        }
        return Ok(None);
    }
    if bytes.length > maximum_bytes {
        return Err(protocol(format!(
            "throw {name} metadata exceeded the {maximum_bytes}-byte bound"
        )));
    }
    if bytes.length != 0 && bytes.data.is_null() {
        return Err(protocol(format!(
            "throw {name} metadata has a null pointer with nonzero length"
        )));
    }
    if bytes.length == 0 {
        if truncated {
            return Err(protocol(format!(
                "truncated throw {name} metadata omitted its trusted marker"
            )));
        }
        return Ok(Some(Arc::from("")));
    }
    let slice = unsafe { std::slice::from_raw_parts(bytes.data.cast_const(), bytes.length) };
    let text = std::str::from_utf8(slice)
        .map_err(|_| protocol(format!("throw {name} metadata is not UTF-8")))?;
    if truncated && !text.ends_with(SAFE_TEXT_TRUNCATION_MARKER) {
        return Err(protocol(format!(
            "truncated throw {name} metadata omitted its trusted marker"
        )));
    }
    Ok(Some(Arc::from(text)))
}

fn owned_bytes_are_absent(bytes: NativeOwnedBytes) -> bool {
    bytes.data.is_null() && bytes.length == 0
}

fn decode_handle(
    raw: NativeValueHandle,
    runtime_nonce: NonZeroU64,
) -> Result<ValueHandle, EngineFault> {
    let native_nonce = NonZeroU64::new(raw.runtime_nonce)
        .ok_or_else(|| protocol("native value handle has a zero runtime nonce"))?;
    let handle_id = NonZeroU64::new(raw.handle_id)
        .ok_or_else(|| protocol("native value handle has a zero handle id"))?;
    if native_nonce != runtime_nonce {
        return Err(protocol(
            "native value handle belongs to a different runtime nonce",
        ));
    }
    Ok(ValueHandle::from_runtime(
        native_nonce,
        handle_id,
        std::thread::current().id(),
    ))
}

fn decode_fault(code: u32) -> Result<Option<StructuredEngineFault>, EngineFault> {
    let fault = match code {
        FAULT_NONE => return Ok(None),
        1 => StructuredEngineFault::InvalidInput,
        2 => StructuredEngineFault::InvalidUtf8,
        3 => StructuredEngineFault::OutOfMemory,
        4 => StructuredEngineFault::Engine,
        5 => StructuredEngineFault::ArmedIngressRequired,
        6 => StructuredEngineFault::WrongThread,
        7 => StructuredEngineFault::StaleHandle,
        8 => StructuredEngineFault::RawThrowUnavailable,
        9 => StructuredEngineFault::CompletionRecordUnavailable,
        10 => StructuredEngineFault::SessionNotBound,
        11 => StructuredEngineFault::WrongSession,
        12 => StructuredEngineFault::SubmissionReplay,
        13 => StructuredEngineFault::WrongOrdinal,
        14 => StructuredEngineFault::EvaluationInFlight,
        15 => StructuredEngineFault::OrdinalExhausted,
        16 => StructuredEngineFault::ArmedRuntimeRequired,
        17 => StructuredEngineFault::BootstrapNotSealed,
        other => {
            return Err(protocol(format!(
                "native evaluator returned unknown fault code {other}"
            )))
        }
    };
    Ok(Some(fault))
}

unsafe fn live_runtime(
    runtime: *mut c_void,
) -> Result<(*mut HermesRuntimeOpaque, NonZeroU64), EngineFault> {
    if runtime.is_null() {
        return Err(EngineFault::Structured(StructuredEngineFault::InvalidInput));
    }
    let runtime = runtime.cast::<HermesRuntimeOpaque>();
    let nonce = NonZeroU64::new(unsafe { ex_hermes_runtime_nonce(runtime.cast()) })
        .ok_or_else(|| EngineFault::Rejected(Arc::from("Hermes runtime pointer is not live")))?;
    Ok((runtime, nonce))
}

unsafe fn runtime_for_handle(
    runtime: *mut c_void,
    handle: &ValueHandle,
) -> Result<*mut HermesRuntimeOpaque, EngineFault> {
    if !handle.belongs_to_current_thread() {
        return Err(EngineFault::Structured(StructuredEngineFault::WrongThread));
    }
    let (runtime, nonce) = unsafe { live_runtime(runtime)? };
    if nonce != handle.runtime_nonce() {
        return Err(EngineFault::Structured(StructuredEngineFault::StaleHandle));
    }
    Ok(runtime)
}

fn native_handle(handle: &ValueHandle) -> NativeValueHandle {
    NativeValueHandle {
        runtime_nonce: handle.runtime_nonce().get(),
        handle_id: handle.handle_id().get(),
    }
}

fn protocol(message: impl Into<Arc<str>>) -> EngineFault {
    EngineFault::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::offset_of;

    fn successful_raw(tag: u32) -> NativeEvaluationResult {
        NativeEvaluationResult {
            outcome_tag: tag,
            work_target_id: 7,
            capability_flags: CAPABILITY_BASE,
            ..NativeEvaluationResult::empty()
        }
    }

    fn convert(raw: &NativeEvaluationResult) -> Result<ConvertedEvaluation, EngineFault> {
        unsafe { convert_result(raw, NonZeroU64::new(41).unwrap()) }
    }

    #[test]
    fn module_graph_finish_preflight_keeps_owner_cleanup_armed() {
        let other_thread = std::thread::spawn(|| std::thread::current().id())
            .join()
            .unwrap();
        let mut evaluation = AuthenticatedModuleGraphEvaluation {
            runtime: ptr::null_mut(),
            runtime_nonce: NonZeroU64::new(1).unwrap(),
            work_target_id: NonZeroU64::new(1).unwrap(),
            owner_thread: other_thread,
            pending: true,
            suspended: false,
        };

        let wrong_thread = unsafe { evaluation.finish(ModuleGraphExecutionOutcome::Completed) }
            .err()
            .expect("wrong-thread preflight must refuse");
        assert!(matches!(
            wrong_thread,
            EngineFault::Structured(StructuredEngineFault::WrongThread)
        ));
        assert!(evaluation.pending, "preflight consumed the cleanup guard");

        evaluation.owner_thread = std::thread::current().id();
        let dead_runtime = unsafe { evaluation.finish(ModuleGraphExecutionOutcome::Completed) }
            .err()
            .expect("dead-runtime preflight must refuse");
        assert!(matches!(
            dead_runtime,
            EngineFault::Structured(StructuredEngineFault::InvalidInput)
        ));
        assert!(
            evaluation.pending,
            "runtime preflight consumed the cleanup guard"
        );

        // The synthetic null runtime cannot be cleaned up; avoid exercising
        // Drop's real-runtime fallback in this pure preflight test.
        std::mem::forget(evaluation);
    }

    #[test]
    fn c_abi_layout_matches_the_versioned_header() {
        assert_eq!(ABI_VERSION, 2);
        assert_eq!(IMPORT_PLAN_ABI_VERSION, 4);
        assert_eq!(size_of::<NativeValueHandle>(), 16);
        assert_eq!(
            std::mem::align_of::<NativeValueHandle>(),
            std::mem::align_of::<u64>()
        );
        assert_eq!(offset_of!(NativeSessionCredential, abi_version), 0);
        assert_eq!(offset_of!(NativeSessionCredential, struct_size), 4);
        assert_eq!(offset_of!(NativeSessionCredential, session_token), 8);
        assert_eq!(offset_of!(NativeSessionCredential, request_binding), 40);
        assert_eq!(offset_of!(NativeSessionCredential, ordinal), 72);
        assert_eq!(size_of::<NativeSessionCredential>(), 80);

        assert_eq!(offset_of!(NativeSessionStaticImport, abi_version), 0);
        assert_eq!(offset_of!(NativeSessionStaticImport, struct_size), 4);
        assert_eq!(offset_of!(NativeSessionImportBinding, abi_version), 0);
        assert_eq!(offset_of!(NativeSessionImportBinding, struct_size), 4);
        assert_eq!(offset_of!(NativeUtf8Slice, data), 0);
        assert_eq!(offset_of!(NativeSessionImportPlan, abi_version), 0);
        assert_eq!(offset_of!(NativeSessionImportPlan, struct_size), 4);
        if cfg!(target_pointer_width = "64") {
            assert_eq!(offset_of!(NativeSessionStaticImport, specifier), 8);
            assert_eq!(offset_of!(NativeSessionStaticImport, specifier_length), 16);
            assert_eq!(offset_of!(NativeSessionStaticImport, first_binding), 24);
            assert_eq!(offset_of!(NativeSessionStaticImport, binding_count), 32);
            assert_eq!(size_of::<NativeSessionStaticImport>(), 40);

            assert_eq!(offset_of!(NativeSessionImportBinding, local_name), 8);
            assert_eq!(
                offset_of!(NativeSessionImportBinding, local_name_length),
                16
            );
            assert_eq!(offset_of!(NativeSessionImportBinding, imported_name), 24);
            assert_eq!(
                offset_of!(NativeSessionImportBinding, imported_name_length),
                32
            );
            assert_eq!(offset_of!(NativeSessionImportBinding, kind), 40);
            assert_eq!(offset_of!(NativeSessionImportBinding, reserved), 44);
            assert_eq!(size_of::<NativeSessionImportBinding>(), 48);

            assert_eq!(offset_of!(NativeSessionImportPlan, logical_referrer), 8);
            assert_eq!(
                offset_of!(NativeSessionImportPlan, logical_referrer_length),
                16
            );
            assert_eq!(offset_of!(NativeSessionImportPlan, imports), 24);
            assert_eq!(offset_of!(NativeSessionImportPlan, import_count), 32);
            assert_eq!(offset_of!(NativeSessionImportPlan, bindings), 40);
            assert_eq!(offset_of!(NativeSessionImportPlan, binding_count), 48);
            assert_eq!(offset_of!(NativeSessionImportPlan, file_arguments), 56);
            assert_eq!(offset_of!(NativeSessionImportPlan, file_argument_count), 64);
            assert_eq!(offset_of!(NativeSessionImportPlan, source_id), 72);
            assert_eq!(offset_of!(NativeSessionImportPlan, source_id_length), 80);
            assert_eq!(
                offset_of!(NativeSessionImportPlan, generated_entry_record),
                88
            );
            assert_eq!(
                offset_of!(NativeSessionImportPlan, generated_entry_record_length),
                96
            );
            assert_eq!(offset_of!(NativeSessionImportPlan, source_kind), 104);
            assert_eq!(offset_of!(NativeSessionImportPlan, reserved), 108);
            assert_eq!(size_of::<NativeSessionImportPlan>(), 112);
            assert_eq!(offset_of!(NativeUtf8Slice, length), 8);
            assert_eq!(size_of::<NativeUtf8Slice>(), 16);
        }

        assert_eq!(offset_of!(NativeEvaluationResult, abi_version), 0);
        assert_eq!(offset_of!(NativeEvaluationResult, struct_size), 4);
        assert_eq!(offset_of!(NativeEvaluationResult, outcome_tag), 8);
        assert_eq!(offset_of!(NativeEvaluationResult, fault), 12);
        assert_eq!(offset_of!(NativeEvaluationResult, work_target_id), 16);
        assert_eq!(offset_of!(NativeEvaluationResult, value), 24);
        assert_eq!(
            offset_of!(NativeEvaluationResult, throw_metadata_status),
            40
        );
        assert_eq!(
            offset_of!(NativeEvaluationResult, throw_metadata_fields),
            44
        );
        assert_eq!(offset_of!(NativeEvaluationResult, throw_error_class), 48);
        assert_eq!(offset_of!(NativeEvaluationResult, lifecycle_exit_code), 52);
        assert_eq!(offset_of!(NativeEvaluationResult, capability_flags), 56);
        assert_eq!(offset_of!(NativeSourcePosition, source_label), 0);
        if cfg!(target_pointer_width = "64") {
            assert_eq!(offset_of!(NativeSourcePosition, line), 16);
            assert_eq!(offset_of!(NativeSourcePosition, column), 20);
            assert_eq!(size_of::<NativeSourcePosition>(), 24);
            assert_eq!(offset_of!(NativeEvaluationResult, message), 64);
            assert_eq!(offset_of!(NativeEvaluationResult, stack), 80);
            assert_eq!(offset_of!(NativeEvaluationResult, positions), 96);
            assert_eq!(offset_of!(NativeEvaluationResult, position_count), 104);
            assert_eq!(size_of::<NativeEvaluationResult>(), 112);
        }
    }

    #[test]
    fn lowered_native_path_preflights_and_executes_with_source_map() {
        let native = include_str!("hermes_runtime.cc");
        let evaluator = native
            .split_once("int evaluateLoweredPreparedSession(")
            .expect("lowered evaluator definition")
            .1
            .split_once("}  // namespace")
            .expect("lowered evaluator namespace boundary")
            .0;
        assert!(evaluator.contains("evaluateJavaScriptWithSourceMap("));
        assert!(evaluator.contains(": rt.evaluatePreparedJavaScript(prepared)"));

        let ingress = native
            .split_once("extern \"C\" int ex_hermes_eval_lowered_session(")
            .expect("lowered ingress definition")
            .1
            .split_once("extern \"C\" int ex_hermes_resume_structured_session(")
            .expect("lowered ingress boundary")
            .0;
        assert!(ingress.contains("prepareJavaScript(sourceBuffer, label)"));
        assert!(ingress.contains("sourceMapBuffer"));
        assert!(ingress.contains("evaluateLoweredPreparedSession("));
    }

    #[test]
    fn exact_native_fault_codes_remain_typed_and_exhaustive() {
        for code in 1..=17 {
            let fault = decode_fault(code).unwrap().unwrap();
            assert_eq!(fault as u32, code);
        }
        assert!(matches!(decode_fault(18), Err(EngineFault::Protocol(_))));
    }

    #[test]
    fn successful_outcomes_require_target_and_base_but_not_optional_strata() {
        let mut raw = successful_raw(OUTCOME_EMPTY);
        raw.work_target_id = 0;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));

        raw.work_target_id = 1;
        assert!(convert(&raw).is_ok());

        raw.capability_flags = CAPABILITY_SAFE_THROW;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
    }

    #[test]
    fn engine_fault_preserves_optional_work_target_and_exact_refusal() {
        let mut raw = NativeEvaluationResult {
            outcome_tag: OUTCOME_ENGINE_FAULT,
            fault: StructuredEngineFault::BootstrapNotSealed as u32,
            ..NativeEvaluationResult::empty()
        };
        let converted = convert(&raw).unwrap().evaluation;
        assert_eq!(converted.work_target, None);
        assert_eq!(
            converted.result.unwrap_err(),
            EngineFault::Structured(StructuredEngineFault::BootstrapNotSealed)
        );

        raw.work_target_id = 9;
        assert_eq!(
            convert(&raw)
                .unwrap()
                .evaluation
                .work_target
                .unwrap()
                .id
                .get(),
            9
        );
    }

    #[test]
    fn value_handles_are_nonzero_and_runtime_bound() {
        let mut raw = successful_raw(OUTCOME_VALUE);
        raw.value = NativeValueHandle {
            runtime_nonce: 41,
            handle_id: 3,
        };
        let converted = convert(&raw).unwrap();
        assert!(converted.transferred_handle);
        let EvaluationOutcome::Value(handle) = converted.evaluation.result.unwrap() else {
            panic!("expected value outcome")
        };
        assert_eq!(handle.runtime_nonce().get(), 41);
        assert_eq!(handle.handle_id().get(), 3);

        raw.value.runtime_nonce = 42;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
        raw.value.runtime_nonce = 41;
        raw.value.handle_id = 0;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
    }

    #[test]
    fn throw_metadata_is_length_bearing_strict_utf8_and_nul_preserving() {
        let mut message = b"boom\0after".to_vec();
        let mut raw = successful_raw(OUTCOME_THROW);
        raw.value = NativeValueHandle {
            runtime_nonce: 41,
            handle_id: 4,
        };
        raw.throw_metadata_status = THROW_METADATA_CAPTURED;
        raw.throw_metadata_fields = THROW_FIELD_MESSAGE;
        raw.throw_error_class = ERROR_CLASS_TYPE_ERROR;
        raw.capability_flags |= CAPABILITY_SAFE_THROW;
        raw.message = NativeOwnedBytes {
            data: message.as_mut_ptr(),
            length: message.len(),
        };
        let converted = convert(&raw).unwrap();
        let EvaluationOutcome::Throw { metadata, .. } = converted.evaluation.result.unwrap() else {
            panic!("expected throw outcome")
        };
        assert_eq!(
            metadata,
            ThrowMetadata::Captured {
                error_class: NativeErrorClass::TypeError,
                message: Some(Arc::from("boom\0after")),
                message_truncated: false,
                stack: None,
                stack_truncated: false,
                positions: Vec::new(),
            }
        );

        message[0] = 0xff;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
    }

    #[test]
    fn throw_truncation_bits_require_presence_bound_and_trusted_marker() {
        let mut message = format!("prefix{SAFE_TEXT_TRUNCATION_MARKER}").into_bytes();
        let mut raw = successful_raw(OUTCOME_THROW);
        raw.value = NativeValueHandle {
            runtime_nonce: 41,
            handle_id: 5,
        };
        raw.throw_metadata_status = THROW_METADATA_CAPTURED;
        raw.throw_metadata_fields = THROW_FIELD_MESSAGE | THROW_FIELD_MESSAGE_TRUNCATED;
        raw.throw_error_class = ERROR_CLASS_ERROR;
        raw.capability_flags |= CAPABILITY_SAFE_THROW;
        raw.message = NativeOwnedBytes {
            data: message.as_mut_ptr(),
            length: message.len(),
        };
        let converted = convert(&raw).unwrap();
        let EvaluationOutcome::Throw { metadata, .. } = converted.evaluation.result.unwrap() else {
            panic!("expected throw outcome")
        };
        assert!(matches!(
            metadata,
            ThrowMetadata::Captured {
                message_truncated: true,
                stack_truncated: false,
                ..
            }
        ));

        raw.throw_metadata_fields = THROW_FIELD_MESSAGE_TRUNCATED;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
        raw.throw_metadata_fields = THROW_FIELD_MESSAGE | THROW_FIELD_MESSAGE_TRUNCATED;
        message.truncate("prefix".len());
        raw.message.length = message.len();
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));

        let mut oversized = vec![b'x'; SAFE_TEXT_MAX_BYTES + 1];
        raw.throw_metadata_fields = THROW_FIELD_MESSAGE;
        raw.message = NativeOwnedBytes {
            data: oversized.as_mut_ptr(),
            length: oversized.len(),
        };
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
    }

    #[test]
    fn source_positions_are_owned_length_bearing_and_capability_checked() {
        let mut label = b"repl:17:/project/input.ts".to_vec();
        let mut native_positions = vec![NativeSourcePosition {
            source_label: NativeOwnedBytes {
                data: label.as_mut_ptr(),
                length: label.len(),
            },
            line: 4,
            column: 9,
        }];
        let mut raw = successful_raw(OUTCOME_THROW);
        raw.value = NativeValueHandle {
            runtime_nonce: 41,
            handle_id: 4,
        };
        raw.throw_metadata_status = THROW_METADATA_CAPTURED;
        raw.throw_metadata_fields = THROW_FIELD_POSITIONS;
        raw.capability_flags |= CAPABILITY_SAFE_THROW | CAPABILITY_SOURCE_POSITIONS;
        raw.positions = native_positions.as_mut_ptr();
        raw.position_count = native_positions.len();

        let converted = convert(&raw).unwrap();
        let EvaluationOutcome::Throw { metadata, .. } = converted.evaluation.result.unwrap() else {
            panic!("expected throw outcome")
        };
        let ThrowMetadata::Captured { positions, .. } = metadata else {
            panic!("expected captured throw metadata")
        };
        assert_eq!(positions.len(), 1);
        assert_eq!(
            positions[0].source_label.as_str(),
            "repl:17:/project/input.ts"
        );
        assert_eq!((positions[0].line, positions[0].column), (4, 9));

        raw.capability_flags &= !CAPABILITY_SOURCE_POSITIONS;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
        raw.capability_flags |= CAPABILITY_SOURCE_POSITIONS;

        native_positions[0].column = 0;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
        native_positions[0].column = 9;

        raw.throw_metadata_fields = 0;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
        raw.throw_metadata_fields = THROW_FIELD_POSITIONS;

        raw.position_count = 0;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
        raw.position_count = usize::MAX;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
        raw.position_count = native_positions.len();

        label[4] = 0;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
        label[4] = 0xff;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
    }

    #[test]
    fn throw_capability_exactly_matches_metadata_availability() {
        let mut raw = successful_raw(OUTCOME_THROW);
        raw.value = NativeValueHandle {
            runtime_nonce: 41,
            handle_id: 4,
        };

        let converted = convert(&raw).unwrap();
        let EvaluationOutcome::Throw { metadata, .. } = converted.evaluation.result.unwrap() else {
            panic!("expected throw outcome")
        };
        assert_eq!(
            metadata,
            ThrowMetadata::Unavailable {
                required_stratum: CapabilityStratum::SafeThrow,
            }
        );

        raw.capability_flags |= CAPABILITY_SAFE_THROW;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
    }

    #[test]
    fn malformed_owned_byte_metadata_is_rejected() {
        let mut raw = successful_raw(OUTCOME_THROW);
        raw.value = NativeValueHandle {
            runtime_nonce: 41,
            handle_id: 4,
        };
        raw.throw_metadata_status = THROW_METADATA_CAPTURED;
        raw.throw_metadata_fields = THROW_FIELD_MESSAGE;
        raw.capability_flags |= CAPABILITY_SAFE_THROW;
        raw.message.length = 1;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));

        raw.message.length = 0;
        raw.throw_metadata_fields = 1 << 8;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));

        raw.throw_metadata_fields = 0;
        raw.throw_error_class = 99;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
    }

    #[test]
    fn non_throw_outcomes_reject_handles_metadata_and_lifecycle_payloads() {
        let mut raw = successful_raw(OUTCOME_EMPTY);
        raw.value.handle_id = 1;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));

        raw.value = NativeValueHandle::EMPTY;
        raw.throw_metadata_status = THROW_METADATA_CAPTURED;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));

        raw.throw_metadata_status = THROW_METADATA_UNAVAILABLE;
        raw.throw_error_class = ERROR_CLASS_TYPE_ERROR;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));

        raw.throw_error_class = ERROR_CLASS_UNCLASSIFIED;
        raw.lifecycle_exit_code = 1;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
    }

    #[test]
    fn unknown_capability_bits_and_fault_capabilities_are_rejected() {
        let mut raw = successful_raw(OUTCOME_EMPTY);
        raw.capability_flags |= 1 << 31;
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));

        raw = NativeEvaluationResult {
            outcome_tag: OUTCOME_ENGINE_FAULT,
            fault: StructuredEngineFault::WrongOrdinal as u32,
            capability_flags: CAPABILITY_BASE,
            ..NativeEvaluationResult::empty()
        };
        assert!(matches!(convert(&raw), Err(EngineFault::Protocol(_))));
    }

    #[test]
    fn json_data_is_refused_before_the_raw_runtime_is_touched() {
        use super::super::evaluation::{
            EntryKind, ExecutionMode, SourceShape, SubmissionOrigin, SubmissionSequence,
        };
        use capsec_semantics::model::{
            Digest, LogicalPath, LogicalRoot, NonEmptyString, Principal,
        };

        let digest = || Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let session = ArmedSessionToken::from_authenticated_snapshot(
            digest(),
            Arc::from("AQIDBAUGBwgJCgsMDQ4PEA"),
            Principal::Root {
                identity: NonEmptyString::new("project-root").unwrap(),
            },
            EntryKind::Eval,
            Arc::from("ibex:eval"),
            ExecutionMode::OneShot,
            digest(),
        )
        .unwrap();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let request = sequence
            .mint(
                SubmissionOrigin::Eval,
                LogicalPath {
                    root: LogicalRoot::Project,
                    components: Vec::new(),
                    host_bound: None,
                },
                SourceShape::JsonData,
            )
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"{}".to_vec())
            .into_request()
            .unwrap();

        let error = unsafe { evaluate_authenticated(ptr::null_mut(), &session, request) }
            .expect_err("JSON data must never reach the evaluator");
        assert!(matches!(&error, EngineFault::Rejected(_)));
        assert!(error.to_string().contains("parsed, not evaluated"));
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn constrained_principals_are_rejected_before_admission_unless_canonical() {
        use super::super::evaluation::{ExecutionMode, SubmissionSequence};
        use capsec_semantics::model::{
            Digest, LogicalPath, LogicalRoot, NonEmptyString, Principal,
        };

        let digest = || Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let session = ArmedSessionToken::from_authenticated_snapshot(
            digest(),
            Arc::from("AQIDBAUGBwgJCgsMDQ4PEA"),
            Principal::Root {
                identity: NonEmptyString::new("project-root").unwrap(),
            },
            super::super::evaluation::EntryKind::Eval,
            Arc::from("ibex:eval"),
            ExecutionMode::OneShot,
            digest(),
        )
        .unwrap();

        for principals in [&[][..], &[1, 1][..], &[2, 1][..]] {
            let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
            let request = sequence
                .mint_repl(LogicalPath {
                    root: LogicalRoot::Project,
                    components: Vec::new(),
                    host_bound: None,
                })
                .unwrap()
                .authorize_inline()
                .bind_bytes(b"1".to_vec())
                .into_request()
                .unwrap();
            let error = unsafe {
                evaluate_authenticated_with_constrained_principals(
                    ptr::null_mut(),
                    &session,
                    request,
                    principals,
                )
            }
            .expect_err("non-canonical conformance principal set reached native admission");
            assert!(matches!(&error, EngineFault::Rejected(_)));
            assert!(error.to_string().contains("nonempty canonical set"));
        }
    }
}
