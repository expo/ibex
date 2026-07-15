/*
 * exact_runtime.h
 *
 * C API for the Exact shared runtime.
 * Used by the iOS app via the Swift bridging header.
 *
 * This header exposes the Hermes JS engine functions and host ABI,
 * providing the full runtime capabilities (module loader, crypto,
 * fetch, timers, etc.) that power both the CLI and iOS app.
 */

#ifndef EXACT_RUNTIME_H
#define EXACT_RUNTIME_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Types
// =============================================================================

/// Opaque handle to an Exact Hermes runtime
typedef struct ExactHermesRuntime ExactHermesRuntime;

// =============================================================================
// Runtime Lifecycle
// =============================================================================

/// Legacy lifecycle symbol retained for ABI compatibility. It is deliberately
/// non-executable and always returns NULL. Production callers must use
/// ex_hermes_create_armed; isolated tests and foreground diagnostics may use
/// ex_hermes_create_diagnostic explicitly.
ExactHermesRuntime* ex_hermes_create(void);

/// Explicit non-production constructor for isolated tests and foreground
/// diagnostic audit. Never use this for project execution.
ExactHermesRuntime* ex_hermes_create_diagnostic(void);

/// Create a runtime only when the installed host carries this exact immutable
/// armed-snapshot identity. Returns NULL on absence or mismatch.
ExactHermesRuntime* ex_hermes_create_armed(const char* armed_snapshot_digest);

/// Irreversibly seal the armed runtime's phase-limited bare bootstrap
/// evaluator after the trusted runtime bundle and compartment baseline are
/// installed. Idempotent on an already-sealed armed runtime.
uint32_t ex_hermes_finish_bootstrap(ExactHermesRuntime* runtime);

/// Copy the filesystem path of the loaded artifact that contains Hermes'
/// runtime factory. Returns the byte length, or -1 on failure.
int32_t ex_hermes_engine_binary_path(char* out, size_t out_len);

/// Return the device/inode identity of the mapped Hermes factory image when
/// the platform can attest it (currently macOS). Returns 1 or -1.
int32_t ex_hermes_engine_mapped_object(uint64_t* out_device,
                                      uint64_t* out_inode);

/// Bytecode version accepted by the loaded Hermes engine. This is runtime
/// truth from the mapped engine's root API, not a sibling CLI executable.
/// Returns zero when the root API is unavailable.
uint32_t ex_hermes_bytecode_version(void);

/// Runtime nonce selected by the active engine entry-point scope. Zero means
/// no runtime is active on this thread. Native registries use this as an owner
/// namespace; it is not a user-visible identifier.
uint64_t ex_hermes_current_runtime_nonce(void);

/// Principal selected by exact frame attribution for the active engine entry
/// point. Consumers must pair it with a nonzero runtime nonce; zero is also the
/// legitimate root principal.
uint64_t ex_hermes_current_principal_id(void);
/// Destroy a Hermes runtime and free all resources.
void ex_hermes_destroy(ExactHermesRuntime* runtime);

// =============================================================================
// Evaluation
// =============================================================================

/// Evaluate JavaScript source code or Hermes bytecode.
/// @param runtime The runtime handle
/// @param data Source code bytes (UTF-8) or bytecode
/// @param len Length of data in bytes
/// @param source_url Source URL for error messages (null-terminated C string)
/// @param is_bytecode 1 if data is Hermes bytecode, 0 if JavaScript source
/// @param out_value On success, points to malloc'd result string (caller frees
///                  with ex_hermes_free_string). NULL if result is undefined.
/// @return 0 on success; 1 on a program/evaluation error; 2 only when a
///         bytecode buffer was rejected before execution. out_value contains
///         the diagnostic for either error status.
int ex_hermes_eval(
    ExactHermesRuntime* runtime,
    const uint8_t* data,
    size_t len,
    const char* source_url,
    int is_bytecode,
    char** out_value);

// Versioned, length-bearing evaluation values. The only source evaluator
// exposed here is explicitly diagnostic and rejects armed runtimes. Armed
// operator source uses the authenticated session-submit route; it must never
// fall back to this API or to ex_hermes_eval.
// @ref LLP 0024#6-evaluation-outcomes-and-the-abi — typed outcomes preserve
// thrown values and embedded NUL bytes without coercing user values.
#define EX_HERMES_STRUCTURED_EVAL_ABI_VERSION 2u

typedef enum ExHermesEvaluationOutcomeTag {
  EX_HERMES_EVAL_OUTCOME_EMPTY = 1,
  EX_HERMES_EVAL_OUTCOME_VALUE = 2,
  EX_HERMES_EVAL_OUTCOME_THROW = 3,
  EX_HERMES_EVAL_OUTCOME_CANCELLED = 4,
  EX_HERMES_EVAL_OUTCOME_LIFECYCLE = 5,
  EX_HERMES_EVAL_OUTCOME_ENGINE_FAULT = 6
} ExHermesEvaluationOutcomeTag;

// Nonterminal continuation discriminator carried in `outcome_tag`. This is a
// progress state, not an EvaluationOutcome: the same work target remains live
// and must be resumed until it produces one of the terminal tags above.
#define EX_HERMES_EVAL_CONTINUATION_SUSPENDED 7u

typedef enum ExHermesEvaluationFault {
  EX_HERMES_EVAL_FAULT_NONE = 0,
  EX_HERMES_EVAL_FAULT_INVALID_INPUT = 1,
  EX_HERMES_EVAL_FAULT_INVALID_UTF8 = 2,
  EX_HERMES_EVAL_FAULT_OUT_OF_MEMORY = 3,
  EX_HERMES_EVAL_FAULT_ENGINE = 4,
  EX_HERMES_EVAL_FAULT_ARMED_INGRESS_REQUIRED = 5,
  EX_HERMES_EVAL_FAULT_WRONG_THREAD = 6,
  EX_HERMES_EVAL_FAULT_STALE_HANDLE = 7,
  EX_HERMES_EVAL_FAULT_RAW_THROW_UNAVAILABLE = 8,
  EX_HERMES_EVAL_FAULT_COMPLETION_RECORD_UNAVAILABLE = 9,
  EX_HERMES_EVAL_FAULT_SESSION_NOT_BOUND = 10,
  EX_HERMES_EVAL_FAULT_WRONG_SESSION = 11,
  EX_HERMES_EVAL_FAULT_SUBMISSION_REPLAY = 12,
  EX_HERMES_EVAL_FAULT_WRONG_ORDINAL = 13,
  EX_HERMES_EVAL_FAULT_EVALUATION_IN_FLIGHT = 14,
  EX_HERMES_EVAL_FAULT_ORDINAL_EXHAUSTED = 15,
  EX_HERMES_EVAL_FAULT_ARMED_RUNTIME_REQUIRED = 16,
  EX_HERMES_EVAL_FAULT_BOOTSTRAP_NOT_SEALED = 17
} ExHermesEvaluationFault;

#define EX_HERMES_EVAL_CAPABILITY_BASE (1u << 0)
#define EX_HERMES_EVAL_CAPABILITY_SAFE_THROW (1u << 1)
#define EX_HERMES_EVAL_CAPABILITY_SOURCE_POSITIONS (1u << 2)
#define EX_HERMES_EVAL_CAPABILITY_RICH_INSPECTION (1u << 3)
#define EX_HERMES_SESSION_TOKEN_LENGTH 32u
#define EX_HERMES_REQUEST_BINDING_LENGTH 32u
#define EX_HERMES_SESSION_LOWERING_PROTOCOL_VERSION 1u
#define EX_HERMES_SESSION_IMPORT_PLAN_ABI_VERSION 4u

typedef enum ExHermesStructuredSourceKind {
  EX_HERMES_STRUCTURED_SOURCE_SESSION = 1,
  EX_HERMES_STRUCTURED_SOURCE_COMMONJS_ENTRY = 2,
  /// A digest-verified single-original generated CommonJS representation.
  /// The raw file credential remains the admitted submission; the record is a
  /// native-only projection of the authenticated v4 provenance sidecar.
  EX_HERMES_STRUCTURED_SOURCE_GENERATED_COMMONJS_ENTRY = 3
} ExHermesStructuredSourceKind;

typedef enum ExHermesThrowMetadataStatus {
  EX_HERMES_THROW_METADATA_UNAVAILABLE = 0,
  EX_HERMES_THROW_METADATA_CAPTURED = 1
} ExHermesThrowMetadataStatus;

#define EX_HERMES_THROW_FIELD_MESSAGE (1u << 0)
#define EX_HERMES_THROW_FIELD_STACK (1u << 1)
#define EX_HERMES_THROW_FIELD_POSITIONS (1u << 2)

typedef enum ExHermesValueKind {
  EX_HERMES_VALUE_INVALID = 0,
  EX_HERMES_VALUE_UNDEFINED = 1,
  EX_HERMES_VALUE_NULL = 2,
  EX_HERMES_VALUE_BOOLEAN = 3,
  EX_HERMES_VALUE_NUMBER = 4,
  EX_HERMES_VALUE_STRING = 5,
  EX_HERMES_VALUE_SYMBOL = 6,
  EX_HERMES_VALUE_BIGINT = 7,
  EX_HERMES_VALUE_FUNCTION = 8,
  EX_HERMES_VALUE_OBJECT = 9,
  EX_HERMES_VALUE_ARRAY = 10
} ExHermesValueKind;

typedef struct ExHermesOwnedBytes {
  uint8_t* data;
  size_t length;
} ExHermesOwnedBytes;

/// One original source coordinate captured by the evaluator. `source_label`
/// is an independently owned, explicit-length UTF-8 buffer; line and column
/// are one-based and nonzero. An evaluation result owns both the position
/// array and every nested source-label allocation until result disposal.
typedef struct ExHermesSourcePosition {
  ExHermesOwnedBytes source_label;
  uint32_t line;
  uint32_t column;
} ExHermesSourcePosition;

typedef struct ExHermesValueHandle {
  uint64_t runtime_nonce;
  uint64_t handle_id;
} ExHermesValueHandle;

/// Linear credential produced by the authenticated Rust ingress. The token is
/// bound once to one armed runtime; ordinal 1 is the first submission and each
/// accepted call consumes exactly one ordinal, including a JavaScript throw.
/// `request_binding` is the SHA-256 binding over the complete typed request and
/// bytes. It is opaque to C++ but must be nonzero; the Rust ingress recomputes
/// it before crossing this seam.
typedef struct ExHermesSessionCredential {
  uint32_t abi_version;
  uint32_t struct_size;
  uint8_t session_token[EX_HERMES_SESSION_TOKEN_LENGTH];
  uint8_t request_binding[EX_HERMES_REQUEST_BINDING_LENGTH];
  uint64_t ordinal;
} ExHermesSessionCredential;

/// Declaration inventory produced by the checked AST lowering. Names are
/// explicit-length UTF-8 and are borrowed only for the native call.
typedef enum ExHermesSessionDeclarationKind {
  EX_HERMES_SESSION_DECL_VAR = 1,
  EX_HERMES_SESSION_DECL_FUNCTION = 2,
  EX_HERMES_SESSION_DECL_LET = 3,
  EX_HERMES_SESSION_DECL_CONST = 4,
  EX_HERMES_SESSION_DECL_CLASS = 5,
  EX_HERMES_SESSION_DECL_IMPORT = 6
} ExHermesSessionDeclarationKind;

typedef struct ExHermesSessionDeclaration {
  const uint8_t* name;
  size_t name_length;
  uint32_t kind;
  uint32_t reserved;
} ExHermesSessionDeclaration;

/// Closed static-import materialization plan produced by checked AST
/// lowering. All rows are versioned independently so a caller cannot make a
/// newer layout appear valid by supplying only a current outer plan.
typedef enum ExHermesSessionImportBindingKind {
  EX_HERMES_SESSION_IMPORT_DEFAULT = 1,
  EX_HERMES_SESSION_IMPORT_NAMED = 2,
  EX_HERMES_SESSION_IMPORT_NAMESPACE = 3
} ExHermesSessionImportBindingKind;

typedef struct ExHermesSessionStaticImport {
  uint32_t abi_version;
  uint32_t struct_size;
  const uint8_t* specifier;
  size_t specifier_length;
  size_t first_binding;
  size_t binding_count;
} ExHermesSessionStaticImport;

typedef struct ExHermesSessionImportBinding {
  uint32_t abi_version;
  uint32_t struct_size;
  const uint8_t* local_name;
  size_t local_name_length;
  const uint8_t* imported_name;
  size_t imported_name_length;
  uint32_t kind;
  uint32_t reserved;
} ExHermesSessionImportBinding;

/// One borrowed explicit-length UTF-8 value. Authenticated file argv uses
/// this layout so no hidden realm-global string or delimiter convention can
/// carry execution identity into project code.
typedef struct ExHermesUtf8Slice {
  const uint8_t* data;
  size_t length;
} ExHermesUtf8Slice;

typedef struct ExHermesSessionImportPlan {
  uint32_t abi_version;
  uint32_t struct_size;
  const uint8_t* logical_referrer;
  size_t logical_referrer_length;
  const ExHermesSessionStaticImport* imports;
  size_t import_count;
  const ExHermesSessionImportBinding* bindings;
  size_t binding_count;
  const ExHermesUtf8Slice* file_arguments;
  size_t file_argument_count;
  /// Canonical authenticated VFS SourceId cache key for a direct file module.
  /// Empty for script inputs and synthetic modules not yet migrated to this
  /// identity arm. Borrowed for the duration of the native call.
  const uint8_t* source_id;
  size_t source_id_length;
  /// Closed JSON metadata for a single-original generated CommonJS entry.
  /// Non-empty only for GENERATED_COMMONJS_ENTRY; borrowed for this call.
  const uint8_t* generated_entry_record;
  size_t generated_entry_record_length;
  uint32_t source_kind;
  uint32_t reserved;
} ExHermesSessionImportPlan;

typedef struct ExHermesEvaluationResult {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t outcome_tag;
  uint32_t fault;
  uint64_t work_target_id;
  ExHermesValueHandle value;
  uint32_t throw_metadata_status;
  uint32_t throw_metadata_fields; /* bit 0 message; bit 1 stack; bit 2 positions */
  int32_t lifecycle_exit_code;
  uint32_t capability_flags;
  ExHermesOwnedBytes message;
  ExHermesOwnedBytes stack;
  ExHermesSourcePosition* positions;
  size_t position_count;
} ExHermesEvaluationResult;

// Versioned native publication record for one authenticated work-unit state
// transition. `target_id` is nonzero only for Begin/Suspended/End; timer
// Due/Undue records instead carry the stable native timer scheduling identity.
// @ref LLP 0024#6-evaluation-outcomes-and-the-abi
// @ref LLP 0025#6-interruption-and-cancellation
#define EX_HERMES_WORK_UNIT_EVENT_ABI_VERSION 1u

typedef enum ExHermesWorkUnitKind {
  EX_HERMES_WORK_UNIT_EVALUATION = 1,
  EX_HERMES_WORK_UNIT_CALLBACK = 2,
  EX_HERMES_WORK_UNIT_TIMER = 3,
  EX_HERMES_WORK_UNIT_MICROTASK_DRAIN = 4,
  EX_HERMES_WORK_UNIT_COMPLETION_QUERY = 5
} ExHermesWorkUnitKind;

typedef enum ExHermesWorkUnitPhase {
  EX_HERMES_WORK_UNIT_DUE = 1,
  EX_HERMES_WORK_UNIT_UNDUE = 2,
  EX_HERMES_WORK_UNIT_BEGIN = 3,
  EX_HERMES_WORK_UNIT_SUSPENDED = 4,
  EX_HERMES_WORK_UNIT_END = 5
} ExHermesWorkUnitPhase;

typedef struct ExHermesWorkUnitEvent {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t kind;
  uint32_t phase;
  uint64_t target_id;
  uint64_t scheduling_id;
} ExHermesWorkUnitEvent;

// Versioned terminal record for a delivered cancellation request. Delivery is
// deliberately not represented here: a record exists only after the exact
// target returned. Unavailable/stale requests are returned synchronously by
// ex_hermes_cancel_structured_work_target and therefore never enter this queue.
// @ref LLP 0024#6-evaluation-outcomes-and-the-abi
#define EX_HERMES_CANCELLATION_EVENT_ABI_VERSION 1u

typedef enum ExHermesCancellationResolution {
  EX_HERMES_CANCELLATION_ACCEPTED = 1,
  EX_HERMES_CANCELLATION_FAILED = 3,
  EX_HERMES_CANCELLATION_DEFEATED = 4
} ExHermesCancellationResolution;

typedef struct ExHermesCancellationEvent {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t resolution;
  uint32_t reserved;
  uint64_t target_id;
} ExHermesCancellationEvent;

// Versioned owner-thread record for one uncaught background JavaScript
// failure. The value handle is a worker-local root and must be rendered and
// released on the runtime's owning thread; it must never cross an IPC seam.
// `associated_evaluation` is the authenticated submission ordinal captured by
// the scheduling source, or zero when the work was not scheduled by an active
// evaluation. Missing/ambiguous ownership is explicit and must not be replaced
// with the root principal.
// @ref LLP 0024#9-asynchronous-failures
#define EX_HERMES_ASYNC_FAILURE_EVENT_ABI_VERSION 1u

typedef enum ExHermesAsyncFailureKind {
  EX_HERMES_ASYNC_FAILURE_TIMER = 1,
  EX_HERMES_ASYNC_FAILURE_NEXT_TICK = 2,
  EX_HERMES_ASYNC_FAILURE_MICROTASK = 3,
  EX_HERMES_ASYNC_FAILURE_NATIVE_COMPLETION = 4,
  EX_HERMES_ASYNC_FAILURE_NATIVE_TASK = 5
} ExHermesAsyncFailureKind;

typedef enum ExHermesAsyncFailurePrincipalStatus {
  EX_HERMES_ASYNC_FAILURE_PRINCIPAL_AUTHENTICATED = 1,
  EX_HERMES_ASYNC_FAILURE_PRINCIPAL_UNAVAILABLE = 2,
  EX_HERMES_ASYNC_FAILURE_PRINCIPAL_AMBIGUOUS = 3
} ExHermesAsyncFailurePrincipalStatus;

typedef struct ExHermesAsyncFailureEvent {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t kind;
  uint32_t principal_status;
  ExHermesValueHandle value;
  uint64_t host_context_id;
  uint64_t owning_principal_id;
  uint64_t event_id;
  uint64_t associated_evaluation;
  uint64_t dropped_count;
} ExHermesAsyncFailureEvent;

enum {
  EX_HERMES_WORK_UNIT_EVENT_EMPTY = 0,
  EX_HERMES_WORK_UNIT_EVENT_AVAILABLE = 1,
  EX_HERMES_WORK_UNIT_EVENT_OVERFLOW = 2,
  EX_HERMES_WORK_UNIT_EVENT_FAILED = 3
};

enum {
  EX_HERMES_ASYNC_FAILURE_EVENT_EMPTY = 0,
  EX_HERMES_ASYNC_FAILURE_EVENT_AVAILABLE = 1,
  EX_HERMES_ASYNC_FAILURE_EVENT_DROPPED = 2,
  EX_HERMES_ASYNC_FAILURE_EVENT_FAILED = 3
};

enum {
  EX_HERMES_CANCELLATION_EVENT_EMPTY = 0,
  EX_HERMES_CANCELLATION_EVENT_AVAILABLE = 1,
  EX_HERMES_CANCELLATION_EVENT_OVERFLOW = 2,
  EX_HERMES_CANCELLATION_EVENT_FAILED = 3
};

/// Initialize a caller-owned result with the current version and size.
void ex_hermes_evaluation_result_init(ExHermesEvaluationResult* result);

/// Free owned byte payloads, the position array, and every source label owned
/// by a position. Value handles remain explicitly owned and must be released
/// separately, on their runtime's owning thread.
void ex_hermes_evaluation_result_dispose(ExHermesEvaluationResult* result);

/// Structured diagnostic evaluation. Source and label are explicit-length
/// UTF-8 (empty source is valid); labels containing NUL are refused. This API
/// never assimilates thenables and never coerces a returned or thrown value.
/// It deliberately rejects an armed runtime.
///
/// Returns 0 when a typed outcome (including an engine-fault outcome) was
/// written, or -1 when the caller supplied an incompatible result layout.
int ex_hermes_eval_structured_diagnostic(
    ExactHermesRuntime* runtime,
    const uint8_t* source,
    size_t source_length,
    const uint8_t* source_label,
    size_t source_label_length,
    ExHermesEvaluationResult* result);

/// Bind one opaque authenticated-session token to an armed runtime. Repeating
/// the call with the identical token is idempotent; a different token is a
/// wrong-session refusal. Tokens are exact-length binary values and are never
/// exposed to JavaScript.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry — the
/// armed source route is separate from JavaScript-reachable vm:evaluate.
uint32_t ex_hermes_structured_session_bind(
    ExactHermesRuntime* runtime,
    const uint8_t* session_token,
    size_t session_token_length);

/// Admit one exact authenticated submission before syntax/lowering begins.
/// Admission consumes the ordinal and reserves a work target, so a later
/// recoverable parse/lowering failure cannot make the submitted ordinal
/// reusable. The admitted credential must be continued by
/// ex_hermes_eval_lowered_session or settled explicitly.
uint32_t ex_hermes_structured_submission_admit(
    ExactHermesRuntime* runtime,
    const ExHermesSessionCredential* credential,
    uint64_t* out_work_target_id);

/// Settle an admitted submission which intentionally does not enter Hermes,
/// such as rejected syntax or authenticated JSON-data parsing. This never
/// rolls back the ordinal already consumed at admission.
uint32_t ex_hermes_structured_submission_settle(
    ExactHermesRuntime* runtime,
    const ExHermesSessionCredential* credential);

enum {
  EX_HERMES_CANCEL_UNAVAILABLE = 0,
  EX_HERMES_CANCEL_ACCEPTED = 1,
  EX_HERMES_CANCEL_STALE_TARGET = 2,
  EX_HERMES_CANCEL_FAILED = 3
};

/// Take the oldest native work-unit transition without waiting. This operation
/// is callable from any thread while the runtime owner is inside Hermes. The
/// queue is bounded; OVERFLOW is a fail-loud terminal state, never permission
/// to reconstruct a partial live-unit set by polling the active target.
uint32_t ex_hermes_take_work_unit_event(
    ExactHermesRuntime* runtime,
    ExHermesWorkUnitEvent* event);

/// Take the oldest terminal cancellation result without waiting. ACCEPTED is
/// published only after the exact target returned because of the request and a
/// fixed native consistency probe proved that the runtime remains reusable.
uint32_t ex_hermes_take_cancellation_event(
    ExactHermesRuntime* runtime,
    ExHermesCancellationEvent* event);

/// Return the exact authenticated work target currently owned by this runtime,
/// or zero when no native work unit is executing. Suspended evaluations and
/// due-but-not-begun timers are deliberately not cancellation targets. This is
/// any-thread and is intended only for the native terminal-session controller.
uint64_t ex_hermes_structured_active_work_target(
    ExactHermesRuntime* runtime);

/// Request cancellation of exactly `work_target_id`. The native target lock
/// prevents a check for one unit from landing on a successor. The
/// EX_HERMES_CANCEL_ACCEPTED return means only that the request was delivered;
/// terminal acceptance arrives through ex_hermes_take_cancellation_event after
/// the target returns. This call never waits for JavaScript to cooperate.
uint32_t ex_hermes_cancel_structured_work_target(
    ExactHermesRuntime* runtime,
    uint64_t work_target_id);

/// Consume one authenticated credential and evaluate its exact source bytes.
/// This is the only structured source evaluator which accepts an armed
/// runtime. It rejects wrong-session, replayed, skipped, and concurrent
/// credentials before executing source, and requires both the raw-throw and
/// completion-record Hermes patches before advertising Base.
int ex_hermes_eval_structured_session(
    ExactHermesRuntime* runtime,
    const ExHermesSessionCredential* credential,
    const uint8_t* source,
    size_t source_length,
    const uint8_t* source_label,
    size_t source_label_length,
    ExHermesEvaluationResult* result);

/// Continue the exact submission previously accepted by
/// ex_hermes_structured_submission_admit. Compile a checked lowered wrapper
/// before mutating the persistent session record, instantiate its declaration
/// inventory atomically, then invoke it with native-only checked-cell hooks.
/// `lowered_source_map` is the composed map whose original source name is
/// `source_label`; neither buffer is ever exposed as a realm-global property.
int ex_hermes_eval_lowered_session(
    ExactHermesRuntime* runtime,
    const ExHermesSessionCredential* credential,
    uint32_t lowering_protocol_version,
    const uint8_t* lowered_source,
    size_t lowered_source_length,
    const uint8_t* lowered_source_map,
    size_t lowered_source_map_length,
    const uint8_t* source_label,
    size_t source_label_length,
    const ExHermesSessionDeclaration* declarations,
    size_t declaration_count,
    const ExHermesSessionImportPlan* import_plan,
    bool asynchronous,
    ExHermesEvaluationResult* result);

/// Re-enter the exact top-level-await settlement started by
/// ex_hermes_eval_lowered_session. The host drives ready engine work between
/// calls; this function never waits, assimilates the user's completion value,
/// or applies a timeout. It returns the suspended continuation discriminator
/// again while the unit is pending, otherwise one terminal typed outcome.
int ex_hermes_resume_structured_session(
    ExactHermesRuntime* runtime,
    uint64_t work_target_id,
    ExHermesEvaluationResult* result);

/// Trap-free top-level kind query. Returns EX_HERMES_VALUE_INVALID for a stale,
/// wrong-runtime, or wrong-thread handle.
uint32_t ex_hermes_value_kind(
    ExactHermesRuntime* runtime,
    ExHermesValueHandle handle);

/// Copy the Stage-1 text of a primitive rooted value without invoking
/// JavaScript, property access, or user coercion. Object/function/array values
/// intentionally return an empty payload and are displayed from value_kind.
/// The returned buffer is explicit-length UTF-8, NUL-terminated for allocator
/// compatibility, and must be released with ex_hermes_free_string.
uint32_t ex_hermes_value_stage1_text(
    ExactHermesRuntime* runtime,
    ExHermesValueHandle handle,
    uint8_t** out_data,
    size_t* out_length);

/// Copy trap-free Error metadata retained by Hermes for one rooted value.
/// Ordinary Error objects return optional owned UTF-8 message and stack
/// buffers; arbitrary values succeed with both buffers empty. No JavaScript
/// property, accessor, Proxy trap, prepareStackTrace, or coercion is invoked.
/// Buffers are released with ex_hermes_free_string.
/// @ref LLP 0024#8-safe-inspection
uint32_t ex_hermes_value_safe_throw_metadata(
    ExactHermesRuntime* runtime,
    ExHermesValueHandle handle,
    ExHermesOwnedBytes* message,
    ExHermesOwnedBytes* stack);

/// Settle the exact pending Stage-1 display receipt. A displayed receipt
/// updates the private persistent `$_` cell before releasing the handle;
/// fallback/write-failed dispositions release it without updating history.
uint32_t ex_hermes_session_display_ack(
    ExactHermesRuntime* runtime,
    uint64_t work_target_id,
    ExHermesValueHandle handle,
    bool displayed);

/// Release a rooted value. Returns EX_HERMES_EVAL_FAULT_NONE on success or the
/// exact wrong-thread/stale-handle fault code.
uint32_t ex_hermes_value_release(
    ExactHermesRuntime* runtime,
    ExHermesValueHandle handle);

/// Take one structured background failure on the runtime's owning thread.
/// AVAILABLE transfers ownership of `event->value` to the caller. DROPPED is
/// an explicit pre-receipt loss marker in `dropped_count`; every dropped value
/// handle has already been released by the runtime. Once loss begins, later
/// failures coalesce into the same window until its marker is taken, so a
/// newer event cannot overtake an older loss marker.
uint32_t ex_hermes_take_async_failure_event(
    ExactHermesRuntime* runtime,
    ExHermesAsyncFailureEvent* event);

/// Free a string returned by ex_hermes_eval or other functions.
void ex_hermes_free_string(char* value);

// =============================================================================
// Event Loop
// =============================================================================

/// Poll the event loop, executing any due timers and callbacks.
/// Call this repeatedly from the host event loop (e.g., CADisplayLink or GCD timer).
///
/// CLOCK DOMAIN (ENG-23611 / exact ENG-23637): timer deadlines are stored as
/// MONOTONIC milliseconds (steady_clock; `nowMs() + delay` in
/// hermes_runtime_timers.cc), NOT wall/epoch time. `now_ms` MUST come from
/// ex_hermes_now_ms(). Passing epoch milliseconds (e.g.
/// Date().timeIntervalSince1970 * 1000) makes every pending timer due
/// immediately — a 60 s setTimeout fires on the next poll.
/// @param runtime The runtime handle
/// @param now_ms Current time from ex_hermes_now_ms() (monotonic ms)
/// @return Number of tasks executed, EX_HERMES_POLL_ERROR on a legacy-runtime
/// asynchronous error, or EX_HERMES_POLL_LIFECYCLE_REQUESTED after an armed
/// callback has published a cooperative lifecycle event. Authenticated
/// asynchronous throws use ex_hermes_take_async_failure_event instead. Pending
/// work is not drained after the lifecycle status.
#define EX_HERMES_POLL_ERROR (-1)
#define EX_HERMES_POLL_LIFECYCLE_REQUESTED (-2)
int ex_hermes_poll(ExactHermesRuntime* runtime, uint64_t now_ms);

/// Get the deadline of the next pending timer, on the same monotonic clock as
/// ex_hermes_now_ms() (NOT epoch time). To convert to a host wait interval,
/// subtract ex_hermes_now_ms() and clamp negative to 0.
/// @return Next timer due time in monotonic ms, or -1 if no timers are pending
int64_t ex_hermes_next_timer(ExactHermesRuntime* runtime);

/// The runtime's monotonic timer clock, in milliseconds. setTimeout /
/// setInterval deadlines and ex_hermes_next_timer() are measured on THIS
/// clock; hosts must pass it as `now_ms` to ex_hermes_poll(). There is exactly
/// one source of truth for timer time — do not substitute a host-side
/// monotonic clock (epochs of distinct monotonic sources are unrelated), and
/// never wall time (NTP/manual steps would stall or mass-fire timers).
uint64_t ex_hermes_now_ms(void);

/// Host policy for JS errors escaping drained async callbacks (timers,
/// microtasks, nextTick, cross-thread tasks). Default (0, the CLI contract —
/// ENG-23130): an unconsumed error reports and the observing ex_hermes_poll
/// returns -1 so the host loop exits nonzero. Embedded app hosts pass 1
/// (ENG-23731): the error still reports through the
/// __exactUncaughtExceptionHandler consult + raw console path, but the poll
/// keeps executing and never returns -1 for it — one bad app callback must
/// not crash or zombify the host. Call during engine construction, before
/// the event loop starts.
void ex_hermes_set_keep_alive_on_async_error(ExactHermesRuntime* runtime,
                                             int enabled);

/// Check if there are any pending tasks (timers, callbacks, etc.)
/// @return 1 if there are pending tasks, 0 if idle
int ex_hermes_has_pending_tasks(ExactHermesRuntime* runtime);

/// Get the current number of queued cross-thread callbacks waiting to run.
uint32_t ex_hermes_callback_backlog(ExactHermesRuntime* runtime);

/// Snapshot the generation nonce for a live runtime handle. Hosts that retain
/// a handle for asynchronous work must capture this while they own the live
/// runtime and carry it with every later completion; never recover a nonce
/// from a possibly stale pointer when the completion fires.
uint64_t ex_hermes_runtime_nonce(ExactHermesRuntime* runtime);

/// Wake the event loop when a callback is pushed from a background thread.
/// Called automatically by the runtime when async operations complete.
void ex_hermes_notify_callback(void);

/// Register (or clear, with NULL) a host wake hook invoked whenever a
/// background thread pushes a runtime callback (exact LLP 0297 W4b/B8).
/// Lets a wake-driven host executor park instead of polling the pending
/// flag. The hook runs on the pushing thread: do only cheap, bounded work
/// (enqueue + signal). Register once at host boot, before runtime traffic.
void ex_hermes_set_host_wake_hook(
    void (*hook)(void* context),
    void* context);

/// Deprecated raw-pointer-only watchdog ABI. This function fails closed and
/// does not invoke `callback`: a raw address cannot identify a runtime after
/// allocator reuse. Use the generation-bearing variant below.
#if defined(__clang__) || defined(__GNUC__)
__attribute__((deprecated(
    "use ex_hermes_schedule_watchdog_heartbeat_for_generation")))
#elif defined(_MSC_VER)
__declspec(deprecated(
    "use ex_hermes_schedule_watchdog_heartbeat_for_generation"))
#endif
void ex_hermes_schedule_watchdog_heartbeat(
    ExactHermesRuntime* runtime,
    void (*callback)(void* context),
    void* context);

/// Queue a lightweight watchdog callback onto the cross-thread callback queue.
/// `runtime_nonce` must be the value captured for this exact handle generation
/// with `ex_hermes_runtime_nonce` while the runtime was live. A stale pointer
/// paired with an old nonce is rejected even if its address has been reused.
/// The callback executes during the next poll on the runtime-owning thread.
void ex_hermes_schedule_watchdog_heartbeat_for_generation(
    ExactHermesRuntime* runtime,
    uint64_t runtime_nonce,
    void (*callback)(void* context),
    void* context);

// =============================================================================
// iOS Rendering Pipeline Callbacks
// =============================================================================

/// Set callback for exact.dispatch(Uint8Array) - binary protocol for view tree.
/// This installs the exact.dispatch() function in JavaScript.
/// @param runtime The runtime handle
/// @param callback Function called with binary buffer data
/// @param context User context passed to callback
void ex_hermes_set_dispatch_callback(
    ExactHermesRuntime* runtime,
    void (*callback)(const uint8_t* data, size_t length, void* context),
    void* context);

/// Set callback for exact.dispatchWithDebugContext(Uint8Array, string|object).
/// This installs exact.dispatchWithDebugContext() in JavaScript.
/// @param runtime The runtime handle
/// @param callback Function called with binary buffer data plus debug context JSON
/// @param context User context passed to callback
void ex_hermes_set_dispatch_with_debug_context_callback(
    ExactHermesRuntime* runtime,
    void (*callback)(const uint8_t* data,
                     size_t length,
                     const char* debug_context_json,
                     void* context),
    void* context);

/// Set callback for exact.dispatchModule(Uint8Array) - async native module calls.
/// This installs exact.dispatchModule() in JavaScript.
/// @param runtime The runtime handle
/// @param callback Function called with module dispatch data
/// @param context User context passed to callback
void ex_hermes_set_module_dispatch_callback(
    ExactHermesRuntime* runtime,
    void (*callback)(const uint8_t* data, size_t length, void* context),
    void* context);

/// Set callback for exact.callModuleSync(Uint8Array) - blocking module calls.
/// This installs exact.callModuleSync() in JavaScript.
/// @param runtime The runtime handle
/// @param callback Function called synchronously; fills result_data/result_length.
///                 Returns 0 on success, non-zero on error.
///                 result_data should be malloc'd (caller frees).
/// @param context User context passed to callback
void ex_hermes_set_module_sync_callback(
    ExactHermesRuntime* runtime,
    int (*callback)(const uint8_t* data, size_t length,
                    uint8_t** result_data, size_t* result_length,
                    void* context),
    void* context);

/// Install the generic `__hostCall(op, argsJson)` bridge in JavaScript.
/// The callback should return a malloc'd C string. Prefix with `+` for a JSON
/// success payload or `-` for an error message. This bridge is available only
/// to unarmed diagnostic/embedder runtimes. For an armed runtime this void
/// function is a silent no-op: it neither stores the callback nor changes the
/// JavaScript global object.
void ex_hermes_set_host_call(
    ExactHermesRuntime* runtime,
    char* (*callback)(const char* op, const char* args_json));

/// Install the async `__hostCallAsync(op, argsJson)` bridge in JavaScript
/// (LLP 0297 W3). `__hostCallAsync` returns a Promise; the callback receives
/// the owning runtime, a call id, and the op/args, and must eventually
/// complete the call with ex_hermes_resolve_host_call — synchronously inline
/// or later from any thread. Payload sigils match `__hostCall`: `+json`
/// resolves with the parsed JSON, `-message` rejects with an Error. This bridge
/// is available only to unarmed diagnostic/embedder runtimes. For an armed
/// runtime this void function is a silent no-op.
void ex_hermes_set_host_call_async(
    ExactHermesRuntime* runtime,
    void (*callback)(ExactHermesRuntime* runtime,
                     uint64_t call_id,
                     const char* op,
                     const char* args_json));

/// Complete a pending `__hostCallAsync` call. Safe to invoke from any thread;
/// resolution is delivered on the runtime's thread via the callback queue.
/// Unknown / already-completed call ids, dead runtimes, and all armed runtimes
/// are silently ignored. This is a void ABI; rejection does not add a return
/// status or change the function signature.
void ex_hermes_resolve_host_call(
    ExactHermesRuntime* runtime,
    uint64_t call_id,
    const char* payload);

/// Attach the Exact kernel handle so the runtime can expose kernel-backed
/// state-mirror snapshots and module metadata through the `exact` global.
void ex_hermes_set_kernel_handle(
    ExactHermesRuntime* runtime,
    void* kernel_handle);

// =============================================================================
// Android Host Integration
// =============================================================================

/// Install Android process state used by Android-native platform bridges.
/// Pass the process JavaVM* and an android.content.Context jobject as opaque
/// pointers from JNI. The context may be an Activity or Application; Ibex keeps
/// its application context.
///
/// Android networking requires the Java helper class
/// dev.ibex.runtime.IbexNetworking and OkHttp on the app classpath.
/// @return 0 on success, negative on setup failure.
#ifdef __ANDROID__
int ex_android_initialize(void* java_vm, void* application_context);
#endif

/// Emit a module event from native code to JavaScript.
/// Calls globalThis.__exactModuleEvent(moduleName, eventName, payload).
/// @param runtime The runtime handle
/// @param module_name Module name (null-terminated)
/// @param event_name Event name (null-terminated)
/// @param payload Binary payload data (MessagePack encoded, may be NULL)
/// @param payload_len Length of payload in bytes
/// @return 0 on success, -1 on error
int ex_hermes_emit_module_event(
    ExactHermesRuntime* runtime,
    const char* module_name,
    const char* event_name,
    const uint8_t* payload,
    size_t payload_len);

/// Emit a native-view instance event from native code to JavaScript.
/// Calls globalThis.__exactModuleEvent(moduleName, eventName, nodeId, payload).
int ex_hermes_emit_module_view_event(
    ExactHermesRuntime* runtime,
    const char* module_name,
    const char* event_name,
    uint32_t node_id,
    const uint8_t* payload,
    size_t payload_len);

/// Dispatch a renderer event from native code to JavaScript.
/// Calls globalThis.__exactDispatchEvent(handlerId, payload).
/// payload_json must be valid JSON for the event payload.
int ex_hermes_dispatch_event(
    ExactHermesRuntime* runtime,
    uint32_t handler_id,
    const char* payload_json);

// =============================================================================
// Host ABI (called from Rust, used by hermes_runtime.cc)
// =============================================================================

/// Install the host singleton. Must be called before creating a runtime.
/// On iOS, this is called from Swift during app initialization.
void ex_host_install(void);

/// Authenticate and install an immutable armed snapshot. Both buffers are
/// copied during the call. Returns 0 on success, non-zero on refusal.
int ex_host_install_armed(const uint8_t* snapshot,
                          size_t snapshot_len,
                          const uint8_t* expected_identity,
                          size_t expected_identity_len);

/// Return 1 only when the installed host has the exact snapshot digest.
int ex_host_matches_armed_snapshot_digest(const char* digest);
int ex_host_is_armed(void);

/// Process-local terminal-session descriptor policy. These checks are a
/// closed native-only routing seam: REFUSED is a typed permission failure,
/// NATIVE permits the ordinary OS/host route, and VIRTUAL means EOF for reads
/// or success-without-close for close. Native consumers must fail closed on
/// any value outside this enum.
typedef enum ExHostSessionDescriptorRoute {
  EX_HOST_SESSION_DESCRIPTOR_ROUTE_REFUSED = -1,
  EX_HOST_SESSION_DESCRIPTOR_ROUTE_NATIVE = 0,
  EX_HOST_SESSION_DESCRIPTOR_ROUTE_VIRTUAL = 1
} ExHostSessionDescriptorRoute;

int32_t ex_host_session_descriptor_is_protected(int32_t fd);
int32_t ex_host_session_descriptor_read_route(int32_t fd);
int32_t ex_host_session_descriptor_write_route(int32_t fd);
int32_t ex_host_session_descriptor_close_route(int32_t fd);
int32_t ex_host_session_descriptor_alias_source_route(int32_t fd);
int32_t ex_host_session_descriptor_alias_target_route(int32_t fd);

/// Query supervisor-authenticated live stdio facts for an isolated session
/// worker. Returns 1 when all outputs were populated, 0 when the caller should
/// query its native descriptor, and -1 for malformed arguments. A zero
/// dimension means that no live size has been received yet.
int32_t ex_host_terminal_session_stdio_query(int32_t fd,
                                             int32_t* out_is_tty,
                                             uint16_t* out_columns,
                                             uint16_t* out_rows);

/// Compatibility query used by terminal adapters that only need the close
/// no-op predicate. New numeric-fd routes must use the closed close route.
int32_t ex_host_terminal_session_close_is_noop(int32_t fd);

/// Evaluate a strict typed decision-set JSON document and its effect-gate JSON
/// array against the installed armed context. Returns a heap-owned JSON
/// decision/evidence or error envelope; free it with ex_host_free_string.
char* ex_host_evaluate_typed_decision(const uint8_t* decision_set,
                                      size_t decision_set_len,
                                      const uint8_t* gates,
                                      size_t gates_len);

/// Typed, root-only lifecycle operations over the authenticated constrained
/// principal stack. These return 1 only for a fully staged allow; denial,
/// missing arming, malformed input, and unknown attribution all return 0.
typedef enum ExHostLifecycleExitSurface {
  EX_HOST_LIFECYCLE_EXIT_SURFACE_PROCESS_EXIT = 1,
  EX_HOST_LIFECYCLE_EXIT_SURFACE_EXACT_EXIT = 2
} ExHostLifecycleExitSurface;

/// `has_requested_code` is the closed boolean 0/1. When it is zero, the Host
/// resolves the request from its supervisor-authoritative `exitCode` mirror.
/// `out_code` is written only after both decision stages allow and the shared
/// lifecycle port has accepted (or idempotently retained) the request.
int32_t ex_host_authorize_typed_lifecycle_exit_stack(
    uint64_t actor,
    const uint64_t* module_ids,
    size_t module_ids_len,
    uint32_t surface,
    int32_t requested_code,
    uint32_t has_requested_code,
    int32_t* out_code);
int32_t ex_host_lifecycle_exit_code_get_stack(
    uint64_t actor,
    const uint64_t* module_ids,
    size_t module_ids_len,
    int32_t* out_code);
int32_t ex_host_lifecycle_exit_code_set_stack(
    uint64_t actor,
    const uint64_t* module_ids,
    size_t module_ids_len,
    int32_t code);

/// Authorize requested (stage=0), retained-fd commit (stage=1), repeated
/// descriptor use (stage=2), path disclosure (stage=3), or pre-open effects
/// (stage=4), or repeated descriptor metadata disclosure (stage=5) for
/// fs.open. Stages after requested require `parent_fd`.
int ex_host_authorize_typed_fs_stack(uint64_t module_id,
                                    const uint64_t* module_ids,
                                    size_t module_ids_len,
                                    const char* path,
                                    uint32_t stage,
                                    uint32_t surface,
                                    int32_t parent_fd,
                                    int32_t fd,
                                    int32_t needs_read,
                                    int32_t needs_write,
                                    const char* presented_handle_id);

/// Publish or revoke ceiling-bounded typed dynamic authority. Grant input is a
/// strict JSON request object; revoke input is a strict JSON string grant ID.
/// Returns 1 when changed, 0 when unchanged, and -1 on refusal.
int ex_host_typed_dynamic_grant(uint64_t module_id,
                                const uint8_t* request,
                                size_t request_len);
int ex_host_typed_dynamic_revoke(uint64_t module_id,
                                 const uint8_t* request,
                                 size_t request_len);

/// Mint/re-attenuate and revoke typed bearer handles. Mint returns a heap-owned
/// JSON handle/error envelope; revoke returns 1/0/-1 like dynamic revocation.
char* ex_host_typed_handle_mint(uint64_t module_id,
                                const uint64_t* module_ids,
                                size_t module_ids_len,
                                const uint8_t* request,
                                size_t request_len);
int ex_host_typed_handle_revoke(uint64_t module_id,
                                const uint8_t* request,
                                size_t request_len);

/// Read the current authenticated negative/dynamic/handle generations.
/// Returns 1 for an armed host and 0 otherwise.
int ex_host_typed_generations(uint64_t* negative,
                              uint64_t* dynamic,
                              uint64_t* handle);

/// Console log output from JS
void ex_host_console_log(int32_t level, const char* message);
/// Length-bearing console output used by authenticated CLI workers so embedded
/// NUL bytes and enqueue-time relay accounting are preserved.
void ex_host_console_log_bytes(int32_t level, const uint8_t* message, size_t length);

/// Fill buffer with random bytes
int32_t ex_host_random_fill(uint8_t* buf, uint32_t len);

// =============================================================================
// Debugger (requires HERMES_ENABLE_DEBUGGER; functions are no-ops otherwise)
// =============================================================================

/// Enable the Hermes debugger. Returns non-zero on success.
int ex_hermes_debugger_enable(ExactHermesRuntime* runtime);

/// Get all loaded scripts as a JSON array string.
/// Returns malloc'd string: [{"id":N,"url":"..."},...]  Free with ex_hermes_free_string().
char* ex_hermes_debugger_get_scripts(ExactHermesRuntime* runtime);

/// Get the source code of a script by ID.
/// Returns malloc'd string. Free with ex_hermes_free_string().
char* ex_hermes_debugger_get_script_source(ExactHermesRuntime* runtime, uint32_t script_id);

/// Set a breakpoint. Returns malloc'd JSON: {"id":N,"scriptId":N,"line":N,"column":N}
/// Condition may be NULL. Free with ex_hermes_free_string().
char* ex_hermes_debugger_set_breakpoint(ExactHermesRuntime* runtime, uint32_t script_id,
                                         uint32_t line_number, uint32_t column_number,
                                         const char* condition);

/// Remove a breakpoint by ID.
void ex_hermes_debugger_remove_breakpoint(ExactHermesRuntime* runtime, uint64_t breakpoint_id);

/// Pause execution.
void ex_hermes_debugger_pause(ExactHermesRuntime* runtime);

/// Resume execution. command: 0=Continue, 1=StepInto, 2=StepOver, 3=StepOut
void ex_hermes_debugger_resume(ExactHermesRuntime* runtime, int command);

/// Get the next pending debug event (non-blocking).
/// Returns malloc'd JSON string, or NULL if no event. Free with ex_hermes_free_string().
char* ex_hermes_debugger_next_event(ExactHermesRuntime* runtime);

/// Evaluate an expression (optionally on a call frame when paused).
/// Returns malloc'd JSON: {"result":{...},"exceptionDetails":{...}}
/// Free with ex_hermes_free_string().
char* ex_hermes_debugger_eval(ExactHermesRuntime* runtime, const char* expression,
                               uint32_t frame_index);

// =============================================================================
// Memory Management
// =============================================================================

/// Request garbage collection
void ex_hermes_gc(ExactHermesRuntime* runtime);

/// Get the current Hermes heap info as a JSON object string.
/// Returns malloc'd string or NULL on failure. Free with ex_hermes_free_string().
char* ex_hermes_get_heap_info(ExactHermesRuntime* runtime, int include_expensive);

/// Get cumulative Hermes GC stats as a JSON string.
/// Returns malloc'd string or NULL on failure. Free with ex_hermes_free_string().
char* ex_hermes_get_gc_stats(ExactHermesRuntime* runtime);

// =============================================================================
// UI Worklet Runtime (LLP 0297 §4.3, exact repo)
// =============================================================================
//
// A second, RESTRICTED Hermes instance owned by the host's main/UI thread:
// no module loader, no fetch/network, no timers, no exact.dispatch, no
// kernel access. Globals: log(...), scheduleOnAppRuntime(name, args),
// measure(nodeId), __svGet/__svSet + the frozen `worklet` stdlib
// (clamp/lerp/sharedValue). Single-owner: every ex_worklet_* call happens
// on the creating thread. Install/invoke are generation-fenced (§4.8):
// stale or not-yet-current generations are defined no-ops.
//
// Result codes for ex_worklet_install / ex_worklet_invoke:
//   0 = ok, 1 = error (out param carries the message), 2 = defined no-op
//       (missing worklet or generation mismatch).

/// Create a restricted worklet runtime (small heap: 1MB init / 8MB max).
/// Compatible with ex_hermes_eval/gc/get_heap_info; destroy with
/// ex_worklet_destroy (NOT ex_hermes_destroy — worklet state must be
/// released first).
ExactHermesRuntime* ex_worklet_create(void);

/// Destroy a worklet runtime on its owning thread.
void ex_worklet_destroy(ExactHermesRuntime* runtime);

/// Set the current app-runtime generation; atomically drops every
/// installed worklet whose generation differs (LLP 0297 §4.8 reset rule).
void ex_worklet_set_generation(ExactHermesRuntime* runtime, uint64_t generation);

/// Current generation (0 if never set).
uint64_t ex_worklet_generation(ExactHermesRuntime* runtime);

/// Install (or replace) a worklet. `source` must be JS source text that
/// evaluates to a function expression, e.g. "(function(event){...})".
/// Installs tagged with an OLDER generation than current are dropped
/// (returns 2); NEWER generations are stored and become invocable when
/// ex_worklet_set_generation catches up. On error returns 1 and sets
/// *out_error (malloc'd; free with ex_hermes_free_string).
int ex_worklet_install(
    ExactHermesRuntime* runtime,
    const char* worklet_id,
    const uint8_t* source,
    size_t source_len,
    uint64_t generation,
    char** out_error);

/// Invoke an installed worklet synchronously with a JSON-encoded argument
/// (may be NULL/empty for zero-arg invocation). On success returns 0 and
/// sets *out_result_json to the JSON-stringified return value (malloc'd;
/// free with ex_hermes_free_string). Returns 2 (no-op) for a missing
/// worklet or generation mismatch; 1 on JS error (out param = message).
int ex_worklet_invoke(
    ExactHermesRuntime* runtime,
    const char* worklet_id,
    const char* args_json,
    char** out_result_json);

/// Bind the SharedValue slab: `slab` points to `slot_count` 32-bit slots
/// (atomic f32 bit patterns; kernel-owned shared memory per LLP 0297 §4.5).
/// Pass NULL to unbind. Out-of-range slot access from worklet JS is a
/// defined no-op.
int ex_worklet_bind_shared_values(
    ExactHermesRuntime* runtime,
    void* slab,
    size_t slot_count);

/// Register the measure(nodeId) host callback. The callback fills
/// out_frame4 with {x, y, width, height} and returns 1, or returns 0 for
/// unknown nodes (worklet JS sees null). Read from the host's presenter
/// snapshot — never the kernel.
void ex_worklet_set_measure_callback(
    ExactHermesRuntime* runtime,
    int (*callback)(uint32_t node_id, float* out_frame4, void* context),
    void* context);

/// Drain buffered log(...) entries as a JSON array of argument arrays
/// (malloc'd; free with ex_hermes_free_string). NULL when empty.
char* ex_worklet_drain_logs(ExactHermesRuntime* runtime);

/// Drain buffered scheduleOnAppRuntime entries as a JSON array of
/// {"name","args"} objects (malloc'd; free with ex_hermes_free_string).
/// NULL when empty. The host forwards these to the app runtime.
char* ex_worklet_drain_scheduled(ExactHermesRuntime* runtime);

#ifdef __cplusplus
}
#endif

#endif // EXACT_RUNTIME_H
