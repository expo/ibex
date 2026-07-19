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

/// Exact embedder execution contexts. App and agent runtimes receive separate
/// operation endowment sets through `ex_hermes_set_exact_host_call_async`.
/// UI worklets are created through `ex_worklet_create` and deliberately cannot
/// install this ingress; their existing SharedValue/Motion ABI is the complete
/// host endowment.
typedef enum ExactEmbedderContext {
    EXACT_EMBEDDER_CONTEXT_APP = 1,
    EXACT_EMBEDDER_CONTEXT_AGENT = 2,
} ExactEmbedderContext;

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

/// Create the profile-distinct `exact-session/v1` runtime only when the Host
/// has authenticated the restricted artifact with this digest. The runtime has
/// no general eval/module/bootstrap surface and accepts exactly one bundle via
/// ex_hermes_run_restricted_exact_bundle.
ExactHermesRuntime* ex_hermes_create_restricted_exact(
    const char* artifact_digest);

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

/// Supply the already authenticated activation inputs before restricted code
/// runs. This is owner-thread-only and single-use. The checkpoint may be empty
/// (genesis) but the deterministic RNG seeds may not both be zero.
int ex_hermes_configure_restricted_exact_activation(
    ExactHermesRuntime* runtime,
    const uint8_t* checkpoint_data,
    size_t checkpoint_len,
    uint64_t wall_clock_ms,
    uint64_t rng_seed_0,
    uint64_t rng_seed_1);

/// Consume and execute the one authenticated bundle bound to the Host artifact.
/// The exact host-operation and output callbacks must already be installed.
/// Returns 0 on success, 1 on refusal/evaluation failure, or 2 when HBC was
/// rejected before execution. `out_error`, when non-NULL, is freed with
/// ex_hermes_free_string. A failed ingress poisons the runtime.
int ex_hermes_run_restricted_exact_bundle(
    ExactHermesRuntime* runtime,
    char** out_error);

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
/// @return Number of tasks executed, or negative on error
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

/// Install the dedicated asynchronous Exact embedder ingress as
/// `exact.invokeHostAsync(operationId, ArrayBuffer | ArrayBufferView)
///   -> Promise<Uint8Array>`.
///
/// This is not the generic `__hostCall` channel: operations are numeric,
/// payloads are binary, and each app/agent runtime receives one immutable,
/// canonical endowment set. The runtime predeclares one stable `exact` object
/// before package-compartment capture; successful installation publishes a
/// non-writable/non-configurable method on that object and atomically performs
/// the one-shot package-baseline finalization when it is still pending.
/// `allowed_operation_ids` must be non-empty,
/// strictly increasing, contain no zero ID, and contain at most 4096 entries.
/// The setter succeeds at most once per runtime. It is available to armed and
/// diagnostic app/agent runtimes, but always refuses restricted UI worklets.
/// Armed runtimes additionally require `operation_manifest_digest` and the
/// context/endowment set to exactly match the Exact binding authenticated by
/// the armed snapshot and its protected operation-manifest artifact.
///
/// Return 0 on success; negative values indicate malformed arguments,
/// unsupported context/runtime kind, or an attempted replacement.
/// This setter creates JSI objects and therefore must be called on the runtime
/// owner thread; an off-owner-thread call returns -7 without touching JSI or
/// installing any endowment.
/// `payload` passed to `callback` is borrowed only for that callback invocation;
/// an asynchronous embedder must copy it before returning.
/// The callback runs inline on the runtime owner thread and must return
/// promptly. `context` and the callback implementation must remain valid until
/// runtime destruction. At most 1024 calls may be pending; excess calls reject
/// deterministically. Runtime destruction abandons pending calls, so the
/// embedder must cancel its native work and must not resolve through a destroyed
/// runtime pointer.
int ex_hermes_set_exact_host_call_async(
    ExactHermesRuntime* runtime,
    ExactEmbedderContext context_kind,
    const uint32_t* allowed_operation_ids,
    size_t allowed_operation_count,
    const char* operation_manifest_digest,
    void (*callback)(ExactHermesRuntime* runtime,
                     uint64_t call_id,
                     uint32_t operation_id,
                     const uint8_t* payload,
                     size_t payload_len,
                     void* context),
    void* context);

/// Complete a pending `exact.invokeHostAsync` call. Safe from any thread.
/// Status zero resolves with a Uint8Array copy of `payload`; non-zero status
/// rejects with an Error whose message is decoded from the payload (or a
/// generic message when the payload is empty). Completion payloads are limited
/// to 16 MiB; a malformed or oversized completion consumes the call ID and
/// rejects it. Unknown, stale, replayed, and already-completed call IDs are
/// ignored.
void ex_hermes_resolve_exact_host_call(
    ExactHermesRuntime* runtime,
    uint64_t call_id,
    int32_t status,
    const uint8_t* payload,
    size_t payload_len);

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

/// Authenticate a paired snapshot template/expected identity against the
/// loaded engine and checked registry, validate protected artifacts/package
/// roots, replace the template nonce with OS randomness, and recompute the
/// checked armed digest. Returns a heap-owned strict JSON success/refusal
/// envelope; free it with `ex_host_free_string`.
/// A success envelope's `artifacts` object has the stable schema
/// `{ artifactSchema, armedSnapshotDigest, snapshot, expectedIdentity }`, with
/// `artifactSchema` equal to `ibex/armed-embedder-artifacts/1`.
///
/// Preparing an artifact does not advertise a target. A later
/// `ex_host_install_armed` still refuses any target without report-derived
/// complete cells.
char* ex_host_prepare_armed_embedder_artifacts(
    const uint8_t* snapshot_template,
    size_t snapshot_template_len,
    const uint8_t* expected_identity,
    size_t expected_identity_len);

/// Authenticate a generic Ibex artifact pair, derive Exact app/agent/UI
/// endowments from one strict operation manifest, materialize that manifest as
/// the fifth protected artifact, and return a fresh paired artifact envelope.
/// This target-local operation must run after installation so filesystem
/// object identities describe the engine and roots that will actually execute.
/// It does not advertise a target; `ex_host_install_armed` retains that gate.
char* ex_host_prepare_exact_armed_embedder_artifacts(
    const uint8_t* snapshot_template,
    size_t snapshot_template_len,
    const uint8_t* expected_identity,
    size_t expected_identity_len,
    const uint8_t* operation_manifest,
    size_t operation_manifest_len);

/// Build a complete production Exact artifact pair directly against the
/// installed target's engine, project root, checked CapSec identities, and
/// strict Exact operation manifest. `project_root_utf8` is not NUL terminated.
/// This removes any requirement to package filesystem identities produced on
/// another machine or at another install path. It does not advertise a target;
/// `ex_host_install_armed` retains that report-derived gate.
char* ex_host_build_exact_armed_embedder_artifacts(
    const uint8_t* project_root_utf8,
    size_t project_root_utf8_len,
    const uint8_t* operation_manifest,
    size_t operation_manifest_len);

/// Release a heap-owned string returned by the host ABI.
void ex_host_free_string(char* value);

/// Return 1 only when the installed host has the exact snapshot digest.
int ex_host_matches_armed_snapshot_digest(const char* digest);
int ex_host_is_armed(void);

/// Evaluate a strict typed decision-set JSON document and its effect-gate JSON
/// array against the installed armed context. Returns a heap-owned JSON
/// decision/evidence or error envelope; free it with ex_host_free_string.
char* ex_host_evaluate_typed_decision(const uint8_t* decision_set,
                                      size_t decision_set_len,
                                      const uint8_t* gates,
                                      size_t gates_len);

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

// M6's steady-state ABI is intentionally fixed-width. These limits are part
// of the C contract: callers reject/lower larger programs at build time
// rather than allocating variable argument/result containers on a frame.
#define EX_WORKLET_MAX_INPUT_SLOTS 16
#define EX_WORKLET_MAX_OUTPUT_SLOTS 16
#define EX_WORKLET_MAX_RUN_ON_JS_SLOTS 8
#define EX_WORKLET_TYPED_QUEUE_CAPACITY 256

/// The restricted runtime currently installs UTF-8 function-expression
/// source. This is an explicit format value rather than an implicit bool so
/// an eventual HBC artifact can be added without guessing from bytes. The M6
/// source-install decision is guarded by the install-cost benchmark in the
/// Ibex engine tests; unsupported formats fail closed.
typedef enum ExWorkletInstallFormat {
    EX_WORKLET_INSTALL_SOURCE_UTF8 = 1,
} ExWorkletInstallFormat;

typedef enum ExWorkletCaptureKind {
    EX_WORKLET_CAPTURE_F32 = 1,
    EX_WORKLET_CAPTURE_BOOL = 2,
    EX_WORKLET_CAPTURE_SHARED_VALUE = 3,
} ExWorkletCaptureKind;

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

/// Durable identity for one Exact Motion SharedValue. Ibex treats the fields
/// as opaque and forwards them to the host's validating accessors.
typedef struct ExWorkletSharedValueHandle {
    uint32_t slot;
    uint32_t generation;
    uint32_t epoch;
} ExWorkletSharedValueHandle;

/// Install-time-only capture record. Scalar values and complete SharedValue
/// identities are the entire legal capture surface for math worklets. A
/// compiler must reject mutable JS/object captures before this ABI.
typedef struct ExWorkletCapture {
    uint32_t kind;
    float scalar;
    ExWorkletSharedValueHandle shared_value;
} ExWorkletCapture;

/// One allocation-free worklet -> app-runtime call. `callback_identity` is
/// generated from the app callback at build time; `source_identity` and
/// `source_sequence` let the consumer preserve/diagnose per-worklet order.
typedef struct ExWorkletScheduledCall {
    uint64_t source_identity;
    uint64_t source_sequence;
    uint64_t generation;
    uint32_t callback_identity;
    uint32_t argument_count;
    float arguments[EX_WORKLET_MAX_RUN_ON_JS_SLOTS];
} ExWorkletScheduledCall;

typedef struct ExWorkletInstallMetrics {
    uint64_t source_install_count;
    uint64_t reused_install_count;
    uint64_t source_install_total_ns;
    uint64_t source_install_max_ns;
} ExWorkletInstallMetrics;

/// Runtime-side rated-publish input. Motion writes the latest finite raw
/// sample plus a monotonically increasing dirty generation; the app-runtime
/// pacer forwards one coalesced sample per declared slot. Payload evaluation
/// and provider invocation are owned by the app callback, never main/UI.
typedef struct ExMotionRatedPublishSample {
    uint64_t channel_identity;
    uint64_t dirty_generation;
    uint64_t sample_time_ns;
    uint32_t value_count;
    uint32_t flags; // bit 0 = heartbeat, bit 1 = programmatic/default sample
    float values[EX_WORKLET_MAX_RUN_ON_JS_SLOTS];
} ExMotionRatedPublishSample;

/// Install a Motion math worklet and return its stable identity, computed
/// from artifact bytes plus the serialized capture set. Reinstalling the
/// same artifact/captures in one generation reuses the resident function.
/// Captures are read by `worklet.capture(index)`,
/// `worklet.captureGet(index)`, and `worklet.captureSet(index, value)`.
int ex_worklet_install_typed(
    ExactHermesRuntime* runtime,
    uint32_t install_format,
    const uint8_t* artifact,
    size_t artifact_len,
    const ExWorkletCapture* captures,
    uint32_t capture_count,
    uint64_t generation,
    uint64_t* out_identity,
    char** out_error);

/// Invoke by stable identity with fixed f32 input/output slots. The worklet
/// receives each input as a positional number and writes results with
/// `worklet.output(index, value)`. No strings, JSON, or result allocation
/// occur on a successful steady-state host path. `out_output_count` is the
/// highest written slot + 1 (zero when no output was written).
int ex_worklet_invoke_typed(
    ExactHermesRuntime* runtime,
    uint64_t identity,
    const float* inputs,
    uint32_t input_count,
    float* outputs,
    uint32_t output_capacity,
    uint32_t* out_output_count);

/// Snapshot source-install cost counters. The call does not reset them.
int ex_worklet_install_metrics(
    ExactHermesRuntime* runtime,
    ExWorkletInstallMetrics* out_metrics);

/// Validating, synchronous main-thread accessors for the restricted worklet
/// runtime. Return 0 for a live read/write; any other verdict is a defined
/// stale/no-op. `read` writes `out_value` only on success. The callbacks must
/// never enter the app runtime or block on another domain.
typedef uint32_t (*ExWorkletSharedValueReadCallback)(
    ExWorkletSharedValueHandle handle,
    float* out_value,
    void* context);
typedef uint32_t (*ExWorkletSharedValueWriteCallback)(
    ExWorkletSharedValueHandle handle,
    float value,
    void* context);

/// Bind typed SharedValue accessors, replacing the historical raw slab
/// pointer. Pass NULL callbacks to unbind. Worklet JS addresses a value as
/// `worklet.sharedValue(slot, generation, epoch)`; invalid/stale identities
/// retain the handle's last-observed local shadow and writes are no-ops.
int ex_worklet_bind_shared_value_accessors(
    ExactHermesRuntime* runtime,
    ExWorkletSharedValueReadCallback read_callback,
    ExWorkletSharedValueWriteCallback write_callback,
    void* context);

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

/// Drain the allocation-free `worklet.runOnJS(callbackIdentity, ...f32)`
/// ring into caller-owned storage. Returns the number copied. A too-small
/// output buffer leaves the remainder queued in FIFO order.
uint32_t ex_worklet_drain_scheduled_typed(
    ExactHermesRuntime* runtime,
    ExWorkletScheduledCall* out_calls,
    uint32_t capacity);

/// Read-and-clear the number of schedule entries evicted by drop-oldest
/// overflow (typed and compatibility JSON queues combined).
uint64_t ex_worklet_take_scheduled_drop_count(ExactHermesRuntime* runtime);

/// Deliver typed runOnJS calls on the APP runtime's owning thread. The app
/// bundle installs `globalThis.__exactRunOnJS(callbackIdentity, metadata,
/// ...args)`. Missing dispatchers are a defined no-op (2).
int ex_hermes_dispatch_worklet_calls(
    ExactHermesRuntime* runtime,
    const ExWorkletScheduledCall* calls,
    uint32_t count,
    uint32_t* out_delivered);

/// Compatibility delivery for `scheduleOnAppRuntime(name, args)`. The app
/// bundle installs `globalThis.__exactScheduleOnAppRuntime(batch,
/// generation)`. Parsing/callback execution happens on the app runtime;
/// the main/UI worklet owner only drains and asynchronously forwards bytes.
int ex_hermes_dispatch_worklet_json_batch(
    ExactHermesRuntime* runtime,
    const uint8_t* batch_json,
    size_t batch_len,
    uint64_t generation);

/// Invoke `globalThis.__exactMotionRatedPublish(channelIdentity, values,
/// metadata)` on the app runtime's owning thread. The callback evaluates the
/// authored payload mapping and calls the capability provider. Missing
/// callback is a defined no-op (2); non-finite input fails closed (1).
int ex_hermes_dispatch_motion_rated_publish(
    ExactHermesRuntime* runtime,
    const ExMotionRatedPublishSample* sample);

#ifdef __cplusplus
}
#endif

#endif // EXACT_RUNTIME_H
