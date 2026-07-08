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

/// Create a new Hermes runtime with all host functions installed.
/// This includes: timers, console, crypto, compression, fetch, WebSocket,
/// module loader, and all Node.js-compatible builtins.
/// @return Pointer to runtime, or NULL on failure
ExactHermesRuntime* ex_hermes_create(void);

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
/// @return 0 on success, non-zero on error (out_value contains error message)
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

/// Check if there are any pending tasks (timers, callbacks, etc.)
/// @return 1 if there are pending tasks, 0 if idle
int ex_hermes_has_pending_tasks(ExactHermesRuntime* runtime);

/// Get the current number of queued cross-thread callbacks waiting to run.
uint32_t ex_hermes_callback_backlog(ExactHermesRuntime* runtime);

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

/// Queue a lightweight watchdog callback onto the cross-thread callback queue.
/// The callback executes during the next poll on the runtime-owning thread.
void ex_hermes_schedule_watchdog_heartbeat(
    ExactHermesRuntime* runtime,
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
/// success payload or `-` for an error message.
void ex_hermes_set_host_call(
    ExactHermesRuntime* runtime,
    char* (*callback)(const char* op, const char* args_json));

/// Install the async `__hostCallAsync(op, argsJson)` bridge in JavaScript
/// (LLP 0297 W3). `__hostCallAsync` returns a Promise; the callback receives
/// the owning runtime, a call id, and the op/args, and must eventually
/// complete the call with ex_hermes_resolve_host_call — synchronously inline
/// or later from any thread. Payload sigils match `__hostCall`: `+json`
/// resolves with the parsed JSON, `-message` rejects with an Error.
void ex_hermes_set_host_call_async(
    ExactHermesRuntime* runtime,
    void (*callback)(ExactHermesRuntime* runtime,
                     uint64_t call_id,
                     const char* op,
                     const char* args_json));

/// Complete a pending `__hostCallAsync` call. Safe to invoke from any thread;
/// resolution is delivered on the runtime's thread via the callback queue.
/// Unknown / already-completed call ids and dead runtimes are ignored.
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
