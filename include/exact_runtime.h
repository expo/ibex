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
/// @param runtime The runtime handle
/// @param now_ms Current time in milliseconds since epoch
/// @return Number of tasks executed, or negative on error
int ex_hermes_poll(ExactHermesRuntime* runtime, uint64_t now_ms);

/// Get the time (in ms since epoch) when the next timer is due.
/// @return Next timer due time, or -1 if no timers are pending
int64_t ex_hermes_next_timer(ExactHermesRuntime* runtime);

/// Check if there are any pending tasks (timers, callbacks, etc.)
/// @return 1 if there are pending tasks, 0 if idle
int ex_hermes_has_pending_tasks(ExactHermesRuntime* runtime);

/// Get the current number of queued cross-thread callbacks waiting to run.
uint32_t ex_hermes_callback_backlog(ExactHermesRuntime* runtime);

/// Wake the event loop when a callback is pushed from a background thread.
/// Called automatically by the runtime when async operations complete.
void ex_hermes_notify_callback(void);

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

/// Attach the Exact kernel handle so the runtime can expose kernel-backed
/// state-mirror snapshots and module metadata through the `exact` global.
void ex_hermes_set_kernel_handle(
    ExactHermesRuntime* runtime,
    void* kernel_handle);

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

#ifdef __cplusplus
}
#endif

#endif // EXACT_RUNTIME_H
