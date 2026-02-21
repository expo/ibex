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

/// Wake the event loop when a callback is pushed from a background thread.
/// Called automatically by the runtime when async operations complete.
void ex_hermes_notify_callback(void);

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
// Debugger (optional, may not be available on iOS builds)
// =============================================================================

/// Enable the Hermes debugger. Returns non-zero on success.
int ex_hermes_debugger_enable(ExactHermesRuntime* runtime);

// =============================================================================
// Memory Management
// =============================================================================

/// Request garbage collection
void ex_hermes_gc(ExactHermesRuntime* runtime);

#ifdef __cplusplus
}
#endif

#endif // EXACT_RUNTIME_H
