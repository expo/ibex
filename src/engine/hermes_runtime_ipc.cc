#include "hermes_runtime_internal.h"

#include <stdexcept>
#include <string>

#if __has_include("bootstrap_bytecode.h")
#include "bootstrap_bytecode.h"
#define HAS_PRECOMPILED_BOOTSTRAP 1
#endif

#if __has_include("bootstrap_source.h")
#include "bootstrap_source.h"
#endif

void installIpcListenerPatch(ExactHermesRuntime* handle) {
  if (!handle || !handle->runtime || IPC_LISTENER_SRC[0] == '\0') {
    return;
  }

#if defined(_WIN32)
  if (startup_trace_enabled()) {
    fprintf(stderr, "[startup]   ipc_listener skipped on Windows\n");
  }
  return;
#endif

  bool sourceIpcListener = env_flag_enabled("EX_IPC_LISTENER_SOURCE");
  bool ipcListenerHbc = env_flag_enabled("EX_IPC_LISTENER_HBC") || !sourceIpcListener;

  try {
#ifdef HAS_PRECOMPILED_BOOTSTRAP
    bool ipcListenerEvaluated = eval_bootstrap_script(
        handle,
        IPC_LISTENER_SRC,
        reinterpret_cast<const uint8_t*>(IPC_LISTENER_HBC),
        IPC_LISTENER_HBC_LEN,
        "<ipc-listener>",
        sourceIpcListener || !ipcListenerHbc,
        ipcListenerHbc);
#else
    bool ipcListenerEvaluated =
        eval_bootstrap_script(handle, IPC_LISTENER_SRC, nullptr, 0, "<ipc-listener>", true, false);
#endif
    if (!ipcListenerEvaluated) {
      throw std::runtime_error("IPC listener patch failed to evaluate");
    }
  } catch (const facebook::jsi::JSError& err) {
    reportStartupFailure(handle, "IPC listener patch", err.getMessage());
  } catch (const std::exception& err) {
    reportStartupFailure(handle, "IPC listener patch", err.what());
  } catch (...) {
    reportStartupFailure(handle, "IPC listener patch", "unknown evaluation failure");
  }
}
