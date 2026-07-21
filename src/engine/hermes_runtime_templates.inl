// hermes_runtime_templates.inl
//
// Template function definitions used by both hermes_runtime.cc and
// hermes_runtime_debugger.cc. Included (not compiled separately)
// because C++ templates require full definitions at the point of
// instantiation.

#ifndef HERMES_RUNTIME_TEMPLATES_INL
#define HERMES_RUNTIME_TEMPLATES_INL

#include "hermes_runtime_internal.h"

template <typename F>
std::string runOnRuntimeThread(
    ExactHermesRuntime* runtime,
    F func,
    bool* ingressBlocked = nullptr) {
  if (!runtime) {
    return std::string();
  }
  if (!exactRuntimeDebuggerIngressAllowed(runtime)) {
    if (ingressBlocked) *ingressBlocked = true;
    return std::string();
  }

  auto safe_call = [runtime, func = std::move(func)]() mutable -> std::string {
    // A command can snapshot the debugger immediately before app-bundle begin
    // closes ingress. Recheck on the runtime thread so that already-queued
    // triggerInterrupt_TS work cannot enter the capture window.
    if (!exactRuntimeDebuggerIngressAllowed(runtime)) {
      return std::string();
    }
    try {
      return func(runtime);
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, err.getMessage().c_str());
      return std::string();
    } catch (const std::exception& err) {
      ex_host_console_log(1, err.what());
      return std::string();
    } catch (...) {
      ex_host_console_log(1, "Unknown native error");
      return std::string();
    }
  };

  if (std::this_thread::get_id() == runtime->runtime_thread) {
    if (!snapshotDebugger(runtime)) {
      if (ingressBlocked && !exactRuntimeDebuggerIngressAllowed(runtime)) {
        *ingressBlocked = true;
      }
      return std::string();
    }
    return safe_call();
  }

  std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI>
      debugger_snapshot;
  auto command = exactRuntimeAdmitDebuggerCommand(runtime, &debugger_snapshot);
  if (!command || !debugger_snapshot) {
    if (ingressBlocked && !exactRuntimeDebuggerIngressAllowed(runtime)) {
      *ingressBlocked = true;
    }
    return std::string();
  }

  try {
    debugger_snapshot->triggerInterrupt_TS(
        [runtime, command, safe_call](
            facebook::hermes::HermesRuntime&) mutable {
          if (exactRuntimeDebuggerCommandCancelled(command)) return;
          exactRuntimeSettleDebuggerCommand(
              runtime, command, safe_call());
        });
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
    exactRuntimeSettleDebuggerCommand(runtime, command);
    return std::string();
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
    exactRuntimeSettleDebuggerCommand(runtime, command);
    return std::string();
  } catch (...) {
    ex_host_console_log(1, "Unknown native error");
    exactRuntimeSettleDebuggerCommand(runtime, command);
    return std::string();
  }
  exactRuntimeDebuggerInterruptQueuedTestPause(runtime, command);
  bool cancelled = false;
  auto result = exactRuntimeWaitDebuggerCommand(
      runtime, command, &cancelled);
  if (ingressBlocked && cancelled &&
      !exactRuntimeDebuggerIngressAllowed(runtime)) {
    *ingressBlocked = true;
  }
  return result;
}

template <typename F>
std::string withDebuggerOnRuntimeThread(ExactHermesRuntime* runtime, F func) {
  if (!exactRuntimeDebuggerIngressAllowed(runtime)) {
    return std::string();
  }
  if (!runtime || !runtime->runtime) {
    return std::string();
  }

  auto safe_call = [runtime, func = std::move(func)]() mutable -> std::string {
    // See runOnRuntimeThread: the second check closes the snapshot-to-callback
    // race for every debugger metadata/breakpoint/pause operation.
    if (!exactRuntimeDebuggerIngressAllowed(runtime)) {
      return std::string();
    }
    try {
      return func(runtime, runtime->runtime->getDebugger());
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, err.getMessage().c_str());
      return std::string();
    } catch (const std::exception& err) {
      ex_host_console_log(1, err.what());
      return std::string();
    } catch (...) {
      ex_host_console_log(1, "Unknown native error");
      return std::string();
    }
  };

  if (std::this_thread::get_id() == runtime->runtime_thread) {
    if (!snapshotDebugger(runtime)) return std::string();
    return safe_call();
  }

  std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI>
      debugger_snapshot;
  auto command = exactRuntimeAdmitDebuggerCommand(runtime, &debugger_snapshot);
  if (!command || !debugger_snapshot) {
    return std::string();
  }

  try {
    debugger_snapshot->triggerInterrupt_TS(
        [runtime, command, safe_call](
            facebook::hermes::HermesRuntime&) mutable {
          if (exactRuntimeDebuggerCommandCancelled(command)) return;
          exactRuntimeSettleDebuggerCommand(
              runtime, command, safe_call());
        });
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
    exactRuntimeSettleDebuggerCommand(runtime, command);
    return std::string();
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
    exactRuntimeSettleDebuggerCommand(runtime, command);
    return std::string();
  } catch (...) {
    ex_host_console_log(1, "Unknown native error");
    exactRuntimeSettleDebuggerCommand(runtime, command);
    return std::string();
  }
  exactRuntimeDebuggerInterruptQueuedTestPause(runtime, command);
  return exactRuntimeWaitDebuggerCommand(runtime, command);
}

#endif // HERMES_RUNTIME_TEMPLATES_INL
