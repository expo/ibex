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
std::string runOnRuntimeThread(ExactHermesRuntime* runtime, F func) {
  if (!runtime) {
    return std::string();
  }

  auto safe_call = [runtime, &func]() -> std::string {
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

  auto debugger_snapshot = snapshotDebugger(runtime);
  if (!debugger_snapshot) {
    return std::string();
  }

  if (std::this_thread::get_id() == runtime->runtime_thread) {
    return safe_call();
  }
  if (!runtime->debugger_available.load()) {
    return std::string();
  }

  auto promise = std::make_shared<std::promise<std::string>>();
  auto future = promise->get_future();
  try {
    debugger_snapshot->triggerInterrupt_TS(
        [promise, safe_call](facebook::hermes::HermesRuntime&) mutable {
          promise->set_value(safe_call());
        });
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
  return future.get();
}

template <typename F>
std::string withDebuggerOnRuntimeThread(ExactHermesRuntime* runtime, F func) {
  auto debugger_snapshot = snapshotDebugger(runtime);
  if (!runtime || !runtime->runtime || !debugger_snapshot) {
    return std::string();
  }

  auto safe_call = [runtime, debugger_snapshot, &func]() -> std::string {
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
    return safe_call();
  }
  if (!runtime->debugger_available.load()) {
    return std::string();
  }

  auto promise = std::make_shared<std::promise<std::string>>();
  auto future = promise->get_future();
  try {
    debugger_snapshot->triggerInterrupt_TS(
        [promise, safe_call](facebook::hermes::HermesRuntime&) mutable {
          promise->set_value(safe_call());
        });
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

  return future.get();
}

#endif // HERMES_RUNTIME_TEMPLATES_INL
