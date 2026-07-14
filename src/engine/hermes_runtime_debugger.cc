// hermes_runtime_debugger.cc
//
// Extracted from hermes_runtime.cc: CDP debugger API functions.
// Provides enable/disable, breakpoints, pause/resume, eval, and event polling.

#include <cstring>
#include <future>
#include <mutex>
#include <sstream>
#include <string>

#include "hermes_runtime_internal.h"

#if defined(HERMES_ENABLE_DEBUGGER) && EXACT_HAS_HERMES_ASYNC_DEBUGGER
#define EXACT_COMPILE_HERMES_DEBUGGER 1
#include "hermes_runtime_templates.inl"
#else
#define EXACT_COMPILE_HERMES_DEBUGGER 0
#endif

// ---------------------------------------------------------------------------
// Debugger API
// ---------------------------------------------------------------------------

extern "C" int ex_hermes_debugger_enable(ExactHermesRuntime* runtime) {
#if !EXACT_COMPILE_HERMES_DEBUGGER
  (void)runtime;
  return 0;
#else
  auto debugger = snapshotDebugger(runtime);
  if (!runtime || !debugger) {
    return 0;
  }
  if (runtime->debugger_attached.load()) {
    return 1;
  }

  runtime->debugger_attached.store(true);
  auto result = runOnRuntimeThread(runtime, [debugger](ExactHermesRuntime* handle) {
    if (!handle || !handle->runtime) {
      return std::string();
    }
    auto& runtime_debugger = handle->runtime->getDebugger();
    runtime_debugger.setIsDebuggerAttached(true);
    auto target = exactRuntimeCallbackTarget(handle);
    debugger->setDebuggerEventCallback_TS(
        [handle, target](facebook::hermes::HermesRuntime& rt,
                 facebook::hermes::debugger::AsyncDebuggerAPI&,
                 facebook::hermes::debugger::DebuggerEventType) {
          // @ref LLP 0003#the-platform-shims-map — async debugger callbacks
          // can run as teardown races the runtime. Pin across every handle
          // deref so ex_hermes_destroy cannot free the runtime in the old
          // check-then-deref gap.
          withRuntimePinned(target, [&]() {
            if (!handle->debugger_attached.load()) {
              return;
            }
            auto event = buildPausedEvent(rt.getDebugger());
            if (!event.empty()) {
              pushDebugEvent(handle, event);
            }
          });
        });
    handle->debugger_callback_set = true;

    emitNewScripts(handle, runtime_debugger);
    return std::string("1");
  });

  if (result != "1") {
    disableDebugger(runtime);
    return 0;
  }

  return 1;
#endif
}

extern "C" char* ex_hermes_debugger_get_scripts(ExactHermesRuntime* runtime) {
#if !EXACT_COMPILE_HERMES_DEBUGGER
  (void)runtime;
  return nullptr;
#else
  auto json = withDebuggerOnRuntimeThread(runtime, [](ExactHermesRuntime* handle, auto& debugger) {
    std::ostringstream out;
    out << "[";
    if (handle && handle->runtime) {
      auto scripts = debugger.getLoadedScripts();
      for (size_t i = 0; i < scripts.size(); ++i) {
        const auto& script = scripts[i];
        if (i > 0) {
          out << ",";
        }
        out << "{";
        out << "\"id\":" << script.fileId << ",";
        out << "\"url\":" << jsonString(script.fileName);
        out << "}";
      }
    }
    out << "]";
    return out.str();
  });

  if (json.empty()) {
    return nullptr;
  }
  char* heap = static_cast<char*>(malloc(json.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, json.data(), json.size());
  heap[json.size()] = '\0';
  return heap;
#endif
}

extern "C" char* ex_hermes_debugger_get_script_source(
    ExactHermesRuntime* runtime,
    uint32_t script_id) {
#if !EXACT_COMPILE_HERMES_DEBUGGER
  (void)runtime;
  (void)script_id;
  return nullptr;
#else
  auto source = withDebuggerOnRuntimeThread(runtime, [=](ExactHermesRuntime* handle, auto& debugger) {
    if (!handle || !handle->runtime) {
      return std::string();
    }
    auto it = handle->script_id_to_name.find(script_id);
    if (it == handle->script_id_to_name.end()) {
      auto scripts = debugger.getLoadedScripts();
      for (const auto& script : scripts) {
        handle->script_id_to_name[script.fileId] = script.fileName;
      }
      it = handle->script_id_to_name.find(script_id);
    }
    if (it == handle->script_id_to_name.end()) {
      return std::string();
    }
    auto src_it = handle->sources_by_name.find(it->second);
    if (src_it == handle->sources_by_name.end()) {
      return std::string();
    }
    return src_it->second;
  });

  if (source.empty()) {
    return nullptr;
  }
  char* heap = static_cast<char*>(malloc(source.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, source.data(), source.size());
  heap[source.size()] = '\0';
  return heap;
#endif
}

extern "C" char* ex_hermes_debugger_set_breakpoint(
    ExactHermesRuntime* runtime,
    uint32_t script_id,
    uint32_t line_number,
    uint32_t column_number,
    const char* condition) {
#if !EXACT_COMPILE_HERMES_DEBUGGER
  (void)runtime;
  (void)script_id;
  (void)line_number;
  (void)column_number;
  (void)condition;
  return nullptr;
#else
  auto json = withDebuggerOnRuntimeThread(runtime, [=](ExactHermesRuntime* handle, auto& debugger) {
    if (!handle || !handle->runtime) {
      return std::string();
    }
    using facebook::hermes::debugger::kInvalidLocation;
    using facebook::hermes::debugger::SourceLocation;

    SourceLocation loc;
    loc.fileId = script_id;
    loc.line = line_number + 1;
    loc.column = column_number + 1;

    auto id = debugger.setBreakpoint(loc);
    if (condition && std::strlen(condition) > 0) {
      debugger.setBreakpointCondition(id, condition);
    }
    auto info = debugger.getBreakpointInfo(id);
    auto resolved = info.resolved ? info.resolvedLocation : info.requestedLocation;

    uint32_t out_line =
        resolved.line == kInvalidLocation ? line_number : (resolved.line > 0 ? resolved.line - 1 : 0);
    uint32_t out_column =
        resolved.column == kInvalidLocation ? column_number : (resolved.column > 0 ? resolved.column - 1 : 0);

    std::ostringstream out;
    out << "{";
    out << "\"id\":" << id << ",";
    out << "\"scriptId\":" << resolved.fileId << ",";
    out << "\"line\":" << out_line << ",";
    out << "\"column\":" << out_column;
    out << "}";
    return out.str();
  });

  if (json.empty()) {
    return nullptr;
  }
  char* heap = static_cast<char*>(malloc(json.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, json.data(), json.size());
  heap[json.size()] = '\0';
  return heap;
#endif
}

extern "C" void ex_hermes_debugger_remove_breakpoint(
    ExactHermesRuntime* runtime,
    uint64_t breakpoint_id) {
#if !EXACT_COMPILE_HERMES_DEBUGGER
  (void)runtime;
  (void)breakpoint_id;
  return;
#else
  withDebuggerOnRuntimeThread(runtime, [=](ExactHermesRuntime* handle, auto& debugger) {
    if (handle && handle->runtime) {
      debugger.deleteBreakpoint(breakpoint_id);
    }
    return std::string();
  });
#endif
}

extern "C" void ex_hermes_debugger_pause(ExactHermesRuntime* runtime) {
#if !EXACT_COMPILE_HERMES_DEBUGGER
  (void)runtime;
  return;
#else
  if (!runtime || !runtime->runtime || !runtime->debugger_available.load()) {
    return;
  }
  withDebuggerOnRuntimeThread(runtime, [](ExactHermesRuntime* handle, auto& debugger) {
    if (!handle || !handle->runtime) {
      return std::string();
    }
    debugger.triggerAsyncPause(facebook::hermes::debugger::AsyncPauseKind::Explicit);
    return std::string();
  });
#endif
}

extern "C" void ex_hermes_debugger_resume(ExactHermesRuntime* runtime, int command) {
#if !EXACT_COMPILE_HERMES_DEBUGGER
  (void)runtime;
  (void)command;
  return;
#else
  auto debugger = snapshotDebugger(runtime);
  if (!runtime || !debugger) {
    return;
  }
  auto cmd = facebook::hermes::debugger::AsyncDebugCommand::Continue;
  switch (command) {
    case 1:
      cmd = facebook::hermes::debugger::AsyncDebugCommand::StepInto;
      break;
    case 2:
      cmd = facebook::hermes::debugger::AsyncDebugCommand::StepOver;
      break;
    case 3:
      cmd = facebook::hermes::debugger::AsyncDebugCommand::StepOut;
      break;
    default:
      cmd = facebook::hermes::debugger::AsyncDebugCommand::Continue;
      break;
  }

  try {
    auto target = exactRuntimeCallbackTarget(runtime);
    debugger->triggerInterrupt_TS([runtime, target, debugger, cmd](facebook::hermes::HermesRuntime&) {
      // @ref LLP 0003#the-platform-shims-map — see the event callback above.
      withRuntimePinned(target, [&]() {
        if (debugger->resumeFromPaused(cmd)) {
          pushDebugEvent(runtime, "{\"method\":\"Debugger.resumed\",\"params\":{}}");
        }
      });
    });
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
  } catch (...) {
    ex_host_console_log(1, "Unknown native error");
  }
#endif
}

extern "C" char* ex_hermes_debugger_next_event(ExactHermesRuntime* runtime) {
#if !EXACT_COMPILE_HERMES_DEBUGGER
  (void)runtime;
  return nullptr;
#else
  if (!runtime) {
    return nullptr;
  }
  std::lock_guard<std::mutex> lock(runtime->debug_mutex);
  if (runtime->debug_events.empty()) {
    return nullptr;
  }
  auto event = std::move(runtime->debug_events.front());
  runtime->debug_events.pop_front();
  if (event.empty()) {
    return nullptr;
  }
  char* heap = static_cast<char*>(malloc(event.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, event.data(), event.size());
  heap[event.size()] = '\0';
  return heap;
#endif
}

extern "C" char* ex_hermes_debugger_eval(
    ExactHermesRuntime* runtime,
    const char* expression,
    uint32_t frame_index) {
#if !EXACT_COMPILE_HERMES_DEBUGGER
  (void)runtime;
  (void)expression;
  (void)frame_index;
  return nullptr;
#else
  auto debugger = snapshotDebugger(runtime);
  if (!expression || !runtime || !debugger) {
    return nullptr;
  }
  auto expr = std::string(expression);

  auto result_holder = std::make_shared<std::string>();
  auto result_mutex = std::make_shared<std::mutex>();
  auto result_cv = std::make_shared<std::condition_variable>();
  auto result_ready = std::make_shared<bool>(false);

  if (runtime->debugger_attached.load()) {
    debugger->triggerInterrupt_TS(
        [debugger, expr, frame_index, result_holder, result_mutex, result_cv, result_ready](
            facebook::hermes::HermesRuntime& rt) {
          auto ok = debugger->evalWhilePaused(
              expr,
              frame_index,
              [&rt, result_holder, result_mutex, result_cv, result_ready](
                  facebook::hermes::HermesRuntime&,
                  const facebook::hermes::debugger::EvalResult& result) {
                std::ostringstream out;
                if (result.isException) {
                  out << "{\"exceptionDetails\":{\"text\":"
                      << jsonString(result.exceptionDetails.text) << "}}";
                } else {
                  out << "{\"result\":" << makeRemoteObject(rt, result.value) << "}";
                }
                std::lock_guard<std::mutex> lock(*result_mutex);
                *result_holder = out.str();
                *result_ready = true;
                result_cv->notify_one();
              });

          if (!ok) {
            try {
              auto buffer = std::make_shared<facebook::jsi::StringBuffer>(expr);
              auto result = rt.evaluateJavaScript(buffer, "<cdp>");
              std::ostringstream out;
              out << "{\"result\":" << makeRemoteObject(rt, result) << "}";
              std::lock_guard<std::mutex> lock(*result_mutex);
              *result_holder = out.str();
              *result_ready = true;
              result_cv->notify_one();
            } catch (const facebook::jsi::JSError& err) {
              std::ostringstream out;
              out << "{\"exceptionDetails\":{\"text\":" << jsonString(err.getMessage()) << "}}";
              std::lock_guard<std::mutex> lock(*result_mutex);
              *result_holder = out.str();
              *result_ready = true;
              result_cv->notify_one();
            } catch (const std::exception& err) {
              std::ostringstream out;
              out << "{\"exceptionDetails\":{\"text\":" << jsonString(err.what()) << "}}";
              std::lock_guard<std::mutex> lock(*result_mutex);
              *result_holder = out.str();
              *result_ready = true;
              result_cv->notify_one();
            }
          }
        });

    std::unique_lock<std::mutex> lock(*result_mutex);
    if (result_cv->wait_for(lock, std::chrono::seconds(10), [&result_ready] { return *result_ready; })) {
      if (!result_holder->empty()) {
        char* heap = static_cast<char*>(malloc(result_holder->size() + 1));
        if (heap) {
          memcpy(heap, result_holder->data(), result_holder->size());
          heap[result_holder->size()] = '\0';
          return heap;
        }
      }
    }
  }

  // Fallback: use runOnRuntimeThread for regular evaluation (not paused)
  auto json = runOnRuntimeThread(runtime, [expr](ExactHermesRuntime* handle) {
    if (!handle || !handle->runtime) {
      return std::string();
    }
    auto& rt = *handle->runtime;
    try {
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(expr);
      auto result = rt.evaluateJavaScript(buffer, "<cdp>");
      std::ostringstream out;
      out << "{\"result\":" << makeRemoteObject(rt, result) << "}";
      return out.str();
    } catch (const facebook::jsi::JSError& err) {
      std::ostringstream out;
      out << "{\"exceptionDetails\":{\"text\":" << jsonString(err.getMessage()) << "}}";
      return out.str();
    } catch (const std::exception& err) {
      std::ostringstream out;
      out << "{\"exceptionDetails\":{\"text\":" << jsonString(err.what()) << "}}";
      return out.str();
    }
  });

  if (json.empty()) {
    return nullptr;
  }
  char* heap = static_cast<char*>(malloc(json.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, json.data(), json.size());
  heap[json.size()] = '\0';
  return heap;
#endif
}
