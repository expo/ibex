// hermes_runtime_debugger.cc
//
// Extracted from hermes_runtime.cc: CDP debugger API functions.
// Provides enable/disable, breakpoints, pause/resume, eval, and event polling.

#include <cstring>
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

#if EXACT_COMPILE_HERMES_DEBUGGER
namespace {

constexpr const char* kDebuggerHostTaskUnavailable =
    "{\"exceptionDetails\":{\"text\":\"Debugger host-task boundary is unavailable\"}}";
constexpr const char* kDebuggerHostTaskCheckpointFailed =
    "{\"exceptionDetails\":{\"text\":\"Debugger host-task checkpoint failed\"}}";

struct DebuggerPausedEvalPublishState {
  std::mutex mutex;
  bool outer_task_open{true};
  bool callback_claimed{false};
  bool has_staged_result{false};
  std::string staged_result;
};

std::string debuggerExceptionResult(const std::string& message) {
  std::ostringstream out;
  out << "{\"exceptionDetails\":{\"text\":" << jsonString(message) << "}}";
  return out.str();
}

std::string debuggerValueResult(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  std::ostringstream out;
  out << "{\"result\":" << makeRemoteObject(runtime, value) << "}";
  return out.str();
}

}  // namespace
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

  bool ingressBlocked = false;
  auto result = runOnRuntimeThread(runtime, [](ExactHermesRuntime* handle) {
    if (!handle || !handle->runtime) {
      return std::string();
    }
    auto debugger = snapshotDebugger(handle);
    if (!debugger) return std::string();
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
            if (!handle->debugger_attached.load() ||
                !exactRuntimeDebuggerIngressAllowed(handle)) {
              return;
            }
            auto event = buildPausedEvent(rt.getDebugger());
            if (!event.empty()) {
              pushDebugEvent(handle, event);
            }
          });
        });
    handle->debugger_callback_set = true;
    handle->debugger_attached.store(true, std::memory_order_release);

    emitNewScripts(handle, runtime_debugger);
    return std::string("1");
  }, &ingressBlocked);

  if (result != "1") {
    runtime->debugger_attached.store(false, std::memory_order_release);
    if (ingressBlocked) {
      return 0;
    }
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
  if (!runtime) {
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

  std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI> debugger;
  auto pending = exactRuntimeAdmitDebuggerCommand(runtime, &debugger);
  if (!pending || !debugger) return;
  try {
    auto target = exactRuntimeCallbackTarget(runtime);
    std::weak_ptr<facebook::hermes::debugger::AsyncDebuggerAPI> debuggerWeak =
        debugger;
    debugger->triggerInterrupt_TS([runtime, target, debuggerWeak, pending, cmd](facebook::hermes::HermesRuntime&) {
      if (exactRuntimeDebuggerCommandCancelled(pending)) return;
      // @ref LLP 0003#the-platform-shims-map — see the event callback above.
      withRuntimePinned(target, [&]() {
        if (!exactRuntimeDebuggerIngressAllowed(runtime)) {
          return;
        }
        auto debugger = debuggerWeak.lock();
        if (!debugger) return;
        if (debugger->resumeFromPaused(cmd)) {
          pushDebugEvent(runtime, "{\"method\":\"Debugger.resumed\",\"params\":{}}");
        }
      });
      exactRuntimeSettleDebuggerCommand(runtime, pending);
    });
  } catch (const facebook::jsi::JSError& err) {
    exactRuntimeSettleDebuggerCommand(runtime, pending);
    ex_host_console_log(1, err.getMessage().c_str());
  } catch (const std::exception& err) {
    exactRuntimeSettleDebuggerCommand(runtime, pending);
    ex_host_console_log(1, err.what());
  } catch (...) {
    exactRuntimeSettleDebuggerCommand(runtime, pending);
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
  if (!exactRuntimeDebuggerIngressAllowed(runtime)) {
    return nullptr;
  }
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

  if (runtime->debugger_attached.load()) {
    std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI>
        admittedDebugger;
    auto pending =
        exactRuntimeAdmitDebuggerCommand(runtime, &admittedDebugger);
    if (!pending || !admittedDebugger) return nullptr;
    auto publishState = std::make_shared<DebuggerPausedEvalPublishState>();
    std::weak_ptr<facebook::hermes::debugger::AsyncDebuggerAPI> debuggerWeak =
        admittedDebugger;
    try {
      admittedDebugger->triggerInterrupt_TS(
        [runtime, debuggerWeak, pending, publishState, expr, frame_index](
            facebook::hermes::HermesRuntime& rt) {
          if (exactRuntimeDebuggerCommandCancelled(pending)) return;
          if (!exactRuntimeDebuggerIngressAllowed(runtime)) {
            exactRuntimeSettleDebuggerCommand(
                runtime,
                pending,
                "{\"exceptionDetails\":{\"text\":\"Debugger ingress is excluded during GPU Canvas app-bundle evaluation\"}}");
            return;
          }
          if (!exactRuntimeEnterUserExecution(runtime)) {
            exactRuntimeSettleDebuggerCommand(
                runtime,
                pending,
                "{\"exceptionDetails\":{\"text\":\"Hermes embedder capability transaction is not finalized\"}}");
            return;
          }
          ScopedGpuHostTask hostTask(runtime);
          if (!hostTask) {
            exactRuntimeSettleDebuggerCommand(
                runtime, pending, kDebuggerHostTaskUnavailable);
            return;
          }

          auto claimOuterResult =
              [publishState](std::string result) {
                std::lock_guard<std::mutex> lock(publishState->mutex);
                if (publishState->callback_claimed) return;
                publishState->callback_claimed = true;
                publishState->has_staged_result = true;
                publishState->staged_result = std::move(result);
              };

          auto debugger = debuggerWeak.lock();
          if (!debugger) {
            claimOuterResult({});
          } else {
            bool pausedEvalAccepted = false;
            try {
              pausedEvalAccepted = debugger->evalWhilePaused(
                  expr,
                  frame_index,
                  [runtime, pending, publishState](
                      facebook::hermes::HermesRuntime& callbackRuntime,
                      const facebook::hermes::debugger::EvalResult& result) {
                    if (exactRuntimeDebuggerCommandCancelled(pending)) return;
                    {
                      std::lock_guard<std::mutex> lock(publishState->mutex);
                      if (publishState->callback_claimed) return;
                      publishState->callback_claimed = true;
                    }

                    ScopedGpuHostTask callbackTask(runtime);
                    std::string stagedResult;
                    if (!callbackTask) {
                      stagedResult = kDebuggerHostTaskUnavailable;
                    } else {
                      try {
                        stagedResult = result.isException
                            ? debuggerExceptionResult(
                                  result.exceptionDetails.text)
                            : debuggerValueResult(
                                  callbackRuntime, result.value);
                      } catch (const facebook::jsi::JSError& error) {
                        stagedResult = debuggerExceptionResult(
                            error.getMessage());
                      } catch (const std::exception& error) {
                        stagedResult = debuggerExceptionResult(error.what());
                      } catch (...) {
                        stagedResult = debuggerExceptionResult(
                            "Unknown debugger result conversion failure");
                      }
                      if (!callbackTask.finish()) {
                        stagedResult = kDebuggerHostTaskCheckpointFailed;
                      }
                    }

                    bool publishDirectly = false;
                    {
                      std::lock_guard<std::mutex> lock(publishState->mutex);
                      if (publishState->outer_task_open) {
                        publishState->has_staged_result = true;
                        publishState->staged_result = std::move(stagedResult);
                      } else {
                        publishDirectly = true;
                      }
                    }
                    if (publishDirectly) {
                      exactRuntimeSettleDebuggerCommand(
                          runtime, pending, std::move(stagedResult));
                    }
                  });
            } catch (const facebook::jsi::JSError& err) {
              claimOuterResult(debuggerExceptionResult(err.getMessage()));
            } catch (const std::exception& err) {
              claimOuterResult(debuggerExceptionResult(err.what()));
            } catch (...) {
              claimOuterResult(debuggerExceptionResult(
                  "Unknown paused debugger evaluation failure"));
            }

            if (!pausedEvalAccepted) {
              bool runFallback = false;
              {
                std::lock_guard<std::mutex> lock(publishState->mutex);
                if (!publishState->callback_claimed) {
                  publishState->callback_claimed = true;
                  runFallback = true;
                }
              }
              if (runFallback) {
                std::string fallbackResult;
                try {
                  auto buffer =
                      std::make_shared<facebook::jsi::StringBuffer>(expr);
                  auto result = rt.evaluateJavaScript(buffer, "<cdp>");
                  fallbackResult = debuggerValueResult(rt, result);
                } catch (const facebook::jsi::JSError& err) {
                  fallbackResult = debuggerExceptionResult(err.getMessage());
                } catch (const std::exception& err) {
                  fallbackResult = debuggerExceptionResult(err.what());
                } catch (...) {
                  fallbackResult = debuggerExceptionResult(
                      "Unknown debugger evaluation failure");
                }
                std::lock_guard<std::mutex> lock(publishState->mutex);
                publishState->has_staged_result = true;
                publishState->staged_result = std::move(fallbackResult);
              }
            }
          }

          const bool checkpointSucceeded = hostTask.finish();
          bool publishStagedResult = false;
          std::string stagedResult;
          {
            std::lock_guard<std::mutex> lock(publishState->mutex);
            publishState->outer_task_open = false;
            if (!checkpointSucceeded) {
              publishState->callback_claimed = true;
              publishState->has_staged_result = true;
              publishState->staged_result =
                  kDebuggerHostTaskCheckpointFailed;
            }
            if (publishState->has_staged_result) {
              publishStagedResult = true;
              stagedResult = std::move(publishState->staged_result);
              publishState->has_staged_result = false;
            }
          }
          if (publishStagedResult) {
            exactRuntimeSettleDebuggerCommand(
                runtime, pending, std::move(stagedResult));
          }
        });
      exactRuntimeDebuggerInterruptQueuedTestPause(runtime, pending);
      auto result = exactRuntimeWaitDebuggerCommand(runtime, pending);
      if (!result.empty()) {
        char* heap = static_cast<char*>(malloc(result.size() + 1));
        if (heap) {
          memcpy(heap, result.data(), result.size());
          heap[result.size()] = '\0';
          return heap;
        }
      }
    } catch (const facebook::jsi::JSError& err) {
      exactRuntimeSettleDebuggerCommand(runtime, pending);
      ex_host_console_log(1, err.getMessage().c_str());
    } catch (const std::exception& err) {
      exactRuntimeSettleDebuggerCommand(runtime, pending);
      ex_host_console_log(1, err.what());
    } catch (...) {
      exactRuntimeSettleDebuggerCommand(runtime, pending);
      ex_host_console_log(1, "Unknown native error");
    }
  }

  // Fallback: use runOnRuntimeThread for regular evaluation (not paused)
  auto json = runOnRuntimeThread(runtime, [expr](ExactHermesRuntime* handle) {
    if (!exactRuntimeEnterUserExecution(handle)) {
      return std::string();
    }
    ScopedGpuHostTask hostTask(handle);
    if (!hostTask) return std::string(kDebuggerHostTaskUnavailable);
    auto& rt = *handle->runtime;
    std::string stagedResult;
    try {
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(expr);
      auto result = rt.evaluateJavaScript(buffer, "<cdp>");
      stagedResult = debuggerValueResult(rt, result);
    } catch (const facebook::jsi::JSError& err) {
      stagedResult = debuggerExceptionResult(err.getMessage());
    } catch (const std::exception& err) {
      stagedResult = debuggerExceptionResult(err.what());
    } catch (...) {
      stagedResult = debuggerExceptionResult(
          "Unknown debugger evaluation failure");
    }
    if (!hostTask.finish()) {
      return std::string(kDebuggerHostTaskCheckpointFailed);
    }
    return stagedResult;
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
