#include "hermes_runtime_internal.h"

#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>

#if __has_include("bootstrap_bytecode.h")
#include "bootstrap_bytecode.h"
#define HAS_PRECOMPILED_BOOTSTRAP 1
#endif

#if __has_include("bootstrap_source.h")
#include "bootstrap_source.h"
#endif

namespace {

facebook::jsi::Function makeLogFunction(facebook::jsi::Runtime& rt, int32_t level) {
  return facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "log"),
      1,
      [level](facebook::jsi::Runtime& runtime,
              const facebook::jsi::Value&,
              const facebook::jsi::Value* args,
              size_t count) -> facebook::jsi::Value {
        std::string message;
        for (size_t i = 0; i < count; ++i) {
          if (i > 0) {
            message += " ";
          }
          message += valueToString(runtime, args[i]);
        }
        ex_host_console_log_bytes(
            level,
            reinterpret_cast<const uint8_t*>(message.data()),
            message.size());
        return facebook::jsi::Value::undefined();
      });
}

} // namespace

void installConsoleGlobals(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  bool tracing = startup_trace_enabled();
  bool skip_console_init = env_flag_enabled("EX_SKIP_STARTUP_CONSOLE_INIT");
  if (skip_console_init) {
    if (tracing) {
      fprintf(stderr,
              "[startup]   console_init skipped (set EX_SKIP_STARTUP_CONSOLE_INIT=0 to "
              "re-enable)\n");
    }
    reportStartupFailure(handle, "Console globals", "disabled by startup control");
    return;
  }

  auto printFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "print"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        authorizeTypedPrint(runtime);
        std::string message;
        for (size_t i = 0; i < count; ++i) {
          if (i > 0) {
            message += " ";
          }
          message += valueToString(runtime, args[i]);
        }
        ex_host_console_log_bytes(
            0,
            reinterpret_cast<const uint8_t*>(message.data()),
            message.size());
        return facebook::jsi::Value::undefined();
      });

  rt.global().setProperty(rt, "print", std::move(printFn));

  facebook::jsi::Object console(rt);
  console.setProperty(rt, "log", makeLogFunction(rt, 0));
  console.setProperty(rt, "info", makeLogFunction(rt, 0));
  console.setProperty(rt, "debug", makeLogFunction(rt, 0));
  console.setProperty(rt, "error", makeLogFunction(rt, 1));
  console.setProperty(rt, "warn", makeLogFunction(rt, 1));
  console.setProperty(rt, "trace", makeLogFunction(rt, 0));
  console.setProperty(rt, "dir", makeLogFunction(rt, 0));
  rt.global().setProperty(rt, "console", std::move(console));

  bool skip_console_enhance = env_flag_enabled("EX_SKIP_STARTUP_CONSOLE_ENHANCE");
#if defined(_WIN32)
  skip_console_enhance = true;
#endif
  bool source_console_enhance = env_flag_enabled("EX_CONSOLE_ENHANCE_SOURCE");
  bool console_enhance_hbc =
      env_flag_enabled("EX_CONSOLE_ENHANCE_HBC") || !source_console_enhance;
  if (skip_console_enhance) {
    if (tracing) {
#if defined(_WIN32)
      fprintf(stderr, "[startup]   console_enhance skipped on Windows\n");
#else
      fprintf(stderr,
              "[startup]   console_enhance skipped (set EX_SKIP_STARTUP_CONSOLE_ENHANCE=0 "
              "to re-enable)\n");
#endif
    }
    if (handle->armed) {
      reportStartupFailure(handle, "Console enhance", "disabled by startup control");
    }
    return;
  }

  auto start = std::chrono::steady_clock::now();
  try {
    const char* consoleEnhance = CONSOLE_ENHANCE_SRC;
#ifdef HAS_PRECOMPILED_BOOTSTRAP
    bool consoleEnhanceEvaluated = eval_bootstrap_script(
        handle,
        consoleEnhance,
        reinterpret_cast<const uint8_t*>(CONSOLE_ENHANCE_HBC),
        CONSOLE_ENHANCE_HBC_LEN,
        "<console>",
        source_console_enhance || !console_enhance_hbc,
        console_enhance_hbc);
#else
    bool consoleEnhanceEvaluated =
        eval_bootstrap_script(handle, consoleEnhance, nullptr, 0, "<console>", true, false);
#endif
    if (!consoleEnhanceEvaluated) {
      throw std::runtime_error("console.enhance failed to evaluate");
    }
  } catch (const facebook::jsi::JSError& err) {
    reportStartupFailure(handle, "Console enhance", err.getMessage());
  } catch (const std::exception& err) {
    reportStartupFailure(handle, "Console enhance", err.what());
  } catch (...) {
    reportStartupFailure(handle, "Console enhance", "unknown evaluation failure");
  }

  if (tracing) {
    auto elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() -
                                                              start)
            .count();
    fprintf(stderr,
            "[startup]   %-28s %6lld us (%5.1f ms)\n",
            "console_enhance",
            static_cast<long long>(elapsed),
            elapsed / 1000.0);
  }
}
