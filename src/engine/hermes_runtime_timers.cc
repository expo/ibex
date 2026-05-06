#include "hermes_runtime_internal.h"

#include <vector>

void installTimerGlobals(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  auto setTimeoutFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "setTimeout"),
      2,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() || !args[0].asObject(runtime).isFunction(runtime)) {
          return facebook::jsi::Value::undefined();
        }
        auto callback = args[0].asObject(runtime).asFunction(runtime);
        uint64_t delay = 0;
        if (count > 1 && args[1].isNumber()) {
          delay = static_cast<uint64_t>(args[1].asNumber());
        }
        std::vector<facebook::jsi::Value> callbackArgs;
        if (count > 2) {
          callbackArgs.reserve(count - 2);
          for (size_t i = 2; i < count; i++) {
            callbackArgs.emplace_back(runtime, args[i]);
          }
        }
        uint64_t id = handle->next_timer_id++;
        TimerEntry entry{
            id,
            nowMs() + delay,
            delay,
            false,
            true,
            std::move(callback),
            std::move(callbackArgs),
        };
        handle->timers.emplace(id, std::move(entry));
        return facebook::jsi::Value(static_cast<double>(id));
      });

  auto clearTimeoutFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "clearTimeout"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        (void)runtime;
        if (count == 0 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        uint64_t id = static_cast<uint64_t>(args[0].asNumber());
        handle->timers.erase(id);
        return facebook::jsi::Value::undefined();
      });

  auto setIntervalFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "setInterval"),
      2,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() || !args[0].asObject(runtime).isFunction(runtime)) {
          return facebook::jsi::Value::undefined();
        }
        auto callback = args[0].asObject(runtime).asFunction(runtime);
        uint64_t delay = 0;
        if (count > 1 && args[1].isNumber()) {
          delay = static_cast<uint64_t>(args[1].asNumber());
        }
        std::vector<facebook::jsi::Value> callbackArgs;
        if (count > 2) {
          callbackArgs.reserve(count - 2);
          for (size_t i = 2; i < count; i++) {
            callbackArgs.emplace_back(runtime, args[i]);
          }
        }
        uint64_t id = handle->next_timer_id++;
        TimerEntry entry{
            id,
            nowMs() + delay,
            delay,
            true,
            true,
            std::move(callback),
            std::move(callbackArgs),
        };
        handle->timers.emplace(id, std::move(entry));
        return facebook::jsi::Value(static_cast<double>(id));
      });

  auto clearIntervalFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "clearInterval"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        (void)runtime;
        if (count == 0 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        uint64_t id = static_cast<uint64_t>(args[0].asNumber());
        handle->timers.erase(id);
        return facebook::jsi::Value::undefined();
      });

  auto queueMicrotaskFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "queueMicrotask"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() || !args[0].asObject(runtime).isFunction(runtime)) {
          return facebook::jsi::Value::undefined();
        }
        auto callback = args[0].asObject(runtime).asFunction(runtime);
#if defined(_WIN32)
        handle->next_tick.push_back(NextTickEntry{std::move(callback), {}});
#else
        (void)handle;
        runtime.queueMicrotask(callback);
#endif
        return facebook::jsi::Value::undefined();
      });

  auto timerRefFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTimerRef"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        (void)runtime;
        if (count > 0 && args[0].isNumber()) {
          uint64_t id = static_cast<uint64_t>(args[0].asNumber());
          auto it = handle->timers.find(id);
          if (it != handle->timers.end()) {
            it->second.referenced = true;
          }
        }
        return facebook::jsi::Value::undefined();
      });

  auto timerUnrefFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTimerUnref"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        (void)runtime;
        if (count > 0 && args[0].isNumber()) {
          uint64_t id = static_cast<uint64_t>(args[0].asNumber());
          auto it = handle->timers.find(id);
          if (it != handle->timers.end()) {
            it->second.referenced = false;
          }
        }
        return facebook::jsi::Value::undefined();
      });

  rt.global().setProperty(rt, "setTimeout", std::move(setTimeoutFn));
  rt.global().setProperty(rt, "clearTimeout", std::move(clearTimeoutFn));
  rt.global().setProperty(rt, "setInterval", std::move(setIntervalFn));
  rt.global().setProperty(rt, "clearInterval", std::move(clearIntervalFn));
  rt.global().setProperty(rt, "queueMicrotask", std::move(queueMicrotaskFn));
  rt.global().setProperty(rt, "__exactTimerRef", std::move(timerRefFn));
  rt.global().setProperty(rt, "__exactTimerUnref", std::move(timerUnrefFn));
}
