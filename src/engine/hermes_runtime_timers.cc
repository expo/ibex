#include "hermes_runtime_internal.h"

#include <cmath>
#include <limits>
#include <vector>

namespace {

// Coerce a setTimeout/setInterval delay argument to a whole-millisecond deadline
// offset with Web/Node semantics.
//
// The naive `static_cast<uint64_t>(args[1].asNumber())` had two defects:
//   * it only accepted a JS number, silently treating `'5'` (and every other
//     non-number) as 0 instead of applying ToNumber coercion; and
//   * `static_cast<uint64_t>` of a negative or NaN double is undefined
//     behaviour in C++. On arm64 (`fcvtzu`) it happens to saturate to 0, but on
//     x86_64 (`cvttsd2si`) negative/NaN become 0x8000000000000000, so
//     `nowMs() + delay` lands ~292M years out and the timer never fires.
//
// Web and Node both ToNumber-coerce the delay and then clamp NaN/negative to 0.
// We mirror that: coerce via the global `Number` (so strings, booleans, null and
// objects with valueOf behave like the platform), then clamp non-finite/negative
// to 0 and truncate toward zero, guarding the cast so it is never reached with a
// value outside the uint64_t range.
uint64_t coerceTimerDelayMs(facebook::jsi::Runtime& runtime,
                            const facebook::jsi::Value* args,
                            size_t count) {
  if (count <= 1) {
    return 0;
  }
  const facebook::jsi::Value& arg = args[1];
  double delay;
  if (arg.isNumber()) {
    delay = arg.getNumber();
  } else if (arg.isNull()) {
    delay = 0.0;  // ToNumber(null) === 0
  } else if (arg.isBool()) {
    delay = arg.getBool() ? 1.0 : 0.0;
  } else if (arg.isUndefined()) {
    delay = std::numeric_limits<double>::quiet_NaN();  // ToNumber(undefined) === NaN
  } else {
    // Strings, objects: defer to JS ToNumber via the global Number() so that
    // '5' -> 5, ' 0x10 ' -> 16, '' -> 0, 'abc' -> NaN, etc. If Number is
    // unavailable or coercion throws (e.g. a Symbol or a throwing valueOf),
    // fall back to 0 rather than propagating an exception out of the timer
    // host function (matching the old lenient behaviour for non-numbers).
    delay = std::numeric_limits<double>::quiet_NaN();
    try {
      auto numberCtor = runtime.global().getPropertyAsFunction(runtime, "Number");
      auto coerced = numberCtor.call(runtime, facebook::jsi::Value(runtime, arg));
      if (coerced.isNumber()) {
        delay = coerced.getNumber();
      }
    } catch (...) {
      delay = std::numeric_limits<double>::quiet_NaN();
    }
  }

  // Web/Node: NaN and negative delays clamp to 0.
  if (std::isnan(delay) || delay <= 0.0) {
    return 0;
  }
  // Clamp absurdly large / infinite delays so the cast stays in range and the
  // deadline arithmetic (nowMs() + delay) cannot overflow.
  constexpr double kMaxDelayMs = 9223372036854775807.0;  // INT64_MAX ms (~292M yr)
  if (delay >= kMaxDelayMs) {
    return static_cast<uint64_t>(9223372036854775807ULL);
  }
  return static_cast<uint64_t>(delay);
}

}  // namespace

void installTimerGlobals(
    ExactHermesRuntime* handle,
    bool install_ref_controls) {
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
        uint64_t delay = coerceTimerDelayMs(runtime, args, count);
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
            currentPrincipalId(),
            exactCollectTypedPrincipalStack(),
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
        uint64_t delay = coerceTimerDelayMs(runtime, args, count);
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
            currentPrincipalId(),
            exactCollectTypedPrincipalStack(),
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
#if defined(EXACT_HAVE_JSI_QUEUE_MICROTASK)
        (void)handle;
        runtime.queueMicrotask(callback);
#else
        handle->next_tick.push_back(
            NextTickEntry{currentPrincipalId(), exactCollectTypedPrincipalStack(),
                          std::move(callback), {}});
#endif
        return facebook::jsi::Value::undefined();
      });

  rt.global().setProperty(rt, "setTimeout", std::move(setTimeoutFn));
  rt.global().setProperty(rt, "clearTimeout", std::move(clearTimeoutFn));
  rt.global().setProperty(rt, "setInterval", std::move(setIntervalFn));
  rt.global().setProperty(rt, "clearInterval", std::move(clearIntervalFn));
  rt.global().setProperty(rt, "queueMicrotask", std::move(queueMicrotaskFn));
  if (install_ref_controls) {
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
    rt.global().setProperty(rt, "__exactTimerRef", std::move(timerRefFn));
    rt.global().setProperty(rt, "__exactTimerUnref", std::move(timerUnrefFn));
  }
}
