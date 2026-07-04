// hermes_runtime_worklet.cc
//
// @system @ref LLP 0297 §4.3 (exact repo) — the restricted UI worklet
// runtime. A second, single-owner Hermes instance created by the host's
// main/UI thread and kept warm for the process lifetime. Restricted by
// construction: created bare (no installGlobals), so there is no module
// loader, no fetch/network, no timers, no exact.dispatch, and no kernel
// access. The global surface is exactly:
//
//   - log(...args)                  -> buffered, drained by the host
//   - scheduleOnAppRuntime(name, a) -> buffered, drained by the host and
//                                      forwarded to the app runtime (the
//                                      async-only escape to Context 3)
//   - measure(nodeId)               -> host callback against the main-side
//                                      presenter snapshot (never the kernel)
//   - __svGet(slot) / __svSet(slot, v) + worklet.sharedValue(slot)
//                                   -> atomic f32 slots in a host-bound slab
//   - worklet.{clamp, lerp}         -> frozen stdlib prelude
//
// Threading contract: exactly one owner thread (the creator). All
// ex_worklet_* calls happen on that thread; none of them block on another
// runtime. Install/invoke are generation-fenced per LLP 0297 §4.8: invoking
// a worklet whose generation is stale — or whose generation's install has
// not yet arrived — is a defined no-op (EX_WORKLET_NOOP).

#include "hermes_runtime_internal.h"

#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

using facebook::jsi::Function;
using facebook::jsi::Object;
using facebook::jsi::PropNameID;
using facebook::jsi::Runtime;
using facebook::jsi::String;
using facebook::jsi::Value;

// External-linkage helpers from hermes_runtime.cc / hermes_runtime_utils.cc.
void registerRuntime(ExactHermesRuntime* runtime);
void unregisterRuntime(ExactHermesRuntime* runtime);
extern "C" void ex_hermes_destroy(ExactHermesRuntime* runtime);

namespace {

struct WorkletEntry {
  uint64_t generation = 0;
  std::shared_ptr<Function> fn;
};

struct WorkletState {
  uint64_t generation = 0;
  std::unordered_map<std::string, WorkletEntry> worklets;
  // Both deques store fully JSON-encoded strings so draining is pure
  // concatenation (no re-escaping).
  std::deque<std::string> logs;
  std::deque<std::string> scheduled;
  std::atomic<uint32_t>* shared_values = nullptr;
  size_t shared_value_count = 0;
  int (*measure_callback)(uint32_t node_id, float* out_frame4, void* ctx) = nullptr;
  void* measure_context = nullptr;
};

constexpr size_t kWorkletQueueCap = 1024;

std::mutex g_workletStateMutex;
std::unordered_map<ExactHermesRuntime*, std::unique_ptr<WorkletState>> g_workletStates;

WorkletState* stateFor(ExactHermesRuntime* handle) {
  std::lock_guard<std::mutex> lock(g_workletStateMutex);
  auto it = g_workletStates.find(handle);
  return it == g_workletStates.end() ? nullptr : it->second.get();
}

char* mallocString(const std::string& text) {
  char* heap = static_cast<char*>(malloc(text.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, text.data(), text.size());
  heap[text.size()] = '\0';
  return heap;
}

void pushCapped(std::deque<std::string>& queue, std::string entry) {
  if (queue.size() >= kWorkletQueueCap) {
    queue.pop_front();
  }
  queue.push_back(std::move(entry));
}

char* drainJsonArray(std::deque<std::string>& queue) {
  if (queue.empty()) {
    return nullptr;
  }
  std::string out = "[";
  bool first = true;
  for (auto& entry : queue) {
    if (!first) {
      out += ",";
    }
    out += entry;
    first = false;
  }
  out += "]";
  queue.clear();
  return mallocString(out);
}

float bitsToFloat(uint32_t bits) {
  float value;
  memcpy(&value, &bits, sizeof(value));
  return value;
}

uint32_t floatToBits(float value) {
  uint32_t bits;
  memcpy(&bits, &value, sizeof(bits));
  return bits;
}

void installWorkletGlobals(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  // log(...args) — buffered; each argument is JSON-stringified on the spot.
  rt.global().setProperty(
      rt,
      "log",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "log"),
          1,
          [handle](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
            std::string line = "[";
            for (size_t i = 0; i < count; i++) {
              if (i > 0) {
                line += ",";
              }
              line += stringifyValue(rt, args[i]);
            }
            line += "]";
            if (auto* state = stateFor(handle)) {
              pushCapped(state->logs, std::move(line));
            }
            return Value::undefined();
          }));

  // scheduleOnAppRuntime(name, args) — the async-only escape to Context 3.
  rt.global().setProperty(
      rt,
      "scheduleOnAppRuntime",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "scheduleOnAppRuntime"),
          2,
          [handle](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
            if (count < 1 || !args[0].isString()) {
              throw facebook::jsi::JSError(
                  rt, "scheduleOnAppRuntime(name, args) requires a string name");
            }
            std::string entry = "{\"name\":";
            entry += stringifyValue(rt, args[0]);
            entry += ",\"args\":";
            entry += count > 1 ? stringifyValue(rt, args[1]) : "null";
            entry += "}";
            if (auto* state = stateFor(handle)) {
              pushCapped(state->scheduled, std::move(entry));
            }
            return Value::undefined();
          }));

  // measure(nodeId) — geometry read against the host's presenter snapshot.
  rt.global().setProperty(
      rt,
      "measure",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "measure"),
          1,
          [handle](Runtime& rt, const Value&, const Value* args, size_t count) -> Value {
            auto* state = stateFor(handle);
            if (!state || !state->measure_callback || count < 1 || !args[0].isNumber()) {
              return Value::null();
            }
            float frame[4] = {0, 0, 0, 0};
            uint32_t nodeId = static_cast<uint32_t>(args[0].asNumber());
            if (state->measure_callback(nodeId, frame, state->measure_context) == 0) {
              return Value::null();
            }
            Object result(rt);
            result.setProperty(rt, "x", static_cast<double>(frame[0]));
            result.setProperty(rt, "y", static_cast<double>(frame[1]));
            result.setProperty(rt, "width", static_cast<double>(frame[2]));
            result.setProperty(rt, "height", static_cast<double>(frame[3]));
            return result;
          }));

  // __svGet / __svSet — atomic f32 slots. Out-of-range slots are defined
  // no-ops (LLP 0297 §4.4 stale-id tolerance): get returns undefined, set
  // does nothing.
  rt.global().setProperty(
      rt,
      "__svGet",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "__svGet"),
          1,
          [handle](Runtime&, const Value&, const Value* args, size_t count) -> Value {
            auto* state = stateFor(handle);
            if (!state || !state->shared_values || count < 1 || !args[0].isNumber()) {
              return Value::undefined();
            }
            auto slot = static_cast<size_t>(args[0].asNumber());
            if (slot >= state->shared_value_count) {
              return Value::undefined();
            }
            uint32_t bits = state->shared_values[slot].load(std::memory_order_relaxed);
            return Value(static_cast<double>(bitsToFloat(bits)));
          }));

  rt.global().setProperty(
      rt,
      "__svSet",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "__svSet"),
          2,
          [handle](Runtime&, const Value&, const Value* args, size_t count) -> Value {
            auto* state = stateFor(handle);
            if (!state || !state->shared_values || count < 2 || !args[0].isNumber() ||
                !args[1].isNumber()) {
              return Value::undefined();
            }
            auto slot = static_cast<size_t>(args[0].asNumber());
            if (slot >= state->shared_value_count) {
              return Value::undefined();
            }
            state->shared_values[slot].store(
                floatToBits(static_cast<float>(args[1].asNumber())),
                std::memory_order_relaxed);
            return Value::undefined();
          }));

  // Frozen stdlib prelude.
  static const char* kPrelude = R"PRELUDE(
(function () {
  "use strict";
  var w = {
    clamp: function (v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; },
    lerp: function (a, b, t) { return a + (b - a) * t; },
    sharedValue: function (slot) {
      return Object.freeze({
        get: function () { return __svGet(slot); },
        set: function (v) { __svSet(slot, v); }
      });
    }
  };
  Object.freeze(w);
  Object.defineProperty(globalThis, "worklet", {
    value: w, writable: false, enumerable: false, configurable: false
  });
})();
)PRELUDE";
  rt.evaluateJavaScript(
      std::make_shared<facebook::jsi::StringBuffer>(kPrelude), "worklet-prelude.js");
}

} // namespace

extern "C" ExactHermesRuntime* ex_worklet_create() {
  // Small heap by design (LLP 0297 §4.3: target <=4MB steady state, 8MB
  // limit) so worklet GC pauses stay sub-millisecond.
  auto gcConfig = ::hermes::vm::GCConfig::Builder()
                      .withShouldRecordStats(true)
                      .withName("ibex-worklet")
                      .withInitHeapSize(1 << 20)
                      .withMaxHeapSize(8 << 20)
                      .build();
  auto config =
      ::hermes::vm::RuntimeConfig::Builder().withGCConfig(gcConfig).withEnableEval(true).build();

  auto runtime = facebook::hermes::makeHermesRuntime(config);
  if (!runtime) {
    return nullptr;
  }

  auto handle = new ExactHermesRuntime();
  handle->runtime = std::move(runtime);
  handle->runtime_thread = std::this_thread::get_id();
  handle->restricted = true;
  disableDebugger(handle);

  {
    std::lock_guard<std::mutex> lock(g_workletStateMutex);
    g_workletStates[handle] = std::make_unique<WorkletState>();
  }

  try {
    installWorkletGlobals(handle);
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
    {
      std::lock_guard<std::mutex> lock(g_workletStateMutex);
      g_workletStates.erase(handle);
    }
    delete handle;
    return nullptr;
  }

  registerRuntime(handle);
  return handle;
}

extern "C" void ex_worklet_destroy(ExactHermesRuntime* handle) {
  if (!handle) {
    return;
  }
  {
    // Drop installed jsi::Functions BEFORE the runtime is destroyed.
    std::lock_guard<std::mutex> lock(g_workletStateMutex);
    g_workletStates.erase(handle);
  }
  ex_hermes_destroy(handle);
}

extern "C" void ex_worklet_set_generation(ExactHermesRuntime* handle, uint64_t generation) {
  auto* state = stateFor(handle);
  if (!state) {
    return;
  }
  state->generation = generation;
  // §4.8: the worklet runtime atomically drops all stale-generation
  // worklets before the new bundle's installs apply.
  for (auto it = state->worklets.begin(); it != state->worklets.end();) {
    if (it->second.generation != generation) {
      it = state->worklets.erase(it);
    } else {
      ++it;
    }
  }
}

extern "C" uint64_t ex_worklet_generation(ExactHermesRuntime* handle) {
  auto* state = stateFor(handle);
  return state ? state->generation : 0;
}

// Result codes shared by install/invoke.
#define EX_WORKLET_OK 0
#define EX_WORKLET_ERROR 1
#define EX_WORKLET_NOOP 2

extern "C" int ex_worklet_install(
    ExactHermesRuntime* handle,
    const char* worklet_id,
    const uint8_t* source,
    size_t source_len,
    uint64_t generation,
    char** out_error) {
  if (out_error) {
    *out_error = nullptr;
  }
  auto* state = stateFor(handle);
  if (!state || !worklet_id || !source || source_len == 0) {
    if (out_error) {
      *out_error = mallocString("ex_worklet_install: invalid input");
    }
    return EX_WORKLET_ERROR;
  }
  // Installs from a generation older than current are stale by definition
  // (a reset already advanced the runtime); drop them as defined no-ops.
  // Installs from a NEWER generation are accepted and become invocable when
  // ex_worklet_set_generation catches up (install batches may arrive before
  // the host flips the generation).
  if (generation < state->generation) {
    return EX_WORKLET_NOOP;
  }

  try {
    auto& rt = *handle->runtime;
    auto value = rt.evaluateJavaScript(
        std::make_shared<facebook::jsi::StringBuffer>(
            std::string(reinterpret_cast<const char*>(source), source_len)),
        std::string("worklet:") + worklet_id);
    if (!value.isObject() || !value.asObject(rt).isFunction(rt)) {
      if (out_error) {
        *out_error = mallocString("worklet source must evaluate to a function expression");
      }
      return EX_WORKLET_ERROR;
    }
    WorkletEntry entry;
    entry.generation = generation;
    entry.fn = std::make_shared<Function>(value.asObject(rt).asFunction(rt));
    state->worklets[worklet_id] = std::move(entry);
    return EX_WORKLET_OK;
  } catch (const facebook::jsi::JSError& err) {
    if (out_error) {
      *out_error = mallocString(err.getMessage());
    }
    return EX_WORKLET_ERROR;
  } catch (const std::exception& err) {
    if (out_error) {
      *out_error = mallocString(err.what());
    }
    return EX_WORKLET_ERROR;
  }
}

extern "C" int ex_worklet_invoke(
    ExactHermesRuntime* handle,
    const char* worklet_id,
    const char* args_json,
    char** out_result_json) {
  if (out_result_json) {
    *out_result_json = nullptr;
  }
  auto* state = stateFor(handle);
  if (!state || !worklet_id) {
    return EX_WORKLET_ERROR;
  }
  auto it = state->worklets.find(worklet_id);
  // Missing worklet, or a generation mismatch in either direction, is the
  // §4.8 defined no-op: the binding holds its last value until the matching
  // install lands.
  if (it == state->worklets.end() || it->second.generation != state->generation) {
    return EX_WORKLET_NOOP;
  }

  try {
    auto& rt = *handle->runtime;
    Value result;
    if (args_json && args_json[0] != '\0') {
      result = it->second.fn->call(rt, parseJsonValue(rt, args_json));
    } else {
      result = it->second.fn->call(rt);
    }
    if (out_result_json) {
      *out_result_json = mallocString(stringifyValue(rt, result));
    }
    return EX_WORKLET_OK;
  } catch (const facebook::jsi::JSError& err) {
    if (out_result_json) {
      *out_result_json = mallocString(err.getMessage());
    }
    return EX_WORKLET_ERROR;
  } catch (const std::exception& err) {
    if (out_result_json) {
      *out_result_json = mallocString(err.what());
    }
    return EX_WORKLET_ERROR;
  }
}

extern "C" int ex_worklet_bind_shared_values(
    ExactHermesRuntime* handle,
    void* slab,
    size_t slot_count) {
  auto* state = stateFor(handle);
  if (!state) {
    return EX_WORKLET_ERROR;
  }
  state->shared_values = static_cast<std::atomic<uint32_t>*>(slab);
  state->shared_value_count = slab ? slot_count : 0;
  return EX_WORKLET_OK;
}

extern "C" void ex_worklet_set_measure_callback(
    ExactHermesRuntime* handle,
    int (*callback)(uint32_t node_id, float* out_frame4, void* context),
    void* context) {
  auto* state = stateFor(handle);
  if (!state) {
    return;
  }
  state->measure_callback = callback;
  state->measure_context = context;
}

extern "C" char* ex_worklet_drain_logs(ExactHermesRuntime* handle) {
  auto* state = stateFor(handle);
  return state ? drainJsonArray(state->logs) : nullptr;
}

extern "C" char* ex_worklet_drain_scheduled(ExactHermesRuntime* handle) {
  auto* state = stateFor(handle);
  return state ? drainJsonArray(state->scheduled) : nullptr;
}
