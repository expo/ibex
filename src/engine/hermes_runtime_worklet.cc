// hermes_runtime_worklet.cc
//
// @system See LLP 0297 §4.3 in the exact monorepo (an inherited cross-repo
// reference; kept as prose because that corpus is not carried under this
// repo's llp/) — the restricted UI worklet
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
//   - __svGet(slot, generation, epoch) / __svSet(..., value)
//                                   -> host-validating typed SharedValues
//   - worklet.{clamp, lerp}         -> frozen stdlib prelude
//
// Threading contract: exactly one owner thread (the creator). All
// ex_worklet_* calls happen on that thread; none of them block on another
// runtime. Install/invoke are generation-fenced per LLP 0297 §4.8: invoking
// a worklet whose generation is stale — or whose generation's install has
// not yet arrived — is a defined no-op (EX_WORKLET_NOOP).

#include "../../include/exact_runtime.h"
#include "hermes_runtime_internal.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using facebook::jsi::Array;
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
  uint64_t identity = 0;
  uint64_t fingerprint_hi = 0;
  uint64_t source_sequence = 0;
  std::shared_ptr<Function> fn;
  struct Capture {
    uint32_t kind = 0;
    float scalar = 0.0f;
    ExWorkletSharedValueHandle shared_value{};
    float shadow = 0.0f;
    bool has_shadow = false;
  };
  std::vector<Capture> captures;
};

struct WorkletState {
  uint64_t generation = 0;
  std::unordered_map<std::string, WorkletEntry> worklets;
  std::unordered_map<uint64_t, WorkletEntry> typed_worklets;
  // Both deques store fully JSON-encoded strings so draining is pure
  // concatenation (no re-escaping).
  std::deque<std::string> logs;
  std::deque<std::string> scheduled;
  std::array<ExWorkletScheduledCall, EX_WORKLET_TYPED_QUEUE_CAPACITY> typed_scheduled{};
  uint32_t typed_scheduled_head = 0;
  uint32_t typed_scheduled_count = 0;
  uint64_t scheduled_drops = 0;
  ExWorkletInstallMetrics install_metrics{};
  ExWorkletSharedValueReadCallback shared_value_read = nullptr;
  ExWorkletSharedValueWriteCallback shared_value_write = nullptr;
  void* shared_value_context = nullptr;
  int (*measure_callback)(uint32_t node_id, float* out_frame4, void* ctx) = nullptr;
  void* measure_context = nullptr;
  WorkletEntry* current_entry = nullptr;
  float* current_outputs = nullptr;
  uint32_t current_output_capacity = 0;
  uint32_t current_output_count = 0;
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

void pushCapped(
    WorkletState* state,
    std::deque<std::string>& queue,
    std::string entry,
    bool count_scheduled_drop) {
  if (queue.size() >= kWorkletQueueCap) {
    queue.pop_front();
    if (count_scheduled_drop) {
      state->scheduled_drops++;
    }
  }
  queue.push_back(std::move(entry));
}

void pushTypedScheduled(WorkletState* state, const ExWorkletScheduledCall& call) {
  if (state->typed_scheduled_count == EX_WORKLET_TYPED_QUEUE_CAPACITY) {
    state->typed_scheduled_head =
        (state->typed_scheduled_head + 1) % EX_WORKLET_TYPED_QUEUE_CAPACITY;
    state->typed_scheduled_count--;
    state->scheduled_drops++;
  }
  const uint32_t tail =
      (state->typed_scheduled_head + state->typed_scheduled_count) %
      EX_WORKLET_TYPED_QUEUE_CAPACITY;
  state->typed_scheduled[tail] = call;
  state->typed_scheduled_count++;
}

uint64_t hashBytes(uint64_t hash, const uint8_t* bytes, size_t count) {
  constexpr uint64_t kPrime = 1099511628211ULL;
  for (size_t index = 0; index < count; index++) {
    hash ^= bytes[index];
    hash *= kPrime;
  }
  return hash;
}

uint64_t hashU32(uint64_t hash, uint32_t value) {
  uint8_t bytes[4] = {
      static_cast<uint8_t>(value),
      static_cast<uint8_t>(value >> 8),
      static_cast<uint8_t>(value >> 16),
      static_cast<uint8_t>(value >> 24),
  };
  return hashBytes(hash, bytes, sizeof(bytes));
}

std::pair<uint64_t, uint64_t> workletFingerprint(
    const uint8_t* artifact,
    size_t artifact_len,
    const ExWorkletCapture* captures,
    uint32_t capture_count) {
  uint64_t low = hashBytes(1469598103934665603ULL, artifact, artifact_len);
  uint64_t high = hashBytes(7809847782465536322ULL, artifact, artifact_len);
  low = hashU32(low, capture_count);
  high = hashU32(high, capture_count ^ 0x9e3779b9U);
  for (uint32_t index = 0; index < capture_count; index++) {
    const auto& capture = captures[index];
    const uint32_t scalar_bits = [&]() {
      uint32_t bits = 0;
      static_assert(sizeof(bits) == sizeof(capture.scalar));
      memcpy(&bits, &capture.scalar, sizeof(bits));
      return bits;
    }();
    for (uint32_t value : {
             capture.kind,
             scalar_bits,
             capture.shared_value.slot,
             capture.shared_value.generation,
             capture.shared_value.epoch,
         }) {
      low = hashU32(low, value);
      high = hashU32(high, value ^ 0xa5a5a5a5U);
    }
  }
  // Identity zero is reserved as "no current typed worklet".
  if (low == 0) {
    low = 1;
  }
  return {low, high};
}

class CurrentInvocationScope {
 public:
  CurrentInvocationScope(
      WorkletState* state,
      WorkletEntry* entry,
      float* outputs = nullptr,
      uint32_t output_capacity = 0)
      : state_(state),
        previous_entry_(state->current_entry),
        previous_outputs_(state->current_outputs),
        previous_output_capacity_(state->current_output_capacity),
        previous_output_count_(state->current_output_count) {
    state_->current_entry = entry;
    state_->current_outputs = outputs;
    state_->current_output_capacity = output_capacity;
    state_->current_output_count = 0;
  }

  ~CurrentInvocationScope() {
    state_->current_entry = previous_entry_;
    state_->current_outputs = previous_outputs_;
    state_->current_output_capacity = previous_output_capacity_;
    state_->current_output_count = previous_output_count_;
  }

 private:
  WorkletState* state_;
  WorkletEntry* previous_entry_;
  float* previous_outputs_;
  uint32_t previous_output_capacity_;
  uint32_t previous_output_count_;
};

bool readU32(const Value& value, uint32_t* out) {
  if (!out || !value.isNumber()) {
    return false;
  }
  double number = value.asNumber();
  if (!std::isfinite(number) || number < 0.0 ||
      number > static_cast<double>(UINT32_MAX) || std::trunc(number) != number) {
    return false;
  }
  *out = static_cast<uint32_t>(number);
  return true;
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
              pushCapped(state, state->logs, std::move(line), false);
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
            if (auto* state = stateFor(handle); state && state->current_entry) {
              const uint64_t sequence = ++state->current_entry->source_sequence;
              entry += ",\"sourceIdentity\":\"";
              entry += std::to_string(state->current_entry->identity);
              entry += "\",\"sourceSequence\":";
              entry += std::to_string(sequence);
              entry += ",\"generation\":";
              entry += std::to_string(state->current_entry->generation);
            }
            entry += "}";
            if (auto* state = stateFor(handle)) {
              pushCapped(state, state->scheduled, std::move(entry), true);
            }
            return Value::undefined();
          }));

  // Fixed-slot math worklet primitives. The public frozen `worklet` object
  // below forwards to these host functions; the private names keep capture
  // and output state out of ordinary app code.
  rt.global().setProperty(
      rt,
      "__workletCapture",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "__workletCapture"),
          1,
          [handle](Runtime&, const Value&, const Value* args, size_t count) -> Value {
            auto* state = stateFor(handle);
            uint32_t index = 0;
            if (!state || !state->current_entry || count < 1 ||
                !readU32(args[0], &index) ||
                index >= state->current_entry->captures.size()) {
              return Value::undefined();
            }
            const auto& capture = state->current_entry->captures[index];
            if (capture.kind == EX_WORKLET_CAPTURE_F32) {
              return Value(static_cast<double>(capture.scalar));
            }
            if (capture.kind == EX_WORKLET_CAPTURE_BOOL) {
              return Value(capture.scalar != 0.0f);
            }
            return Value::undefined();
          }));

  rt.global().setProperty(
      rt,
      "__workletCaptureGet",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "__workletCaptureGet"),
          1,
          [handle](Runtime&, const Value&, const Value* args, size_t count) -> Value {
            auto* state = stateFor(handle);
            uint32_t index = 0;
            if (!state || !state->current_entry || count < 1 ||
                !readU32(args[0], &index) ||
                index >= state->current_entry->captures.size()) {
              return Value::undefined();
            }
            auto& capture = state->current_entry->captures[index];
            if (capture.kind != EX_WORKLET_CAPTURE_SHARED_VALUE ||
                !state->shared_value_read) {
              return Value::undefined();
            }
            float value = 0.0f;
            if (state->shared_value_read(
                    capture.shared_value,
                    &value,
                    state->shared_value_context) == 0 &&
                std::isfinite(value)) {
              capture.shadow = value;
              capture.has_shadow = true;
              return Value(static_cast<double>(value));
            }
            return capture.has_shadow ? Value(static_cast<double>(capture.shadow))
                                      : Value::undefined();
          }));

  rt.global().setProperty(
      rt,
      "__workletCaptureSet",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "__workletCaptureSet"),
          2,
          [handle](Runtime&, const Value&, const Value* args, size_t count) -> Value {
            auto* state = stateFor(handle);
            uint32_t index = 0;
            if (!state || !state->current_entry || count < 2 ||
                !readU32(args[0], &index) ||
                index >= state->current_entry->captures.size() ||
                !args[1].isNumber()) {
              return Value(false);
            }
            auto& capture = state->current_entry->captures[index];
            const double number = args[1].asNumber();
            if (capture.kind != EX_WORKLET_CAPTURE_SHARED_VALUE ||
                !state->shared_value_write || !std::isfinite(number) ||
                number < -static_cast<double>(std::numeric_limits<float>::max()) ||
                number > static_cast<double>(std::numeric_limits<float>::max())) {
              return Value(false);
            }
            const float value = static_cast<float>(number);
            if (state->shared_value_write(
                    capture.shared_value,
                    value,
                    state->shared_value_context) != 0) {
              return Value(false);
            }
            capture.shadow = value;
            capture.has_shadow = true;
            return Value(true);
          }));

  rt.global().setProperty(
      rt,
      "__workletOutput",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "__workletOutput"),
          2,
          [handle](Runtime&, const Value&, const Value* args, size_t count) -> Value {
            auto* state = stateFor(handle);
            uint32_t index = 0;
            if (!state || !state->current_outputs || count < 2 ||
                !readU32(args[0], &index) ||
                index >= state->current_output_capacity ||
                !args[1].isNumber()) {
              return Value(false);
            }
            const double number = args[1].asNumber();
            if (!std::isfinite(number) ||
                number < -static_cast<double>(std::numeric_limits<float>::max()) ||
                number > static_cast<double>(std::numeric_limits<float>::max())) {
              return Value(false);
            }
            state->current_outputs[index] = static_cast<float>(number);
            state->current_output_count =
                std::max(state->current_output_count, index + 1);
            return Value(true);
          }));

  rt.global().setProperty(
      rt,
      "__workletRunOnJS",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "__workletRunOnJS"),
          1,
          [handle](Runtime&, const Value&, const Value* args, size_t count) -> Value {
            auto* state = stateFor(handle);
            uint32_t callback_identity = 0;
            if (!state || !state->current_entry || count < 1 ||
                !readU32(args[0], &callback_identity) ||
                callback_identity == 0 ||
                count - 1 > EX_WORKLET_MAX_RUN_ON_JS_SLOTS) {
              return Value(false);
            }
            ExWorkletScheduledCall call{};
            call.source_identity = state->current_entry->identity;
            call.generation = state->current_entry->generation;
            call.callback_identity = callback_identity;
            call.argument_count = static_cast<uint32_t>(count - 1);
            for (size_t index = 1; index < count; index++) {
              if (!args[index].isNumber()) {
                return Value(false);
              }
              const double number = args[index].asNumber();
              if (!std::isfinite(number) ||
                  number < -static_cast<double>(std::numeric_limits<float>::max()) ||
                  number > static_cast<double>(std::numeric_limits<float>::max())) {
                return Value(false);
              }
              call.arguments[index - 1] = static_cast<float>(number);
            }
            call.source_sequence = ++state->current_entry->source_sequence;
            pushTypedScheduled(state, call);
            return Value(true);
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

  // __svGet / __svSet — typed, validating accessors. Stale generation/epoch,
  // malformed handles, and host rejection are defined no-ops (LLP 0297 §4.4).
  // The private primitives report rejection as undefined/false; the durable
  // language handle below owns its last-observed local shadow. Ibex never
  // sees a raw slab.
  rt.global().setProperty(
      rt,
      "__svGet",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "__svGet"),
          3,
          [handle](Runtime&, const Value&, const Value* args, size_t count) -> Value {
            auto* state = stateFor(handle);
            if (!state || !state->shared_value_read || count < 3) {
              return Value::undefined();
            }
            ExWorkletSharedValueHandle shared_value{};
            if (!readU32(args[0], &shared_value.slot) ||
                !readU32(args[1], &shared_value.generation) ||
                !readU32(args[2], &shared_value.epoch)) {
              return Value::undefined();
            }
            float value = 0.0f;
            if (state->shared_value_read(
                    shared_value, &value, state->shared_value_context) != 0 ||
                !std::isfinite(value)) {
              return Value::undefined();
            }
            return Value(static_cast<double>(value));
          }));

  rt.global().setProperty(
      rt,
      "__svSet",
      Function::createFromHostFunction(
          rt,
          PropNameID::forAscii(rt, "__svSet"),
          4,
          [handle](Runtime&, const Value&, const Value* args, size_t count) -> Value {
            auto* state = stateFor(handle);
            if (!state || !state->shared_value_write || count < 4 || !args[3].isNumber()) {
              return Value::undefined();
            }
            ExWorkletSharedValueHandle shared_value{};
            double number = args[3].asNumber();
            if (!readU32(args[0], &shared_value.slot) ||
                !readU32(args[1], &shared_value.generation) ||
                !readU32(args[2], &shared_value.epoch) || !std::isfinite(number) ||
                number < -static_cast<double>(std::numeric_limits<float>::max()) ||
                number > static_cast<double>(std::numeric_limits<float>::max())) {
              return Value::undefined();
            }
            const uint32_t verdict = state->shared_value_write(
                shared_value, static_cast<float>(number), state->shared_value_context);
            return Value(verdict == 0);
          }));

  // Frozen stdlib prelude.
  static const char* kPrelude = R"PRELUDE(
(function () {
  "use strict";
  var w = {
    clamp: function (v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; },
    lerp: function (a, b, t) { return a + (b - a) * t; },
    capture: __workletCapture,
    captureGet: __workletCaptureGet,
    captureSet: __workletCaptureSet,
    output: __workletOutput,
    runOnJS: __workletRunOnJS,
    sharedValue: function (slot, generation, epoch) {
      var shadow;
      return Object.freeze({
        get: function () {
          var value = __svGet(slot, generation, epoch);
          if (value !== undefined) shadow = value;
          return value === undefined ? shadow : value;
        },
        set: function (v) {
          if (__svSet(slot, generation, epoch, v)) shadow = v;
        }
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
  // A restricted runtime still needs an exact Host-selection generation for
  // the common drive guard. Its private context is closed to every Host
  // capability and does not consume the app runtime's pending constructor
  // handoff.
  // @ref LLP 0002#runtime-driving-thread-contract
  const uint64_t hostContext = ibex_private_claim_restricted_host_context();
  if (hostContext == 0) {
    return nullptr;
  }
  // Small heap by design (LLP 0297 §4.3: target <=4MB steady state, 8MB
  // limit) so worklet GC pauses stay sub-millisecond.
  auto gcConfig = ::hermes::vm::GCConfig::Builder()
                      .withShouldRecordStats(true)
                      .withName("ibex-worklet")
                      .withInitHeapSize(1 << 20)
                      .withMaxHeapSize(8 << 20)
                      .build();
  auto configBuilder = ::hermes::vm::RuntimeConfig::Builder().withGCConfig(gcConfig);
#if defined(EXACT_HAVE_HERMES_ES6_BLOCK_SCOPING_CONFIG)
  configBuilder.withES6BlockScoping(ibexHermesES6BlockScopingEnabled());
#elif defined(EXACT_HAVE_HERMES_ENABLE_BLOCK_SCOPING_CONFIG)
  configBuilder.withEnableBlockScoping(ibexHermesES6BlockScopingEnabled());
#endif
  auto config = configBuilder.withEnableEval(true).build();

  auto runtime = facebook::hermes::makeHermesRuntime(config);
  if (!runtime) {
    ex_host_release_context(hostContext);
    return nullptr;
  }

  auto handle = new ExactHermesRuntime();
  handle->runtime = std::move(runtime);
  handle->runtime_thread = std::this_thread::get_id();
  handle->host_context_id = hostContext;
  handle->restricted = true;
  handle->runtime_nonce = exactAllocateRuntimeNonce();
  if (handle->runtime_nonce == 0) {
    delete handle;
    ex_host_release_context(hostContext);
    return nullptr;
  }
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
    ex_host_release_context(hostContext);
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
  for (auto it = state->typed_worklets.begin();
       it != state->typed_worklets.end();) {
    if (it->second.generation != generation) {
      it = state->typed_worklets.erase(it);
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

// @abi-output ex_worklet_install out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
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
    const auto fingerprint = workletFingerprint(source, source_len, nullptr, 0);
    entry.identity = fingerprint.first;
    entry.fingerprint_hi = fingerprint.second;
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

// @abi-output ex_worklet_invoke out_result_json role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
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
    CurrentInvocationScope invocation(state, &it->second);
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

// @abi-output ex_worklet_install_typed out_error role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
extern "C" int ex_worklet_install_typed(
    ExactHermesRuntime* handle,
    uint32_t install_format,
    const uint8_t* artifact,
    size_t artifact_len,
    const ExWorkletCapture* captures,
    uint32_t capture_count,
    uint64_t generation,
    uint64_t* out_identity,
    char** out_error) {
  if (out_error) {
    *out_error = nullptr;
  }
  if (out_identity) {
    *out_identity = 0;
  }
  auto* state = stateFor(handle);
  if (!state || install_format != EX_WORKLET_INSTALL_SOURCE_UTF8 ||
      !artifact || artifact_len == 0 ||
      (capture_count > 0 && !captures) || !out_identity) {
    if (out_error) {
      *out_error = mallocString(
          "ex_worklet_install_typed: invalid input or format");
    }
    return EX_WORKLET_ERROR;
  }
  if (generation < state->generation) {
    return EX_WORKLET_NOOP;
  }
  for (uint32_t index = 0; index < capture_count; index++) {
    const auto& capture = captures[index];
    if (capture.kind != EX_WORKLET_CAPTURE_F32 &&
        capture.kind != EX_WORKLET_CAPTURE_BOOL &&
        capture.kind != EX_WORKLET_CAPTURE_SHARED_VALUE) {
      if (out_error) {
        *out_error = mallocString(
            "typed worklet capture kind is not supported");
      }
      return EX_WORKLET_ERROR;
    }
    if ((capture.kind == EX_WORKLET_CAPTURE_F32 ||
         capture.kind == EX_WORKLET_CAPTURE_BOOL) &&
        !std::isfinite(capture.scalar)) {
      if (out_error) {
        *out_error = mallocString(
            "typed worklet scalar capture must be finite");
      }
      return EX_WORKLET_ERROR;
    }
  }

  const auto fingerprint =
      workletFingerprint(artifact, artifact_len, captures, capture_count);
  *out_identity = fingerprint.first;
  if (auto existing = state->typed_worklets.find(fingerprint.first);
      existing != state->typed_worklets.end()) {
    if (existing->second.fingerprint_hi != fingerprint.second) {
      if (out_error) {
        *out_error = mallocString("typed worklet stable-identity collision");
      }
      return EX_WORKLET_ERROR;
    }
    if (existing->second.generation == generation) {
      state->install_metrics.reused_install_count++;
      return EX_WORKLET_OK;
    }
  }

  const auto started = std::chrono::steady_clock::now();
  try {
    auto& rt = *handle->runtime;
    auto value = rt.evaluateJavaScript(
        std::make_shared<facebook::jsi::StringBuffer>(std::string(
            reinterpret_cast<const char*>(artifact), artifact_len)),
        std::string("motion-worklet:") + std::to_string(fingerprint.first));
    if (!value.isObject() || !value.asObject(rt).isFunction(rt)) {
      if (out_error) {
        *out_error = mallocString(
            "typed worklet source must evaluate to a function expression");
      }
      return EX_WORKLET_ERROR;
    }
    WorkletEntry entry;
    entry.generation = generation;
    entry.identity = fingerprint.first;
    entry.fingerprint_hi = fingerprint.second;
    entry.fn = std::make_shared<Function>(
        value.asObject(rt).asFunction(rt));
    entry.captures.reserve(capture_count);
    for (uint32_t index = 0; index < capture_count; index++) {
      WorkletEntry::Capture stored;
      stored.kind = captures[index].kind;
      stored.scalar = captures[index].kind == EX_WORKLET_CAPTURE_BOOL
          ? (captures[index].scalar == 0.0f ? 0.0f : 1.0f)
          : captures[index].scalar;
      stored.shared_value = captures[index].shared_value;
      entry.captures.push_back(stored);
    }
    state->typed_worklets[fingerprint.first] = std::move(entry);
    const uint64_t elapsed_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started)
            .count());
    state->install_metrics.source_install_count++;
    state->install_metrics.source_install_total_ns += elapsed_ns;
    state->install_metrics.source_install_max_ns = std::max(
        state->install_metrics.source_install_max_ns, elapsed_ns);
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

// @abi-output ex_worklet_invoke_typed outputs role=output kind=buffer length=output_capacity ownership=caller-storage
extern "C" int ex_worklet_invoke_typed(
    ExactHermesRuntime* handle,
    uint64_t identity,
    const float* inputs,
    uint32_t input_count,
    float* outputs,
    uint32_t output_capacity,
    uint32_t* out_output_count) {
  if (out_output_count) {
    *out_output_count = 0;
  }
  auto* state = stateFor(handle);
  if (!state || identity == 0 ||
      input_count > EX_WORKLET_MAX_INPUT_SLOTS ||
      output_capacity > EX_WORKLET_MAX_OUTPUT_SLOTS ||
      (input_count > 0 && !inputs) ||
      (output_capacity > 0 && !outputs) || !out_output_count) {
    return EX_WORKLET_ERROR;
  }
  auto it = state->typed_worklets.find(identity);
  if (it == state->typed_worklets.end() ||
      it->second.generation != state->generation) {
    return EX_WORKLET_NOOP;
  }
  for (uint32_t index = 0; index < input_count; index++) {
    if (!std::isfinite(inputs[index])) {
      return EX_WORKLET_ERROR;
    }
  }
  for (uint32_t index = 0; index < output_capacity; index++) {
    outputs[index] = 0.0f;
  }

  try {
    auto& rt = *handle->runtime;
    std::array<Value, EX_WORKLET_MAX_INPUT_SLOTS> arguments;
    for (uint32_t index = 0; index < input_count; index++) {
      arguments[index] = Value(static_cast<double>(inputs[index]));
    }
    CurrentInvocationScope invocation(
        state, &it->second, outputs, output_capacity);
    (void)it->second.fn->call(
        rt,
        static_cast<const Value*>(arguments.data()),
        static_cast<size_t>(input_count));
    *out_output_count = state->current_output_count;
    return EX_WORKLET_OK;
  } catch (const facebook::jsi::JSError&) {
    return EX_WORKLET_ERROR;
  } catch (const std::exception&) {
    return EX_WORKLET_ERROR;
  }
}

extern "C" int ex_worklet_install_metrics(
    ExactHermesRuntime* handle,
    ExWorkletInstallMetrics* out_metrics) {
  auto* state = stateFor(handle);
  if (!state || !out_metrics) {
    return EX_WORKLET_ERROR;
  }
  *out_metrics = state->install_metrics;
  return EX_WORKLET_OK;
}

extern "C" int ex_worklet_bind_shared_value_accessors(
    ExactHermesRuntime* handle,
    ExWorkletSharedValueReadCallback read_callback,
    ExWorkletSharedValueWriteCallback write_callback,
    void* context) {
  auto* state = stateFor(handle);
  if (!state) {
    return EX_WORKLET_ERROR;
  }
  state->shared_value_read = read_callback;
  state->shared_value_write = write_callback;
  state->shared_value_context = context;
  return EX_WORKLET_OK;
}

// @abi-callback ex_worklet_set_measure_callback callback output=1 kind=buffer fixed-length=4 ownership=caller-storage
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

extern "C" uint32_t ex_worklet_drain_scheduled_typed(
    ExactHermesRuntime* handle,
    ExWorkletScheduledCall* out_calls,
    uint32_t capacity) {
  auto* state = stateFor(handle);
  if (!state || !out_calls || capacity == 0) {
    return 0;
  }
  const uint32_t copied = std::min(capacity, state->typed_scheduled_count);
  for (uint32_t index = 0; index < copied; index++) {
    out_calls[index] = state->typed_scheduled[
        (state->typed_scheduled_head + index) %
        EX_WORKLET_TYPED_QUEUE_CAPACITY];
  }
  state->typed_scheduled_head =
      (state->typed_scheduled_head + copied) %
      EX_WORKLET_TYPED_QUEUE_CAPACITY;
  state->typed_scheduled_count -= copied;
  return copied;
}

extern "C" uint64_t ex_worklet_take_scheduled_drop_count(
    ExactHermesRuntime* handle) {
  auto* state = stateFor(handle);
  if (!state) {
    return 0;
  }
  const uint64_t dropped = state->scheduled_drops;
  state->scheduled_drops = 0;
  return dropped;
}

extern "C" int ex_hermes_dispatch_worklet_calls(
    ExactHermesRuntime* handle,
    const ExWorkletScheduledCall* calls,
    uint32_t count,
    uint32_t* out_delivered) {
  if (out_delivered) {
    *out_delivered = 0;
  }
  if (!handle || (count > 0 && !calls) || !out_delivered) {
    return EX_WORKLET_ERROR;
  }
  if (!exactRuntimeEnterUserExecution(handle)) {
    return EX_WORKLET_ERROR;
  }
  ScopedRuntimeExtensionHostTask hostTask(handle);
  if (!hostTask) return EX_WORKLET_ERROR;
  try {
    auto& rt = *handle->runtime;
    auto dispatcher_value =
        rt.global().getProperty(rt, "__exactRunOnJS");
    if (!dispatcher_value.isObject() ||
        !dispatcher_value.asObject(rt).isFunction(rt)) {
      return EX_WORKLET_NOOP;
    }
    auto dispatcher = dispatcher_value.asObject(rt).asFunction(rt);
    for (uint32_t call_index = 0; call_index < count; call_index++) {
      const auto& call = calls[call_index];
      if (call.source_identity == 0 || call.callback_identity == 0 ||
          call.argument_count > EX_WORKLET_MAX_RUN_ON_JS_SLOTS) {
        return EX_WORKLET_ERROR;
      }
      for (uint32_t argument_index = 0;
           argument_index < call.argument_count;
           argument_index++) {
        if (!std::isfinite(call.arguments[argument_index])) {
          return EX_WORKLET_ERROR;
        }
      }
      Object metadata(rt);
      metadata.setProperty(
          rt,
          "sourceIdentity",
          String::createFromUtf8(
              rt, std::to_string(call.source_identity)));
      metadata.setProperty(
          rt,
          "sourceSequence",
          String::createFromUtf8(
              rt, std::to_string(call.source_sequence)));
      metadata.setProperty(
          rt,
          "generation",
          String::createFromUtf8(rt, std::to_string(call.generation)));
      std::array<Value, EX_WORKLET_MAX_RUN_ON_JS_SLOTS + 2> arguments;
      arguments[0] = Value(static_cast<double>(call.callback_identity));
      arguments[1] = Value(std::move(metadata));
      for (uint32_t argument_index = 0;
           argument_index < call.argument_count;
           argument_index++) {
        arguments[argument_index + 2] =
            Value(static_cast<double>(call.arguments[argument_index]));
      }
      (void)dispatcher.call(
          rt,
          static_cast<const Value*>(arguments.data()),
          static_cast<size_t>(call.argument_count + 2));
      (*out_delivered)++;
    }
    if (!hostTask.finish()) return EX_WORKLET_ERROR;
    return EX_WORKLET_OK;
  } catch (const facebook::jsi::JSError&) {
    return EX_WORKLET_ERROR;
  } catch (const std::exception&) {
    return EX_WORKLET_ERROR;
  }
}

extern "C" int ex_hermes_dispatch_worklet_json_batch(
    ExactHermesRuntime* handle,
    const uint8_t* batch_json,
    size_t batch_len,
    uint64_t generation) {
  if (!handle || !batch_json || batch_len == 0) {
    return EX_WORKLET_ERROR;
  }
  if (!exactRuntimeEnterUserExecution(handle)) {
    return EX_WORKLET_ERROR;
  }
  ScopedRuntimeExtensionHostTask hostTask(handle);
  if (!hostTask) return EX_WORKLET_ERROR;
  try {
    auto& rt = *handle->runtime;
    auto dispatcher_value =
        rt.global().getProperty(rt, "__exactScheduleOnAppRuntime");
    if (!dispatcher_value.isObject() ||
        !dispatcher_value.asObject(rt).isFunction(rt)) {
      return EX_WORKLET_NOOP;
    }
    const std::string encoded(
        reinterpret_cast<const char*>(batch_json), batch_len);
    auto batch = parseJsonValue(rt, encoded.c_str());
    auto dispatcher = dispatcher_value.asObject(rt).asFunction(rt);
    (void)dispatcher.call(
        rt, std::move(batch), static_cast<double>(generation));
    if (!hostTask.finish()) return EX_WORKLET_ERROR;
    return EX_WORKLET_OK;
  } catch (const facebook::jsi::JSError&) {
    return EX_WORKLET_ERROR;
  } catch (const std::exception&) {
    return EX_WORKLET_ERROR;
  }
}

extern "C" int ex_hermes_dispatch_motion_rated_publish(
    ExactHermesRuntime* handle,
    const ExMotionRatedPublishSample* sample) {
  if (!handle || !sample || sample->channel_identity == 0 ||
      sample->value_count > EX_WORKLET_MAX_RUN_ON_JS_SLOTS) {
    return EX_WORKLET_ERROR;
  }
  if (!exactRuntimeEnterUserExecution(handle)) {
    return EX_WORKLET_ERROR;
  }
  ScopedRuntimeExtensionHostTask hostTask(handle);
  if (!hostTask) return EX_WORKLET_ERROR;
  for (uint32_t index = 0; index < sample->value_count; index++) {
    if (!std::isfinite(sample->values[index])) {
      return EX_WORKLET_ERROR;
    }
  }
  try {
    auto& rt = *handle->runtime;
    auto dispatcher_value =
        rt.global().getProperty(rt, "__exactMotionRatedPublish");
    if (!dispatcher_value.isObject() ||
        !dispatcher_value.asObject(rt).isFunction(rt)) {
      return EX_WORKLET_NOOP;
    }
    Array values(rt, sample->value_count);
    for (uint32_t index = 0; index < sample->value_count; index++) {
      values.setValueAtIndex(
          rt, index, static_cast<double>(sample->values[index]));
    }
    Object metadata(rt);
    metadata.setProperty(
        rt,
        "dirtyGeneration",
        String::createFromUtf8(
            rt, std::to_string(sample->dirty_generation)));
    metadata.setProperty(
        rt,
        "sampleTimeNs",
        String::createFromUtf8(rt, std::to_string(sample->sample_time_ns)));
    metadata.setProperty(rt, "heartbeat", (sample->flags & 1U) != 0);
    metadata.setProperty(rt, "programmatic", (sample->flags & 2U) != 0);
    auto dispatcher = dispatcher_value.asObject(rt).asFunction(rt);
    (void)dispatcher.call(
        rt,
        String::createFromUtf8(
            rt, std::to_string(sample->channel_identity)),
        std::move(values),
        std::move(metadata));
    if (!hostTask.finish()) return EX_WORKLET_ERROR;
    return EX_WORKLET_OK;
  } catch (const facebook::jsi::JSError&) {
    return EX_WORKLET_ERROR;
  } catch (const std::exception&) {
    return EX_WORKLET_ERROR;
  }
}
