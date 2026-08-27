// hermes_runtime_ios.cc
//
// Extracted from hermes_runtime.cc: iOS rendering pipeline callbacks.
// Provides dispatch, module dispatch, sync call, kernel integration,
// and module event emission. The kernel-only build of this source is selected
// by hermes_runtime_kernel_bridge.cc so its host ABI stays in a separate
// static-archive member.

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <hermes/hermes.h>
#include <jsi/jsi.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <atomic>
#include <cmath>
#include <cstdlib>
#if defined(__APPLE__)
#include <time.h>
#endif
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "hermes_runtime_internal.h"

// The display-paced animation-frame host path (opaque token provider +
// any-thread delivery ABI) is an Apple host feature, not an iOS-only one:
// macOS ExactAppMac installs the same ExactRuntimeAnimationFramePacer. Before
// this gate, macOS silently fell back to the 16ms setTimeout rAF shim.
#if defined(__APPLE__)
#define EXACT_APPLE_ANIMATION_FRAME_HOST 1
#endif

#if defined(IBEX_KERNEL_BRIDGE_OBJECT)
// Kernel FFI functions (implemented in Rust kernel crate)
extern "C" int32_t exact_get_state_mirror_buffer(
    void* handle, uint8_t** out_ptr, size_t* out_size);
extern "C" int64_t exact_module_get_state_offset(void* handle, uint16_t module_id);
extern "C" int32_t exact_get_layout(
    void* handle, uint32_t view_id,
    float* out_x, float* out_y, float* out_width, float* out_height);
extern "C" int32_t exact_get_absolute_layout(
    void* handle, uint32_t view_id,
    float* out_x, float* out_y, float* out_width, float* out_height);
extern "C" uint32_t exact_kernel_node_count(void* handle);
extern "C" int32_t exact_get_layout_tree_buffer_v1(
    void* handle,
    uint32_t root_view_id,
    uint8_t* out_buffer,
    uint32_t capacity,
    uint32_t* out_required);
extern "C" uint32_t exact_get_layout_generation(void* handle);
extern "C" int32_t exact_hit_test(void* handle, float x, float y);
extern "C" int32_t exact_node_exists(void* handle, uint32_t view_id);
extern "C" int32_t exact_get_root_view_id(void* handle, uint32_t root_id);
#else

namespace {

#if defined(EXACT_APPLE_ANIMATION_FRAME_HOST)
struct IOSAnimationFrameCallback {
  RuntimeCallbackTarget target;
  std::shared_ptr<facebook::jsi::Function> callback;
};

std::mutex g_ios_animation_frame_mutex;
std::unordered_map<uint64_t, IOSAnimationFrameCallback>
    g_ios_animation_frame_callbacks;
std::atomic<uint64_t> g_next_ios_animation_frame_token{1};

uint64_t allocateIOSAnimationFrameToken() {
  uint64_t token =
      g_next_ios_animation_frame_token.load(std::memory_order_relaxed);
  for (;;) {
    if (token == 0 || token == std::numeric_limits<uint64_t>::max()) return 0;
    if (g_next_ios_animation_frame_token.compare_exchange_weak(
            token, token + 1, std::memory_order_relaxed,
            std::memory_order_relaxed)) {
      return token;
    }
  }
}

uint64_t registerIOSAnimationFrameCallback(
    ExactHermesRuntime* handle, facebook::jsi::Function callback) {
  const uint64_t token = allocateIOSAnimationFrameToken();
  if (token == 0) return 0;

  auto target = exactRuntimeCallbackTarget(handle);
  if (!exactPinRuntimeNativeWorker(target)) return 0;

  bool inserted = false;
  try {
    auto owned = exactMakeTrackedJsiCallbackOwner(
        handle->runtime_thread, std::move(callback));
    std::lock_guard<std::mutex> lock(g_ios_animation_frame_mutex);
    inserted = g_ios_animation_frame_callbacks
                   .emplace(
                       token,
                       IOSAnimationFrameCallback{target, std::move(owned)})
                   .second;
  } catch (...) {
    exactUnpinRuntimeNativeWorker(target);
    throw;
  }
  if (!inserted) {
    exactUnpinRuntimeNativeWorker(target);
    return 0;
  }
  return token;
}

void removeIOSAnimationFrameCallback(uint64_t token) {
  RuntimeCallbackTarget target;
  {
    std::lock_guard<std::mutex> lock(g_ios_animation_frame_mutex);
    auto it = g_ios_animation_frame_callbacks.find(token);
    if (it == g_ios_animation_frame_callbacks.end()) return;
    target = it->second.target;
    g_ios_animation_frame_callbacks.erase(it);
  }
  exactUnpinRuntimeNativeWorker(target);
}

void removeIOSAnimationFrameCallbacksForRuntime(ExactHermesRuntime* handle) {
  std::vector<RuntimeCallbackTarget> targets;
  {
    std::lock_guard<std::mutex> lock(g_ios_animation_frame_mutex);
    for (auto it = g_ios_animation_frame_callbacks.begin();
         it != g_ios_animation_frame_callbacks.end();) {
      if (it->second.target.runtime == handle) {
        targets.push_back(it->second.target);
        it = g_ios_animation_frame_callbacks.erase(it);
      } else {
        ++it;
      }
    }
  }
  for (auto target : targets) exactUnpinRuntimeNativeWorker(target);
}
#endif

}  // namespace

void installIOSHostFunctions(ExactHermesRuntime* handle) {
  if (!handle || handle->restricted) return;
  auto& rt = *handle->runtime;
#if defined(EXACT_APPLE_ANIMATION_FRAME_HOST)
  auto requestAnimationFrameFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRequestAnimationFrame"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() ||
            !args[0].asObject(runtime).isFunction(runtime) ||
            !handle->ios_animation_frame_request_callback) {
          return facebook::jsi::Value(false);
        }

        auto callback = args[0].asObject(runtime).asFunction(runtime);
        const uint64_t token =
            registerIOSAnimationFrameCallback(handle, std::move(callback));
        if (token == 0) return facebook::jsi::Value(false);

        try {
          // This provider only hands an opaque token to the host. The host
          // asynchronously moves it to the primary surface clock; it must not
          // enter Hermes or synchronously wait for main from this callback.
          handle->ios_animation_frame_request_callback(
              token, handle->ios_animation_frame_request_context);
        } catch (...) {
          removeIOSAnimationFrameCallback(token);
          return facebook::jsi::Value(false);
        }
        return facebook::jsi::Value(true);
      });
  rt.global().setProperty(
      rt, "__exactRequestAnimationFrame", std::move(requestAnimationFrameFn));
#endif

  auto registerExactDispatchEvent =
      facebook::jsi::Function::createFromHostFunction(
          rt,
          facebook::jsi::PropNameID::forAscii(
              rt, "__ibexRegisterExactDispatchEvent"),
          1,
          [handle](facebook::jsi::Runtime& callbackRuntime,
                   const facebook::jsi::Value&,
                   const facebook::jsi::Value* args,
                   size_t count) -> facebook::jsi::Value {
            if (count != 1 || !args[0].isObject() ||
                !args[0].asObject(callbackRuntime).isFunction(
                    callbackRuntime) ||
                currentPrincipalId() !=
                    static_cast<uint64_t>(kFirstPartyRootPrincipalId)) {
              return facebook::jsi::Value(false);
            }
            auto candidate =
                args[0].asObject(callbackRuntime).asFunction(callbackRuntime);
            auto publicValue = callbackRuntime.global().getProperty(
                callbackRuntime, "__exactDispatchEvent");
            if (!publicValue.isObject() ||
                !publicValue.getObject(callbackRuntime).isFunction(
                    callbackRuntime)) {
              return facebook::jsi::Value(false);
            }
            auto publicDispatcher =
                publicValue.getObject(callbackRuntime).asFunction(
                    callbackRuntime);
            if (!facebook::jsi::Object::strictEquals(
                    callbackRuntime, candidate, publicDispatcher)) {
              return facebook::jsi::Value(false);
            }
            if (handle->clock_i_dispatcher) {
              return facebook::jsi::Value(
                  facebook::jsi::Object::strictEquals(
                      callbackRuntime,
                      *handle->clock_i_dispatcher,
                      candidate));
            }
            auto retained = std::make_unique<facebook::jsi::Function>(
                std::move(candidate));
            const std::string identity =
                "ibex-clock-i-dispatcher-u64:" +
                std::to_string(handle->runtime_nonce);
            handle->clock_i_dispatcher = std::move(retained);
            handle->clock_i_dispatcher_identity = identity;
            return facebook::jsi::Value(true);
          });
  rt.global().setProperty(
      rt,
      "__ibexRegisterExactDispatchEvent",
      std::move(registerExactDispatchEvent));
  sealGlobalHostFunction(rt, "__ibexRegisterExactDispatchEvent");
}

void unregisterIOSHostFunctions(ExactHermesRuntime* handle) {
  if (!handle) return;
  handle->clock_i_dispatcher.reset();
  handle->clock_i_dispatcher_identity.clear();
#if defined(EXACT_APPLE_ANIMATION_FRAME_HOST)
  handle->ios_animation_frame_request_callback = nullptr;
  handle->ios_animation_frame_request_context = nullptr;
  removeIOSAnimationFrameCallbacksForRuntime(handle);
#else
  (void)handle;
#endif
}

// @abi-callback ex_hermes_set_animation_frame_request_callback callback delivery=none
extern "C" void ex_hermes_set_animation_frame_request_callback(
    ExactHermesRuntime* runtime,
    void (*callback)(uint64_t token, void* context),
    void* context) {
  if (!runtime) return;
  ExactRuntimeDriveGuard drive(runtime);
  if (!drive || runtime->restricted) return;
#if defined(EXACT_APPLE_ANIMATION_FRAME_HOST)
  runtime->ios_animation_frame_request_callback = callback;
  runtime->ios_animation_frame_request_context = callback ? context : nullptr;
  if (!callback) removeIOSAnimationFrameCallbacksForRuntime(runtime);
#else
  (void)callback;
  (void)context;
#endif
}

extern "C" int32_t ex_hermes_deliver_animation_frame(uint64_t token) {
#if defined(EXACT_APPLE_ANIMATION_FRAME_HOST)
  IOSAnimationFrameCallback entry;
  {
    std::lock_guard<std::mutex> lock(g_ios_animation_frame_mutex);
    auto it = g_ios_animation_frame_callbacks.find(token);
    if (it == g_ios_animation_frame_callbacks.end()) return 0;
    entry = std::move(it->second);
    g_ios_animation_frame_callbacks.erase(it);
  }

  if (!entry.target || !entry.callback) {
    exactUnpinRuntimeNativeWorker(entry.target);
    return 0;
  }

  // Stamp the host-monotonic delivery time on the delivering (clock) thread.
  // CLOCK_UPTIME_RAW is mach_absolute_time, the same clock family as
  // CACurrentMediaTime(), so JavaScript can place this frame on one axis
  // with presenter apply stamps (Exact LLP 0488 W4 measured-box evidence).
  // It is a plain number handed to the callback; no clock is read on the
  // runtime thread and the delivery ABI is unchanged.
  double host_monotonic_ms = std::nan("");
#if defined(__APPLE__)
  host_monotonic_ms =
      static_cast<double>(clock_gettime_nsec_np(CLOCK_UPTIME_RAW)) / 1e6;
#endif

  bool accepted = false;
  // Delivery may originate on main, but the retained JSI function is only
  // called (or discarded during teardown) on the exact runtime owner thread.
  pushRuntimeCallback(
      entry.target,
      [callback = std::move(entry.callback),
       host_monotonic_ms](facebook::jsi::Runtime& runtime) {
        if (std::isfinite(host_monotonic_ms)) {
          callback->call(runtime, facebook::jsi::Value(host_monotonic_ms));
        } else {
          callback->call(runtime);
        }
      },
      &accepted);
  exactUnpinRuntimeNativeWorker(entry.target);
  return accepted ? 1 : 0;
#else
  (void)token;
  return 0;
#endif
}

// iOS Rendering Pipeline Callbacks
// =============================================================================
// These functions allow the iOS app to register callbacks for:
// - exact.dispatch(Uint8Array) - binary protocol for view tree operations
// - exact.dispatchModule(Uint8Array) - async native module calls
// - exact.callModuleSync(Uint8Array) - blocking native module calls

extern "C" void ex_hermes_set_dispatch_callback(
    ExactHermesRuntime* runtime,
    void (*callback)(const uint8_t* data, size_t length, void* context),
    void* context) {
  if (!runtime) return;
  if (runtime->restricted) return;  // no exact.dispatch on worklet runtimes (LLP 0297 §4.3)
  runtime->ios_dispatch_callback = callback;
  runtime->ios_dispatch_context = context;

  // Install exact.dispatch() in JS
  auto& rt = *runtime->runtime;

  // Get or create the 'exact' global object
  facebook::jsi::Value exactVal = rt.global().getProperty(rt, "exact");
  facebook::jsi::Object exactObj = exactVal.isObject()
      ? exactVal.getObject(rt)
      : facebook::jsi::Object(rt);

  auto dispatchFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "dispatch"),
      1,
      [runtime](facebook::jsi::Runtime& rt,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() || !runtime->ios_dispatch_callback) {
          return facebook::jsi::Value::undefined();
        }

        auto obj = args[0].getObject(rt);
        if (obj.isArrayBuffer(rt)) {
          auto ab = obj.getArrayBuffer(rt);
          runtime->ios_dispatch_callback(ab.data(rt), ab.size(rt),
                                          runtime->ios_dispatch_context);
        } else if (obj.hasProperty(rt, "buffer")) {
          auto bufVal = obj.getProperty(rt, "buffer");
          if (bufVal.isObject()) {
            auto bufObj = bufVal.getObject(rt);
            if (bufObj.isArrayBuffer(rt)) {
              auto ab = bufObj.getArrayBuffer(rt);
              size_t offset = 0, length = ab.size(rt);
              auto offVal = obj.getProperty(rt, "byteOffset");
              if (offVal.isNumber()) offset = static_cast<size_t>(offVal.getNumber());
              auto lenVal = obj.getProperty(rt, "byteLength");
              if (lenVal.isNumber()) length = static_cast<size_t>(lenVal.getNumber());
              runtime->ios_dispatch_callback(ab.data(rt) + offset, length,
                                              runtime->ios_dispatch_context);
            }
          }
        }
        return facebook::jsi::Value::undefined();
      });

  exactObj.setProperty(rt, "dispatch", std::move(dispatchFn));
  rt.global().setProperty(rt, "exact", std::move(exactObj));
}

extern "C" void ex_hermes_set_dispatch_with_debug_context_callback(
    ExactHermesRuntime* runtime,
    void (*callback)(
        const uint8_t* data,
        size_t length,
        const char* debug_context_json,
        void* context),
    void* context) {
  if (!runtime) return;
  if (runtime->restricted) return;  // LLP 0297 §4.3
  runtime->ios_dispatch_with_debug_context_callback = callback;
  runtime->ios_dispatch_context = context;

  auto& rt = *runtime->runtime;

  facebook::jsi::Value exactVal = rt.global().getProperty(rt, "exact");
  facebook::jsi::Object exactObj = exactVal.isObject()
      ? exactVal.getObject(rt)
      : facebook::jsi::Object(rt);

  auto dispatchWithDebugContextFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "dispatchWithDebugContext"),
      2,
      [runtime](facebook::jsi::Runtime& rt,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (count < 2 || !runtime->ios_dispatch_with_debug_context_callback) {
          return facebook::jsi::Value::undefined();
        }

        auto bytes = extractBytes(rt, args[0]);
        if (bytes.empty()) {
          return facebook::jsi::Value::undefined();
        }

        std::string contextJson;
        if (args[1].isString()) {
          contextJson = args[1].asString(rt).utf8(rt);
        } else if (!args[1].isNull() && !args[1].isUndefined()) {
          auto jsonGlobal = rt.global().getPropertyAsObject(rt, "JSON");
          auto stringifyFn = jsonGlobal.getPropertyAsFunction(rt, "stringify");
          auto stringified = stringifyFn.call(rt, args[1]);
          if (stringified.isString()) {
            contextJson = stringified.asString(rt).utf8(rt);
          }
        }

        runtime->ios_dispatch_with_debug_context_callback(
            bytes.data(),
            bytes.size(),
            contextJson.empty() ? nullptr : contextJson.c_str(),
            runtime->ios_dispatch_context);
        return facebook::jsi::Value::undefined();
      });

  exactObj.setProperty(rt, "dispatchWithDebugContext", std::move(dispatchWithDebugContextFn));
  rt.global().setProperty(rt, "exact", std::move(exactObj));
}

extern "C" void ex_hermes_set_module_dispatch_callback(
    ExactHermesRuntime* runtime,
    void (*callback)(const uint8_t* data, size_t length, void* context),
    void* context) {
  if (!runtime) return;
  if (runtime->restricted) return;  // LLP 0297 §4.3
  runtime->ios_module_dispatch_callback = callback;
  runtime->ios_module_dispatch_context = context;

  auto& rt = *runtime->runtime;

  facebook::jsi::Value exactVal = rt.global().getProperty(rt, "exact");
  facebook::jsi::Object exactObj = exactVal.isObject()
      ? exactVal.getObject(rt)
      : facebook::jsi::Object(rt);

  auto fn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "dispatchModule"),
      1,
      [runtime](facebook::jsi::Runtime& rt,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() || !runtime->ios_module_dispatch_callback) {
          return facebook::jsi::Value::undefined();
        }

        auto obj = args[0].getObject(rt);
        if (obj.isArrayBuffer(rt)) {
          auto ab = obj.getArrayBuffer(rt);
          runtime->ios_module_dispatch_callback(ab.data(rt), ab.size(rt),
                                                 runtime->ios_module_dispatch_context);
        } else if (obj.hasProperty(rt, "buffer")) {
          auto bufVal = obj.getProperty(rt, "buffer");
          if (bufVal.isObject()) {
            auto bufObj = bufVal.getObject(rt);
            if (bufObj.isArrayBuffer(rt)) {
              auto ab = bufObj.getArrayBuffer(rt);
              size_t offset = 0, length = ab.size(rt);
              auto offVal = obj.getProperty(rt, "byteOffset");
              if (offVal.isNumber()) offset = static_cast<size_t>(offVal.getNumber());
              auto lenVal = obj.getProperty(rt, "byteLength");
              if (lenVal.isNumber()) length = static_cast<size_t>(lenVal.getNumber());
              runtime->ios_module_dispatch_callback(ab.data(rt) + offset, length,
                                                     runtime->ios_module_dispatch_context);
            }
          }
        }
        return facebook::jsi::Value::undefined();
      });

  exactObj.setProperty(rt, "dispatchModule", std::move(fn));
  rt.global().setProperty(rt, "exact", std::move(exactObj));
}

// @abi-callback ex_hermes_set_module_sync_callback callback output=2 ownership=native-consumes
extern "C" void ex_hermes_set_module_sync_callback(
    ExactHermesRuntime* runtime,
    int (*callback)(const uint8_t* data, size_t length,
                    uint8_t** result_data, size_t* result_length,
                    void* context),
    void* context) {
  if (!runtime) return;
  if (runtime->restricted) return;  // LLP 0297 §4.3
  runtime->ios_module_sync_callback = callback;
  runtime->ios_module_sync_context = context;

  auto& rt = *runtime->runtime;

  facebook::jsi::Value exactVal = rt.global().getProperty(rt, "exact");
  facebook::jsi::Object exactObj = exactVal.isObject()
      ? exactVal.getObject(rt)
      : facebook::jsi::Object(rt);

  auto fn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "callModuleSync"),
      1,
      [runtime](facebook::jsi::Runtime& rt,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() || !runtime->ios_module_sync_callback) {
          return facebook::jsi::Value::undefined();
        }

        const uint8_t* inputData = nullptr;
        size_t inputLength = 0;

        auto obj = args[0].getObject(rt);
        if (obj.isArrayBuffer(rt)) {
          auto ab = obj.getArrayBuffer(rt);
          inputData = ab.data(rt);
          inputLength = ab.size(rt);
        } else if (obj.hasProperty(rt, "buffer")) {
          auto bufVal = obj.getProperty(rt, "buffer");
          if (bufVal.isObject()) {
            auto bufObj = bufVal.getObject(rt);
            if (bufObj.isArrayBuffer(rt)) {
              auto ab = bufObj.getArrayBuffer(rt);
              inputData = ab.data(rt);
              inputLength = ab.size(rt);
              auto offVal = obj.getProperty(rt, "byteOffset");
              if (offVal.isNumber()) inputData += static_cast<size_t>(offVal.getNumber());
              auto lenVal = obj.getProperty(rt, "byteLength");
              if (lenVal.isNumber()) inputLength = static_cast<size_t>(lenVal.getNumber());
            }
          }
        }

        if (!inputData) {
          return facebook::jsi::Value::undefined();
        }

        uint8_t* resultData = nullptr;
        size_t resultLength = 0;
        int status = runtime->ios_module_sync_callback(
            inputData, inputLength,
            &resultData, &resultLength,
            runtime->ios_module_sync_context);

        if (status != 0) {
          return facebook::jsi::Value::undefined();
        }

        if (!resultData && resultLength == 0) {
          return makeUint8Array(rt, {});
        }

        if (!resultData) {
          return facebook::jsi::Value::undefined();
        }

        std::vector<uint8_t> resultBytes(resultData, resultData + resultLength);
        free(resultData);
        return makeUint8Array(rt, std::move(resultBytes));
      });

  exactObj.setProperty(rt, "callModuleSync", std::move(fn));
  rt.global().setProperty(rt, "exact", std::move(exactObj));
}
#endif

#if defined(IBEX_KERNEL_BRIDGE_OBJECT)
extern "C" void ex_hermes_set_kernel_handle(
    ExactHermesRuntime* runtime,
    void* kernel_handle) {
  if (!runtime || !runtime->runtime) return;
  // Restricted worklet runtimes get no direct kernel access (LLP 0297
  // §4.3); geometry reads go through the measure() host callback against
  // the presenter snapshot instead.
  if (runtime->restricted) return;
  runtime->kernel_handle = kernel_handle;

  auto& rt = *runtime->runtime;

  facebook::jsi::Value exactVal = rt.global().getProperty(rt, "exact");
  facebook::jsi::Object exactObj = exactVal.isObject()
      ? exactVal.getObject(rt)
      : facebook::jsi::Object(rt);

  auto getStateMirrorFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getStateMirror"),
      0,
      [runtime](facebook::jsi::Runtime& rt,
                const facebook::jsi::Value&,
                const facebook::jsi::Value*,
                size_t) -> facebook::jsi::Value {
        if (!runtime->kernel_handle) {
          return facebook::jsi::Value::null();
        }

        uint8_t* buffer = nullptr;
        size_t size = 0;
        if (exact_get_state_mirror_buffer(runtime->kernel_handle, &buffer, &size) != 0 ||
            !buffer) {
          return facebook::jsi::Value::null();
        }

        auto arrayBufferObject = rt.global()
            .getPropertyAsFunction(rt, "ArrayBuffer")
            .callAsConstructor(rt, static_cast<double>(size))
            .getObject(rt);
        auto arrayBuffer = arrayBufferObject.getArrayBuffer(rt);
        if (size > 0) {
          memcpy(arrayBuffer.data(rt), buffer, size);
        }
        return facebook::jsi::Value(std::move(arrayBufferObject));
      });

  auto getModuleStateOffsetFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getModuleStateOffset"),
      1,
      [runtime](facebook::jsi::Runtime&,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (!runtime->kernel_handle || count == 0 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }

        double rawModuleId = args[0].asNumber();
        if (rawModuleId < 0 || rawModuleId > static_cast<double>(UINT16_MAX)) {
          return facebook::jsi::Value::null();
        }

        auto offset = exact_module_get_state_offset(
            runtime->kernel_handle,
            static_cast<uint16_t>(rawModuleId));
        if (offset < 0) {
          return facebook::jsi::Value::null();
        }

        return facebook::jsi::Value(static_cast<double>(offset));
      });

  auto getLayoutFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getLayout"),
      1,
      [runtime](facebook::jsi::Runtime& rt,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (!runtime->kernel_handle || count == 0 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }

        double rawViewId = args[0].asNumber();
        if (rawViewId < 0 || rawViewId > static_cast<double>(UINT32_MAX)) {
          return facebook::jsi::Value::null();
        }

        float x = 0;
        float y = 0;
        float width = 0;
        float height = 0;
        int32_t result = exact_get_layout(
            runtime->kernel_handle,
            static_cast<uint32_t>(rawViewId),
            &x,
            &y,
            &width,
            &height);

        if (result != 0) {
          return facebook::jsi::Value::null();
        }

        facebook::jsi::Object frame(rt);
        frame.setProperty(rt, "x", static_cast<double>(x));
        frame.setProperty(rt, "y", static_cast<double>(y));
        frame.setProperty(rt, "width", static_cast<double>(width));
        frame.setProperty(rt, "height", static_cast<double>(height));
        return facebook::jsi::Value(std::move(frame));
      });

  auto getAbsoluteLayoutFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getAbsoluteLayout"),
      1,
      [runtime](facebook::jsi::Runtime& rt,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (!runtime->kernel_handle || count == 0 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }

        double rawViewId = args[0].asNumber();
        if (rawViewId < 0 || rawViewId > static_cast<double>(UINT32_MAX)) {
          return facebook::jsi::Value::null();
        }

        float x = 0;
        float y = 0;
        float width = 0;
        float height = 0;
        int32_t result = exact_get_absolute_layout(
            runtime->kernel_handle,
            static_cast<uint32_t>(rawViewId),
            &x,
            &y,
            &width,
            &height);

        if (result != 0) {
          return facebook::jsi::Value::null();
        }

        facebook::jsi::Object frame(rt);
        frame.setProperty(rt, "x", static_cast<double>(x));
        frame.setProperty(rt, "y", static_cast<double>(y));
        frame.setProperty(rt, "width", static_cast<double>(width));
        frame.setProperty(rt, "height", static_cast<double>(height));
        return facebook::jsi::Value(std::move(frame));
      });

  // Whole-subtree EXLT v1 export. The Exact renderer decodes this fixed-width
  // byte schema once per frame-index cache miss, replacing one JSI object call
  // per node while retaining getLayout/getAbsoluteLayout as sparse/debug
  // compatibility reads (ENG-24390).
  auto getLayoutTreeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getLayoutTree"),
      1,
      [runtime](facebook::jsi::Runtime& rt,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (!runtime->kernel_handle || count == 0 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }

        double rawRootViewId = args[0].asNumber();
        if (!std::isfinite(rawRootViewId) ||
            std::floor(rawRootViewId) != rawRootViewId ||
            rawRootViewId < 0 ||
            rawRootViewId > static_cast<double>(INT32_MAX)) {
          return facebook::jsi::Value::null();
        }

        constexpr uint64_t kHeaderBytes = 32;
        constexpr uint64_t kRowBytes = 32;
        uint64_t capacity64 = kHeaderBytes +
            static_cast<uint64_t>(exact_kernel_node_count(runtime->kernel_handle)) *
                kRowBytes;
        if (capacity64 > UINT32_MAX) {
          return facebook::jsi::Value::null();
        }

        std::vector<uint8_t> bytes(static_cast<size_t>(capacity64));
        uint32_t required = 0;
        int32_t status = exact_get_layout_tree_buffer_v1(
            runtime->kernel_handle,
            static_cast<uint32_t>(rawRootViewId),
            bytes.data(),
            static_cast<uint32_t>(bytes.size()),
            &required);
        if (status != 0 || required > bytes.size()) {
          return facebook::jsi::Value::null();
        }

        bytes.resize(required);
        return makeUint8Array(rt, std::move(bytes));
      });

  auto getLayoutGenerationFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getLayoutGeneration"),
      0,
      [runtime](facebook::jsi::Runtime&,
                const facebook::jsi::Value&,
                const facebook::jsi::Value*,
                size_t) -> facebook::jsi::Value {
        if (!runtime->kernel_handle) {
          return facebook::jsi::Value(0);
        }

        return facebook::jsi::Value(static_cast<double>(
            exact_get_layout_generation(runtime->kernel_handle)));
      });

  auto hitTestFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "hitTest"),
      2,
      [runtime](facebook::jsi::Runtime&,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (!runtime->kernel_handle || count < 2 ||
            !args[0].isNumber() || !args[1].isNumber()) {
          return facebook::jsi::Value::null();
        }

        int32_t viewId = exact_hit_test(
            runtime->kernel_handle,
            static_cast<float>(args[0].asNumber()),
            static_cast<float>(args[1].asNumber()));

        if (viewId < 0) {
          return facebook::jsi::Value::null();
        }

        return facebook::jsi::Value(static_cast<double>(viewId));
      });

  auto nodeExistsFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "nodeExists"),
      1,
      [runtime](facebook::jsi::Runtime&,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (!runtime->kernel_handle || count == 0 || !args[0].isNumber()) {
          return facebook::jsi::Value(false);
        }

        double rawViewId = args[0].asNumber();
        if (rawViewId < 0 || rawViewId > static_cast<double>(UINT32_MAX)) {
          return facebook::jsi::Value(false);
        }

        return facebook::jsi::Value(
            exact_node_exists(runtime->kernel_handle, static_cast<uint32_t>(rawViewId)) == 1);
      });

  auto getRootViewIdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getRootViewId"),
      1,
      [runtime](facebook::jsi::Runtime&,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
        if (!runtime->kernel_handle || count == 0 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }

        double rawRootId = args[0].asNumber();
        if (rawRootId < 0 || rawRootId > static_cast<double>(UINT32_MAX)) {
          return facebook::jsi::Value::null();
        }

        int32_t rootViewId = exact_get_root_view_id(
            runtime->kernel_handle,
            static_cast<uint32_t>(rawRootId));
        if (rootViewId < 0) {
          return facebook::jsi::Value::null();
        }

        return facebook::jsi::Value(static_cast<double>(rootViewId));
      });

  exactObj.setProperty(rt, "getStateMirror", std::move(getStateMirrorFn));
  exactObj.setProperty(rt, "getModuleStateOffset", std::move(getModuleStateOffsetFn));
  exactObj.setProperty(rt, "getLayout", std::move(getLayoutFn));
  exactObj.setProperty(rt, "getAbsoluteLayout", std::move(getAbsoluteLayoutFn));
  exactObj.setProperty(rt, "getLayoutTree", std::move(getLayoutTreeFn));
  exactObj.setProperty(rt, "getLayoutGeneration", std::move(getLayoutGenerationFn));
  exactObj.setProperty(rt, "hitTest", std::move(hitTestFn));
  exactObj.setProperty(rt, "nodeExists", std::move(nodeExistsFn));
  exactObj.setProperty(rt, "getRootViewId", std::move(getRootViewIdFn));
  exactObj.setProperty(rt, "hasKernelInspector", runtime->kernel_handle != nullptr);
  rt.global().setProperty(rt, "exact", std::move(exactObj));
}
#else

static int emit_module_event_impl(
    ExactHermesRuntime* runtime,
    const char* module_name,
    const char* event_name,
    const uint32_t* node_id,
    const uint8_t* payload,
    size_t payload_len) {
  if (!exactRuntimeEnterUserExecution(runtime)) return -1;

  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) return -1;

  auto& rt = *runtime->runtime;

  try {
    auto handlerVal = rt.global().getProperty(rt, "__exactModuleEvent");
    if (!handlerVal.isObject() || !handlerVal.getObject(rt).isFunction(rt)) {
      return -1;
    }

    auto handler = handlerVal.getObject(rt).asFunction(rt);

    auto moduleStr = facebook::jsi::String::createFromUtf8(rt, module_name);
    auto eventStr = facebook::jsi::String::createFromUtf8(rt, event_name);
    facebook::jsi::Value nodeIdValue = node_id
        ? facebook::jsi::Value(static_cast<double>(*node_id))
        : facebook::jsi::Value::undefined();

    // Create Uint8Array for payload
    if (payload && payload_len > 0) {
      auto ab = rt.global()
          .getPropertyAsFunction(rt, "ArrayBuffer")
          .callAsConstructor(rt, static_cast<int>(payload_len))
          .getObject(rt)
          .getArrayBuffer(rt);
      memcpy(ab.data(rt), payload, payload_len);
      auto uint8ArrayCtor = rt.global().getPropertyAsFunction(rt, "Uint8Array");
      auto payloadArray = uint8ArrayCtor.callAsConstructor(
          rt, std::move(ab));
      if (node_id) {
        handler.call(
            rt,
            std::move(moduleStr),
            std::move(eventStr),
            std::move(nodeIdValue),
            std::move(payloadArray));
      } else {
        handler.call(rt, std::move(moduleStr), std::move(eventStr), std::move(payloadArray));
      }
    } else {
      if (node_id) {
        handler.call(
            rt,
            std::move(moduleStr),
            std::move(eventStr),
            std::move(nodeIdValue));
      } else {
        handler.call(rt, std::move(moduleStr), std::move(eventStr));
      }
    }
    if (!hostTask.finish()) return -1;
    return 0;
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
    return -1;
  } catch (...) {
    return -1;
  }
}

// Emit a module event to JS (for native -> JS events)
extern "C" int ex_hermes_emit_module_event(
    ExactHermesRuntime* runtime,
    const char* module_name,
    const char* event_name,
    const uint8_t* payload,
    size_t payload_len) {
  return emit_module_event_impl(
      runtime,
      module_name,
      event_name,
      nullptr,
      payload,
      payload_len);
}

extern "C" int ex_hermes_emit_module_view_event(
    ExactHermesRuntime* runtime,
    const char* module_name,
    const char* event_name,
    uint32_t node_id,
    const uint8_t* payload,
    size_t payload_len) {
  return emit_module_event_impl(
      runtime,
      module_name,
      event_name,
      &node_id,
      payload,
      payload_len);
}

extern "C" int ex_hermes_dispatch_event(
    ExactHermesRuntime* runtime,
    uint32_t handler_id,
    const char* payload_json) {
  if (!runtime) return -1;
  // Standard public-entry hygiene: every other embedder ingress validates the
  // generation/owner and enters the runtime security context before touching
  // JSI. Input dispatch previously skipped this, entering JS as an undeclared
  // native boundary that inherited whatever residual principal/carrier state
  // the thread last held. This API delivers FRESH host events only;
  // continuations and completions must use the carrier-bearing queues, and a
  // REENTRANT drive is a refusal (the host requeues as a new outer drive).
  // @ref LLP 0051#a-runtime-entry-hygiene-at-ex_hermes_dispatch_event-landed-shape — fresh-host-event ingress takes the drive guard
  ExactRuntimeDriveGuard drive(runtime);
  if (!drive || runtime->restricted) return -1;
  if (!exactRuntimeEnterUserExecution(runtime)) return -1;

  ScopedRuntimeExtensionHostTask hostTask(runtime);
  if (!hostTask) return -1;

  auto& rt = *runtime->runtime;

  try {
    auto handlerVal = rt.global().getProperty(rt, "__exactDispatchEvent");
    if (!handlerVal.isObject() || !handlerVal.getObject(rt).isFunction(rt)) {
      return -1;
    }

    auto handler = handlerVal.getObject(rt).asFunction(rt);
    auto payload = payload_json && payload_json[0] != '\0'
        ? parseJsonValue(rt, payload_json)
        : facebook::jsi::Value::undefined();
    handler.call(
        rt,
        facebook::jsi::Value(static_cast<double>(handler_id)),
        std::move(payload));
    if (!hostTask.finish()) return -1;
    return 0;
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
    return -1;
  } catch (...) {
    return -1;
  }
}

namespace {

struct ClockICarrierAttestorState {
  enum class Phase {
    AwaitingEnter,
    AwaitingHandlerReturn,
    Complete,
    Invalid,
  };

  bool active{true};
  Phase phase{Phase::AwaitingEnter};
  uint64_t principal_id{static_cast<uint64_t>(kNoUserPrincipalId)};
  uint64_t runtime_nonce{0};
  uint64_t entry_runtime_monotonic_ms{0};
  uint64_t handler_returned_runtime_monotonic_ms{0};
};

bool validClockIUtf8(const uint8_t* bytes, size_t length) {
  size_t index = 0;
  while (index < length) {
    const uint8_t first = bytes[index++];
    if (first <= 0x7Fu) continue;
    if (first >= 0xC2u && first <= 0xDFu) {
      if (index >= length || (bytes[index++] & 0xC0u) != 0x80u) return false;
      continue;
    }
    if (first >= 0xE0u && first <= 0xEFu) {
      if (index + 1 >= length) return false;
      const uint8_t second = bytes[index++];
      const uint8_t third = bytes[index++];
      if ((second & 0xC0u) != 0x80u || (third & 0xC0u) != 0x80u ||
          (first == 0xE0u && second < 0xA0u) ||
          (first == 0xEDu && second >= 0xA0u)) {
        return false;
      }
      continue;
    }
    if (first >= 0xF0u && first <= 0xF4u) {
      if (index + 2 >= length) return false;
      const uint8_t second = bytes[index++];
      const uint8_t third = bytes[index++];
      const uint8_t fourth = bytes[index++];
      if ((second & 0xC0u) != 0x80u || (third & 0xC0u) != 0x80u ||
          (fourth & 0xC0u) != 0x80u ||
          (first == 0xF0u && second < 0x90u) ||
          (first == 0xF4u && second >= 0x90u)) {
        return false;
      }
      continue;
    }
    return false;
  }
  return true;
}

bool copyClockIBindingSlice(
    const uint8_t* bytes,
    size_t length,
    std::string& destination) {
  if (bytes == nullptr || length == 0 ||
      length > EX_HERMES_CLOCK_I_DISPATCH_BINDING_MAX_BYTES_V1 ||
      !validClockIUtf8(bytes, length)) {
    return false;
  }
  destination.assign(reinterpret_cast<const char*>(bytes), length);
  return true;
}

void appendClockIJsonString(std::string& output, const std::string& value) {
  constexpr char kHex[] = "0123456789abcdef";
  output.push_back('"');
  for (const unsigned char byte : value) {
    switch (byte) {
      case '"': output += "\\\""; break;
      case '\\': output += "\\\\"; break;
      case '\b': output += "\\b"; break;
      case '\f': output += "\\f"; break;
      case '\n': output += "\\n"; break;
      case '\r': output += "\\r"; break;
      case '\t': output += "\\t"; break;
      default:
        if (byte < 0x20u) {
          output += "\\u00";
          output.push_back(kHex[(byte >> 4) & 0x0Fu]);
          output.push_back(kHex[byte & 0x0Fu]);
        } else {
          output.push_back(static_cast<char>(byte));
        }
    }
  }
  output.push_back('"');
}

const char* clockIPrincipalLabel(uint64_t principal_id) {
  if (principal_id == static_cast<uint64_t>(kNoUserPrincipalId)) {
    return "no-user";
  }
  if (principal_id == static_cast<uint64_t>(kFirstPartyRootPrincipalId)) {
    return "root";
  }
  if (principal_id == static_cast<uint64_t>(kRuntimePrincipalId)) {
    return "runtime";
  }
  return "package";
}

uint32_t clockIPrincipalStatus(uint64_t principal_id) {
  return principal_id == static_cast<uint64_t>(kNoUserPrincipalId)
      ? EX_HERMES_ASYNC_FAILURE_PRINCIPAL_UNAVAILABLE
      : EX_HERMES_ASYNC_FAILURE_PRINCIPAL_AUTHENTICATED;
}

const char* clockIPrincipalStatusLabel(uint32_t status) {
  return status == EX_HERMES_ASYNC_FAILURE_PRINCIPAL_UNAVAILABLE
      ? "unavailable"
      : "authenticated";
}

std::string clockICarrierReceiptJson(
    uint64_t sequence,
    uint32_t handler_id,
    const std::string& dispatcher_identity,
    const std::string& nonce,
    const std::string& input_id_json,
    const std::string& generation_json,
    const std::string& host_input_receipt_id,
    const ClockICarrierAttestorState& attestation) {
  const uint32_t principal_status =
      clockIPrincipalStatus(attestation.principal_id);
  std::string output;
  output.reserve(
      nonce.size() + input_id_json.size() + generation_json.size() +
      host_input_receipt_id.size() + 512);
  output += "{\"schemaVersion\":\"ibex-clock-i-carrier-attestation/1\",";
  output += "\"receiptId\":";
  appendClockIJsonString(
      output,
      "ibex-clock-i-" + std::to_string(attestation.runtime_nonce) + "-" +
          std::to_string(sequence));
  output += ",\"nonce\":";
  appendClockIJsonString(output, nonce);
  output += ",\"inputIdJson\":";
  appendClockIJsonString(output, input_id_json);
  output += ",\"generationJson\":";
  appendClockIJsonString(output, generation_json);
  output += ",\"hostInputReceiptId\":";
  appendClockIJsonString(output, host_input_receipt_id);
  output += ",\"handlerId\":" + std::to_string(handler_id);
  output += ",\"dispatcherIdentity\":";
  appendClockIJsonString(output, dispatcher_identity);
  output += ",\"handlerIdentity\":";
  appendClockIJsonString(
      output,
      dispatcher_identity + ":handler:" + std::to_string(handler_id));
  output += ",\"principal\":";
  appendClockIJsonString(output, clockIPrincipalLabel(attestation.principal_id));
  output += ",\"principalStatus\":";
  appendClockIJsonString(
      output, clockIPrincipalStatusLabel(principal_status));
  output += ",\"authority\":";
  // V1 preserves the carrier tuple shape but does not sample a second
  // authority source: authority deliberately duplicates principalStatus.
  // Exact must describe this as a status-label duplicate, not independent
  // authority evidence. @ref LLP 0013/0040
  appendClockIJsonString(
      output, clockIPrincipalStatusLabel(principal_status));
  output += ",\"principalStatusCode\":" + std::to_string(principal_status);
  output += ",\"runtimeNonce\":";
  appendClockIJsonString(
      output, "u64:" + std::to_string(attestation.runtime_nonce));
  output += ",\"principalId\":";
  appendClockIJsonString(
      output, "u64:" + std::to_string(attestation.principal_id));
  output += ",\"entryRuntimeMonotonicMs\":" +
      std::to_string(attestation.entry_runtime_monotonic_ms);
  output += ",\"handlerOutcome\":\"returned\"";
  output += ",\"handlerReturnedRuntimeMonotonicMs\":" +
      std::to_string(attestation.handler_returned_runtime_monotonic_ms);
  output += ",\"entryClockDomain\":\"ibex-steady-monotonic\"}";
  return output;
}

}  // namespace

// This sibling entry is deliberately not factored through the legacy
// ex_hermes_dispatch_event above: the established two-argument ingress remains
// byte-for-byte source compatible, while callers opt into the versioned
// binding and caller-owned result explicitly.
// @ref LLP 0013#mechanism-3 — sample the engine frame, never a host claim
// @ref LLP 0040 — the two-phase call-scoped HostFunction is the complete
// added endowment
// @ref LLP 0051 — clean fresh-host-event admission precedes the frame sample
// @ref https://github.com/expo/exact/blob/main/llp/0565.006-m0-attribution-instrument.spec.md#32-clock-i
// @abi-output ex_hermes_dispatch_event_attested_v1 out_receipt_json role=output kind=pointer ownership=caller-frees:ex_hermes_free_string
extern "C" int32_t ex_hermes_dispatch_event_attested_v1(
    ExactHermesRuntime* runtime,
    uint32_t handler_id,
    const char* payload_json,
    const ExHermesClockIDispatchBindingV1* binding,
    char** out_receipt_json) {
  if (out_receipt_json == nullptr) return EXACT_RUNTIME_DRIVE_INVALID;
  *out_receipt_json = nullptr;
  if (runtime == nullptr || binding == nullptr ||
      binding->abi_version !=
          EX_HERMES_CLOCK_I_DISPATCH_BINDING_ABI_VERSION_V1 ||
      binding->struct_size != sizeof(ExHermesClockIDispatchBindingV1) ||
      binding->expected_runtime_nonce == 0) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }
  const uint64_t expected_runtime_nonce = binding->expected_runtime_nonce;

  std::string nonce;
  std::string input_id_json;
  std::string generation_json;
  std::string host_input_receipt_id;
  if (!copyClockIBindingSlice(binding->nonce, binding->nonce_len, nonce) ||
      !copyClockIBindingSlice(
          binding->input_id_json,
          binding->input_id_json_len,
          input_id_json) ||
      !copyClockIBindingSlice(
          binding->generation_json,
          binding->generation_json_len,
          generation_json) ||
      !copyClockIBindingSlice(
          binding->host_input_receipt_id,
          binding->host_input_receipt_id_len,
          host_input_receipt_id)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }

  ExactRuntimeDriveGuard drive(runtime, expected_runtime_nonce);
  if (!drive) return drive.status();
  if (runtime->restricted || !exactRuntimeEnterUserExecution(runtime)) {
    return EXACT_RUNTIME_DRIVE_INVALID;
  }

  ScopedRuntimeExtensionHostTask host_task(runtime);
  if (!host_task) return EX_HERMES_CLOCK_I_DISPATCH_FAILED_V1;
  auto& rt = *runtime->runtime;
  auto state = std::make_shared<ClockICarrierAttestorState>();

  try {
    if (!runtime->clock_i_dispatcher ||
        runtime->clock_i_dispatcher_identity.empty()) {
      return EX_HERMES_CLOCK_I_DISPATCHER_UNREGISTERED_V1;
    }
    auto publicDispatcherValue =
        rt.global().getProperty(rt, "__exactDispatchEvent");
    if (!publicDispatcherValue.isObject() ||
        !publicDispatcherValue.getObject(rt).isFunction(rt) ||
        !facebook::jsi::Object::strictEquals(
            rt,
            *runtime->clock_i_dispatcher,
            publicDispatcherValue.getObject(rt))) {
      return EX_HERMES_CLOCK_I_DISPATCHER_TAMPERED_V1;
    }
    auto payload = payload_json && payload_json[0] != '\0'
        ? parseJsonValue(rt, payload_json)
        : facebook::jsi::Value::undefined();
    auto attestor = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "clockICarrierAttestor"),
        1,
        [state](facebook::jsi::Runtime& callback_runtime,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* arguments,
                size_t count) -> facebook::jsi::Value {
          if (!state->active) {
            throw facebook::jsi::JSError(
                callback_runtime,
                "Clock I carrier attestor is no longer active");
          }
          if (count != 1 || !arguments[0].isString()) {
            state->phase = ClockICarrierAttestorState::Phase::Invalid;
            throw facebook::jsi::JSError(
                callback_runtime,
                "Clock I carrier attestor requires one string phase");
          }
          const std::string phase =
              arguments[0].getString(callback_runtime).utf8(callback_runtime);
          if (phase == "enter") {
            if (state->phase !=
                ClockICarrierAttestorState::Phase::AwaitingEnter) {
              state->phase = ClockICarrierAttestorState::Phase::Invalid;
              throw facebook::jsi::JSError(
                  callback_runtime,
                  "Clock I carrier attestor enter phase is out of order");
            }
            // Capture before returning to JS: this is the only point at which
            // the receiving first-party frame is live and engine-attributable.
            state->principal_id = currentPrincipalId();
            state->runtime_nonce = ex_hermes_current_runtime_nonce();
            state->entry_runtime_monotonic_ms = ex_hermes_now_ms();
            state->phase =
                ClockICarrierAttestorState::Phase::AwaitingHandlerReturn;
            return facebook::jsi::Value::undefined();
          }
          if (phase == "handler-returned") {
            if (state->phase !=
                ClockICarrierAttestorState::Phase::AwaitingHandlerReturn) {
              state->phase = ClockICarrierAttestorState::Phase::Invalid;
              throw facebook::jsi::JSError(
                  callback_runtime,
                  "Clock I carrier attestor handler-returned phase is out of order");
            }
            const uint64_t returned_runtime_nonce =
                ex_hermes_current_runtime_nonce();
            const uint64_t returned_at_ms = ex_hermes_now_ms();
            if (returned_runtime_nonce == 0 ||
                returned_runtime_nonce != state->runtime_nonce ||
                returned_at_ms < state->entry_runtime_monotonic_ms) {
              state->phase = ClockICarrierAttestorState::Phase::Invalid;
              throw facebook::jsi::JSError(
                  callback_runtime,
                  "Clock I carrier attestor handler-returned identity changed");
            }
            state->handler_returned_runtime_monotonic_ms = returned_at_ms;
            state->phase = ClockICarrierAttestorState::Phase::Complete;
            return facebook::jsi::Value::undefined();
          }
          state->phase = ClockICarrierAttestorState::Phase::Invalid;
          throw facebook::jsi::JSError(
              callback_runtime,
              "Clock I carrier attestor received an unknown phase");
        });
    runtime->clock_i_dispatcher->call(
        rt,
        facebook::jsi::Value(static_cast<double>(handler_id)),
        std::move(payload),
        std::move(attestor));
    state->active = false;
    if (!host_task.finish()) {
      return EX_HERMES_CLOCK_I_DISPATCH_FAILED_V1;
    }
  } catch (const facebook::jsi::JSError& error) {
    state->active = false;
    ex_host_console_log(1, error.getMessage().c_str());
    return EX_HERMES_CLOCK_I_DISPATCH_FAILED_V1;
  } catch (...) {
    state->active = false;
    return EX_HERMES_CLOCK_I_DISPATCH_FAILED_V1;
  }

  if (state->phase == ClockICarrierAttestorState::Phase::AwaitingEnter) {
    return EX_HERMES_CLOCK_I_DISPATCH_ATTESTOR_NOT_CALLED_V1;
  }
  if (state->phase != ClockICarrierAttestorState::Phase::Complete) {
    return EX_HERMES_CLOCK_I_DISPATCH_ATTESTATION_INCOMPLETE_V1;
  }
  if (state->runtime_nonce != expected_runtime_nonce ||
      state->runtime_nonce != runtime->runtime_nonce) {
    return EXACT_RUNTIME_DRIVE_STALE;
  }

  const uint64_t sequence = runtime->next_clock_i_attestation_sequence;
  if (sequence == 0 || sequence == std::numeric_limits<uint64_t>::max()) {
    return EX_HERMES_CLOCK_I_DISPATCH_FAILED_V1;
  }
  runtime->next_clock_i_attestation_sequence = sequence + 1;
  const std::string receipt = clockICarrierReceiptJson(
      sequence,
      handler_id,
      runtime->clock_i_dispatcher_identity,
      nonce,
      input_id_json,
      generation_json,
      host_input_receipt_id,
      *state);
  char* owned = static_cast<char*>(std::malloc(receipt.size() + 1));
  if (owned == nullptr) {
    return EX_HERMES_CLOCK_I_DISPATCH_RECEIPT_ALLOCATION_FAILED_V1;
  }
  std::memcpy(owned, receipt.data(), receipt.size());
  owned[receipt.size()] = '\0';
  *out_receipt_json = owned;
  return EX_HERMES_CLOCK_I_DISPATCH_OK_V1;
}

// =============================================================================
#endif
