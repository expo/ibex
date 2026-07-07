// hermes_runtime_ios.cc
//
// Extracted from hermes_runtime.cc: iOS rendering pipeline callbacks.
// Provides dispatch, module dispatch, sync call, kernel integration,
// and module event emission.

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

#include <cstring>
#include <mutex>
#include <string>

#include "hermes_runtime_internal.h"

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
extern "C" uint32_t exact_get_layout_generation(void* handle);
extern "C" int32_t exact_hit_test(void* handle, float x, float y);
extern "C" int32_t exact_node_exists(void* handle, uint32_t view_id);
extern "C" int32_t exact_get_root_view_id(void* handle, uint32_t root_id);

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
  exactObj.setProperty(rt, "getLayoutGeneration", std::move(getLayoutGenerationFn));
  exactObj.setProperty(rt, "hitTest", std::move(hitTestFn));
  exactObj.setProperty(rt, "nodeExists", std::move(nodeExistsFn));
  exactObj.setProperty(rt, "getRootViewId", std::move(getRootViewIdFn));
  exactObj.setProperty(rt, "hasKernelInspector", runtime->kernel_handle != nullptr);
  rt.global().setProperty(rt, "exact", std::move(exactObj));
}

static int emit_module_event_impl(
    ExactHermesRuntime* runtime,
    const char* module_name,
    const char* event_name,
    const uint32_t* node_id,
    const uint8_t* payload,
    size_t payload_len) {
  if (!runtime || !runtime->runtime) return -1;

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
  if (!runtime || !runtime->runtime) return -1;

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
    return 0;
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
    return -1;
  } catch (...) {
    return -1;
  }
}

// =============================================================================
