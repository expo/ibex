#include "hermes_runtime_internal.h"

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

extern "C" char* ex_host_http_serve(uint16_t port, const char* hostname);
extern "C" char* ex_host_http_wait(uint32_t server_id, uint32_t timeout_ms);
extern "C" char* ex_host_http_read_body(uint32_t server_id, uint32_t request_id);
extern "C" int32_t ex_host_http_respond(
    uint32_t server_id,
    uint32_t request_id,
    uint16_t status,
    const char* headers_json,
    const uint8_t* body,
    uint32_t body_len);
extern "C" int32_t ex_host_http_respond_text(
    uint32_t server_id,
    uint32_t request_id,
    uint16_t status,
    const uint8_t* body,
    uint32_t body_len);
extern "C" int32_t ex_host_http_respond_json(
    uint32_t server_id,
    uint32_t request_id,
    uint16_t status,
    const uint8_t* body,
    uint32_t body_len);
extern "C" int32_t ex_host_http_respond_stream(
    uint32_t server_id,
    uint32_t request_id,
    uint16_t status,
    const char* headers_json);
extern "C" int32_t ex_host_http_respond_chunk(
    uint32_t server_id,
    uint32_t request_id,
    const uint8_t* body,
    uint32_t body_len);
extern "C" int32_t ex_host_http_respond_end(uint32_t server_id, uint32_t request_id);
extern "C" int32_t ex_host_http_respond_string(
    uint32_t server_id,
    uint32_t request_id,
    uint16_t status,
    const char* headers_json,
    const uint8_t* body,
    uint32_t body_len);
extern "C" char* ex_host_http_address(uint32_t server_id);
extern "C" char* ex_host_http_poll(uint32_t server_id);
extern "C" char* ex_host_http_drain(uint32_t server_id, uint32_t max_count);
extern "C" int32_t ex_host_http_close(uint32_t server_id, int32_t force);
extern "C" void ex_host_http_set_ref(uint32_t server_id, int32_t referenced);
extern "C" void ex_host_free_string(char* value);

void installHttpHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  // __exactHttpServe(port, hostname) -> JSON string {"id":N,"port":N} or {"error":"..."}
  auto httpServeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpServe"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        uint16_t port = 0;
        if (count > 0 && args[0].isNumber()) {
          port = static_cast<uint16_t>(args[0].asNumber());
        }
        std::string hostname = "127.0.0.1";
        if (count > 1 && args[1].isString()) {
          hostname = args[1].toString(runtime).utf8(runtime);
        }
        // @ref LLP 0013#policy — importing http/Bun.serve is not authority to
        // open a listening socket. Gate the native serve boundary. (ENG-22722)
        if (!checkCapability("network:listen:" + hostname + ":" + std::to_string(port))) {
          throw facebook::jsi::JSError(
              runtime,
              "Permission denied: network:listen capability required");
        }
        char* json = ex_host_http_serve(port, hostname.c_str());
        if (!json) {
          throw facebook::jsi::JSError(runtime, "Failed to start HTTP server");
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactHttpServe", std::move(httpServeFn));

  // __exactHttpPoll(serverId) -> JSON string | null (synchronous, non-blocking)
  // Item 6: Synchronous poll fast-path. If a request is already queued,
  // returns it immediately without Promise/async overhead.
  auto httpPollFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpPoll"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        char* json = ex_host_http_poll(server_id);
        if (!json) {
          return facebook::jsi::Value::null();
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactHttpPoll", std::move(httpPollFn));

  // __exactHttpDrain(serverId, maxCount) -> JSON array string | null (synchronous)
  // Item 8: Batch dequeue. Pops up to maxCount requests at once to reduce
  // FFI round-trips under load.
  auto httpDrainFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpDrain"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t max_count = 16; // default
        if (count > 1 && args[1].isNumber()) {
          max_count = static_cast<uint32_t>(args[1].asNumber());
        }
        char* json = ex_host_http_drain(server_id, max_count);
        if (!json) {
          return facebook::jsi::Value::null();
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactHttpDrain", std::move(httpDrainFn));

  // __exactHttpWait(serverId, timeoutMs) -> Promise(JSON string | null)
  // Waits can stay parked for a long time, so a fixed-size worker pool is
  // incorrect here: one native server can legitimately keep multiple waits
  // outstanding, which can starve unrelated waits forever. Keep an adaptive
  // reusable pool instead so each concurrent wait gets a worker.
  auto httpWaitFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpWait"),
      2,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }

        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t timeout_ms = 0;
        if (count > 1 && args[1].isNumber()) {
          timeout_ms = static_cast<uint32_t>(args[1].asNumber());
        }

        // Fast path: try synchronous poll first to avoid Promise overhead entirely
        {
          char* json = ex_host_http_poll(server_id);
          if (json) {
            auto result = facebook::jsi::String::createFromUtf8(runtime, json);
            ex_host_free_string(json);
            // Wrap in resolved Promise to maintain API contract
            auto promiseCtor = runtime.global().getPropertyAsFunction(runtime, "Promise");
            auto resolveFn = promiseCtor.getPropertyAsFunction(runtime, "resolve");
            return resolveFn.call(runtime, result);
          }
        }

        auto promiseCtor = runtime.global().getPropertyAsFunction(runtime, "Promise");
        auto executor = facebook::jsi::Function::createFromHostFunction(
            runtime,
            facebook::jsi::PropNameID::forAscii(runtime, "__exactHttpWaitExecutor"),
            2,
            [handle, server_id, timeout_ms](facebook::jsi::Runtime& runtime,
                                           const facebook::jsi::Value&,
                                           const facebook::jsi::Value* args,
                                           size_t count) -> facebook::jsi::Value {
              if (count < 2 || !args[0].isObject() || !args[1].isObject()) {
                return facebook::jsi::Value::undefined();
              }

              auto resolve = std::make_shared<facebook::jsi::Function>(
                  args[0].asObject(runtime).asFunction(runtime));
              auto reject = std::make_shared<facebook::jsi::Function>(
                  args[1].asObject(runtime).asFunction(runtime));

              struct WaitTask {
                ExactHermesRuntime* handle;
                uint32_t server_id;
                uint32_t timeout_ms;
                std::shared_ptr<facebook::jsi::Function> resolve;
                std::shared_ptr<facebook::jsi::Function> reject;
              };

              struct WaitWorkerPool {
                std::mutex mutex;
                std::condition_variable cv;
                std::deque<WaitTask> queue;
                size_t idle_workers{0};

                void spawnWorkerIfNeededLocked() {
                  if (idle_workers > 0) {
                    return;
                  }

                  std::thread([this]() {
                    while (true) {
                      WaitTask t;
                      {
                        std::unique_lock<std::mutex> lock(mutex);
                        idle_workers += 1;
                        cv.wait(lock, [this] { return !queue.empty(); });
                        idle_workers -= 1;
                        t = std::move(queue.front());
                        queue.pop_front();
                      }

                      char* json = ex_host_http_wait(t.server_id, t.timeout_ms);
                      std::string payload;
                      bool has_payload = false;
                      if (json) {
                        payload = json;
                        has_payload = true;
                        ex_host_free_string(json);
                      }

                      pushRuntimeCallback(
                          t.handle,
                          [resolve = t.resolve, reject = t.reject,
                           has_payload, payload = std::move(payload)](
                              facebook::jsi::Runtime& rt) {
                            try {
                              if (has_payload) {
                                resolve->call(rt,
                                    facebook::jsi::String::createFromUtf8(rt, payload));
                              } else {
                                resolve->call(rt, facebook::jsi::Value::null());
                              }
                            } catch (const facebook::jsi::JSError& err) {
                              reject->call(rt,
                                  facebook::jsi::JSError(rt, err.getMessage().c_str()).value());
                            } catch (...) {
                              reject->call(rt,
                                  facebook::jsi::JSError(rt,
                                      "Failed to complete __exactHttpWait").value());
                            }
                          });
                    }
                  }).detach();
                }

                void enqueue(WaitTask task) {
                  {
                    std::lock_guard<std::mutex> lock(mutex);
                    spawnWorkerIfNeededLocked();
                    queue.push_back(std::move(task));
                  }
                  cv.notify_one();
                }
              };

              static WaitWorkerPool workerPool;

              auto task = WaitTask{handle, server_id, timeout_ms, resolve, reject};
              workerPool.enqueue(std::move(task));

              return facebook::jsi::Value::undefined();
            });

        return promiseCtor.callAsConstructor(runtime, executor);
      });
  rt.global().setProperty(rt, "__exactHttpWait", std::move(httpWaitFn));

  // __exactHttpReadBody(serverId, requestId) -> JSON string or null
  auto httpReadBodyFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpReadBody"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          return facebook::jsi::Value::null();
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());
        char* json = ex_host_http_read_body(server_id, request_id);
        if (!json) {
          return facebook::jsi::Value::null();
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactHttpReadBody", std::move(httpReadBodyFn));

  // __exactHttpRespond(serverId, requestId, status, headersJson, bodyUint8Array) -> 0 or -1
  auto httpRespondFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpRespond"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactHttpRespond: serverId, requestId, status required");
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());
        uint16_t status = static_cast<uint16_t>(args[2].asNumber());

        // Headers JSON string
        const char* headers_json = nullptr;
        std::string headers_str;
        if (count > 3 && args[3].isString()) {
          headers_str = args[3].toString(runtime).utf8(runtime);
          headers_json = headers_str.c_str();
        }

        // Body as Uint8Array
        const uint8_t* body = nullptr;
        uint32_t body_len = 0;
        if (count > 4 && !args[4].isNull() && !args[4].isUndefined() && args[4].isObject()) {
          auto bodyObj = args[4].asObject(runtime);
          if (bodyObj.hasProperty(runtime, "buffer")) {
            auto bufVal = bodyObj.getProperty(runtime, "buffer");
            if (bufVal.isObject()) {
              auto buf = bufVal.asObject(runtime).getArrayBuffer(runtime);
              auto offset = bodyObj.hasProperty(runtime, "byteOffset")
                  ? static_cast<size_t>(bodyObj.getProperty(runtime, "byteOffset").asNumber())
                  : 0;
              auto length = bodyObj.hasProperty(runtime, "byteLength")
                  ? static_cast<size_t>(bodyObj.getProperty(runtime, "byteLength").asNumber())
                  : buf.size(runtime) - offset;
              body = buf.data(runtime) + offset;
              body_len = static_cast<uint32_t>(length);
            }
          }
        }

        int32_t result = ex_host_http_respond(
            server_id, request_id, status, headers_json, body, body_len);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespond", std::move(httpRespondFn));

  // __exactHttpRespondText(serverId, requestId, status, bodyUint8Array) -> 0 or -1
  auto httpRespondTextFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpRespondText"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactHttpRespondText: serverId, requestId, status required");
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());
        uint16_t status = static_cast<uint16_t>(args[2].asNumber());

        const uint8_t* body = nullptr;
        uint32_t body_len = 0;
        if (count > 3 && !args[3].isNull() && !args[3].isUndefined() && args[3].isObject()) {
          auto bodyObj = args[3].asObject(runtime);
          if (bodyObj.hasProperty(runtime, "buffer")) {
            auto bufVal = bodyObj.getProperty(runtime, "buffer");
            if (bufVal.isObject()) {
              auto buf = bufVal.asObject(runtime).getArrayBuffer(runtime);
              auto offset = bodyObj.hasProperty(runtime, "byteOffset")
                  ? static_cast<size_t>(bodyObj.getProperty(runtime, "byteOffset").asNumber())
                  : 0;
              auto length = bodyObj.hasProperty(runtime, "byteLength")
                  ? static_cast<size_t>(bodyObj.getProperty(runtime, "byteLength").asNumber())
                  : buf.size(runtime) - offset;
              body = buf.data(runtime) + offset;
              body_len = static_cast<uint32_t>(length);
            }
          }
        }

        int32_t result = ex_host_http_respond_text(
            server_id, request_id, status, body, body_len);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespondText", std::move(httpRespondTextFn));

  // __exactHttpRespondJson(serverId, requestId, status, bodyUint8Array) -> 0 or -1
  auto httpRespondJsonFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpRespondJson"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactHttpRespondJson: serverId, requestId, status required");
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());
        uint16_t status = static_cast<uint16_t>(args[2].asNumber());

        const uint8_t* body = nullptr;
        uint32_t body_len = 0;
        if (count > 3 && !args[3].isNull() && !args[3].isUndefined() && args[3].isObject()) {
          auto bodyObj = args[3].asObject(runtime);
          if (bodyObj.hasProperty(runtime, "buffer")) {
            auto bufVal = bodyObj.getProperty(runtime, "buffer");
            if (bufVal.isObject()) {
              auto buf = bufVal.asObject(runtime).getArrayBuffer(runtime);
              auto offset = bodyObj.hasProperty(runtime, "byteOffset")
                  ? static_cast<size_t>(bodyObj.getProperty(runtime, "byteOffset").asNumber())
                  : 0;
              auto length = bodyObj.hasProperty(runtime, "byteLength")
                  ? static_cast<size_t>(bodyObj.getProperty(runtime, "byteLength").asNumber())
                  : buf.size(runtime) - offset;
              body = buf.data(runtime) + offset;
              body_len = static_cast<uint32_t>(length);
            }
          }
        }

        int32_t result = ex_host_http_respond_json(
            server_id, request_id, status, body, body_len);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespondJson", std::move(httpRespondJsonFn));

  // __exactHttpRespondString(serverId, requestId, status, headersJson, bodyString) -> 0 or -1
  // Item 10: Zero-copy string response. Takes a JS string directly and passes
  // its UTF-8 buffer to Rust without requiring JS to encode to Uint8Array first.
  auto httpRespondStringFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpRespondString"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactHttpRespondString: serverId, requestId, status required");
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());
        uint16_t status = static_cast<uint16_t>(args[2].asNumber());

        // Headers JSON string
        const char* headers_json = nullptr;
        std::string headers_str;
        if (count > 3 && args[3].isString()) {
          headers_str = args[3].toString(runtime).utf8(runtime);
          headers_json = headers_str.c_str();
        }

        // Body as JS string - extract UTF-8 bytes directly
        const uint8_t* body = nullptr;
        uint32_t body_len = 0;
        std::string body_str;
        if (count > 4 && args[4].isString()) {
          body_str = args[4].toString(runtime).utf8(runtime);
          body = reinterpret_cast<const uint8_t*>(body_str.data());
          body_len = static_cast<uint32_t>(body_str.size());
        }

        int32_t result = ex_host_http_respond_string(
            server_id, request_id, status, headers_json, body, body_len);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespondString", std::move(httpRespondStringFn));

  // __exactHttpRespondStream(serverId, requestId, status, headersJson) -> 0 or -1
  auto httpRespondStreamFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpRespondStream"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactHttpRespondStream: serverId, requestId, status required");
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());
        uint16_t status = static_cast<uint16_t>(args[2].asNumber());

        const char* headers_json = nullptr;
        std::string headers_str;
        if (count > 3 && args[3].isString()) {
          headers_str = args[3].toString(runtime).utf8(runtime);
          headers_json = headers_str.c_str();
        }

        int32_t result = ex_host_http_respond_stream(
            server_id, request_id, status, headers_json);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespondStream", std::move(httpRespondStreamFn));

  // __exactHttpRespondChunk(serverId, requestId, bodyUint8Array) -> 0 or -1
  auto httpRespondChunkFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpRespondChunk"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactHttpRespondChunk: serverId, requestId, body required");
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());

        const uint8_t* body = nullptr;
        uint32_t body_len = 0;
        if (count > 2 && !args[2].isNull() && !args[2].isUndefined() && args[2].isObject()) {
          auto bodyObj = args[2].asObject(runtime);
          if (bodyObj.hasProperty(runtime, "buffer")) {
            auto bufVal = bodyObj.getProperty(runtime, "buffer");
            if (bufVal.isObject()) {
              auto buf = bufVal.asObject(runtime).getArrayBuffer(runtime);
              auto offset = bodyObj.hasProperty(runtime, "byteOffset")
                  ? static_cast<size_t>(bodyObj.getProperty(runtime, "byteOffset").asNumber())
                  : 0;
              auto length = bodyObj.hasProperty(runtime, "byteLength")
                  ? static_cast<size_t>(bodyObj.getProperty(runtime, "byteLength").asNumber())
                  : buf.size(runtime) - offset;
              body = buf.data(runtime) + offset;
              body_len = static_cast<uint32_t>(length);
            }
          }
        }

        int32_t result = ex_host_http_respond_chunk(
            server_id, request_id, body, body_len);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespondChunk", std::move(httpRespondChunkFn));

  // __exactHttpRespondEnd(serverId, requestId) -> 0 or -1
  auto httpRespondEndFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpRespondEnd"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactHttpRespondEnd: serverId, requestId required");
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());

        int32_t result = ex_host_http_respond_end(server_id, request_id);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespondEnd", std::move(httpRespondEndFn));

  // __exactHttpAddress(serverId) -> JSON string or null
  auto httpAddressFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpAddress"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        char* json = ex_host_http_address(server_id);
        if (!json) {
          return facebook::jsi::Value::null();
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactHttpAddress", std::move(httpAddressFn));

  // __exactHttpClose(serverId, force?) -> 0 or -1
  auto httpCloseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpClose"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        int32_t force = count > 1 && args[1].isNumber() ? static_cast<int32_t>(args[1].asNumber()) : 0;
        int32_t result = ex_host_http_close(server_id, force);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpClose", std::move(httpCloseFn));

  // __exactHttpSetRef(serverId, referenced) -> void
  auto httpSetRefFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpSetRef"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count >= 2 && args[0].isNumber()) {
          uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
          int32_t referenced = count > 1 && args[1].isNumber()
              ? static_cast<int32_t>(args[1].asNumber()) : 1;
          ex_host_http_set_ref(server_id, referenced);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactHttpSetRef", std::move(httpSetRefFn));

}
