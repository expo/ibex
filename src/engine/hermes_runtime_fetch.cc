#include "hermes_runtime_internal.h"

#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

typedef void (*NativeFetchResponseCallback)(uint32_t request_id,
                                            int status,
                                            const char* status_text,
                                            const char* headers,
                                            const uint8_t* body,
                                            size_t body_length,
                                            void* context);
extern "C" void native_fetch_perform(uint32_t request_id,
                                     const char* method,
                                     const char* url,
                                     const char* headers,
                                     int decompress,
                                     const uint8_t* body,
                                     size_t body_length,
                                     NativeFetchResponseCallback response_callback,
                                     void* context);
extern "C" void native_fetch_cancel(uint32_t request_id);

namespace {

constexpr uint32_t EXACT_FETCH_TIMEOUT_MS = 30000;

} // namespace

void installFetchGlobals(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  auto nativeFetchFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__nativeFetch"),
      3,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__nativeFetch: url and init required");
        }
        if (!checkCapability("network:fetch")) {
          throw facebook::jsi::JSError(
              runtime, "Permission denied: network:fetch capability required");
        }

        std::string url = args[0].toString(runtime).utf8(runtime);
        auto init = args[1].asObject(runtime);
        std::string method = "GET";
        if (init.hasProperty(runtime, "method")) {
          auto methodVal = init.getProperty(runtime, "method");
          if (methodVal.isString()) {
            method = methodVal.toString(runtime).utf8(runtime);
          }
        }

        std::string headers;
        bool decompress = true;
        if (init.hasProperty(runtime, "headers")) {
          auto headersVal = init.getProperty(runtime, "headers");
          if (headersVal.isObject()) {
            auto headersObj = headersVal.asObject(runtime);
            if (headersObj.isArray(runtime)) {
              auto headersArray = headersObj.getArray(runtime);
              for (size_t i = 0; i < headersArray.size(runtime); i++) {
                auto tuple = headersArray.getValueAtIndex(runtime, i);
                if (tuple.isObject() && tuple.asObject(runtime).isArray(runtime)) {
                  auto pair = tuple.asObject(runtime).getArray(runtime);
                  if (pair.size(runtime) >= 2) {
                    auto name = pair.getValueAtIndex(runtime, 0).toString(runtime).utf8(runtime);
                    auto value = pair.getValueAtIndex(runtime, 1).toString(runtime).utf8(runtime);
                    headers += name + ": " + value + "\r\n";
                  }
                }
              }
            }
          }
        }
        if (init.hasProperty(runtime, "decompress")) {
          auto decompressVal = init.getProperty(runtime, "decompress");
          if (decompressVal.isBool()) {
            decompress = decompressVal.getBool();
          }
        }

        uint32_t timeout_ms = EXACT_FETCH_TIMEOUT_MS;
        if (init.hasProperty(runtime, "timeout")) {
          auto timeoutVal = init.getProperty(runtime, "timeout");
          if (timeoutVal.isNumber()) {
            auto timeoutNumber = timeoutVal.asNumber();
            if (timeoutNumber > 0 && timeoutNumber <= 4294967295.0) {
              timeout_ms = static_cast<uint32_t>(timeoutNumber);
            }
          }
        }

        std::vector<uint8_t> body;
        if (count > 2 && !args[2].isNull() && !args[2].isUndefined()) {
          if (args[2].isObject()) {
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
                body.assign(buf.data(runtime) + offset, buf.data(runtime) + offset + length);
              }
            }
          }
        }

        uint32_t requestId;
        {
          std::lock_guard<std::mutex> lock(handle->fetchMutex);
          requestId = handle->nextFetchId++;
        }

        auto promiseCtor = runtime.global().getPropertyAsFunction(runtime, "Promise");
        auto methodCopy = std::make_shared<std::string>(method);
        auto urlCopy = std::make_shared<std::string>(url);
        auto headersCopy = std::make_shared<std::string>(headers);
        auto bodyCopy = std::make_shared<std::vector<uint8_t>>(body);
        auto timeoutCopy = timeout_ms;

        auto executor = facebook::jsi::Function::createFromHostFunction(
            runtime,
            facebook::jsi::PropNameID::forAscii(runtime, "executor"),
            2,
            [handle,
             requestId,
             methodCopy,
             urlCopy,
             headersCopy,
             bodyCopy,
             timeoutCopy,
             decompress](facebook::jsi::Runtime& rt,
                         const facebook::jsi::Value&,
                         const facebook::jsi::Value* args,
                         size_t count) -> facebook::jsi::Value {
              if (count >= 2 && args[0].isObject() && args[1].isObject()) {
                auto resolve =
                    std::make_shared<facebook::jsi::Function>(args[0].asObject(rt).asFunction(rt));
                auto reject =
                    std::make_shared<facebook::jsi::Function>(args[1].asObject(rt).asFunction(rt));

                auto deadline =
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutCopy);

                cleanupFetchCallbacks(handle);
                {
                  std::lock_guard<std::mutex> lock(handle->fetchMutex);
                  handle->fetchCallbacks[requestId] = {
                      std::move(resolve),
                      std::move(reject),
                      *urlCopy,
                      deadline,
                  };
                }

                native_fetch_perform(
                    requestId,
                    methodCopy->c_str(),
                    urlCopy->c_str(),
                    headersCopy->empty() ? nullptr : headersCopy->c_str(),
                    decompress ? 1 : 0,
                    bodyCopy->empty() ? nullptr : bodyCopy->data(),
                    bodyCopy->size(),
                    [](uint32_t req_id,
                       int status,
                       const char* status_text,
                       const char* resp_headers,
                       const uint8_t* resp_body,
                       size_t resp_body_length,
                       void* ctx) {
                      auto* wrapper = static_cast<ExactHermesRuntime*>(ctx);
                      if (!wrapper || !runtimeIsAlive(wrapper)) return;

                      std::vector<uint8_t> bodyCopy;
                      if (resp_body && resp_body_length > 0) {
                        bodyCopy.assign(resp_body, resp_body + resp_body_length);
                      }
                      std::string statusTextCopy = status_text ? status_text : "";
                      std::string headersCopy = resp_headers ? resp_headers : "";
                      int statusCopy = status;

                      std::shared_ptr<facebook::jsi::Function> resolve;
                      std::shared_ptr<facebook::jsi::Function> reject;
                      std::string requestUrl;
                      {
                        std::lock_guard<std::mutex> lock(wrapper->fetchMutex);
                        auto it = wrapper->fetchCallbacks.find(req_id);
                        if (it == wrapper->fetchCallbacks.end()) return;
                        resolve = std::move(it->second.resolve);
                        reject = std::move(it->second.reject);
                        requestUrl = std::move(it->second.url);
                        wrapper->fetchCallbacks.erase(it);
                      }

                      if (!resolve || !reject) {
                        return;
                      }

                      pushRuntimeCallback(
                          wrapper,
                          [resolve,
                           reject,
                           statusCopy,
                           statusTextCopy,
                           headersCopy,
                           requestUrl = std::move(requestUrl),
                           bodyCopy = std::move(bodyCopy)](facebook::jsi::Runtime& rt) {
                            try {
                              if (statusCopy == 0) {
                                reject->call(
                                    rt,
                                    facebook::jsi::JSError(
                                        rt,
                                        statusTextCopy.empty() ? "Network error"
                                                               : statusTextCopy)
                                        .value());
                                return;
                              }

                              facebook::jsi::Object response(rt);
                              response.setProperty(rt, "status", facebook::jsi::Value(statusCopy));
                              response.setProperty(
                                  rt,
                                  "statusText",
                                  facebook::jsi::String::createFromUtf8(rt, statusTextCopy));
                              response.setProperty(
                                  rt, "url", facebook::jsi::String::createFromUtf8(rt, requestUrl));
                              response.setProperty(rt, "redirected", facebook::jsi::Value(false));

                              facebook::jsi::Array headersArray(rt, 0);
                              if (!headersCopy.empty()) {
                                std::vector<std::pair<std::string, std::string>> headerPairs;
                                size_t pos = 0;
                                while (pos < headersCopy.size()) {
                                  size_t lineEnd = headersCopy.find("\r\n", pos);
                                  if (lineEnd == std::string::npos) lineEnd = headersCopy.size();
                                  std::string line = headersCopy.substr(pos, lineEnd - pos);
                                  size_t colonPos = line.find(':');
                                  if (colonPos != std::string::npos) {
                                    std::string key = line.substr(0, colonPos);
                                    std::string value = line.substr(colonPos + 1);
                                    while (!value.empty() && value[0] == ' ') value.erase(0, 1);
                                    headerPairs.push_back({key, value});
                                  }
                                  pos = lineEnd + 2;
                                }
                                headersArray = facebook::jsi::Array(rt, headerPairs.size());
                                for (size_t i = 0; i < headerPairs.size(); i++) {
                                  facebook::jsi::Array tuple(rt, 2);
                                  tuple.setValueAtIndex(
                                      rt,
                                      0,
                                      facebook::jsi::String::createFromUtf8(
                                          rt, headerPairs[i].first));
                                  tuple.setValueAtIndex(
                                      rt,
                                      1,
                                      facebook::jsi::String::createFromUtf8(
                                          rt, headerPairs[i].second));
                                  headersArray.setValueAtIndex(rt, i, tuple);
                                }
                              }
                              response.setProperty(rt, "headers", headersArray);

                              if (!bodyCopy.empty()) {
                                auto arrayBufferCtor =
                                    rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
                                auto arrayBuffer = arrayBufferCtor
                                                       .callAsConstructor(
                                                           rt, static_cast<double>(bodyCopy.size()))
                                                       .getObject(rt);
                                auto ab = arrayBuffer.getArrayBuffer(rt);
                                memcpy(ab.data(rt), bodyCopy.data(), bodyCopy.size());
                                response.setProperty(rt, "body", arrayBuffer);
                              } else {
                                response.setProperty(rt, "body", facebook::jsi::Value::null());
                              }

                              resolve->call(rt, response);
                            } catch (const std::exception& e) {
                              try {
                                reject->call(rt, facebook::jsi::JSError(rt, e.what()).value());
                              } catch (...) {
                              }
                            } catch (...) {
                            }
                          });
                    },
                    handle);
              }
              return facebook::jsi::Value::undefined();
            });

        auto promise = promiseCtor.callAsConstructor(runtime, executor).getObject(runtime);
        auto cancelFn = facebook::jsi::Function::createFromHostFunction(
            runtime,
            facebook::jsi::PropNameID::forAscii(runtime, "__exactCancel"),
            0,
            [handle, requestId](facebook::jsi::Runtime&,
                                const facebook::jsi::Value&,
                                const facebook::jsi::Value*,
                                size_t) -> facebook::jsi::Value {
              {
                std::lock_guard<std::mutex> lock(handle->fetchMutex);
                auto it = handle->fetchCallbacks.find(requestId);
                if (it != handle->fetchCallbacks.end()) {
                  handle->fetchCallbacks.erase(it);
                }
              }
              native_fetch_cancel(requestId);
              return facebook::jsi::Value::undefined();
            });
        promise.setProperty(runtime, "__exactCancel", std::move(cancelFn));
        return promise;
      });
  rt.global().setProperty(rt, "__nativeFetch", std::move(nativeFetchFn));
}
