#include "hermes_runtime_internal.h"

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
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
                                      uint64_t runtime_nonce,
                                      const char* method,
                                     const char* url,
                                     const char* headers,
                                     int decompress,
                                     const uint8_t* body,
                                     size_t body_length,
                                     NativeFetchResponseCallback response_callback,
                                     void* context);
extern "C" void native_fetch_cancel(uint32_t request_id, uint64_t runtime_nonce);

namespace {

std::atomic<uint32_t> g_nextFetchId{1};
std::mutex g_fetchTargetMutex;
std::unordered_map<uint32_t, RuntimeCallbackTarget> g_fetchTargets;

void registerFetchTarget(uint32_t requestId, RuntimeCallbackTarget target) {
  std::lock_guard<std::mutex> lock(g_fetchTargetMutex);
  g_fetchTargets[requestId] = target;
}

RuntimeCallbackTarget takeFetchTarget(uint32_t requestId) {
  std::lock_guard<std::mutex> lock(g_fetchTargetMutex);
  auto it = g_fetchTargets.find(requestId);
  if (it == g_fetchTargets.end()) return {};
  auto target = it->second;
  g_fetchTargets.erase(it);
  return target;
}

uint32_t allocateFetchId() {
  auto current = g_nextFetchId.load(std::memory_order_relaxed);
  for (;;) {
    if (current == 0 || current == std::numeric_limits<uint32_t>::max()) {
      return 0;
    }
    if (g_nextFetchId.compare_exchange_weak(
            current, current + 1,
            std::memory_order_relaxed, std::memory_order_relaxed)) {
      return current;
    }
  }
}

// Web fetch has no default timeout: when JS passes no `timeout` (or 0), the
// request runs until the network layer resolves it or JS aborts it via
// `__exactCancel`. JS-side timeouts arrive through `init.timeout`.
  // @ref LLP 0008#linux-networking
constexpr uint32_t EXACT_FETCH_NO_TIMEOUT_MS = 0;

bool isFetchHeaderNameChar(unsigned char c) {
  return std::isalnum(c) || c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
      c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
      c == '`' || c == '|' || c == '~';
}

void appendFetchHeader(
    facebook::jsi::Runtime& runtime,
    std::string& headers,
    const std::string& name,
    const std::string& value) {
  if (name.empty()) {
    throw facebook::jsi::JSError(runtime, "__nativeFetch: invalid empty header name");
  }
  for (unsigned char c : name) {
    if (!isFetchHeaderNameChar(c)) {
      throw facebook::jsi::JSError(runtime, "__nativeFetch: invalid header name");
    }
  }
  for (unsigned char c : value) {
    // ENG-23471 — per WHATWG fetch / RFC 9110 field values may contain
    // interior HTAB (0x09); the JS Headers layer already trims leading/
    // trailing whitespace. Ban the other C0 controls (incl. CR/LF) and DEL.
    if ((c <= 0x1f && c != 0x09) || c == 0x7f) {
      throw facebook::jsi::JSError(runtime, "__nativeFetch: invalid header value");
    }
  }
  headers += name + ": " + value + "\r\n";
}

std::string buildFetchHeaders(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Object& init) {
  std::string headers;
  if (!init.hasProperty(runtime, "headers")) {
    return headers;
  }
  auto headersVal = init.getProperty(runtime, "headers");
  if (!headersVal.isObject()) {
    return headers;
  }
  auto headersObj = headersVal.asObject(runtime);
  if (!headersObj.isArray(runtime)) {
    return headers;
  }
  auto headersArray = headersObj.getArray(runtime);
  for (size_t i = 0; i < headersArray.size(runtime); i++) {
    auto tuple = headersArray.getValueAtIndex(runtime, i);
    if (tuple.isObject() && tuple.asObject(runtime).isArray(runtime)) {
      auto pair = tuple.asObject(runtime).getArray(runtime);
      if (pair.size(runtime) >= 2) {
        auto name = pair.getValueAtIndex(runtime, 0).toString(runtime).utf8(runtime);
        auto value = pair.getValueAtIndex(runtime, 1).toString(runtime).utf8(runtime);
        appendFetchHeader(runtime, headers, name, value);
      }
    }
  }
  return headers;
}

#if defined(_WIN32)
struct SyncFetchResult {
  std::mutex mutex;
  std::condition_variable cv;
  bool done = false;
  int status = 0;
  std::string statusText;
  std::string headers;
  std::vector<uint8_t> body;
};

// ENG-23113 — keep-alive registry so a SyncFetchResult outlives the sync
// fetch's stack frame. `native_fetch_perform` runs `performFetch` on a DETACHED
// worker thread whose completion callback may fire AFTER the waiter timed out and
// unwound. Keying the result by request_id (which the callback receives) — rather
// than by the address of a stack local — lets whichever of {completion callback,
// timeout waiter} runs first take ownership under g_syncFetchMutex and the other
// observe the entry already gone. Result: the callback never dereferences a
// destroyed object (no UAF / no notify on a freed condition_variable), and the
// entry is erased exactly once (no leak, even on the Windows error/cancel paths
// where performFetch returns without ever calling the callback).
static std::mutex g_syncFetchMutex;
static std::unordered_map<uint32_t, std::shared_ptr<SyncFetchResult>>
    g_syncFetchResults;
#endif

} // namespace

void exactForgetNativeFetchTarget(uint32_t requestId, uint64_t runtimeNonce) {
  std::lock_guard<std::mutex> lock(g_fetchTargetMutex);
  auto it = g_fetchTargets.find(requestId);
  if (it != g_fetchTargets.end() && it->second.nonce == runtimeNonce) {
    g_fetchTargets.erase(it);
  }
}

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
        std::string url = args[0].toString(runtime).utf8(runtime);
        ParsedNetworkUrl parsedUrl;
        if (!parseNetworkUrl(url, parsedUrl) ||
            (parsedUrl.scheme != "http" && parsedUrl.scheme != "https")) {
          throw facebook::jsi::JSError(runtime, "__nativeFetch: invalid network URL");
        }
        // Armed fetch stays closed until this transport reports the complete
        // requested/candidate/verified-peer facts required by the typed
        // decision model. In particular, never fall back to the legacy string
        // oracle: an armed Host deliberately refuses that oracle, and treating
        // a requested-host check as sufficient would reopen DNS/redirect/peer
        // substitution. Diagnostic runtimes retain their endpoint-scoped
        // legacy check unchanged.
        // @ref LLP 0021#wp6--convert-network-effects-and-protected-peers
        if (ex_host_is_armed() == 1) {
#if defined(IBEX_CAPSEC_SIMULATOR_PERFORMANCE_OBSERVER)
          if (parsedUrl.host != "127.0.0.1" ||
              !checkCapability("network:fetch:127.0.0.1")) {
            throw facebook::jsi::JSError(
                runtime,
                "Permission denied: performance observer admits only authenticated-root IPv4 loopback fetch");
          }
          static std::once_flag observerLoopbackMarker;
          std::call_once(observerLoopbackMarker, []() {
            fprintf(
                stderr,
                "[Ibex] CAPSEC_SIMULATOR_PERFORMANCE_OBSERVER_V1 stage=loopback-fetch-substituted\n");
          });
#else
          throw facebook::jsi::JSError(
              runtime,
              "Permission denied: typed network:fetch transport is unavailable");
#endif
        } else if (!checkCapability("network:fetch:" + parsedUrl.host)) {
          throw facebook::jsi::JSError(
              runtime, "Permission denied: network:fetch capability required");
        }
        // @ref LLP 0013#policy — generated legacy policies can grant fetch to
        // a specific endpoint (`network:fetch:host`), so the diagnostic native
        // boundary checks the concrete URL host rather than only the broad class.
        auto requestPrincipal = currentPrincipalId();

        auto init = args[1].asObject(runtime);
        std::string method = "GET";
        if (init.hasProperty(runtime, "method")) {
          auto methodVal = init.getProperty(runtime, "method");
          if (methodVal.isString()) {
            method = methodVal.toString(runtime).utf8(runtime);
          }
        }

        std::string headers = buildFetchHeaders(runtime, init);
        bool decompress = true;
        if (init.hasProperty(runtime, "decompress")) {
          auto decompressVal = init.getProperty(runtime, "decompress");
          if (decompressVal.isBool()) {
            decompress = decompressVal.getBool();
          }
        }

        uint32_t timeout_ms = EXACT_FETCH_NO_TIMEOUT_MS;
        if (init.hasProperty(runtime, "timeout")) {
          auto timeoutVal = init.getProperty(runtime, "timeout");
          if (timeoutVal.isNumber()) {
            timeout_ms = exactUint32FromValue(
                runtime, timeoutVal, "timeout", EXACT_FETCH_NO_TIMEOUT_MS);
          }
        }

        std::vector<uint8_t> body;
        if (count > 2 && !args[2].isNull() && !args[2].isUndefined()) {
          if (args[2].isObject()) {
            auto bodyObj = args[2].asObject(runtime);
            const uint8_t* data = nullptr;
            size_t length = 0;
            if (extractArrayBufferView(runtime, bodyObj, data, length) && data && length > 0) {
              body.assign(data, data + length);
            }
          }
        }

        uint32_t requestId = allocateFetchId();
        if (requestId == 0) {
          throw facebook::jsi::JSError(runtime, "Fetch request id space exhausted");
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
             requestPrincipal,
             decompress](facebook::jsi::Runtime& rt,
                         const facebook::jsi::Value&,
                         const facebook::jsi::Value* args,
                         size_t count) -> facebook::jsi::Value {
              if (count >= 2 && args[0].isObject() && args[1].isObject()) {
                auto resolve = exactMakeTrackedJsiCallbackOwner(
                    handle->runtime_thread, args[0].asObject(rt).asFunction(rt));
                auto reject = exactMakeTrackedJsiCallbackOwner(
                    handle->runtime_thread, args[1].asObject(rt).asFunction(rt));

                auto deadline = timeoutCopy == 0
                    ? std::chrono::steady_clock::time_point::max()
                    : std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutCopy);

                cleanupFetchCallbacks(handle);
                {
                  std::lock_guard<std::mutex> lock(handle->fetchMutex);
                  handle->fetchCallbacks[requestId] = {
                      std::move(resolve),
                      std::move(reject),
                      requestPrincipal,
                      *urlCopy,
                      deadline,
                  };
                }

                registerFetchTarget(requestId, exactRuntimeCallbackTarget(handle));

                native_fetch_perform(
                    requestId,
                    handle->runtime_nonce,
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
                      (void)ctx;
                      auto target = takeFetchTarget(req_id);
                      exactTestDelayRuntimeProducer();
                      if (!target || !exactPinRuntimeNativeWorker(target)) return;
                      auto* wrapper = target.runtime;

                      std::vector<uint8_t> bodyCopy;
                      if (resp_body && resp_body_length > 0) {
                        bodyCopy.assign(resp_body, resp_body + resp_body_length);
                      }
                      std::string statusTextCopy = status_text ? status_text : "";
                      std::string headersCopy = resp_headers ? resp_headers : "";
                      int statusCopy = status;

                      std::shared_ptr<facebook::jsi::Function> resolve;
                      std::shared_ptr<facebook::jsi::Function> reject;
                      uint64_t principal = 0;
                      std::string requestUrl;
                      // @ref LLP 0003#the-event-loop — ENG-23028: this completion
                      // fires on an NSURLSession/libcurl network thread. The old
                      // `runtimeIsAlive(wrapper)` locked the registry, tested
                      // membership, then RELEASED it before the fetchMutex deref
                      // below — the exact check-then-lock TOCTOU that ENG-22925
                      // (489bf65) removed from resolve_host_call. ex_hermes_destroy
                      // runs on the runtime thread on dev-server reconnect and
                      // enters Closing under g_runtimeRegistryMutex, so a free
                      // landing in that gap made `wrapper->fetchMutex` a UAF. Pin
                      // the runtime across the liveness check AND the fetchCallbacks
                      // extraction (registry -> fetchMutex; destroy never locks
                      // fetchMutex, so no inversion). If it returns false the
                      // wrapper is gone: drop without dereferencing it.
                      bool alive = withRuntimePinned(target, [&]() {
                        std::lock_guard<std::mutex> lock(wrapper->fetchMutex);
                        auto it = wrapper->fetchCallbacks.find(req_id);
                        if (it == wrapper->fetchCallbacks.end()) return;
                        resolve = std::move(it->second.resolve);
                        reject = std::move(it->second.reject);
                        principal = it->second.principal;
                        requestUrl = std::move(it->second.url);
                      });
                      if (!alive) {
                        exactUnpinRuntimeNativeWorker(target);
                        return;
                      }

                      if (!resolve || !reject) {
                        withRuntimePinned(target, [&]() {
                          std::lock_guard<std::mutex> lock(wrapper->fetchMutex);
                          wrapper->fetchCallbacks.erase(req_id);
                        });
                        ex_hermes_notify_callback();
                        exactUnpinRuntimeNativeWorker(target);
                        return;
                      }

                      // Keep the request registered until its completion is
                      // visible in callbackQueue. Otherwise the event loop can
                      // observe neither source in the erase-before-enqueue gap
                      // and return a still-pending fetch promise as settled.
                      // @ref LLP 0003#the-event-loop — pending work remains
                      // continuously visible across the native-to-runtime handoff.
                      // The queued callback must become the SOLE owner of the
                      // JSI closures: a copy left in these locals can become
                      // the final owner once the runtime thread drains and
                      // releases the queued entry first, running the JSI
                      // destructors on this network thread.
                      pushRuntimeCallback(
                          target,
                          [resolve = std::move(resolve),
                           reject = std::move(reject),
                           statusCopy,
                           statusTextCopy,
                           headersCopy,
                           requestUrl = std::move(requestUrl),
                           principal,
                           bodyCopy = std::move(bodyCopy)](facebook::jsi::Runtime& rt) {
                            ScopedNativePrincipal nativePrincipal(principal);
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
                      withRuntimePinned(target, [&]() {
                        std::lock_guard<std::mutex> lock(wrapper->fetchMutex);
                        wrapper->fetchCallbacks.erase(req_id);
                      });
                      // pushRuntimeCallback wakes the host after publication,
                      // but the runtime may drain that callback before this
                      // worker releases the overlapping fetch keepalive. Wake
                      // once more after the release so that inverse race cannot
                      // strand the loop waiting on work that is now complete.
                      ex_hermes_notify_callback();
                      exactUnpinRuntimeNativeWorker(target);
                    },
                    nullptr);
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
              exactForgetNativeFetchTarget(requestId, handle->runtime_nonce);
              native_fetch_cancel(requestId, handle->runtime_nonce);
              return facebook::jsi::Value::undefined();
            });
        promise.setProperty(runtime, "__exactCancel", std::move(cancelFn));
        return promise;
      });
  rt.global().setProperty(rt, "__nativeFetch", std::move(nativeFetchFn));

#if defined(_WIN32)
  auto nativeFetchSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__nativeFetchSync"),
      3,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__nativeFetchSync: url and init required");
        }
        std::string url = args[0].toString(runtime).utf8(runtime);
        ParsedNetworkUrl parsedUrl;
        if (!parseNetworkUrl(url, parsedUrl) ||
            (parsedUrl.scheme != "http" && parsedUrl.scheme != "https")) {
          throw facebook::jsi::JSError(runtime, "__nativeFetchSync: invalid network URL");
        }
        // Keep the synchronous Windows bridge aligned with the asynchronous
        // one above: typed armed fetch is explicitly closed, while diagnostic
        // runtimes retain the endpoint-scoped legacy oracle.
        // @ref LLP 0021#wp6--convert-network-effects-and-protected-peers
        if (ex_host_is_armed() == 1) {
          throw facebook::jsi::JSError(
              runtime,
              "Permission denied: typed network:fetch transport is unavailable");
        }
        if (!checkCapability("network:fetch:" + parsedUrl.host)) {
          throw facebook::jsi::JSError(
              runtime, "Permission denied: network:fetch capability required");
        }

        auto init = args[1].asObject(runtime);
        std::string method = "GET";
        if (init.hasProperty(runtime, "method")) {
          auto methodVal = init.getProperty(runtime, "method");
          if (methodVal.isString()) {
            method = methodVal.toString(runtime).utf8(runtime);
          }
        }

        std::string headers = buildFetchHeaders(runtime, init);
        bool decompress = true;
        if (init.hasProperty(runtime, "decompress")) {
          auto decompressVal = init.getProperty(runtime, "decompress");
          if (decompressVal.isBool()) {
            decompress = decompressVal.getBool();
          }
        }

        uint32_t timeout_ms = EXACT_FETCH_NO_TIMEOUT_MS;
        if (init.hasProperty(runtime, "timeout")) {
          auto timeoutVal = init.getProperty(runtime, "timeout");
          if (timeoutVal.isNumber()) {
            timeout_ms = exactUint32FromValue(
                runtime, timeoutVal, "timeout", EXACT_FETCH_NO_TIMEOUT_MS);
          }
        }

        std::vector<uint8_t> body;
        if (count > 2 && !args[2].isNull() && !args[2].isUndefined() && args[2].isObject()) {
          auto bodyObj = args[2].asObject(runtime);
          const uint8_t* data = nullptr;
          size_t length = 0;
          if (extractArrayBufferView(runtime, bodyObj, data, length) && data && length > 0) {
            body.assign(data, data + length);
          }
        }

        uint32_t requestId = allocateFetchId();
        if (requestId == 0) {
          throw facebook::jsi::JSError(runtime, "Fetch request id space exhausted");
        }

        // ENG-23113 — the completion callback runs on a DETACHED worker
        // thread that may fire after this frame unwinds, so it must NOT reference a
        // `SyncFetchResult` on this stack. Register a heap-owned result keyed by
        // requestId (the callback receives request_id) BEFORE performing the fetch,
        // so whichever of {callback, timeout waiter} runs first takes ownership and
        // the other sees the entry gone — no waiter-destroys-cv UAF, no write to a
        // freed stack on timeout, and no leak.
        auto result = std::make_shared<SyncFetchResult>();
        {
          std::lock_guard<std::mutex> lk(g_syncFetchMutex);
          g_syncFetchResults[requestId] = result;
        }
        native_fetch_perform(
            requestId,
            handle->runtime_nonce,
            method.c_str(),
            url.c_str(),
            headers.empty() ? nullptr : headers.c_str(),
            decompress ? 1 : 0,
            body.empty() ? nullptr : body.data(),
            body.size(),
            [](uint32_t request_id,
               int status,
               const char* status_text,
               const char* resp_headers,
               const uint8_t* resp_body,
               size_t resp_body_length,
               void* /*ctx*/) {
              // Take ownership of the result via the registry (keyed by the
              // request_id the backend hands back). If the waiter already gave up
              // and erased it, do nothing rather than touch freed memory.
              std::shared_ptr<SyncFetchResult> result;
              {
                std::lock_guard<std::mutex> lk(g_syncFetchMutex);
                auto it = g_syncFetchResults.find(request_id);
                if (it == g_syncFetchResults.end()) return;
                result = it->second;  // local ref keeps it alive past the erase
                g_syncFetchResults.erase(it);
              }
              std::lock_guard<std::mutex> lock(result->mutex);
              result->status = status;
              result->statusText = status_text ? status_text : "";
              result->headers = resp_headers ? resp_headers : "";
              if (resp_body && resp_body_length > 0) {
                result->body.assign(resp_body, resp_body + resp_body_length);
              }
              result->done = true;
              // Notify UNDER the lock: the local `result` keeps the cv alive, and
              // this closes the notify-after-unlock / lost-wakeup window entirely.
              result->cv.notify_one();
            },
            nullptr);

        {
          std::unique_lock<std::mutex> lock(result->mutex);
          if (timeout_ms == 0) {
            // 0 = no timeout (web semantics); block until the network layer
            // resolves or fails the request. @ref LLP 0008#linux-networking
            result->cv.wait(lock, [&] { return result->done; });
          } else if (!result->cv.wait_for(
                  lock, std::chrono::milliseconds(timeout_ms), [&] { return result->done; })) {
            lock.unlock();
            native_fetch_cancel(requestId, handle->runtime_nonce);
            // Drop the keep-alive so a cancelled request whose worker never calls
            // back (Windows error/cancel paths) — or races this timeout — can't
            // leak the result. If the callback already took it, this is a no-op.
            {
              std::lock_guard<std::mutex> lk(g_syncFetchMutex);
              g_syncFetchResults.erase(requestId);
            }
            throw facebook::jsi::JSError(runtime, "Fetch timed out");
          }
        }

        if (result->status == 0) {
          throw facebook::jsi::JSError(
              runtime, result->statusText.empty() ? "Network error" : result->statusText);
        }

        facebook::jsi::Object response(runtime);
        response.setProperty(runtime, "status", facebook::jsi::Value(result->status));
        response.setProperty(
            runtime,
            "statusText",
            facebook::jsi::String::createFromUtf8(runtime, result->statusText));
        response.setProperty(runtime, "url", facebook::jsi::String::createFromUtf8(runtime, url));
        response.setProperty(runtime, "redirected", facebook::jsi::Value(false));

        std::vector<std::pair<std::string, std::string>> headerPairs;
        size_t pos = 0;
        while (pos < result->headers.size()) {
          size_t lineEnd = result->headers.find("\r\n", pos);
          if (lineEnd == std::string::npos) lineEnd = result->headers.size();
          std::string line = result->headers.substr(pos, lineEnd - pos);
          size_t colonPos = line.find(':');
          if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);
            while (!value.empty() && value[0] == ' ') value.erase(0, 1);
            headerPairs.push_back({key, value});
          }
          pos = lineEnd + 2;
        }
        facebook::jsi::Array headersArray(runtime, headerPairs.size());
        for (size_t i = 0; i < headerPairs.size(); i++) {
          facebook::jsi::Array tuple(runtime, 2);
          tuple.setValueAtIndex(
              runtime, 0, facebook::jsi::String::createFromUtf8(runtime, headerPairs[i].first));
          tuple.setValueAtIndex(
              runtime, 1, facebook::jsi::String::createFromUtf8(runtime, headerPairs[i].second));
          headersArray.setValueAtIndex(runtime, i, tuple);
        }
        response.setProperty(runtime, "headers", headersArray);

        if (!result->body.empty()) {
          auto arrayBufferCtor = runtime.global().getPropertyAsFunction(runtime, "ArrayBuffer");
          auto arrayBuffer =
              arrayBufferCtor.callAsConstructor(runtime, static_cast<double>(result->body.size()))
                  .getObject(runtime);
          auto ab = arrayBuffer.getArrayBuffer(runtime);
          memcpy(ab.data(runtime), result->body.data(), result->body.size());
          response.setProperty(runtime, "body", arrayBuffer);
        } else {
          response.setProperty(runtime, "body", facebook::jsi::Value::null());
        }

        return response;
      });
  rt.global().setProperty(rt, "__nativeFetchSync", std::move(nativeFetchSyncFn));

  // @ref LLP 0003#windows-native-smoke-coverage — Windows skips the shared
  // runtime bundle, so expose a small public fetch surface over the WinHTTP
  // native bridge here instead of loading the full TypeScript fetch layer.
  static const char* windowsFetchShim = R"JS(
(function(g) {
  if (typeof g.fetch === 'function' || typeof g.__nativeFetch !== 'function') return;

  function HeaderList(init) {
    this._pairs = [];
    if (!init) return;
    if (init instanceof HeaderList) {
      this._pairs = init._pairs.slice(0);
      return;
    }
    if (Array.isArray(init)) {
      for (var i = 0; i < init.length; i++) {
        if (init[i] && init[i].length >= 2) {
          this.append(init[i][0], init[i][1]);
        }
      }
      return;
    }
    if (typeof init === 'object') {
      for (var key in init) {
        if (Object.prototype.hasOwnProperty.call(init, key)) {
          this.append(key, init[key]);
        }
      }
    }
  }
  HeaderList.prototype.append = function(name, value) {
    this._pairs.push([String(name).toLowerCase(), String(value)]);
  };
  HeaderList.prototype.get = function(name) {
    var wanted = String(name).toLowerCase();
    for (var i = 0; i < this._pairs.length; i++) {
      if (this._pairs[i][0].toLowerCase() === wanted) return this._pairs[i][1];
    }
    return null;
  };
  HeaderList.prototype.forEach = function(callback, thisArg) {
    for (var i = 0; i < this._pairs.length; i++) {
      callback.call(thisArg, this._pairs[i][1], this._pairs[i][0], this);
    }
  };

  function bytesFromBody(body) {
    if (!body) return new Uint8Array(0);
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView && ArrayBuffer.isView(body)) {
      return new Uint8Array(body.buffer, body.byteOffset || 0, body.byteLength);
    }
    return new Uint8Array(0);
  }
  // ENG-23471 — decode response bodies as UTF-8 (with U+FFFD replacement, per
  // WHATWG). The previous per-byte String.fromCharCode loop was a Latin-1
  // decode that mojibake'd every non-ASCII UTF-8 body.
  function textFromBody(body) {
    var bytes = bytesFromBody(body);
    if (typeof g.TextDecoder === 'function') {
      try {
        return new g.TextDecoder('utf-8').decode(bytes);
      } catch (e) {}
    }
    var out = '';
    var i = 0;
    var len = bytes.length;
    while (i < len) {
      var b = bytes[i];
      if (b <= 0x7f) {
        out += String.fromCharCode(b);
        i++;
        continue;
      }
      var cp, extra, lower = 0x80, upper = 0xbf;
      if (b >= 0xc2 && b <= 0xdf) { cp = b & 0x1f; extra = 1; }
      else if (b === 0xe0) { cp = b & 0x0f; extra = 2; lower = 0xa0; }
      else if (b === 0xed) { cp = b & 0x0f; extra = 2; upper = 0x9f; }
      else if (b >= 0xe1 && b <= 0xef) { cp = b & 0x0f; extra = 2; }
      else if (b === 0xf0) { cp = b & 0x07; extra = 3; lower = 0x90; }
      else if (b >= 0xf1 && b <= 0xf3) { cp = b & 0x07; extra = 3; }
      else if (b === 0xf4) { cp = b & 0x07; extra = 3; upper = 0x8f; }
      else { out += '\uFFFD'; i++; continue; }
      var valid = true;
      var next = i + 1;
      for (var k = 0; k < extra; k++) {
        var c = next < len ? bytes[next] : -1;
        var lo = k === 0 ? lower : 0x80;
        var hi = k === 0 ? upper : 0xbf;
        if (c < lo || c > hi) { valid = false; break; }
        cp = (cp << 6) | (c & 0x3f);
        next++;
      }
      // On an invalid sequence, emit one replacement char and resume at the
      // first unconsumed byte (WHATWG "restart" behavior).
      i = next;
      if (!valid) {
        out += '\uFFFD';
        continue;
      }
      if (cp > 0xffff) {
        cp -= 0x10000;
        out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
      } else {
        out += String.fromCharCode(cp);
      }
    }
    return out;
  }
  function emptyArrayBuffer() {
    return new ArrayBuffer(0);
  }

  function FetchResponse(nativeResponse) {
    nativeResponse = nativeResponse || {};
    this.status = Number(nativeResponse.status) || 0;
    this.statusText = nativeResponse.statusText || '';
    this.url = nativeResponse.url || '';
    this.redirected = !!nativeResponse.redirected;
    this.ok = this.status >= 200 && this.status < 300;
    this.headers = new HeaderList(nativeResponse.headers || []);
    this._body = nativeResponse.body || emptyArrayBuffer();
  }
  FetchResponse.prototype.arrayBuffer = function() {
    return Promise.resolve(this._body || emptyArrayBuffer());
  };
  FetchResponse.prototype.text = function() {
    return Promise.resolve(textFromBody(this._body));
  };
  // ENG-23471 — json() was missing entirely from the Windows fetch surface.
  FetchResponse.prototype.json = function() {
    return this.text().then(function(text) { return JSON.parse(text); });
  };

  function initForNative(init) {
    init = init || {};
    var headers = init.headers instanceof HeaderList
      ? init.headers._pairs
      : new HeaderList(init.headers)._pairs;
    return {
      method: init.method || 'GET',
      headers: headers,
      decompress: init.decompress !== false,
      timeout: init.timeout || 0
    };
  }

  function fetch(input, init) {
    try {
      var url = input && input.url ? input.url : String(input);
      return g.__nativeFetch(url, initForNative(init)).then(function(nativeResponse) {
        return new FetchResponse(nativeResponse);
      });
    } catch (error) {
      return Promise.reject(error);
    }
  }

  Object.defineProperty(g, 'Headers', {
    value: HeaderList,
    writable: true,
    configurable: true
  });
  Object.defineProperty(g, 'Response', {
    value: FetchResponse,
    writable: true,
    configurable: true
  });
  Object.defineProperty(g, 'fetch', {
    value: fetch,
    writable: true,
    configurable: true
  });
})(globalThis);
)JS";
  try {
    auto buffer = std::make_shared<facebook::jsi::StringBuffer>(windowsFetchShim);
    rt.evaluateJavaScript(buffer, "<windows-fetch-shim>");
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
  }
#endif
}
