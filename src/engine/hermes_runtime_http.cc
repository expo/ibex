#include "hermes_runtime_internal.h"

#include <cctype>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <thread>

extern "C" char* ex_host_http_serve(uint16_t port, const char* hostname);
extern "C" char* ex_host_http_wait(uint32_t server_id, uint32_t timeout_ms);
extern "C" char* ex_host_http_wait_owned(
    uint32_t server_id,
    uint32_t timeout_ms,
    uint64_t runtime_nonce);
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
extern "C" int32_t ex_host_http_respond_chunk_try(
    uint32_t server_id,
    uint32_t request_id,
    const uint8_t* body,
    uint32_t body_len);
extern "C" int32_t ex_host_http_respond_end(uint32_t server_id, uint32_t request_id);
extern "C" int32_t ex_host_http_respond_end_try(uint32_t server_id, uint32_t request_id);
extern "C" int32_t ex_host_http_respond_abort(uint32_t server_id, uint32_t request_id);
extern "C" int32_t ex_host_http_await_writable(
    uint32_t server_id,
    uint32_t request_id,
    uint32_t timeout_ms);
extern "C" int32_t ex_host_http_await_writable_owned(
    uint32_t server_id,
    uint32_t request_id,
    uint32_t timeout_ms,
    uint64_t runtime_nonce);
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

namespace {

struct HttpServerEntry {
  uint64_t runtimeNonce;
  uint64_t owner;
  std::string capability;
  bool typedListen{false};
  std::string typedHost;
  uint16_t typedPort{0};
  std::string typedBoundAddress;
  uint16_t typedBoundPort{0};
  std::string typedListenerId;
};

static std::mutex g_http_server_mutex;
static std::unordered_map<uint32_t, HttpServerEntry> g_http_servers;

class HttpAsyncLifetime {
 public:
  explicit HttpAsyncLifetime(RuntimeCallbackTarget target) : target_(target) {}
  void activate() noexcept { active_ = true; }
  ~HttpAsyncLifetime() {
    if (active_) exactUnpinRuntimeNativeWorker(target_);
  }

 private:
  RuntimeCallbackTarget target_;
  bool active_{false};
};

void exactTestDelayHttpWaitWorkerIdle(std::unique_lock<std::mutex>& lock) {
#if defined(IBEX_CAPSEC_CONFORMANCE_OBSERVER)
  const char* value = std::getenv("IBEX_TEST_HTTP_WAIT_IDLE_DELAY_MS");
  if (!value || !*value) return;
  char* end = nullptr;
  auto milliseconds = std::strtoull(value, &end, 10);
  if (end == value || *end != '\0') return;
  milliseconds = std::min<unsigned long long>(milliseconds, 2000);

  // Keep the worker accounted as idle while making its wake deterministic.
  // Notifications cannot be lost: the worker re-locks and checks the queue
  // predicate before sleeping on the condition variable.
  lock.unlock();
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
  lock.lock();
#else
  (void)lock;
#endif
}

uint32_t parseHttpServerId(const std::string& json) {
  auto id_pos = json.find("\"id\"");
  if (id_pos == std::string::npos) {
    return 0;
  }
  auto colon = json.find(':', id_pos);
  if (colon == std::string::npos) {
    return 0;
  }
  size_t pos = colon + 1;
  while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) {
    pos++;
  }
  uint32_t id = 0;
  bool saw_digit = false;
  while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
    saw_digit = true;
    id = id * 10 + static_cast<uint32_t>(json[pos] - '0');
    pos++;
  }
  return saw_digit ? id : 0;
}

uint16_t parseHttpPort(const std::string& json) {
  auto port_pos = json.find("\"port\"");
  if (port_pos == std::string::npos) return 0;
  auto colon = json.find(':', port_pos);
  if (colon == std::string::npos) return 0;
  size_t pos = colon + 1;
  while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) pos++;
  uint32_t port = 0;
  bool saw_digit = false;
  while (pos < json.size() && std::isdigit(static_cast<unsigned char>(json[pos]))) {
    saw_digit = true;
    port = port * 10 + static_cast<uint32_t>(json[pos] - '0');
    if (port > 65535) return 0;
    pos++;
  }
  return saw_digit ? static_cast<uint16_t>(port) : 0;
}

bool authorizeTypedHttpListen(
    uint64_t owner,
    const std::string& host,
    uint16_t port,
    uint32_t stage,
    const std::string& boundAddress,
    uint16_t boundPort,
    const std::string& listenerId) {
  auto principals = exactCollectTypedPrincipalStack();
  const int32_t result = ex_host_authorize_typed_listen_stack(
      owner, principals.data(), principals.size(), 1, host.c_str(), port, 0,
      stage, boundAddress.empty() ? nullptr : boundAddress.c_str(), boundPort,
      listenerId.empty() ? nullptr : listenerId.c_str(), nullptr, 0);
  if (result != 1) {
    fprintf(
        stderr,
        "error: typed HTTP listen authorization failed: result=%d owner=%llu principals=%zu host=%s port=%u stage=%u\n",
        result, static_cast<unsigned long long>(owner), principals.size(),
        host.c_str(), static_cast<unsigned int>(port),
        static_cast<unsigned int>(stage));
  }
  return result == 1;
}

bool parseHttpOwnerServerId(
    const facebook::jsi::Value& value,
    uint32_t& server_id) {
  constexpr double kMaxSafeInteger = 9007199254740991.0;
  if (!value.isNumber()) return false;
  const double number = value.asNumber();
  if (!std::isfinite(number) || number < 1.0 ||
      number > kMaxSafeInteger || std::floor(number) != number ||
      number > static_cast<double>(std::numeric_limits<uint32_t>::max())) {
    return false;
  }
  server_id = static_cast<uint32_t>(number);
  return true;
}

void registerHttpServer(
    uint32_t server_id,
    const std::string& capability,
    const std::string& typedHost = {},
    uint16_t typedPort = 0,
    const std::string& typedBoundAddress = {},
    uint16_t typedBoundPort = 0,
    const std::string& typedListenerId = {}) {
  if (server_id == 0) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_http_server_mutex);
  HttpServerEntry entry{};
  entry.runtimeNonce = exactCurrentRuntimeNonce();
  entry.owner = currentPrincipalId();
  entry.capability = capability;
  if (!typedListenerId.empty()) {
    entry.typedListen = true;
    entry.typedHost = typedHost;
    entry.typedPort = typedPort;
    entry.typedBoundAddress = typedBoundAddress;
    entry.typedBoundPort = typedBoundPort;
    entry.typedListenerId = typedListenerId;
  }
  g_http_servers[server_id] = std::move(entry);
}

bool requireHttpServerOwner(
    facebook::jsi::Runtime& runtime,
    uint32_t server_id,
    const char* syscall,
    bool requireLiveAuthority = true) {
  HttpServerEntry entry;
  {
    std::lock_guard<std::mutex> lock(g_http_server_mutex);
    auto it = g_http_servers.find(server_id);
    if (it == g_http_servers.end()) {
      return false;
    }
    entry = it->second;
  }
  if (entry.runtimeNonce != exactCurrentRuntimeNonce()) {
    throw facebook::jsi::JSError(
        runtime, std::string(syscall) + ": server belongs to a different runtime");
  }
  // Capability posture never changes ownership of a forgeable numeric id.
  // Keep package isolation in diagnostic/allow-all runtimes too.
  if (entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime, std::string(syscall) + ": server belongs to a different principal");
  }
  if (requireLiveAuthority && entry.typedListen) {
    if (!authorizeTypedHttpListen(
            entry.owner, entry.typedHost, entry.typedPort, 2,
            entry.typedBoundAddress, entry.typedBoundPort,
            entry.typedListenerId)) {
      throw facebook::jsi::JSError(
          runtime, std::string("Permission denied: ") + syscall);
    }
  } else if (requireLiveAuthority && !isAllowAll() &&
             !entry.capability.empty() && !checkCapability(entry.capability)) {
      throw facebook::jsi::JSError(
          runtime, std::string("Permission denied: ") + syscall);
  }
  return true;
}

void unregisterHttpServer(uint32_t server_id) {
  std::lock_guard<std::mutex> lock(g_http_server_mutex);
  auto server = g_http_servers.find(server_id);
  if (server != g_http_servers.end() &&
      server->second.runtimeNonce == exactCurrentRuntimeNonce() &&
      server->second.owner == currentPrincipalId()) {
    g_http_servers.erase(server);
  }
}

uint32_t extractOptionalHttpBody(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value* args,
    size_t count,
    size_t index,
    const uint8_t*& body) {
  body = nullptr;
  if (count <= index || args[index].isNull() || args[index].isUndefined()) {
    return 0;
  }
  if (!args[index].isObject()) {
    return 0;
  }
  auto bodyObj = args[index].asObject(runtime);
  const uint8_t* data = nullptr;
  size_t length = 0;
  if (!extractArrayBufferView(runtime, bodyObj, data, length)) {
    return 0;
  }
  body = length == 0 ? nullptr : data;
  return exactUint32FromSize(runtime, length, "body length");
}

} // namespace

void exactCleanupRuntimeHttpServers(uint64_t runtimeNonce) {
  std::lock_guard<std::mutex> lock(g_http_server_mutex);
  for (auto it = g_http_servers.begin(); it != g_http_servers.end();) {
    if (it->second.runtimeNonce == runtimeNonce) {
      it = g_http_servers.erase(it);
    } else {
      ++it;
    }
  }
}

void installHttpHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  // __exactHttpOwner(serverId) -> true or false
  // Owner authentication is deliberately independent of the server's live
  // positive grant. Retained JS wrappers use this non-mutating boundary before
  // touching private buffered state, and release paths remain available after
  // revocation. The numeric selector is still runtime- and principal-bound.
  auto httpOwnerFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpOwner"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        uint32_t server_id = 0;
        if (count < 1 || !parseHttpOwnerServerId(args[0], server_id)) {
          return facebook::jsi::Value(false);
        }
        return facebook::jsi::Value(requireHttpServerOwner(
            runtime, server_id, "__exactHttpOwner", false));
      });
  rt.global().setProperty(rt, "__exactHttpOwner", std::move(httpOwnerFn));
  // @ref LLP 0046#34-step-0-the-premise-is-false-the-fix-is-four-lines — the
  // source walker may credit this captured terminal only while it is immutable.
  sealGlobalHostFunction(rt, "__exactHttpOwner");

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
          const double requestedPort = args[0].asNumber();
          if (!std::isfinite(requestedPort) || requestedPort < 0 ||
              requestedPort > 65535 || std::floor(requestedPort) != requestedPort) {
            throw facebook::jsi::JSError(runtime, "__exactHttpServe: invalid port");
          }
          port = static_cast<uint16_t>(requestedPort);
        }
        std::string hostname = "127.0.0.1";
        if (count > 1 && args[1].isString()) {
          hostname = args[1].toString(runtime).utf8(runtime);
        }
        // @ref LLP 0013#policy — importing http/Bun.serve is not authority to
        // open a listening socket. Gate the native serve boundary. (ENG-22722)
        std::string capability = "network:listen:" + formatNetworkEndpoint(hostname, port);
        const bool armed = ex_host_is_armed() == 1;
        const uint64_t owner = currentPrincipalId();
        if (armed) {
          // @ref LLP 0021#wp6--convert-network-effects-and-protected-peers —
          // authorize the requested bind before starting the broker and commit
          // the exact address/ephemeral port it actually selected.
          if (!authorizeTypedHttpListen(owner, hostname, port, 0, "", 0, "")) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else if (!checkCapability(capability)) {
          throw facebook::jsi::JSError(
              runtime,
              "Permission denied: network:listen capability required");
        }
        char* json = ex_host_http_serve(port, hostname.c_str());
        if (!json) {
          throw facebook::jsi::JSError(runtime, "Failed to start HTTP server");
        }
        std::string payload(json);
        const uint32_t serverId = parseHttpServerId(payload);
        if (armed && serverId != 0) {
          // Armed startup accepts only a canonical literal bind. The broker
          // returns the OS-selected bound port in this payload, so together
          // those are the exact committed endpoint without a racy second
          // lookup through the public address bridge.
          const std::string boundAddress = hostname;
          const uint16_t boundPort = parseHttpPort(payload);
          const std::string listenerId =
              "http-listener:" + std::to_string(exactCurrentRuntimeNonce()) +
              ":" + std::to_string(serverId);
          if (boundAddress.empty() || boundPort == 0 ||
              !authorizeTypedHttpListen(
                  owner, hostname, port, 2, boundAddress, boundPort,
                  listenerId)) {
            ex_host_http_close(serverId, 1);
            ex_host_free_string(json);
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          registerHttpServer(
              serverId, "", hostname, port, boundAddress, boundPort,
              listenerId);
        } else {
          registerHttpServer(serverId, capability);
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, payload);
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
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpPoll")) {
          return facebook::jsi::Value::null();
        }
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
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpDrain")) {
          return facebook::jsi::Value::null();
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
  // Waits can stay parked for a long time, so this bridge uses a reusable pool
  // with a hard process-wide cap. Excess concurrent waits reject instead of
  // spawning detached native threads without bound.
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
          timeout_ms = exactUint32FromValue(runtime, args[1], "timeoutMs", 0);
        }
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpWait")) {
          return facebook::jsi::Value::null();
        }
        auto waitPrincipal = currentPrincipalId();

        // Fast path: try synchronous poll first to avoid Promise overhead entirely
        {
          char* json = ex_host_http_poll(server_id);
          if (json) {
            auto result = facebook::jsi::String::createFromUtf8(runtime, json);
            ex_host_free_string(json);
            // Wrap in resolved Promise to maintain API contract
            auto promiseCtor = runtime.global().getPropertyAsFunction(runtime, "Promise");
            auto resolveFn = promiseCtor.getPropertyAsFunction(runtime, "resolve");
            ScopedNativePrincipal nativePrincipal(waitPrincipal);
            return resolveFn.call(runtime, result);
          }
        }

        auto promiseCtor = runtime.global().getPropertyAsFunction(runtime, "Promise");
        auto executor = facebook::jsi::Function::createFromHostFunction(
            runtime,
            facebook::jsi::PropNameID::forAscii(runtime, "__exactHttpWaitExecutor"),
            2,
            [handle, server_id, timeout_ms, waitPrincipal](
                facebook::jsi::Runtime& runtime,
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
              auto target = exactRuntimeCallbackTarget(handle);
              auto lifetime = std::make_shared<HttpAsyncLifetime>(target);
              if (!exactPinRuntimeNativeWorker(target)) {
                throw facebook::jsi::JSError(
                    runtime, "__exactHttpWait: runtime is shutting down");
              }
              lifetime->activate();

              struct WaitTask {
                RuntimeCallbackTarget target;
                uint32_t server_id;
                uint32_t timeout_ms;
                uint64_t runtime_nonce;
                uint64_t principal;
                std::shared_ptr<facebook::jsi::Function> resolve;
                std::shared_ptr<facebook::jsi::Function> reject;
                std::shared_ptr<HttpAsyncLifetime> lifetime;
              };

              constexpr size_t kMaxWaitWorkers = 16;
              constexpr size_t kMaxWaitQueue = 128;

              struct WaitWorkerPool {
                std::mutex mutex;
                std::condition_variable cv;
                std::deque<WaitTask> queue;
                size_t idle_workers{0};
                size_t total_workers{0};

                void spawnWorkerIfNeededLocked() {
                  // Called before the new task is appended. Idle workers are
                  // already owed to queued tasks, so only idle capacity beyond
                  // the current backlog can service this enqueue.
                  if (idle_workers > queue.size()) {
                    return;
                  }
                  if (total_workers >= kMaxWaitWorkers) {
                    return;
                  }

                  total_workers += 1;
                  std::thread([this]() {
                    while (true) {
                      WaitTask t;
                      {
                        std::unique_lock<std::mutex> lock(mutex);
                        idle_workers += 1;
                        exactTestDelayHttpWaitWorkerIdle(lock);
                        cv.wait(lock, [this] { return !queue.empty(); });
                        idle_workers -= 1;
                        t = std::move(queue.front());
                        queue.pop_front();
                      }

                      exactTestDelayRuntimeProducer();
                      char* json = ex_host_http_wait_owned(
                          t.server_id, t.timeout_ms, t.runtime_nonce);
                      std::string payload;
                      bool has_payload = false;
                      if (json) {
                        payload = json;
                        has_payload = true;
                        ex_host_free_string(json);
                      }

                      auto resolve = std::move(t.resolve);
                      auto reject = std::move(t.reject);
                      pushRuntimeCallback(
                          t.target,
                          [resolve = std::move(resolve), reject = std::move(reject),
                           principal = t.principal, has_payload,
                           payload = std::move(payload)](
                              facebook::jsi::Runtime& rt) {
                            ScopedNativePrincipal nativePrincipal(principal);
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

                bool enqueue(WaitTask task, std::string& error) {
                  {
                    std::lock_guard<std::mutex> lock(mutex);
                    // ENG-23114: reject ONLY when the backlog is genuinely
                    // full (same fix as DnsWorkerPool for ENG-23022). The old
                    // `idle == 0 && total >= max` early-reject fired before
                    // the queue-full check, so once every worker was parked in
                    // ex_host_http_wait the kMaxWaitQueue backlog was never
                    // used and the next wait rejected outright. Excess waits
                    // now queue; a worker picks them up on its next loop.
                    if (queue.size() >= kMaxWaitQueue) {
                      error = "__exactHttpWait queue limit reached";
                      return false;
                    }
                    spawnWorkerIfNeededLocked();
                    queue.push_back(std::move(task));
                  }
                  cv.notify_one();
                  return true;
                }
              };

              // ENG-23498 — intentionally leaked (same fix as FetchWorkerPool
              // in native_fetch_linux.cc, ENG-23471): a by-value static pool
              // is destructed during exit() while detached workers are still
              // parked in cv.wait(), and destroying a mutex/condvar with
              // waiters is UB that deadlocks exit() inside glibc's pthread
              // destructors on Linux. Workers are detached, so leaking the
              // pool lets exit() proceed normally.
              static WaitWorkerPool* workerPool = new WaitWorkerPool();

              auto task = WaitTask{
                  target, server_id, timeout_ms, handle->runtime_nonce,
                  waitPrincipal, resolve, reject, lifetime};
              std::string enqueueError;
              if (!workerPool->enqueue(std::move(task), enqueueError)) {
                reject->call(
                    runtime,
                    facebook::jsi::JSError(runtime, enqueueError.c_str()).value());
              }

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
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpReadBody")) {
          return facebook::jsi::Value::null();
        }
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
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpRespond")) {
          return facebook::jsi::Value(-1);
        }

        // Headers JSON string
        const char* headers_json = nullptr;
        std::string headers_str;
        if (count > 3 && args[3].isString()) {
          headers_str = args[3].toString(runtime).utf8(runtime);
          headers_json = headers_str.c_str();
        }

        // Body as Uint8Array
        const uint8_t* body = nullptr;
        uint32_t body_len = extractOptionalHttpBody(runtime, args, count, 4, body);

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
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpRespondText")) {
          return facebook::jsi::Value(-1);
        }

        const uint8_t* body = nullptr;
        uint32_t body_len = extractOptionalHttpBody(runtime, args, count, 3, body);

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
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpRespondJson")) {
          return facebook::jsi::Value(-1);
        }

        const uint8_t* body = nullptr;
        uint32_t body_len = extractOptionalHttpBody(runtime, args, count, 3, body);

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
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpRespondString")) {
          return facebook::jsi::Value(-1);
        }

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
          body_len = exactUint32FromSize(runtime, body_str.size(), "body length");
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
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpRespondStream")) {
          return facebook::jsi::Value(-1);
        }

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
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpRespondChunk")) {
          return facebook::jsi::Value(-1);
        }

        const uint8_t* body = nullptr;
        uint32_t body_len = extractOptionalHttpBody(runtime, args, count, 2, body);

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
        // A response terminator carries no new payload and only relinquishes
        // the already-owned response pipe, so grant revocation must not strand
        // it. Runtime and principal ownership remain unconditional.
        if (!requireHttpServerOwner(
                runtime, server_id, "__exactHttpRespondEnd", false)) {
          return facebook::jsi::Value(-1);
        }

        int32_t result = ex_host_http_respond_end(server_id, request_id);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespondEnd", std::move(httpRespondEndFn));

  // __exactHttpRespondChunkTry(serverId, requestId, bodyUint8Array) -> 0 | 2 | -1
  // Non-blocking chunk send for the serve({fetch}) streaming path. A return of 2
  // means "would block": the caller must await __exactHttpAwaitWritable and
  // retry the same chunk rather than parking the JS event loop.
  auto httpRespondChunkTryFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpRespondChunkTry"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactHttpRespondChunkTry: serverId, requestId, body required");
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpRespondChunkTry")) {
          return facebook::jsi::Value(-1);
        }

        const uint8_t* body = nullptr;
        uint32_t body_len = extractOptionalHttpBody(runtime, args, count, 2, body);

        int32_t result = ex_host_http_respond_chunk_try(
            server_id, request_id, body, body_len);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespondChunkTry", std::move(httpRespondChunkTryFn));

  // __exactHttpRespondEndTry(serverId, requestId) -> 0 | 2 | -1
  // Non-blocking stream terminator paired with __exactHttpRespondChunkTry.
  auto httpRespondEndTryFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpRespondEndTry"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactHttpRespondEndTry: serverId, requestId required");
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());
        if (!requireHttpServerOwner(
                runtime, server_id, "__exactHttpRespondEndTry", false)) {
          return facebook::jsi::Value(-1);
        }

        int32_t result = ex_host_http_respond_end_try(server_id, request_id);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespondEndTry", std::move(httpRespondEndTryFn));

  // __exactHttpRespondAbort(serverId, requestId) -> 0 or -1
  // Abort a streamed response. Unlike the end/end-try terminators this cannot
  // report would-block: it errors the response pipe regardless of channel
  // fullness so the client observes a broken transfer instead of a
  // clean-looking truncated body, and the host-side pipe entry cannot leak.
  // (ENG-23114)
  auto httpRespondAbortFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpRespondAbort"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());
        // @ref LLP 0021#handles-dynamic-authority-and-generations — abort only
        // relinquishes an owned response pipe, so revocation must not prevent
        // cleanup; runtime and principal ownership still apply unconditionally.
        if (!requireHttpServerOwner(
                runtime, server_id, "__exactHttpRespondAbort", false)) {
          return facebook::jsi::Value(-1);
        }

        int32_t result = ex_host_http_respond_abort(server_id, request_id);
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpRespondAbort", std::move(httpRespondAbortFn));

  // __exactHttpAwaitWritable(serverId, requestId, timeoutMs?) -> Promise(number)
  // Resolves with 0 once the streamed response body channel has room for another
  // chunk, or -1 if the peer is gone / has stalled. The blocking wait runs on a
  // pooled worker thread (mirroring __exactHttpWait) so the JS event loop is
  // never parked on backpressure.
  auto httpAwaitWritableFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpAwaitWritable"),
      3,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        uint32_t request_id = static_cast<uint32_t>(args[1].asNumber());
        uint32_t timeout_ms = 0;
        if (count > 2 && args[2].isNumber()) {
          timeout_ms = exactUint32FromValue(runtime, args[2], "timeoutMs", 0);
        }
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpAwaitWritable")) {
          return facebook::jsi::Value(-1);
        }
        auto waitPrincipal = currentPrincipalId();

        auto promiseCtor = runtime.global().getPropertyAsFunction(runtime, "Promise");
        auto executor = facebook::jsi::Function::createFromHostFunction(
            runtime,
            facebook::jsi::PropNameID::forAscii(runtime, "__exactHttpAwaitWritableExecutor"),
            2,
            [handle, server_id, request_id, timeout_ms, waitPrincipal](
                facebook::jsi::Runtime& runtime,
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
              auto target = exactRuntimeCallbackTarget(handle);
              auto lifetime = std::make_shared<HttpAsyncLifetime>(target);
              if (!exactPinRuntimeNativeWorker(target)) {
                throw facebook::jsi::JSError(
                    runtime, "__exactHttpAwaitWritable: runtime is shutting down");
              }
              lifetime->activate();

              struct WritableTask {
                RuntimeCallbackTarget target;
                uint32_t server_id;
                uint32_t request_id;
                uint32_t timeout_ms;
                uint64_t runtime_nonce;
                uint64_t principal;
                std::shared_ptr<facebook::jsi::Function> resolve;
                std::shared_ptr<facebook::jsi::Function> reject;
                std::shared_ptr<HttpAsyncLifetime> lifetime;
              };

              constexpr size_t kMaxWritableWorkers = 16;
              constexpr size_t kMaxWritableQueue = 256;

              struct WritableWorkerPool {
                std::mutex mutex;
                std::condition_variable cv;
                std::deque<WritableTask> queue;
                size_t idle_workers{0};
                size_t total_workers{0};

                void spawnWorkerIfNeededLocked() {
                  if (idle_workers > queue.size()) {
                    return;
                  }
                  if (total_workers >= kMaxWritableWorkers) {
                    return;
                  }

                  total_workers += 1;
                  std::thread([this]() {
                    while (true) {
                      WritableTask t;
                      {
                        std::unique_lock<std::mutex> lock(mutex);
                        idle_workers += 1;
                        cv.wait(lock, [this] { return !queue.empty(); });
                        idle_workers -= 1;
                        t = std::move(queue.front());
                        queue.pop_front();
                      }

                      exactTestDelayRuntimeProducer();
                      int32_t code = ex_host_http_await_writable_owned(
                          t.server_id, t.request_id, t.timeout_ms,
                          t.runtime_nonce);

                      auto resolve = std::move(t.resolve);
                      auto reject = std::move(t.reject);
                      pushRuntimeCallback(
                          t.target,
                          [resolve = std::move(resolve), reject = std::move(reject),
                           principal = t.principal, code](
                              facebook::jsi::Runtime& rt) {
                            ScopedNativePrincipal nativePrincipal(principal);
                            try {
                              resolve->call(rt, facebook::jsi::Value(code));
                            } catch (const facebook::jsi::JSError& err) {
                              reject->call(rt,
                                  facebook::jsi::JSError(rt, err.getMessage().c_str()).value());
                            } catch (...) {
                              reject->call(rt,
                                  facebook::jsi::JSError(rt,
                                      "Failed to complete __exactHttpAwaitWritable").value());
                            }
                          });
                    }
                  }).detach();
                }

                bool enqueue(WritableTask task, std::string& error) {
                  {
                    std::lock_guard<std::mutex> lock(mutex);
                    // ENG-23114: reject ONLY when the backlog is genuinely
                    // full (same fix as DnsWorkerPool for ENG-23022). This
                    // pool parks one wait per backpressured streamed response
                    // and is process-global, so with the old `idle == 0 &&
                    // total >= max` early-reject 16 slow readers were enough
                    // to make the 17th __exactHttpAwaitWritable reject — a
                    // rejection the serve({fetch}) writer surfaces as a
                    // stream abort, i.e. a silently truncated response body.
                    // Excess waits now queue for the next free worker.
                    if (queue.size() >= kMaxWritableQueue) {
                      error = "__exactHttpAwaitWritable queue limit reached";
                      return false;
                    }
                    spawnWorkerIfNeededLocked();
                    queue.push_back(std::move(task));
                  }
                  cv.notify_one();
                  return true;
                }
              };

              // ENG-23498 — intentionally leaked (same fix as FetchWorkerPool
              // in native_fetch_linux.cc, ENG-23471): a by-value static pool
              // is destructed during exit() while detached workers are still
              // parked in cv.wait(), and destroying a mutex/condvar with
              // waiters is UB that deadlocks exit() inside glibc's pthread
              // destructors on Linux. Workers are detached, so leaking the
              // pool lets exit() proceed normally.
              static WritableWorkerPool* writablePool = new WritableWorkerPool();

              auto task = WritableTask{
                  target, server_id, request_id, timeout_ms,
                  handle->runtime_nonce, waitPrincipal, resolve, reject, lifetime};
              std::string enqueueError;
              if (!writablePool->enqueue(std::move(task), enqueueError)) {
                reject->call(
                    runtime,
                    facebook::jsi::JSError(runtime, enqueueError.c_str()).value());
              }

              return facebook::jsi::Value::undefined();
            });

        return promiseCtor.callAsConstructor(runtime, executor);
      });
  rt.global().setProperty(rt, "__exactHttpAwaitWritable", std::move(httpAwaitWritableFn));

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
        if (!requireHttpServerOwner(runtime, server_id, "__exactHttpAddress")) {
          return facebook::jsi::Value::null();
        }
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
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
        int32_t force = count > 1 && args[1].isNumber() ? static_cast<int32_t>(args[1].asNumber()) : 0;
        // @ref LLP 0021#handles-dynamic-authority-and-generations — releasing
        // an owned server remains possible after its positive grant is revoked.
        if (!requireHttpServerOwner(
                runtime, server_id, "__exactHttpClose", false)) {
          return facebook::jsi::Value(-1);
        }
        int32_t result = ex_host_http_close(server_id, force);
        if (result == 0) {
          unregisterHttpServer(server_id);
        }
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactHttpClose", std::move(httpCloseFn));

  // __exactHttpSetRef(serverId, referenced) -> void
  auto httpSetRefFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHttpSetRef"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count >= 2 && args[0].isNumber()) {
          uint32_t server_id = static_cast<uint32_t>(args[0].asNumber());
          int32_t referenced = count > 1 && args[1].isNumber()
              ? static_cast<int32_t>(args[1].asNumber()) : 1;
          if (!requireHttpServerOwner(runtime, server_id, "__exactHttpSetRef")) {
            return facebook::jsi::Value::undefined();
          }
          ex_host_http_set_ref(server_id, referenced);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactHttpSetRef", std::move(httpSetRefFn));

}
