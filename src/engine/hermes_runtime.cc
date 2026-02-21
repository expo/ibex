#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <hermes/AsyncDebuggerAPI.h>
#include <hermes/hermes.h>
#include <jsi/jsi.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#if defined(__APPLE__)
#include <crt_externs.h>
#endif
#include <chrono>
#include <deque>
#include <future>
#include <iomanip>
#include <cctype>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <vector>
#include <thread>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <csignal>
#include <pwd.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ifaddrs.h>
#include <net/if.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHmac.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <Security/SecRandom.h>
#include <Security/Security.h>
// GCM functions exist in CommonCrypto but are not in public headers
extern "C" {
  CCCryptorStatus CCCryptorGCMOneshotEncrypt(
      CCAlgorithm alg, const void *key, size_t keyLength,
      const void *iv, size_t ivLength,
      const void *aData, size_t aDataLength,
      const void *dataIn, size_t dataInLength,
      void *cipherOut,
      void *tagOut, size_t tagLength);
  CCCryptorStatus CCCryptorGCMOneshotDecrypt(
      CCAlgorithm alg, const void *key, size_t keyLength,
      const void *iv, size_t ivLength,
      const void *aData, size_t aDataLength,
      const void *cipherIn, size_t dataInLength,
      void *dataOut,
      const void *tagIn, size_t tagLength);
}
#include <zlib.h>
#if !defined(EXACT_NO_BROTLI)
#include <brotli/encode.h>
#include <brotli/decode.h>
#endif
#include <resolv.h>
#include <arpa/nameser.h>
#if !defined(EXACT_NO_OPENSSL)
// OpenSSL on macOS for Ed25519/X25519/ECDSA and key import/export
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif // !EXACT_NO_OPENSSL
#else
#include <sys/sysinfo.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <zlib.h>
#include <brotli/encode.h>
#include <brotli/decode.h>
#include <resolv.h>
#include <arpa/nameser.h>
#endif

// Process start time for process.uptime()
static const auto g_process_start_time = std::chrono::steady_clock::now();

// Signal handling globals
static std::atomic<int> g_pending_signal{0};

static void signal_handler(int sig) {
  g_pending_signal.store(sig, std::memory_order_relaxed);
}

extern "C" void ex_host_console_log(int32_t level, const char* message);
extern "C" int32_t ex_host_is_allow_all(void);
extern "C" int32_t ex_host_check_capability(uint64_t module_id, const char* capability);
extern "C" void ex_host_grant_capability(uint64_t module_id, const char* capability);
extern "C" void ex_host_log_event(const char* event_type,
                                  uint64_t module_id,
                                  const char* capability,
                                  int32_t result);
extern "C" void* ex_host_fs_open(const char* path, uint32_t flags);
extern "C" int32_t ex_host_fs_read(void* file, uint8_t* buf, uint32_t len);
extern "C" int32_t ex_host_fs_write(void* file, const uint8_t* buf, uint32_t len);
extern "C" void ex_host_fs_close(void* file);
extern "C" uint8_t* ex_host_fs_read_file(const char* path, uint32_t* out_len);
extern "C" void ex_host_free_buffer(uint8_t* buf, uint32_t len);
extern "C" char* ex_host_fs_stat(const char* path);
extern "C" char* ex_host_fs_lstat(const char* path);
extern "C" char* ex_host_fs_readdir(const char* path);
extern "C" int32_t ex_host_fs_mkdir(const char* path, int32_t recursive);
extern "C" int32_t ex_host_fs_rmdir(const char* path);
extern "C" int32_t ex_host_fs_unlink(const char* path);
extern "C" int32_t ex_host_fs_rename(const char* from, const char* to);
extern "C" int32_t ex_host_fs_copy(const char* from, const char* to);
extern "C" char* ex_host_fs_realpath(const char* path);
extern "C" int32_t ex_host_fs_access(const char* path, int32_t mode);
extern "C" int32_t ex_host_fs_chmod(const char* path, uint32_t mode);
extern "C" char* ex_host_fs_mkdtemp(const char* prefix);
extern "C" int32_t ex_host_fs_append(const char* path, const uint8_t* data, uint32_t len);
extern "C" uint32_t ex_host_env_get(const char* key, char* out_buf, uint32_t len);
extern "C" int32_t ex_host_random_fill(uint8_t* buf, uint32_t len);
extern "C" char* ex_host_module_resolve(const char* specifier, const char* referrer);
extern "C" void ex_host_free_string(char* value);

// HTTP server (implemented in host/http_server.rs)
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
    const uint8_t* chunk,
    uint32_t chunk_len);
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
extern "C" int32_t ex_host_http_is_referenced(uint32_t server_id);
extern "C" int32_t ex_host_http_has_referenced(void);
extern "C" int32_t ex_host_http_has_pending_requests(void);
extern "C" void ex_host_http_set_ref(uint32_t server_id, int32_t referenced);
extern "C" uint64_t ex_host_sqlite_open(const char* path, const char* options_json);
extern "C" int32_t ex_host_sqlite_close(uint64_t handle);
extern "C" char* ex_host_sqlite_prepare(uint64_t db_handle, const char* sql);
extern "C" int32_t ex_host_sqlite_finalize(uint64_t statement_handle);
extern "C" char* ex_host_sqlite_expanded_sql(uint64_t statement_handle);
extern "C" int32_t ex_host_sqlite_in_transaction(uint64_t handle);
extern "C" char* ex_host_sqlite_all(uint64_t statement_handle, const char* bindings_json);
extern "C" char* ex_host_sqlite_get(uint64_t statement_handle, const char* bindings_json);
extern "C" char* ex_host_sqlite_run(uint64_t statement_handle, const char* bindings_json);
extern "C" char* ex_host_sqlite_values(uint64_t statement_handle, const char* bindings_json);
extern "C" char* ex_host_sqlite_exec(uint64_t handle, const char* sql, const char* bindings_json);

// Native WebSocket (implemented in native_websocket_macos.mm using NSURLSessionWebSocketTask)
typedef void (*NativeWsOpenCallback)(uint32_t ws_id, const char* protocol, const char* extensions, void* context);
typedef void (*NativeWsMessageCallback)(uint32_t ws_id, const uint8_t* data, size_t length, int is_text, void* context);
typedef void (*NativeWsCloseCallback)(uint32_t ws_id, uint16_t code, const char* reason, int was_clean, void* context);
typedef void (*NativeWsErrorCallback)(uint32_t ws_id, const char* message, void* context);
typedef void (*NativeWsBytesSentCallback)(uint32_t ws_id, size_t bytes_sent, void* context);
extern "C" uint32_t native_ws_connect(
    const char* url,
    const char* protocols,
    NativeWsOpenCallback open_cb,
    NativeWsMessageCallback message_cb,
    NativeWsCloseCallback close_cb,
    NativeWsErrorCallback error_cb,
    NativeWsBytesSentCallback bytes_sent_cb,
    void* context
);
extern "C" void native_ws_send(uint32_t ws_id, const uint8_t* data, size_t length, int is_text);
extern "C" void native_ws_close(uint32_t ws_id, uint16_t code, const char* reason);
extern "C" void native_ws_destroy(uint32_t ws_id);
extern "C" int native_ws_has_active(void);

// Native fetch (implemented in native_fetch_macos.mm using NSURLSession)
typedef void (*NativeFetchResponseCallback)(
    uint32_t request_id,
    int status,
    const char* status_text,
    const char* headers,
    const uint8_t* body,
    size_t body_length,
    void* context
);
extern "C" void native_fetch_perform(
    uint32_t request_id,
    const char* method,
    const char* url,
    const char* headers,
    const uint8_t* body,
    size_t body_length,
    NativeFetchResponseCallback response_callback,
    void* context);

constexpr uint32_t EXACT_FS_WRITE = 1u << 1;
constexpr uint32_t EXACT_FS_CREATE = 1u << 2;
constexpr uint32_t EXACT_FS_TRUNCATE = 1u << 3;

namespace {

class MemoryBuffer : public facebook::jsi::Buffer {
 public:
  MemoryBuffer(const uint8_t* data, size_t len) : data_(data, data + len) {}

  size_t size() const override { return data_.size(); }
  const uint8_t* data() const override { return data_.data(); }

 private:
  std::vector<uint8_t> data_;
};

std::string valueToString(facebook::jsi::Runtime& rt, const facebook::jsi::Value& value) {
  if (value.isUndefined()) {
    return "undefined";
  }
  if (value.isNull()) {
    return "null";
  }
  if (value.isObject()) {
    // Check if this is an Error instance — Error properties are non-enumerable
    // so JSON.stringify returns "{}" which is useless.
    try {
      auto obj = value.getObject(rt);
      auto errorCtor = rt.global().getProperty(rt, "Error");
      if (errorCtor.isObject()) {
        auto isInstance = rt.global()
            .getPropertyAsObject(rt, "Object")
            .getPropertyAsFunction(rt, "getPrototypeOf");
        // Simple check: see if the object has a .message property (duck-type Error)
        auto msgProp = obj.getProperty(rt, "message");
        auto stackProp = obj.getProperty(rt, "stack");
        if (msgProp.isString()) {
          std::string result = msgProp.asString(rt).utf8(rt);
          if (stackProp.isString()) {
            auto stack = stackProp.asString(rt).utf8(rt);
            if (!stack.empty()) {
              result += "\n" + stack;
            }
          }
          return result;
        }
      }
    } catch (...) {
    }
    try {
      auto jsonObj = rt.global().getPropertyAsObject(rt, "JSON");
      auto stringify = jsonObj.getPropertyAsFunction(rt, "stringify");
      auto pretty = stringify.call(rt, value, facebook::jsi::Value::null(), facebook::jsi::Value(2.0));
      if (pretty.isString()) {
        return pretty.asString(rt).utf8(rt);
      }
    } catch (const facebook::jsi::JSError&) {
    } catch (...) {
    }
  }
  return value.toString(rt).utf8(rt);
}

facebook::jsi::Function makeLogFunction(facebook::jsi::Runtime& rt, int32_t level) {
  return facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "log"),
      1,
      [level](facebook::jsi::Runtime& runtime,
              const facebook::jsi::Value&,
              const facebook::jsi::Value* args,
              size_t count) -> facebook::jsi::Value {
        std::string message;
        for (size_t i = 0; i < count; ++i) {
          if (i > 0) {
            message += " ";
          }
          message += valueToString(runtime, args[i]);
        }
        ex_host_console_log(level, message.c_str());
        return facebook::jsi::Value::undefined();
      });
}

struct TimerEntry {
  uint64_t id;
  uint64_t due_ms;
  uint64_t interval_ms;
  bool repeat;
  facebook::jsi::Function callback;
};

uint64_t nowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void drainMicrotasks(facebook::jsi::Runtime& rt) {
  rt.drainMicrotasks(-1);
}

// Fetch callback storage: request_id -> (resolve, reject, url)
using FetchCallbackEntry = std::tuple<
    std::shared_ptr<facebook::jsi::Function>,
    std::shared_ptr<facebook::jsi::Function>,
    std::string
>;

struct ExactHermesRuntime {
  std::unique_ptr<facebook::hermes::HermesRuntime> runtime;
  std::unique_ptr<facebook::hermes::debugger::AsyncDebuggerAPI> debugger;
  bool debugger_callback_set{false};
  std::atomic<bool> debugger_attached{false};
  std::atomic<bool> debugger_available{true};
  std::mutex debug_mutex;
  std::deque<std::string> debug_events;
  std::unordered_set<uint32_t> known_scripts;
  std::unordered_map<uint32_t, std::string> script_id_to_name;
  std::unordered_map<std::string, std::string> sources_by_name;
  std::thread::id runtime_thread;
  uint64_t next_timer_id{1};
  std::unordered_map<uint64_t, TimerEntry> timers;
  std::deque<facebook::jsi::Function> next_tick;
  // Task queue for cross-thread execution
  std::mutex task_mutex;
  std::vector<std::function<void(facebook::jsi::Runtime&)>> pending_tasks;
  // Fetch infrastructure
  std::mutex fetchMutex;
  uint32_t nextFetchId{1};
  std::unordered_map<uint32_t, FetchCallbackEntry> fetchCallbacks;
  // Cross-thread callback queue (for delivering results from background threads)
  std::mutex callbackMutex;
  std::deque<std::function<void(facebook::jsi::Runtime&)>> callbackQueue;

  // --- iOS rendering pipeline callbacks ---
  // These are set by the iOS app to receive binary dispatch and module calls.
  // On CLI, these remain null and the corresponding JS functions are not installed.

  // Callback for exact.dispatch(Uint8Array) - binary protocol for rendering
  void (*ios_dispatch_callback)(const uint8_t* data, size_t length, void* context) = nullptr;
  void* ios_dispatch_context = nullptr;

  // Callback for exact.dispatchModule(Uint8Array) - async native module calls
  void (*ios_module_dispatch_callback)(const uint8_t* data, size_t length, void* context) = nullptr;
  void* ios_module_dispatch_context = nullptr;

  // Callback for exact.callModuleSync(Uint8Array) - blocking native module calls
  // Returns 0 on success, fills result_data/result_length
  int (*ios_module_sync_callback)(const uint8_t* data, size_t length,
                                   uint8_t** result_data, size_t* result_length,
                                   void* context) = nullptr;
  void* ios_module_sync_context = nullptr;
};

class VectorBuffer : public facebook::jsi::MutableBuffer {
 public:
  explicit VectorBuffer(std::vector<uint8_t> data) : data_(std::move(data)) {}

  size_t size() const override { return data_.size(); }
  uint8_t* data() override { return data_.data(); }

 private:
  std::vector<uint8_t> data_;
};

extern "C" void ex_hermes_notify_callback();

void pushRuntimeCallback(ExactHermesRuntime* runtime,
                          std::function<void(facebook::jsi::Runtime&)> fn) {
    std::lock_guard<std::mutex> lock(runtime->callbackMutex);
    runtime->callbackQueue.push_back(std::move(fn));
    ex_hermes_notify_callback();
}

int drainCallbackQueue(ExactHermesRuntime* runtime) {
    std::deque<std::function<void(facebook::jsi::Runtime&)>> queue;
    {
        std::lock_guard<std::mutex> lock(runtime->callbackMutex);
        queue.swap(runtime->callbackQueue);
    }
    int count = 0;
    for (auto& fn : queue) {
        try {
            fn(*runtime->runtime);
            count++;
        } catch (const facebook::jsi::JSError& err) {
            ex_host_console_log(1, err.getMessage().c_str());
        } catch (...) {
            ex_host_console_log(1, "Callback execution failed");
        }
    }
    return count;
}

std::string escapeJson(const std::string& input) {
  std::ostringstream out;
  for (unsigned char c : input) {
    switch (c) {
      case '\"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(c) << std::dec;
        } else {
          out << c;
        }
    }
  }
  return out.str();
}

std::string jsonString(const std::string& value) {
  return std::string("\"") + escapeJson(value) + "\"";
}

std::string makeRemoteObject(facebook::jsi::Runtime& rt, const facebook::jsi::Value& value) {
  if (value.isUndefined()) {
    return "{\"type\":\"undefined\"}";
  }
  if (value.isNull()) {
    return "{\"type\":\"object\",\"subtype\":\"null\",\"value\":null}";
  }
  if (value.isBool()) {
    return std::string("{\"type\":\"boolean\",\"value\":") +
           (value.getBool() ? "true" : "false") + "}";
  }
  if (value.isNumber()) {
    std::ostringstream out;
    out << "{\"type\":\"number\",\"value\":" << value.getNumber() << "}";
    return out.str();
  }
  if (value.isString()) {
    auto text = value.toString(rt).utf8(rt);
    return std::string("{\"type\":\"string\",\"value\":") + jsonString(text) + "}";
  }
  if (value.isObject()) {
    return "{\"type\":\"object\",\"description\":\"[object Object]\"}";
  }
  return "{\"type\":\"undefined\"}";
}

static std::string stringifyValue(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  if (value.isUndefined() || value.isNull()) {
    return "null";
  }
  auto jsonObj = runtime.global().getPropertyAsObject(runtime, "JSON");
  auto stringify = jsonObj.getPropertyAsFunction(runtime, "stringify");
  auto json = stringify.call(runtime, value);
  if (!json.isString()) {
    return "null";
  }
  return json.asString(runtime).utf8(runtime);
}

static facebook::jsi::Value parseJsonValue(
    facebook::jsi::Runtime& runtime,
    const char* json) {
  auto jsonObj = runtime.global().getPropertyAsObject(runtime, "JSON");
  auto parse = jsonObj.getPropertyAsFunction(runtime, "parse");
  return parse.call(runtime, facebook::jsi::String::createFromUtf8(runtime, json));
}

void pushDebugEvent(ExactHermesRuntime* runtime, const std::string& event) {
  if (!runtime) {
    return;
  }
  std::lock_guard<std::mutex> lock(runtime->debug_mutex);
  runtime->debug_events.push_back(event);
}

std::string pauseReasonToString(facebook::hermes::debugger::PauseReason reason) {
  using facebook::hermes::debugger::PauseReason;
  switch (reason) {
    case PauseReason::DebuggerStatement:
      return "debuggerStatement";
    case PauseReason::Breakpoint:
      return "breakpoint";
    case PauseReason::StepFinish:
      return "step";
    case PauseReason::Exception:
      return "exception";
    case PauseReason::AsyncTriggerExplicit:
      return "pause";
    case PauseReason::AsyncTriggerImplicit:
      return "pause";
    default:
      return "other";
  }
}

std::string buildPausedEvent(ExactHermesRuntime* runtime) {
  using facebook::hermes::debugger::kInvalidLocation;
  if (!runtime || !runtime->runtime) {
    return "";
  }
  auto& debugger = runtime->runtime->getDebugger();
  const auto& state = debugger.getProgramState();
  auto reason = pauseReasonToString(state.getPauseReason());
  auto stack = state.getStackTrace();

  std::ostringstream out;
  out << "{\"method\":\"Debugger.paused\",\"params\":{";
  out << "\"reason\":" << jsonString(reason) << ",";
  out << "\"callFrames\":[";

  for (uint32_t i = 0; i < stack.callFrameCount(); ++i) {
    auto frame = stack.callFrameForIndex(i);
    auto loc = frame.location;
    uint32_t line = loc.line == kInvalidLocation ? 0 : (loc.line > 0 ? loc.line - 1 : 0);
    uint32_t column = loc.column == kInvalidLocation ? 0 : (loc.column > 0 ? loc.column - 1 : 0);

    if (i > 0) {
      out << ",";
    }
    out << "{";
    out << "\"callFrameId\":" << jsonString("frame-" + std::to_string(i)) << ",";
    out << "\"functionName\":" << jsonString(frame.functionName) << ",";
    out << "\"location\":{";
    out << "\"scriptId\":" << jsonString(std::to_string(loc.fileId)) << ",";
    out << "\"lineNumber\":" << line << ",";
    out << "\"columnNumber\":" << column;
    out << "},";
    out << "\"url\":" << jsonString(loc.fileName) << ",";
    out << "\"scopeChain\":[]";
    out << "}";
  }

  out << "],";
  out << "\"hitBreakpoints\":[";
  if (state.getPauseReason() == facebook::hermes::debugger::PauseReason::Breakpoint) {
    auto id = state.getBreakpoint();
    if (id != facebook::hermes::debugger::kInvalidBreakpoint) {
      out << jsonString(std::to_string(id));
    }
  }
  out << "]";
  out << "}}";
  return out.str();
}

void emitScriptParsed(ExactHermesRuntime* runtime,
                      const facebook::hermes::debugger::SourceLocation& loc) {
  using facebook::hermes::debugger::kInvalidLocation;
  uint32_t line = loc.line == kInvalidLocation ? 0 : (loc.line > 0 ? loc.line - 1 : 0);
  uint32_t column = loc.column == kInvalidLocation ? 0 : (loc.column > 0 ? loc.column - 1 : 0);

  std::ostringstream out;
  out << "{\"method\":\"Debugger.scriptParsed\",\"params\":{";
  out << "\"scriptId\":" << jsonString(std::to_string(loc.fileId)) << ",";
  out << "\"url\":" << jsonString(loc.fileName) << ",";
  out << "\"startLine\":" << line << ",";
  out << "\"startColumn\":" << column << ",";
  out << "\"endLine\":0,";
  out << "\"endColumn\":0";
  out << "}}";
  pushDebugEvent(runtime, out.str());
}

void emitNewScripts(ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime) {
    return;
  }
  auto scripts = runtime->runtime->getDebugger().getLoadedScripts();
  for (const auto& script : scripts) {
    if (runtime->known_scripts.insert(script.fileId).second) {
      runtime->script_id_to_name[script.fileId] = script.fileName;
      emitScriptParsed(runtime, script);
    }
  }
}

template <typename F>
std::string runOnRuntimeThread(ExactHermesRuntime* runtime, F func) {
  if (!runtime) {
    return std::string();
  }

  auto safe_call = [runtime, &func]() -> std::string {
    try {
      return func(runtime);
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, err.getMessage().c_str());
      return std::string();
    } catch (const std::exception& err) {
      ex_host_console_log(1, err.what());
      return std::string();
    } catch (...) {
      ex_host_console_log(1, "Unknown native error");
      return std::string();
    }
  };

  if (std::this_thread::get_id() == runtime->runtime_thread) {
    return safe_call();
  }
  if (!runtime->debugger || !runtime->debugger_available.load()) {
    return std::string();
  }

  auto promise = std::make_shared<std::promise<std::string>>();
  auto future = promise->get_future();
  try {
    runtime->debugger->triggerInterrupt_TS(
        [promise, safe_call](facebook::hermes::HermesRuntime&) mutable {
          promise->set_value(safe_call());
        });
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
    return std::string();
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
    return std::string();
  } catch (...) {
    ex_host_console_log(1, "Unknown native error");
    return std::string();
  }
  return future.get();
}

// Cached at first use; -1 = uninitialized
static int g_allow_all = -1;
static thread_local uint64_t g_active_module_id = 0;

bool isAllowAll() {
  if (g_allow_all < 0) {
    g_allow_all = ex_host_is_allow_all();
  }
  return g_allow_all != 0;
}

bool checkCapability(const std::string& capability) {
  if (isAllowAll()) {
    return true;
  }
  auto allowed = ex_host_check_capability(g_active_module_id, capability.c_str());
  ex_host_log_event(
      allowed ? "capability_granted" : "capability_denied",
      g_active_module_id,
      capability.c_str(),
      allowed);
  return allowed != 0;
}

std::string getEnvValue(const std::string& key) {
  char buffer[4096];
  auto written = ex_host_env_get(key.c_str(), buffer, sizeof(buffer));
  if (written == 0) {
    return std::string();
  }
  return std::string(buffer, buffer + written);
}

facebook::jsi::Value makeUint8Array(facebook::jsi::Runtime& rt, std::vector<uint8_t> data) {
  auto buffer = std::make_shared<VectorBuffer>(std::move(data));
  facebook::jsi::ArrayBuffer arrayBuffer(rt, buffer);
  auto ctor = rt.global().getPropertyAsFunction(rt, "Uint8Array");
  auto typed = ctor.callAsConstructor(rt, arrayBuffer).getObject(rt);
  return facebook::jsi::Value(std::move(typed));
}

// Extract bytes from a JSI value (string, ArrayBuffer, or TypedArray like Uint8Array)
std::vector<uint8_t> extractBytes(facebook::jsi::Runtime& rt, const facebook::jsi::Value& val) {
  if (val.isString()) {
    auto str = val.asString(rt).utf8(rt);
    return std::vector<uint8_t>(str.begin(), str.end());
  }
  if (val.isObject()) {
    auto obj = val.asObject(rt);
    if (obj.isArrayBuffer(rt)) {
      auto buf = obj.getArrayBuffer(rt);
      return std::vector<uint8_t>(buf.data(rt), buf.data(rt) + buf.size(rt));
    }
    // TypedArray (Uint8Array, etc.) — get the underlying buffer, byteOffset, byteLength
    if (obj.hasProperty(rt, "buffer")) {
      auto bufProp = obj.getProperty(rt, "buffer");
      if (bufProp.isObject()) {
        auto bufObj = bufProp.asObject(rt);
        if (bufObj.isArrayBuffer(rt)) {
          auto ab = bufObj.getArrayBuffer(rt);
          size_t offset = 0;
          size_t length = ab.size(rt);
          auto offProp = obj.getProperty(rt, "byteOffset");
          if (offProp.isNumber()) offset = static_cast<size_t>(offProp.asNumber());
          auto lenProp = obj.getProperty(rt, "byteLength");
          if (lenProp.isNumber()) length = static_cast<size_t>(lenProp.asNumber());
          auto* ptr = ab.data(rt) + offset;
          return std::vector<uint8_t>(ptr, ptr + length);
        }
      }
    }
    // Fallback: try to read .length and index
    if (obj.hasProperty(rt, "length")) {
      auto lenVal = obj.getProperty(rt, "length");
      if (lenVal.isNumber()) {
        size_t len = static_cast<size_t>(lenVal.asNumber());
        std::vector<uint8_t> result(len);
        for (size_t i = 0; i < len; i++) {
          auto v = obj.getPropertyAsObject(rt, "0"); // won't work for indexed
          // Use bracket notation via asArray
          break; // fallback won't work well, use above methods
        }
      }
    }
  }
  return {};
}

#if defined(__APPLE__)
static std::string normalizeHashForNodeCrypto(const std::string& algorithm) {
  auto lowered = algorithm;
  for (auto& ch : lowered) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }

  if (lowered == "ecdsa" || lowered == "ecdsa-with-sha1") return "sha1";
  if (lowered == "ecdsa-with-sha256" || lowered == "rsa-sha256" || lowered == "sha256") return "sha256";
  if (lowered == "ecdsa-with-sha384" || lowered == "rsa-sha384" || lowered == "sha384") return "sha384";
  if (lowered == "ecdsa-with-sha512" || lowered == "rsa-sha512" || lowered == "sha512") return "sha512";
  if (lowered.find("sha1") != std::string::npos) return "sha1";
  if (lowered.find("sha256") != std::string::npos) return "sha256";
  if (lowered.find("sha384") != std::string::npos) return "sha384";
  if (lowered.find("sha512") != std::string::npos) return "sha512";
  if (lowered.find("md5") != std::string::npos) return "md5";
  return "sha256";
}

static SecKeyAlgorithm pickSecKeySignAlgorithm(const std::string& hashName, bool isRsa) {
  if (isRsa) {
    if (hashName == "sha1") return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1;
    if (hashName == "sha256") return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    if (hashName == "sha384") return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384;
    if (hashName == "sha512") return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
    return nullptr;
  }

  if (hashName == "sha1") return kSecKeyAlgorithmECDSASignatureMessageX962SHA1;
  if (hashName == "sha256") return kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
  if (hashName == "sha384") return kSecKeyAlgorithmECDSASignatureMessageX962SHA384;
  if (hashName == "sha512") return kSecKeyAlgorithmECDSASignatureMessageX962SHA512;
  return nullptr;
}

static bool isRsaSecKey(SecKeyRef key) {
  bool isRsa = false;
  auto attrs = SecKeyCopyAttributes(key);
  if (attrs) {
    auto type = CFDictionaryGetValue(attrs, kSecAttrKeyType);
    if (type != nullptr) {
      isRsa = CFEqual(type, kSecAttrKeyTypeRSA);
    }
    CFRelease(attrs);
  }
  return isRsa;
}

static std::string dataToString(CFDataRef data) {
  if (!data) return {};
  const auto bytes = CFDataGetBytePtr(data);
  const auto len = CFDataGetLength(data);
  return std::string(reinterpret_cast<const char*>(bytes), static_cast<size_t>(len));
}

#if !defined(EXACT_PLATFORM_IOS)
// SecItemImport/SecItemExport are macOS-only APIs (not available on iOS)
static SecKeyRef importPemKey(const std::string& pemText, SecExternalItemType itemType) {
  auto keyBytes = std::vector<uint8_t>(pemText.begin(), pemText.end());
  auto keyData = CFDataCreate(kCFAllocatorDefault, keyBytes.data(), static_cast<CFIndex>(keyBytes.size()));
  if (!keyData) {
    return nullptr;
  }

  SecItemImportExportKeyParameters keyParams{};
  keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;

  CFArrayRef importedItems = nullptr;
  SecExternalFormat inputFormat = kSecFormatPEMSequence;
  SecExternalItemType effectiveType = itemType;
  auto status = SecItemImport(
      keyData,
      nullptr,
      &inputFormat,
      &effectiveType,
      0,
      &keyParams,
      nullptr,
      &importedItems);

  if (status != noErr) {
    if (importedItems) {
      CFRelease(importedItems);
      importedItems = nullptr;
    }

    if (status != noErr && itemType != kSecItemTypeUnknown) {
      effectiveType = kSecItemTypeUnknown;
      status = SecItemImport(
          keyData,
          nullptr,
          &inputFormat,
          &effectiveType,
          0,
          &keyParams,
          nullptr,
          &importedItems);
    }
  }

  CFRelease(keyData);

  if (status != noErr || !importedItems) {
    if (importedItems) {
      CFRelease(importedItems);
    }
    return nullptr;
  }

  if (CFArrayGetCount(importedItems) == 0) {
    CFRelease(importedItems);
    return nullptr;
  }

  auto maybeKey = CFArrayGetValueAtIndex(importedItems, 0);
  if (!maybeKey) {
    CFRelease(importedItems);
    return nullptr;
  }

  if (CFGetTypeID(maybeKey) != SecKeyGetTypeID()) {
    CFRelease(importedItems);
    return nullptr;
  }

  auto key = static_cast<SecKeyRef>(const_cast<void*>(maybeKey));
  CFRetain(key);
  CFRelease(importedItems);
  return key;
}
#endif // !EXACT_PLATFORM_IOS
#endif

#if !defined(__APPLE__) || !defined(EXACT_NO_OPENSSL)
const EVP_MD* selectDigestForCryptoAlgo(const std::string& algorithm) {
  if (algorithm == "sha1" || algorithm == "sha-1") return EVP_sha1();
  if (algorithm == "sha256" || algorithm == "sha-256") return EVP_sha256();
  if (algorithm == "sha384" || algorithm == "sha-384") return EVP_sha384();
  if (algorithm == "sha512" || algorithm == "sha-512") return EVP_sha512();
  if (algorithm == "md5" || algorithm == "md5") return EVP_md5();
  return nullptr;
}

std::string digestAlgorithmFromNodeCrypto(const std::string& algorithm) {
  auto lowered = algorithm;
  for (auto& ch : lowered) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }

  if (lowered == "ecdsa" || lowered == "ecdsa-with-sha1") return "sha1";
  if (lowered == "ecdsa-with-sha256" || lowered == "rsa-sha256" || lowered == "sha256") return "sha256";
  if (lowered == "ecdsa-with-sha384" || lowered == "rsa-sha384" || lowered == "sha384") return "sha384";
  if (lowered == "ecdsa-with-sha512" || lowered == "rsa-sha512" || lowered == "sha512") return "sha512";
  if (lowered.find("sha1") != std::string::npos) return "sha1";
  if (lowered.find("sha256") != std::string::npos) return "sha256";
  if (lowered.find("sha384") != std::string::npos) return "sha384";
  if (lowered.find("sha512") != std::string::npos) return "sha512";
  if (lowered.find("md5") != std::string::npos) return "md5";
  return "sha256";
}
#endif

void runNextTickQueue(ExactHermesRuntime* runtime);

void installModuleLoader(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  static const char* loader = R"JS(
(function() {
  if (globalThis.__exactRequire) {
    return;
  }
  var g = globalThis;
  const cache = Object.create(null);
  var mainModule = null;
  function isSameModule(a, b) {
    if (!a || !b) return false;
    return a === b;
  }
  function addChild(parent, child) {
    if (!parent || !child) {
      return;
    }
    if (!parent.children) {
      parent.children = [];
    }
    for (var i = 0; i < parent.children.length; i++) {
      if (isSameModule(parent.children[i], child)) {
        return;
      }
    }
    parent.children.push(child);
  }
  function dirname(path) {
    if (!path) {
      return "";
    }
    const normalized = path.replace(/\\/g, "/");
    const idx = normalized.lastIndexOf("/");
    if (idx <= 0) {
      return "";
    }
    return normalized.slice(0, idx);
  }
  function fixEsmCjsInterop(source) {
    // Patch rolldown's __toCommonJS to return .default with named exports
    // merged, so require('esm-pkg') returns the default export directly.
    if (!source || source.indexOf("__toCommonJS") === -1) return source;
    var marker = "var __toCommonJS = (mod) =>";
    var idx = source.indexOf(marker);
    if (idx === -1) return source;
    var end = source.indexOf(";", idx);
    if (end === -1) return source;
    var replacement = marker + " {\n" +
      "  if (__hasOwnProp.call(mod, 'module.exports')) return mod['module.exports'];\n" +
      "  var __ns = __copyProps(__defProp({}, '__esModule', { value: true }), mod);\n" +
      "  if (__ns.default !== undefined) {\n" +
      "    var __def = __ns.default;\n" +
      "    if (__def && (typeof __def === 'function' || typeof __def === 'object')) {\n" +
      "      var __ks = Object.keys(__ns);\n" +
      "      for (var __ki = 0; __ki < __ks.length; __ki++) {\n" +
      "        if (__ks[__ki] !== 'default' && __ks[__ki] !== '__esModule' && !(__ks[__ki] in __def)) {\n" +
      "          try { __def[__ks[__ki]] = __ns[__ks[__ki]]; } catch(e) {}\n" +
      "        }\n" +
      "      }\n" +
      "    }\n" +
      "    return __def;\n" +
      "  }\n" +
      "  return __ns;\n" +
      "}";
    return source.slice(0, idx) + replacement + source.slice(end + 1);
  }
  function fixForOfScoping(source) {
    if (!source || !/\bfor\s*\(\s*(?:const|let)\b[^)]*\bof\b/.test(source)) {
      return source;
    }
    var lines = source.split("\n");
    var out = [];
    var i = 0;
    while (i < lines.length) {
      var line = lines[i];
      // Match: for (const/let BINDING of EXPR) {
      // Use precise parsing instead of regex to handle nested parens correctly
      var trimmed = line.replace(/^\s*/, "");
      var indent = line.slice(0, line.length - trimmed.length);
      if (!/^for\s*\(/.test(trimmed)) {
        out.push(line);
        i++;
        continue;
      }
      // Find the balanced closing paren for the for(...)
      var forStart = trimmed.indexOf("(");
      if (forStart === -1) { out.push(line); i++; continue; }
      var parenDepth = 0;
      var forEnd = -1;
      var inStr2 = false;
      var strCh2 = 0;
      for (var fi = forStart; fi < trimmed.length; fi++) {
        var fc = trimmed.charCodeAt(fi);
        if (inStr2) {
          if (fc === strCh2 && (fi === 0 || trimmed.charCodeAt(fi-1) !== 92)) inStr2 = false;
        } else {
          if (fc === 34 || fc === 39 || fc === 96) { inStr2 = true; strCh2 = fc; }
          else if (fc === 40) parenDepth++;
          else if (fc === 41) { parenDepth--; if (parenDepth === 0) { forEnd = fi; break; } }
        }
      }
      if (forEnd === -1) { out.push(line); i++; continue; }
      var inner = trimmed.slice(forStart + 1, forEnd).replace(/^\s+|\s+$/g, "");
      // Check if it's const/let ... of ...
      var ofMatch = inner.match(/^(?:const|let)\s+(\S+)\s+of\s+([\s\S]+)$/);
      if (!ofMatch) { out.push(line); i++; continue; }
      var binding = ofMatch[1];
      var expr = ofMatch[2];
      // Rest of line after for(...) must be just "{"
      var afterFor = trimmed.slice(forEnd + 1).replace(/^\s+|\s+$/g, "");
      if (afterFor !== "{") { out.push(line); i++; continue; }
      // Now find the matching closing brace
      var depth = 1;
      var bodyLines = [];
      var j = i + 1;
      var hasBreakContinue = false;
      while (j < lines.length && depth > 0) {
        var bl = lines[j];
        var inStr = false;
        var strCh = 0;
        for (var k = 0; k < bl.length; k++) {
          var ch = bl.charCodeAt(k);
          if (inStr) {
            if (ch === strCh && (k === 0 || bl.charCodeAt(k - 1) !== 92)) inStr = false;
          } else {
            if (ch === 34 || ch === 39 || ch === 96) { inStr = true; strCh = ch; }
            else if (ch === 123) depth++;
            else if (ch === 125) depth--;
          }
          if (depth <= 0) break;
        }
        if (depth > 0) {
          bodyLines.push(bl);
          if (/\b(break|continue)\s*[;\n}]/.test(bl) || /\byield\b/.test(bl) || /\bawait\b/.test(bl) || /\breturn\b/.test(bl)) hasBreakContinue = true;
        }
        j++;
      }
      if (hasBreakContinue || depth !== 0) {
        out.push(line);
        i++;
        continue;
      }
      out.push(indent + "Array.from(" + expr + ").forEach(function(" + binding + ") {");
      for (var b = 0; b < bodyLines.length; b++) {
        out.push(bodyLines[b]);
      }
      out.push(indent + "});");
      i = j;
    }
    return out.join("\n");
  }
  function transformEsmToCjs(source) {
    if (!source) {
      return "";
    }
    var lines = String(source).split("\n");
    var out = [];
    var importCounter = 0;
    var isIdent = /^[A-Za-z_$][\w$]*$/;
    var isExportName = function(value) {
      return value === "default" || isIdent.test(value);
    };
    var quote = function(value) {
      return JSON.stringify(value);
    };
    var emitNamedBindings = function(spec, modName) {
      var parts = spec ? spec.split(",") : [];
      for (var i = 0; i < parts.length; i++) {
        var item = parts[i].trim();
        if (!item) {
          continue;
        }
        var asMatch = item.match(/^(.+?)\s+as\s+(.+)$/);
        if (asMatch) {
          var sourceName = asMatch[1].trim();
          var localName = asMatch[2].trim();
          if (!isExportName(sourceName) || !isIdent.test(localName) || localName === "default") {
            continue;
          }
          if (sourceName === "default") {
            out.push("var " + localName + " = " + modName + " && " + modName + ".default;");
          } else {
            out.push("var " + localName + " = " + modName + "." + sourceName + ";");
          }
        } else if (isIdent.test(item)) {
          out.push("var " + item + " = " + modName + "." + item + ";");
        }
      }
    };
    var emitExportBindings = function(spec, sourceExpr, allowBareDefault, useLocals) {
      var entries = spec ? spec.split(",") : [];
      for (var i = 0; i < entries.length; i++) {
        var item = entries[i].trim();
        if (!item) {
          continue;
        }
        var asMatch = item.match(/^(.+?)\s+as\s+(.+)$/);
        if (asMatch) {
          var sourceName = asMatch[1].trim();
          var exportName = asMatch[2].trim();
          if (!isExportName(sourceName) || !isExportName(exportName)) {
            continue;
          }
          if (useLocals) {
            out.push("module.exports." + exportName + " = " + sourceName + ";");
          } else {
            out.push("module.exports." + exportName + " = " + sourceExpr + "." + sourceName + ";");
          }
          continue;
        }
        if (!allowBareDefault && item === "default") {
          continue;
        }
        if (isExportName(item)) {
          if (useLocals) {
            out.push("module.exports." + item + " = " + item + ";");
          } else {
            out.push("module.exports." + item + " = " + sourceExpr + "." + item + ";");
          }
        }
      }
    };
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var trimmed = line.trim();
      var statement = line;
      if (/^\s*(import|export)\b/.test(trimmed) && trimmed.indexOf(";") === -1) {
        for (var j = i + 1; j < lines.length; j++) {
          statement = statement + "\n" + lines[j];
          if (statement.indexOf(";") !== -1) {
            i = j;
            break;
          }
        }
      }
      if (line.indexOf("import.meta.url") !== -1) {
        statement = statement.replace(/import\.meta\.url/g, "__filename");
      }
      var transformed = statement;
      trimmed = transformed.trim();
      var m;

      if (!trimmed) {
        out.push("");
        continue;
      }

      m = trimmed.match(/^\s*import\s+(["'])([^'"]+)\1\s*;?\s*$/);
      if (m) {
        out.push("require(" + quote(m[2]) + ");");
        continue;
      }

      m = trimmed.match(/^\s*import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        out.push("var " + m[1] + " = require(" + quote(m[3]) + ");");
        continue;
      }

      m = trimmed.match(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\{([\s\S]*?)\}\s+from\s+(["'])([^'"]+)\3\s*;?\s*$/
      );
      if (m) {
        var namedImport = "__exmod" + (importCounter++);
        out.push("var " + namedImport + " = require(" + quote(m[4]) + ");");
        out.push(
          "var " +
            m[1] +
            " = " +
            namedImport +
            " && " +
            namedImport +
            ".__esModule ? " +
            namedImport +
            ".default : " +
            namedImport +
            ";"
        );
        emitNamedBindings(m[2], namedImport);
        continue;
      }

      m = trimmed.match(
        /^\s*import\s+([A-Za-z_$][\w$]*)\s*,\s*\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\3\s*;?\s*$/
      );
      if (m) {
        var nsImport = "__exmod" + (importCounter++);
        out.push("var " + nsImport + " = require(" + quote(m[4]) + ");");
        out.push(
          "var " +
            m[1] +
            " = " +
            nsImport +
            " && " +
            nsImport +
            ".__esModule ? " +
            nsImport +
            ".default : " +
            nsImport +
            ";"
        );
        out.push("var " + m[2] + " = " + nsImport + ";");
        continue;
      }

      m = trimmed.match(/^\s*import\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        out.push(
          "var " +
            m[1] +
            " = require(" +
            quote(m[3]) +
            ").default || require(" +
            quote(m[3]) +
            ");"
        );
        continue;
      }

      m = trimmed.match(/^\s*import\s+\{([\s\S]*?)\}\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        var named = "__exmod" + (importCounter++);
        out.push("var " + named + " = require(" + quote(m[3]) + ");");
        emitNamedBindings(m[1], named);
        continue;
      }

      m = trimmed.match(/^\s*export\s+\*\s+from\s+(["'])([^'"]+)\1\s*;?\s*$/);
      if (m) {
        var exportFrom = "__exmod" + (importCounter++);
        out.push("var " + exportFrom + " = require(" + quote(m[2]) + ");");
        out.push("for (var __exk in " + exportFrom + ") {");
        out.push("  if (Object.prototype.hasOwnProperty.call(" + exportFrom + ", __exk)) {");
        out.push("    module.exports[__exk] = " + exportFrom + "[__exk];");
        out.push("  }");
        out.push("}");
        continue;
      }

      m = trimmed.match(/^\s*export\s+\{([\s\S]*?)\}\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/);
      if (m) {
        var exportFrom = "__exmod" + (importCounter++);
        out.push("var " + exportFrom + " = require(" + quote(m[3]) + ");");
        emitExportBindings(m[1], exportFrom, true, false);
        continue;
      }

      m = trimmed.match(
        /^\s*export\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+(["'])([^'"]+)\2\s*;?\s*$/
      );
      if (m) {
        var nsExport = "__exmod" + (importCounter++);
        out.push("var " + nsExport + " = require(" + quote(m[3]) + ");");
        out.push("module.exports." + m[1] + " = " + nsExport + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+(function|class)\s+([A-Za-z_$][\w$]*)/);
      if (m) {
        out.push(transformed.replace(/\bexport\s+/, ""));
        out.push("module.exports." + m[2] + " = " + m[2] + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+default\s+(.+)\s*$/);
      if (m) {
        out.push("module.exports.default = " + m[1] + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+(const|let|var)\s+([A-Za-z_$][\w$]*)/);
      if (m) {
        out.push(transformed.replace(/\bexport\s+/, ""));
        out.push("module.exports." + m[2] + " = " + m[2] + ";");
        continue;
      }

      m = trimmed.match(/^\s*export\s+\{([^}]*)\}\s*;?\s*$/);
      if (m) {
        emitExportBindings(m[1], null, false, true);
        continue;
      }

      out.push(transformed);
    }
    return out.join("\n");
  }
  function load(specifier, referrer, parent) {
    const json = __exactModuleResolve(specifier, referrer || "");
    if (!json) {
      throw new Error("Module not found: " + specifier);
    }
    let record;
    try {
      record = JSON.parse(json);
    } catch (err) {
      throw new Error("Module resolve failed: " + err.message);
    }
    if (record.error) {
      throw new Error(record.error);
    }
    const id = record.id || specifier;
    var moduleId = idToModuleId(id);
    if (cache[id]) {
      return cache[id].exports;
    }
    const kind = record.kind || "cjs";
    const source = record.source || "";
    var filename = record.path || id;
    // For the entry module, use the original source path so that
    // __dirname/__filename and require.resolve work relative to
    // the source dir, not the bundle cache dir.
    if (g.__exactEntryFile && !g.__exactEntryFileConsumed && filename.indexOf('/Caches/') !== -1) {
      filename = g.__exactEntryFile;
      g.__exactEntryFileConsumed = true;
    }
    const modulePath = filename.indexOf('/') === -1 ? filename : dirname(filename);
    // Compute node_modules search paths for this module
    var modulePaths = [];
    var pathParts = modulePath.split('/');
    for (var pi = pathParts.length - 1; pi >= 0; pi--) {
      if (pathParts[pi] === 'node_modules') continue;
      modulePaths.push(pathParts.slice(0, pi + 1).join('/') + '/node_modules');
    }
    const module = {
      id: id,
      __exactId: moduleId,
      filename: filename,
      path: modulePath,
      exports: {},
      loaded: false,
      parent: parent || null,
      children: [],
      paths: modulePaths,
    };
    cache[id] = module;
    if (!parent && !mainModule) {
      mainModule = module;
    }
    addChild(parent, module);

    module.require = function(next, options) {
      grantCapabilities(next, options, module.__exactId);
      return localRequire(next);
    };

    if (kind === "json") {
      try {
        module.exports = JSON.parse(source || "null");
      } catch (err) {
        delete cache[id];
        throw err;
      }
      module.loaded = true;
      return module.exports;
    }
    const dir = dirname(filename);
    const looksLikeModuleSyntax = function(text) {
      return /\n?\s*(?:import|export)\b/m.test(text || "");
    };
    var localRequire = function(next) {
      var exports = load(next, filename, module);
      // Skip interop for ESM-shimmed modules — the shim's generated
      // import bindings already handle default/named/namespace access.
      if (exports && exports.__esmShimmed) {
        return exports;
      }
      // ESM/CJS interop: when a bundled ESM module is loaded via require(),
      // rolldown wraps it with __esModule:true. Return .default so that
      // require('pkg') returns the default export directly, with named
      // exports merged onto it so destructuring still works.
      if (exports && exports.__esModule && exports.default !== undefined) {
        var def = exports.default;
        if (def && (typeof def === "function" || typeof def === "object")) {
          var keys = Object.keys(exports);
          for (var ki = 0; ki < keys.length; ki++) {
            var k = keys[ki];
            if (k !== "default" && k !== "__esModule" && !(k in def)) {
              try { def[k] = exports[k]; } catch (e) {}
            }
          }
        }
        return def;
      }
      return exports;
    };
    localRequire.resolve = function(specifier) {
      var json = __exactModuleResolve(specifier, filename || "");
      if (!json) {
        throw new Error("Cannot find module '" + specifier + "'");
      }
      var rec = JSON.parse(json);
      if (rec.error) {
        throw new Error("Cannot find module '" + specifier + "'");
      }
      return rec.path || rec.id || specifier;
    };
    localRequire.resolve.paths = function(specifier) {
      return null;
    };
    localRequire.cache = cache;
    localRequire.main = mainModule;
    const restoreModuleId = function(previousId) {
      if (typeof g.__exactSetActiveModuleId === "function") {
        g.__exactSetActiveModuleId(previousId || 0);
      }
    };
    const previousModuleId = typeof g.__exactSetActiveModuleId === "function"
      ? g.__exactSetActiveModuleId(module.__exactId)
      : 0;
    try {
      const directSource = fixForOfScoping(fixEsmCjsInterop(source || "")) + "\n//# sourceURL=" + filename;
      try {
        const directFn = new Function(
          "require",
          "module",
          "exports",
          "__filename",
          "__dirname",
          directSource
        );
        directFn(localRequire, module, module.exports, filename, dir);
      } catch (err) {
        const shouldFallback = (kind === "esm" || looksLikeModuleSyntax(directSource));
        const canFallback = shouldFallback &&
          err &&
          err.name === "SyntaxError" &&
          directSource.length > 0;
        if (!canFallback) {
          throw err;
        }
        const runtimeSource = fixForOfScoping(transformEsmToCjs(directSource)) + "\n//# sourceURL=" + filename;
        const fallbackFn = new Function(
          "require",
          "module",
          "exports",
          "__filename",
          "__dirname",
          runtimeSource
        );
        fallbackFn(localRequire, module, module.exports, filename, dir);
        if (module.exports && typeof module.exports === "object") {
          module.exports.__esModule = true;
          Object.defineProperty(module.exports, '__esmShimmed', { value: true });
        }
      }
    } catch (err) {
      delete cache[id];
      throw err;
    } finally {
      restoreModuleId(previousModuleId);
    }
    module.loaded = true;
    return module.exports;
  }
  // Convert a module specifier or id to a numeric module identifier used
  // by runtime capability checks.
  var idToModuleId = function(specifier) {
    var id = typeof specifier === "string" ? specifier : String(specifier || "");
    var moduleId = 0;
    for (var i = 0; i < id.length; i++) {
      moduleId = ((moduleId << 5) - moduleId) + id.charCodeAt(i);
      moduleId = moduleId & moduleId;
    }
    return moduleId < 0 ? -moduleId : moduleId;
  };

  // Helper to grant capabilities from options parameter
  var grantCapabilities = function(specifier, options, moduleId) {
    if (!options || typeof options !== 'object') return;
    var needs = options.needs;
    if (!needs) return;

    var numericModuleId = typeof moduleId === 'number' && isFinite(moduleId) ? moduleId : idToModuleId(specifier);
    if (numericModuleId < 0) {
      numericModuleId = -numericModuleId;
    }

    // Grant capabilities using Exact.setModuleCapabilities
    if (typeof globalThis.Exact === 'object' &&
        typeof globalThis.Exact.setModuleCapabilities === 'function') {
      var caps = Array.isArray(needs) ? needs : [needs];
      globalThis.Exact.setModuleCapabilities(numericModuleId, caps);
    }
  };

  globalThis.require = function(specifier, options) {
    // Grant capabilities if provided
    grantCapabilities(specifier, options, 0);
    return load(specifier, "");
  };
  globalThis.require.cache = cache;
  globalThis.require.resolve = function(specifier) {
    var json = __exactModuleResolve(specifier, "");
    if (!json) {
      throw new Error("Cannot find module '" + specifier + "'");
    }
    var record = JSON.parse(json);
    if (record.error) {
      throw new Error("Cannot find module '" + specifier + "'");
    }
    return record.path || record.id || specifier;
  };
  globalThis.require.resolve.paths = function(specifier) {
    return null;
  };
  Object.defineProperty(globalThis.require, 'main', {
    get: function() { return mainModule; },
    configurable: true,
    enumerable: true
  });
  globalThis.__exactRequire = load;

  // Polyfill dynamic import() using require()
  // import() returns a Promise that resolves to the module
  // ESM default export becomes { default: ... }, named exports are direct properties
  var importImpl = function(specifier, options) {
    return Promise.resolve().then(function() {
      // Grant capabilities if provided
      grantCapabilities(specifier, options);

      var module = load(specifier, "");
      // Wrap CommonJS modules to look like ESM: { default: module, ...module }
      // This allows: const mod = await import('foo'); mod.default or mod.something
      if (module && !module.__esModule) {
        var moduleType = typeof module;
        // Wrap objects and functions
        if (moduleType === 'object' || moduleType === 'function') {
          var wrapped = { default: module };
          // For objects, copy properties to wrapped
          if (moduleType === 'object') {
            for (var key in module) {
              if (module.hasOwnProperty(key)) {
                wrapped[key] = module[key];
              }
            }
          }
          return wrapped;
        }
      }
      return module;
    });
  };

  // Set as globalThis.import (use globalThis.import('foo') or globalThis['import']('foo'))
  if (typeof globalThis.import === 'undefined') {
    Object.defineProperty(globalThis, 'import', {
      value: importImpl,
      writable: false,
      enumerable: false,
      configurable: true
    });
  }

  // Also provide as importModule() for convenience (since import(...) triggers parser)
  globalThis.importModule = importImpl;
})();
)JS";

  try {
    auto buffer = std::make_shared<facebook::jsi::StringBuffer>(loader);
    rt.evaluateJavaScript(buffer, "<module-loader>");
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
  }

  // Expose common globals from modules (Buffer, URL, URLSearchParams, setImmediate, etc.)
  try {
    std::string globals = R"JS(
(function() {
  try {
    var buf = globalThis.require('buffer');
    if (buf && buf.Buffer) {
      globalThis.Buffer = buf.Buffer;
    }
  } catch(e) {}
  try {
    var urlMod = globalThis.require('url');
    if (urlMod) {
      if (urlMod.URL && typeof globalThis.URL === 'undefined') {
        globalThis.URL = urlMod.URL;
      }
      if (urlMod.URLSearchParams && typeof globalThis.URLSearchParams === 'undefined') {
        globalThis.URLSearchParams = urlMod.URLSearchParams;
      }
    }
  } catch(e) {}
  // setImmediate / clearImmediate (Node.js global)
  if (typeof globalThis.setImmediate === 'undefined') {
    globalThis.setImmediate = function(callback) {
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      return globalThis.setTimeout(function() { callback.apply(null, args); }, 0);
    };
    globalThis.clearImmediate = function(handle) {
      globalThis.clearTimeout(handle);
    };
  }
  // AbortController / AbortSignal (Web API)
  if (typeof globalThis.AbortController === 'undefined') {
    function AbortSignal() {
      this.aborted = false;
      this.reason = undefined;
      this._listeners = [];
    }
    AbortSignal.prototype.addEventListener = function(type, listener) {
      if (type === 'abort') this._listeners.push(listener);
    };
    AbortSignal.prototype.removeEventListener = function(type, listener) {
      if (type === 'abort') {
        var idx = this._listeners.indexOf(listener);
        if (idx !== -1) this._listeners.splice(idx, 1);
      }
    };
    AbortSignal.prototype.throwIfAborted = function() {
      if (this.aborted) throw this.reason;
    };
    AbortSignal.abort = function(reason) {
      var s = new AbortSignal();
      s.aborted = true;
      s.reason = reason !== undefined ? reason : new DOMException('The operation was aborted.', 'AbortError');
      return s;
    };
    AbortSignal.timeout = function(ms) {
      var s = new AbortSignal();
      globalThis.setTimeout(function() {
        s.aborted = true;
        s.reason = new DOMException('The operation was aborted due to timeout.', 'TimeoutError');
        for (var i = 0; i < s._listeners.length; i++) {
          try { s._listeners[i]({ type: 'abort', target: s }); } catch(e) {}
        }
      }, ms);
      return s;
    };
    function AbortController() {
      this.signal = new AbortSignal();
    }
    AbortController.prototype.abort = function(reason) {
      if (this.signal.aborted) return;
      this.signal.aborted = true;
      this.signal.reason = reason !== undefined ? reason : new DOMException('The operation was aborted.', 'AbortError');
      var listeners = this.signal._listeners.slice();
      for (var i = 0; i < listeners.length; i++) {
        try { listeners[i]({ type: 'abort', target: this.signal }); } catch(e) {}
      }
    };
    globalThis.AbortController = AbortController;
    globalThis.AbortSignal = AbortSignal;
  }
  // DOMException polyfill (if not available)
  if (typeof globalThis.DOMException === 'undefined') {
    function DOMException(message, name) {
      this.message = message || '';
      this.name = name || 'Error';
    }
    DOMException.prototype = Object.create(Error.prototype);
    DOMException.prototype.constructor = DOMException;
    globalThis.DOMException = DOMException;
  }
  // structuredClone (Web API)
  if (typeof globalThis.structuredClone === 'undefined') {
    globalThis.structuredClone = function(value) {
      return JSON.parse(JSON.stringify(value));
    };
  }
  // performance (Web API) — use perf_hooks if available
  if (typeof globalThis.performance === 'undefined') {
    var _perfStart = Date.now();
    globalThis.performance = {
      now: function() {
        if (typeof __exactHrtime === 'function') {
          var parts = __exactHrtime();
          if (typeof parts === 'string') {
            var p = parts.split(',');
            return (parseInt(p[0], 10) * 1000) + (parseInt(p[1], 10) / 1000000);
          }
        }
        return Date.now() - _perfStart;
      },
      timeOrigin: _perfStart,
      mark: function() {},
      measure: function() {},
      getEntries: function() { return []; },
      getEntriesByName: function() { return []; },
      getEntriesByType: function() { return []; },
      clearMarks: function() {},
      clearMeasures: function() {}
    };
  }
  // Event / EventTarget / CustomEvent (Web API)
  if (typeof globalThis.EventTarget === 'undefined') {
    function EventTarget() {
      this._listeners = {};
    }
    EventTarget.prototype.addEventListener = function(type, listener, options) {
      if (!this._listeners[type]) this._listeners[type] = [];
      this._listeners[type].push({ fn: listener, once: options && options.once });
    };
    EventTarget.prototype.removeEventListener = function(type, listener) {
      if (!this._listeners[type]) return;
      this._listeners[type] = this._listeners[type].filter(function(l) { return l.fn !== listener; });
    };
    EventTarget.prototype.dispatchEvent = function(event) {
      if (!event || !event.type) return true;
      var listeners = this._listeners[event.type];
      if (!listeners) return true;
      event.target = this;
      event.currentTarget = this;
      var toRemove = [];
      for (var i = 0; i < listeners.length; i++) {
        try { listeners[i].fn.call(this, event); } catch(e) {}
        if (listeners[i].once) toRemove.push(i);
      }
      for (var j = toRemove.length - 1; j >= 0; j--) {
        listeners.splice(toRemove[j], 1);
      }
      return !event.defaultPrevented;
    };
    globalThis.EventTarget = EventTarget;
  }
  if (typeof globalThis.Event === 'undefined') {
    function Event(type, options) {
      this.type = type;
      this.bubbles = (options && options.bubbles) || false;
      this.cancelable = (options && options.cancelable) || false;
      this.composed = (options && options.composed) || false;
      this.defaultPrevented = false;
      this.target = null;
      this.currentTarget = null;
      this.timeStamp = Date.now();
    }
    Event.prototype.preventDefault = function() {
      if (this.cancelable) this.defaultPrevented = true;
    };
    Event.prototype.stopPropagation = function() {};
    Event.prototype.stopImmediatePropagation = function() {};
    globalThis.Event = Event;
  }
  if (typeof globalThis.CustomEvent === 'undefined') {
    function CustomEvent(type, options) {
      Event.call(this, type, options);
      this.detail = (options && options.detail) || null;
    }
    CustomEvent.prototype = Object.create(Event.prototype);
    CustomEvent.prototype.constructor = CustomEvent;
    globalThis.CustomEvent = CustomEvent;
  }
  // Blob (Web API)
  if (typeof globalThis.Blob === 'undefined') {
    function Blob(parts, options) {
      this._parts = parts || [];
      this.type = (options && options.type) || '';
      var totalSize = 0;
      for (var i = 0; i < this._parts.length; i++) {
        var part = this._parts[i];
        if (typeof part === 'string') totalSize += part.length;
        else if (part instanceof Uint8Array) totalSize += part.length;
        else if (part instanceof ArrayBuffer) totalSize += part.byteLength;
        else if (part && part._parts) totalSize += part.size;
        else totalSize += String(part).length;
      }
      this.size = totalSize;
    }
    Blob.prototype.text = function() {
      var result = '';
      for (var i = 0; i < this._parts.length; i++) {
        var part = this._parts[i];
        if (typeof part === 'string') result += part;
        else if (part instanceof Uint8Array) {
          for (var j = 0; j < part.length; j++) result += String.fromCharCode(part[j]);
        } else result += String(part);
      }
      return Promise.resolve(result);
    };
    Blob.prototype.arrayBuffer = function() {
      var self = this;
      return this.text().then(function(text) {
        var buf = new Uint8Array(text.length);
        for (var i = 0; i < text.length; i++) buf[i] = text.charCodeAt(i);
        return buf.buffer;
      });
    };
    Blob.prototype.slice = function(start, end, contentType) {
      return this.text().then(function(text) {
        return new Blob([text.slice(start, end)], { type: contentType || '' });
      });
    };
    Blob.prototype.stream = function() { return null; };
    globalThis.Blob = Blob;

    // File extends Blob
    function File(parts, name, options) {
      Blob.call(this, parts, options);
      this.name = name;
      this.lastModified = (options && options.lastModified) || Date.now();
    }
    File.prototype = Object.create(Blob.prototype);
    File.prototype.constructor = File;
    globalThis.File = File;
  }
})();
)JS";
    auto globalsBuf = std::make_shared<facebook::jsi::StringBuffer>(globals);
    rt.evaluateJavaScript(globalsBuf, "<bootstrap>");
  } catch (...) {}
}

// Native StringBuffer for O(1) amortized string append (avoids O(n^2) JS string concatenation)
class StringBufferHostObject : public facebook::jsi::HostObject {
public:
  std::string buffer;

  facebook::jsi::Value get(facebook::jsi::Runtime& rt, const facebook::jsi::PropNameID& name) override {
    auto propName = name.utf8(rt);
    if (propName == "append") {
      return facebook::jsi::Function::createFromHostFunction(rt, name, 1,
          [this](facebook::jsi::Runtime& rt, const facebook::jsi::Value&,
                 const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
            if (count > 0) {
              buffer += args[0].asString(rt).utf8(rt);
            }
            return facebook::jsi::Value::undefined();
          });
    }
    if (propName == "toString") {
      return facebook::jsi::Function::createFromHostFunction(rt, name, 0,
          [this](facebook::jsi::Runtime& rt, const facebook::jsi::Value&,
                 const facebook::jsi::Value*, size_t) -> facebook::jsi::Value {
            return facebook::jsi::String::createFromUtf8(rt, buffer);
          });
    }
    if (propName == "length") {
      return facebook::jsi::Value(static_cast<int>(buffer.size()));
    }
    if (propName == "clear") {
      return facebook::jsi::Function::createFromHostFunction(rt, name, 0,
          [this](facebook::jsi::Runtime&, const facebook::jsi::Value&,
                 const facebook::jsi::Value*, size_t) -> facebook::jsi::Value {
            buffer.clear();
            return facebook::jsi::Value::undefined();
          });
    }
    if (propName == "reserve") {
      return facebook::jsi::Function::createFromHostFunction(rt, name, 1,
          [this](facebook::jsi::Runtime&, const facebook::jsi::Value&,
                 const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
            if (count > 0) {
              buffer.reserve(static_cast<size_t>(args[0].asNumber()));
            }
            return facebook::jsi::Value::undefined();
          });
    }
    return facebook::jsi::Value::undefined();
  }

  void set(facebook::jsi::Runtime&, const facebook::jsi::PropNameID&, const facebook::jsi::Value&) override {}

  std::vector<facebook::jsi::PropNameID> getPropertyNames(facebook::jsi::Runtime& rt) override {
    std::vector<facebook::jsi::PropNameID> props;
    props.push_back(facebook::jsi::PropNameID::forAscii(rt, "append"));
    props.push_back(facebook::jsi::PropNameID::forAscii(rt, "toString"));
    props.push_back(facebook::jsi::PropNameID::forAscii(rt, "length"));
    props.push_back(facebook::jsi::PropNameID::forAscii(rt, "clear"));
    props.push_back(facebook::jsi::PropNameID::forAscii(rt, "reserve"));
    return props;
  }
};

void installGlobals(struct ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  auto printFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "print"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        std::string message;
        for (size_t i = 0; i < count; ++i) {
          if (i > 0) {
            message += " ";
          }
          message += valueToString(runtime, args[i]);
        }
        ex_host_console_log(0, message.c_str());
        return facebook::jsi::Value::undefined();
      });

  rt.global().setProperty(rt, "print", std::move(printFn));

  facebook::jsi::Object console(rt);
  console.setProperty(rt, "log", makeLogFunction(rt, 0));
  console.setProperty(rt, "info", makeLogFunction(rt, 0));
  console.setProperty(rt, "debug", makeLogFunction(rt, 0));
  console.setProperty(rt, "error", makeLogFunction(rt, 1));
  console.setProperty(rt, "warn", makeLogFunction(rt, 1));
  console.setProperty(rt, "trace", makeLogFunction(rt, 0));
  console.setProperty(rt, "dir", makeLogFunction(rt, 0));
  rt.global().setProperty(rt, "console", std::move(console));

  // Enhance console with time/count/group/table/assert/clear via JS
  try {
    std::string consoleEnhance = R"JS(
(function() {
  var _times = {};
  var _counts = {};
  var _groupDepth = 0;
  var _origLog = console.log;
  var _origError = console.error;

  console.time = function(label) {
    _times[label || 'default'] = Date.now();
  };
  console.timeEnd = function(label) {
    label = label || 'default';
    var start = _times[label];
    if (start !== undefined) {
      _origLog.call(console, label + ': ' + (Date.now() - start) + 'ms');
      delete _times[label];
    }
  };
  console.timeLog = function(label) {
    label = label || 'default';
    var start = _times[label];
    if (start !== undefined) {
      var args = [label + ': ' + (Date.now() - start) + 'ms'];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      _origLog.apply(console, args);
    }
  };
  console.count = function(label) {
    label = label || 'default';
    _counts[label] = (_counts[label] || 0) + 1;
    _origLog.call(console, label + ': ' + _counts[label]);
  };
  console.countReset = function(label) {
    _counts[label || 'default'] = 0;
  };
  console.group = function() {
    _groupDepth++;
    if (arguments.length > 0) _origLog.apply(console, arguments);
  };
  console.groupCollapsed = console.group;
  console.groupEnd = function() {
    if (_groupDepth > 0) _groupDepth--;
  };
  console.table = function(data) {
    if (Array.isArray(data)) {
      _origLog.call(console, '(index) | Value');
      for (var i = 0; i < data.length; i++) {
        if (typeof data[i] === 'object' && data[i] !== null) {
          var keys = Object.keys(data[i]);
          var parts = [];
          for (var k = 0; k < keys.length; k++) parts.push(keys[k] + ': ' + data[i][keys[k]]);
          _origLog.call(console, i + '       | { ' + parts.join(', ') + ' }');
        } else {
          _origLog.call(console, i + '       | ' + data[i]);
        }
      }
    } else if (typeof data === 'object' && data !== null) {
      var objKeys = Object.keys(data);
      for (var j = 0; j < objKeys.length; j++) {
        _origLog.call(console, objKeys[j] + ': ' + data[objKeys[j]]);
      }
    } else {
      _origLog.call(console, data);
    }
  };
  console.assert = function(condition) {
    if (!condition) {
      var args = Array.prototype.slice.call(arguments, 1);
      if (args.length === 0) args = ['Assertion failed'];
      else args[0] = 'Assertion failed: ' + args[0];
      _origError.apply(console, args);
    }
  };
  console.clear = function() {};
})();
)JS";
    auto enhBuf = std::make_shared<facebook::jsi::StringBuffer>(consoleEnhance);
    rt.evaluateJavaScript(enhBuf, "<console>");
  } catch (...) {}

  auto setTimeoutFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "setTimeout"),
      2,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() ||
            !args[0].asObject(runtime).isFunction(runtime)) {
          return facebook::jsi::Value::undefined();
        }
        auto callback = args[0].asObject(runtime).asFunction(runtime);
        uint64_t delay = 0;
        if (count > 1 && args[1].isNumber()) {
          delay = static_cast<uint64_t>(args[1].asNumber());
        }
        uint64_t id = handle->next_timer_id++;
        TimerEntry entry{
            id,
            nowMs() + delay,
            delay,
            false,
            std::move(callback),
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
        if (count == 0 || !args[0].isObject() ||
            !args[0].asObject(runtime).isFunction(runtime)) {
          return facebook::jsi::Value::undefined();
        }
        auto callback = args[0].asObject(runtime).asFunction(runtime);
        uint64_t delay = 0;
        if (count > 1 && args[1].isNumber()) {
          delay = static_cast<uint64_t>(args[1].asNumber());
        }
        uint64_t id = handle->next_timer_id++;
        TimerEntry entry{
            id,
            nowMs() + delay,
            delay,
            true,
            std::move(callback),
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
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() ||
            !args[0].asObject(runtime).isFunction(runtime)) {
          return facebook::jsi::Value::undefined();
        }
        auto callback = args[0].asObject(runtime).asFunction(runtime);
        runtime.queueMicrotask(callback);
        return facebook::jsi::Value::undefined();
      });

  rt.global().setProperty(rt, "setTimeout", std::move(setTimeoutFn));
  rt.global().setProperty(rt, "clearTimeout", std::move(clearTimeoutFn));
  rt.global().setProperty(rt, "setInterval", std::move(setIntervalFn));
  rt.global().setProperty(rt, "clearInterval", std::move(clearIntervalFn));
  rt.global().setProperty(rt, "queueMicrotask", std::move(queueMicrotaskFn));

  auto capabilityCheckFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactCapabilityCheck"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          return facebook::jsi::Value(false);
        }
        auto cap = args[0].toString(runtime).utf8(runtime);
        return facebook::jsi::Value(checkCapability(cap));
      });
  rt.global().setProperty(rt, "__exactCapabilityCheck", std::move(capabilityCheckFn));

  auto getEnvFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetEnv"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          return facebook::jsi::Value::undefined();
        }
        auto key = args[0].toString(runtime).utf8(runtime);
        std::string cap = "env:read:" + key;
        if (!checkCapability(cap)) {
          return facebook::jsi::Value::undefined();
        }
        auto value = getEnvValue(key);
        if (value.empty()) {
          return facebook::jsi::Value::undefined();
        }
        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, value));
      });
  rt.global().setProperty(rt, "__exactGetEnv", std::move(getEnvFn));

  auto getAllEnvFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetAllEnv"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        facebook::jsi::Object env(runtime);
        if (!checkCapability("env:read:*")) {
          return env;
        }
#if defined(__APPLE__)
        char **envp = *_NSGetEnviron();
#else
        extern char **environ;
        char **envp = environ;
#endif
        if (envp) {
          for (char **ep = envp; *ep; ++ep) {
            std::string entry(*ep);
            auto eq = entry.find('=');
            if (eq != std::string::npos) {
              auto key = entry.substr(0, eq);
              auto val = entry.substr(eq + 1);
              env.setProperty(runtime,
                facebook::jsi::PropNameID::forUtf8(runtime, key),
                facebook::jsi::String::createFromUtf8(runtime, val));
            }
          }
        }
        return env;
      });
  rt.global().setProperty(rt, "__exactGetAllEnv", std::move(getAllEnvFn));

  auto setActiveModuleIdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSetActiveModuleId"),
      1,
      [](facebook::jsi::Runtime&,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        auto previous = g_active_module_id;
        if (count > 0 && args[0].isNumber()) {
          auto next = args[0].asNumber();
          g_active_module_id = next < 0.0 ? 0 : static_cast<uint64_t>(next);
        } else {
          g_active_module_id = 0;
        }
        return facebook::jsi::Value(static_cast<double>(previous));
      });
  rt.global().setProperty(rt, "__exactSetActiveModuleId", std::move(setActiveModuleIdFn));

  auto getCwdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetCwd"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        char buffer[4096];
        if (getcwd(buffer, sizeof(buffer)) == nullptr) {
          return facebook::jsi::Value::undefined();
        }
        return facebook::jsi::Value(
          facebook::jsi::String::createFromUtf8(runtime, buffer));
      });
  rt.global().setProperty(rt, "__exactGetCwd", std::move(getCwdFn));

  auto setCwdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSetCwd"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(
              runtime,
              "process.chdir() expected path string");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (chdir(path.c_str()) != 0) {
          throw facebook::jsi::JSError(
              runtime,
              "Failed to change directory: " + std::string(strerror(errno)));
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSetCwd", std::move(setCwdFn));

  // --- OS info native functions ---

  // __exactGetHostname() -> string
  auto getHostnameFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetHostname"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) != 0) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "localhost"));
        }
        hostname[sizeof(hostname) - 1] = '\0';
        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, hostname));
      });
  rt.global().setProperty(rt, "__exactGetHostname", std::move(getHostnameFn));

  // __exactGetCpuCount() -> number
  auto getCpuCountFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetCpuCount"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
#if defined(__APPLE__)
        int cpuCount = 0;
        size_t cpuSize = sizeof(cpuCount);
        if (sysctlbyname("hw.ncpu", &cpuCount, &cpuSize, nullptr, 0) == 0) {
          return facebook::jsi::Value(static_cast<double>(cpuCount));
        }
        return facebook::jsi::Value(1.0);
#else
        long cpuCount = sysconf(_SC_NPROCESSORS_ONLN);
        if (cpuCount < 1) cpuCount = 1;
        return facebook::jsi::Value(static_cast<double>(cpuCount));
#endif
      });
  rt.global().setProperty(rt, "__exactGetCpuCount", std::move(getCpuCountFn));

  // __exactGetTotalMem() -> number (bytes)
  auto getTotalMemFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetTotalMem"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
#if defined(__APPLE__)
        uint64_t memsize = 0;
        size_t memSizeLen = sizeof(memsize);
        if (sysctlbyname("hw.memsize", &memsize, &memSizeLen, nullptr, 0) == 0) {
          return facebook::jsi::Value(static_cast<double>(memsize));
        }
        return facebook::jsi::Value(0.0);
#else
        long pages = sysconf(_SC_PHYS_PAGES);
        long pageSize = sysconf(_SC_PAGESIZE);
        if (pages > 0 && pageSize > 0) {
          return facebook::jsi::Value(static_cast<double>(pages) * static_cast<double>(pageSize));
        }
        return facebook::jsi::Value(0.0);
#endif
      });
  rt.global().setProperty(rt, "__exactGetTotalMem", std::move(getTotalMemFn));

  // __exactGetFreeMem() -> number (bytes)
  auto getFreeMemFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetFreeMem"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
#if defined(__APPLE__)
        vm_size_t vmPageSize;
        mach_msg_type_number_t vmCount = HOST_VM_INFO_COUNT;
        vm_statistics_data_t vmStats;
        if (host_page_size(mach_host_self(), &vmPageSize) == KERN_SUCCESS &&
            host_statistics(mach_host_self(), HOST_VM_INFO,
                           reinterpret_cast<host_info_t>(&vmStats), &vmCount) == KERN_SUCCESS) {
          uint64_t freeMem = static_cast<uint64_t>(vmStats.free_count) * static_cast<uint64_t>(vmPageSize);
          return facebook::jsi::Value(static_cast<double>(freeMem));
        }
        return facebook::jsi::Value(0.0);
#else
        long pages = sysconf(_SC_AVPHYS_PAGES);
        long pageSize = sysconf(_SC_PAGESIZE);
        if (pages > 0 && pageSize > 0) {
          return facebook::jsi::Value(static_cast<double>(pages) * static_cast<double>(pageSize));
        }
        return facebook::jsi::Value(0.0);
#endif
      });
  rt.global().setProperty(rt, "__exactGetFreeMem", std::move(getFreeMemFn));

  // __exactGetUptime() -> number (seconds)
  auto getUptimeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetUptime"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
#if defined(__APPLE__)
        struct timeval boottime;
        size_t btSize = sizeof(boottime);
        int mib[2] = { CTL_KERN, KERN_BOOTTIME };
        if (sysctl(mib, 2, &boottime, &btSize, nullptr, 0) == 0) {
          struct timeval now;
          gettimeofday(&now, nullptr);
          double uptime = static_cast<double>(now.tv_sec - boottime.tv_sec) +
                          static_cast<double>(now.tv_usec - boottime.tv_usec) / 1000000.0;
          return facebook::jsi::Value(uptime);
        }
        return facebook::jsi::Value(0.0);
#else
        struct sysinfo sysInfo;
        if (sysinfo(&sysInfo) == 0) {
          return facebook::jsi::Value(static_cast<double>(sysInfo.uptime));
        }
        return facebook::jsi::Value(0.0);
#endif
      });
  rt.global().setProperty(rt, "__exactGetUptime", std::move(getUptimeFn));

  // __exactGetUserInfo() -> object { uid, gid, username, homedir, shell }
  auto getUserInfoFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetUserInfo"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        facebook::jsi::Object info(runtime);
        uid_t uid = getuid();
        gid_t gid = getgid();
        info.setProperty(runtime, "uid", facebook::jsi::Value(static_cast<double>(uid)));
        info.setProperty(runtime, "gid", facebook::jsi::Value(static_cast<double>(gid)));

        struct passwd* pw = getpwuid(uid);
        if (pw) {
          if (pw->pw_name) {
            info.setProperty(runtime, "username",
                facebook::jsi::String::createFromUtf8(runtime, pw->pw_name));
          } else {
            info.setProperty(runtime, "username",
                facebook::jsi::String::createFromUtf8(runtime, ""));
          }
          if (pw->pw_dir) {
            info.setProperty(runtime, "homedir",
                facebook::jsi::String::createFromUtf8(runtime, pw->pw_dir));
          } else {
            info.setProperty(runtime, "homedir",
                facebook::jsi::String::createFromUtf8(runtime, "/"));
          }
          if (pw->pw_shell) {
            info.setProperty(runtime, "shell",
                facebook::jsi::String::createFromUtf8(runtime, pw->pw_shell));
          } else {
            info.setProperty(runtime, "shell", facebook::jsi::Value::null());
          }
        } else {
          info.setProperty(runtime, "username",
              facebook::jsi::String::createFromUtf8(runtime, ""));
          info.setProperty(runtime, "homedir",
              facebook::jsi::String::createFromUtf8(runtime, "/"));
          info.setProperty(runtime, "shell", facebook::jsi::Value::null());
        }
        return info;
      });
  rt.global().setProperty(rt, "__exactGetUserInfo", std::move(getUserInfoFn));

  // __exactGetLoadAvg() -> array [1min, 5min, 15min]
  auto getLoadAvgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetLoadAvg"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        double loadavgArr[3] = {0.0, 0.0, 0.0};
        getloadavg(loadavgArr, 3);
        auto arr = facebook::jsi::Array(runtime, 3);
        arr.setValueAtIndex(runtime, 0, facebook::jsi::Value(loadavgArr[0]));
        arr.setValueAtIndex(runtime, 1, facebook::jsi::Value(loadavgArr[1]));
        arr.setValueAtIndex(runtime, 2, facebook::jsi::Value(loadavgArr[2]));
        return arr;
      });
  rt.global().setProperty(rt, "__exactGetLoadAvg", std::move(getLoadAvgFn));

  // __exactGetNetworkInterfaces() -> object { name: [{address,netmask,family,mac,internal,cidr}] }
  auto getNetIfsFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetNetworkInterfaces"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        auto result = facebook::jsi::Object(runtime);
        struct ifaddrs* ifaddr = nullptr;
        if (getifaddrs(&ifaddr) == -1) {
          return result;
        }
        // First pass: count entries per interface name
        std::unordered_map<std::string, std::vector<struct ifaddrs*>> ifmap;
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
          if (ifa->ifa_addr == nullptr) continue;
          int family = ifa->ifa_addr->sa_family;
          if (family != AF_INET && family != AF_INET6) continue;
          ifmap[ifa->ifa_name].push_back(ifa);
        }
        // Second pass: build result object
        for (auto& [name, entries] : ifmap) {
          auto arr = facebook::jsi::Array(runtime, entries.size());
          for (size_t i = 0; i < entries.size(); i++) {
            struct ifaddrs* ifa = entries[i];
            auto entry = facebook::jsi::Object(runtime);
            char addrBuf[INET6_ADDRSTRLEN] = {0};
            char maskBuf[INET6_ADDRSTRLEN] = {0};
            int family = ifa->ifa_addr->sa_family;
            int prefixLen = 0;
            if (family == AF_INET) {
              auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
              inet_ntop(AF_INET, &sin->sin_addr, addrBuf, sizeof(addrBuf));
              if (ifa->ifa_netmask) {
                auto* mask = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_netmask);
                inet_ntop(AF_INET, &mask->sin_addr, maskBuf, sizeof(maskBuf));
                uint32_t m = ntohl(mask->sin_addr.s_addr);
                while (m & 0x80000000) { prefixLen++; m <<= 1; }
              }
              entry.setProperty(runtime, "family", facebook::jsi::String::createFromAscii(runtime, "IPv4"));
            } else {
              auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
              inet_ntop(AF_INET6, &sin6->sin6_addr, addrBuf, sizeof(addrBuf));
              if (ifa->ifa_netmask) {
                auto* mask6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_netmask);
                inet_ntop(AF_INET6, &mask6->sin6_addr, maskBuf, sizeof(maskBuf));
                for (int b = 0; b < 16; b++) {
                  uint8_t byte = mask6->sin6_addr.s6_addr[b];
                  while (byte & 0x80) { prefixLen++; byte <<= 1; }
                  if (byte == 0 && mask6->sin6_addr.s6_addr[b] != 0xff) break;
                }
              }
              entry.setProperty(runtime, "family", facebook::jsi::String::createFromAscii(runtime, "IPv6"));
            }
            entry.setProperty(runtime, "address", facebook::jsi::String::createFromAscii(runtime, addrBuf));
            entry.setProperty(runtime, "netmask", facebook::jsi::String::createFromAscii(runtime, maskBuf));
            bool isInternal = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
            entry.setProperty(runtime, "internal", facebook::jsi::Value(isInternal));
            entry.setProperty(runtime, "mac", facebook::jsi::String::createFromAscii(runtime, "00:00:00:00:00:00"));
            // CIDR notation
            std::string cidr = std::string(addrBuf) + "/" + std::to_string(prefixLen);
            entry.setProperty(runtime, "cidr", facebook::jsi::String::createFromAscii(runtime, cidr));
            arr.setValueAtIndex(runtime, i, std::move(entry));
          }
          result.setProperty(runtime, facebook::jsi::String::createFromAscii(runtime, name), std::move(arr));
        }
        freeifaddrs(ifaddr);
        return result;
      });
  rt.global().setProperty(rt, "__exactGetNetworkInterfaces", std::move(getNetIfsFn));

  // --- End OS info native functions ---

  // --- Crypto: sync hash ---
  // __exactHashSync(algorithm, data) -> hex string
  auto hashSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHashSync"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactHashSync: algorithm and data required");
        }
        auto algo = args[0].asString(runtime).utf8(runtime);

        // Get input data as bytes
        std::vector<uint8_t> inputBytes;
        if (args[1].isString()) {
          auto str = args[1].asString(runtime).utf8(runtime);
          inputBytes.assign(str.begin(), str.end());
        } else if (args[1].isObject()) {
          auto obj = args[1].asObject(runtime);
          if (obj.isArrayBuffer(runtime)) {
            auto buf = obj.getArrayBuffer(runtime);
            inputBytes.assign(buf.data(runtime), buf.data(runtime) + buf.size(runtime));
          } else {
            // Try as Uint8Array via __inner
            auto str = args[1].asString(runtime).utf8(runtime);
            inputBytes.assign(str.begin(), str.end());
          }
        }

        std::vector<uint8_t> digest;
#if defined(__APPLE__)
        if (algo == "sha256" || algo == "sha-256") {
          digest.resize(CC_SHA256_DIGEST_LENGTH);
          CC_SHA256(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha1" || algo == "sha-1") {
          digest.resize(CC_SHA1_DIGEST_LENGTH);
          CC_SHA1(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha384" || algo == "sha-384") {
          digest.resize(CC_SHA384_DIGEST_LENGTH);
          CC_SHA384(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha512" || algo == "sha-512") {
          digest.resize(CC_SHA512_DIGEST_LENGTH);
          CC_SHA512(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "md5") {
#if !defined(EXACT_NO_OPENSSL)
          // Use OpenSSL for MD5 — CommonCrypto's CC_MD5 is deprecated
          unsigned int md5Len = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &md5Len, EVP_md5(), nullptr);
          digest.resize(md5Len);
#else
          // Fallback to CommonCrypto CC_MD5 (deprecated but functional)
          digest.resize(CC_MD5_DIGEST_LENGTH);
          CC_MD5(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
#endif
        } else {
          throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algo);
        }
#else
        const EVP_MD* md = nullptr;
        if (algo == "sha256" || algo == "sha-256") md = EVP_sha256();
        else if (algo == "sha1" || algo == "sha-1") md = EVP_sha1();
        else if (algo == "sha384" || algo == "sha-384") md = EVP_sha384();
        else if (algo == "sha512" || algo == "sha-512") md = EVP_sha512();
        else if (algo == "md5") md = EVP_md5();
        else throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algo);

        unsigned int digestLen = 0;
        digest.resize(EVP_MAX_MD_SIZE);
        EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, md, nullptr);
        digest.resize(digestLen);
#endif

        // Convert to hex string
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (auto b : digest) {
          hex << std::setw(2) << static_cast<int>(b);
        }
        return facebook::jsi::String::createFromUtf8(runtime, hex.str());
      });
  rt.global().setProperty(rt, "__exactHashSync", std::move(hashSyncFn));

  // __exactHmacSync(algorithm, key, data) -> hex string
  auto hmacSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHmacSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactHmacSync: algorithm, key, and data required");
        }
        auto algo = args[0].asString(runtime).utf8(runtime);

        // Get key bytes
        std::vector<uint8_t> keyBytes;
        if (args[1].isString()) {
          auto str = args[1].asString(runtime).utf8(runtime);
          keyBytes.assign(str.begin(), str.end());
        }

        // Get data bytes
        std::vector<uint8_t> dataBytes;
        if (args[2].isString()) {
          auto str = args[2].asString(runtime).utf8(runtime);
          dataBytes.assign(str.begin(), str.end());
        }

        std::vector<uint8_t> mac;
#if defined(__APPLE__)
        CCHmacAlgorithm ccAlgo;
        size_t macLen;
        if (algo == "sha256" || algo == "sha-256") {
          ccAlgo = kCCHmacAlgSHA256; macLen = CC_SHA256_DIGEST_LENGTH;
        } else if (algo == "sha1" || algo == "sha-1") {
          ccAlgo = kCCHmacAlgSHA1; macLen = CC_SHA1_DIGEST_LENGTH;
        } else if (algo == "sha384" || algo == "sha-384") {
          ccAlgo = kCCHmacAlgSHA384; macLen = CC_SHA384_DIGEST_LENGTH;
        } else if (algo == "sha512" || algo == "sha-512") {
          ccAlgo = kCCHmacAlgSHA512; macLen = CC_SHA512_DIGEST_LENGTH;
        } else if (algo == "md5") {
          ccAlgo = kCCHmacAlgMD5; macLen = CC_MD5_DIGEST_LENGTH;
        } else {
          throw facebook::jsi::JSError(runtime, "Unsupported HMAC algorithm: " + algo);
        }
        mac.resize(macLen);
        CCHmac(ccAlgo, keyBytes.data(), keyBytes.size(),
               dataBytes.data(), dataBytes.size(), mac.data());
#else
        const EVP_MD* md = nullptr;
        if (algo == "sha256" || algo == "sha-256") md = EVP_sha256();
        else if (algo == "sha1" || algo == "sha-1") md = EVP_sha1();
        else if (algo == "sha384" || algo == "sha-384") md = EVP_sha384();
        else if (algo == "sha512" || algo == "sha-512") md = EVP_sha512();
        else if (algo == "md5") md = EVP_md5();
        else throw facebook::jsi::JSError(runtime, "Unsupported HMAC algorithm: " + algo);

        unsigned int macLen = 0;
        mac.resize(EVP_MAX_MD_SIZE);
        HMAC(md, keyBytes.data(), keyBytes.size(),
             dataBytes.data(), dataBytes.size(), mac.data(), &macLen);
        mac.resize(macLen);
#endif

        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (auto b : mac) {
          hex << std::setw(2) << static_cast<int>(b);
        }
        return facebook::jsi::String::createFromUtf8(runtime, hex.str());
      });
  rt.global().setProperty(rt, "__exactHmacSync", std::move(hmacSyncFn));

  // __exactHashRaw(algorithm, data) -> Uint8Array (raw bytes, not hex)
  auto hashRawFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHashRaw"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactHashRaw: algorithm and data required");
        }
        auto algo = args[0].asString(runtime).utf8(runtime);
        std::vector<uint8_t> inputBytes;
        if (args[1].isString()) {
          auto str = args[1].asString(runtime).utf8(runtime);
          inputBytes.assign(str.begin(), str.end());
        }

        std::vector<uint8_t> digest;
#if defined(__APPLE__)
        if (algo == "sha256" || algo == "sha-256") {
          digest.resize(CC_SHA256_DIGEST_LENGTH);
          CC_SHA256(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha1" || algo == "sha-1") {
          digest.resize(CC_SHA1_DIGEST_LENGTH);
          CC_SHA1(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha384" || algo == "sha-384") {
          digest.resize(CC_SHA384_DIGEST_LENGTH);
          CC_SHA384(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "sha512" || algo == "sha-512") {
          digest.resize(CC_SHA512_DIGEST_LENGTH);
          CC_SHA512(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
        } else if (algo == "md5") {
#if !defined(EXACT_NO_OPENSSL)
          // Use OpenSSL for MD5 — CommonCrypto's CC_MD5 is deprecated
          unsigned int md5Len = 0;
          digest.resize(EVP_MAX_MD_SIZE);
          EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &md5Len, EVP_md5(), nullptr);
          digest.resize(md5Len);
#else
          // Fallback to CommonCrypto CC_MD5 (deprecated but functional)
          digest.resize(CC_MD5_DIGEST_LENGTH);
          CC_MD5(inputBytes.data(), static_cast<CC_LONG>(inputBytes.size()), digest.data());
#endif
        } else {
          throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algo);
        }
#else
        const EVP_MD* md = nullptr;
        if (algo == "sha256" || algo == "sha-256") md = EVP_sha256();
        else if (algo == "sha1" || algo == "sha-1") md = EVP_sha1();
        else if (algo == "sha384" || algo == "sha-384") md = EVP_sha384();
        else if (algo == "sha512" || algo == "sha-512") md = EVP_sha512();
        else if (algo == "md5") md = EVP_md5();
        else throw facebook::jsi::JSError(runtime, "Unsupported hash algorithm: " + algo);

        unsigned int digestLen = 0;
        digest.resize(EVP_MAX_MD_SIZE);
        EVP_Digest(inputBytes.data(), inputBytes.size(), digest.data(), &digestLen, md, nullptr);
        digest.resize(digestLen);
#endif
        return makeUint8Array(runtime, std::move(digest));
      });
  rt.global().setProperty(rt, "__exactHashRaw", std::move(hashRawFn));

  // --- SubtleCrypto: AES-CBC encrypt/decrypt ---
  // __exactAesCbcEncrypt(key, iv, data) -> Uint8Array (ciphertext with PKCS7 padding)
  auto aesCbcEncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesCbcEncrypt"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) throw facebook::jsi::JSError(runtime, "key, iv, data required");
        auto keyBytes = extractBytes(runtime, args[0]);
        auto ivBytes = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);
        if (keyBytes.size() != 16 && keyBytes.size() != 24 && keyBytes.size() != 32) {
          throw facebook::jsi::JSError(runtime, "AES key must be 128, 192, or 256 bits");
        }
        if (ivBytes.size() != 16) {
          throw facebook::jsi::JSError(runtime, "AES-CBC IV must be 16 bytes");
        }
#if defined(__APPLE__)
        size_t outLen = 0;
        std::vector<uint8_t> out(data.size() + kCCBlockSizeAES128);
        CCCryptorStatus status = CCCrypt(
            kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            keyBytes.data(), keyBytes.size(),
            ivBytes.data(),
            data.data(), data.size(),
            out.data(), out.size(), &outLen);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "AES-CBC encryption failed: " + std::to_string(status));
        }
        out.resize(outLen);
        return makeUint8Array(runtime, std::move(out));
#else
        throw facebook::jsi::JSError(runtime, "AES-CBC not yet supported on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactAesCbcEncrypt", std::move(aesCbcEncFn));

  // __exactAesCbcDecrypt(key, iv, data) -> Uint8Array (plaintext)
  auto aesCbcDecFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesCbcDecrypt"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) throw facebook::jsi::JSError(runtime, "key, iv, data required");
        auto keyBytes = extractBytes(runtime, args[0]);
        auto ivBytes = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);
#if defined(__APPLE__)
        size_t outLen = 0;
        std::vector<uint8_t> out(data.size() + kCCBlockSizeAES128);
        CCCryptorStatus status = CCCrypt(
            kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            keyBytes.data(), keyBytes.size(),
            ivBytes.data(),
            data.data(), data.size(),
            out.data(), out.size(), &outLen);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "AES-CBC decryption failed: " + std::to_string(status));
        }
        out.resize(outLen);
        return makeUint8Array(runtime, std::move(out));
#else
        throw facebook::jsi::JSError(runtime, "AES-CBC not yet supported on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactAesCbcDecrypt", std::move(aesCbcDecFn));

  // __exactAesCtrEncrypt(key, counter, data) -> Uint8Array
  auto aesCtrEncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesCtrEncrypt"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) throw facebook::jsi::JSError(runtime, "key, counter, data required");
        auto keyBytes = extractBytes(runtime, args[0]);
        auto ctrBytes = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);
        if (ctrBytes.size() != 16) {
          throw facebook::jsi::JSError(runtime, "AES-CTR counter must be 16 bytes");
        }
#if defined(__APPLE__)
        // CTR mode: use CCCryptorCreateWithMode
        CCCryptorRef cryptor = nullptr;
        CCCryptorStatus status = CCCryptorCreateWithMode(
            kCCEncrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding,
            ctrBytes.data(), keyBytes.data(), keyBytes.size(),
            nullptr, 0, 0, kCCModeOptionCTR_BE, &cryptor);
        if (status != kCCSuccess || !cryptor) {
          throw facebook::jsi::JSError(runtime, "AES-CTR init failed");
        }
        std::vector<uint8_t> out(data.size());
        size_t outLen = 0;
        status = CCCryptorUpdate(cryptor, data.data(), data.size(), out.data(), out.size(), &outLen);
        CCCryptorRelease(cryptor);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "AES-CTR encryption failed");
        }
        out.resize(outLen);
        return makeUint8Array(runtime, std::move(out));
#else
        throw facebook::jsi::JSError(runtime, "AES-CTR not yet supported on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactAesCtrEncrypt", std::move(aesCtrEncFn));

  // __exactAesGcmEncrypt(key, iv, data, aad, tagLength) -> Uint8Array (ciphertext + tag)
  auto aesGcmEncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesGcmEncrypt"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) throw facebook::jsi::JSError(runtime, "key, iv, data required");
        auto keyBytes = extractBytes(runtime, args[0]);
        auto ivBytes = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);
        std::vector<uint8_t> aad;
        if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
          aad = extractBytes(runtime, args[3]);
        }
        size_t tagLen = 16;
        if (count > 4 && args[4].isNumber()) {
          tagLen = static_cast<size_t>(args[4].asNumber()) / 8; // bits to bytes
        }
#if defined(__APPLE__)
        std::vector<uint8_t> out(data.size());
        std::vector<uint8_t> tag(tagLen);
        CCCryptorStatus status = CCCryptorGCMOneshotEncrypt(
            kCCAlgorithmAES,
            keyBytes.data(), keyBytes.size(),
            ivBytes.data(), ivBytes.size(),
            aad.data(), aad.size(),
            data.data(), data.size(),
            out.data(),
            tag.data(), tagLen);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "AES-GCM encryption failed: " + std::to_string(status));
        }
        // Append tag to ciphertext
        out.insert(out.end(), tag.begin(), tag.end());
        return makeUint8Array(runtime, std::move(out));
#else
        throw facebook::jsi::JSError(runtime, "AES-GCM not yet supported on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactAesGcmEncrypt", std::move(aesGcmEncFn));

  // __exactAesGcmDecrypt(key, iv, data, aad, tagLength) -> Uint8Array (plaintext)
  // data includes the tag appended at the end
  auto aesGcmDecFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAesGcmDecrypt"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) throw facebook::jsi::JSError(runtime, "key, iv, data required");
        auto keyBytes = extractBytes(runtime, args[0]);
        auto ivBytes = extractBytes(runtime, args[1]);
        auto dataWithTag = extractBytes(runtime, args[2]);
        std::vector<uint8_t> aad;
        if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
          aad = extractBytes(runtime, args[3]);
        }
        size_t tagLen = 16;
        if (count > 4 && args[4].isNumber()) {
          tagLen = static_cast<size_t>(args[4].asNumber()) / 8;
        }
        if (dataWithTag.size() < tagLen) {
          throw facebook::jsi::JSError(runtime, "Data too short for GCM tag");
        }
        size_t cipherLen = dataWithTag.size() - tagLen;
#if defined(__APPLE__)
        std::vector<uint8_t> out(cipherLen);
        CCCryptorStatus status = CCCryptorGCMOneshotDecrypt(
            kCCAlgorithmAES,
            keyBytes.data(), keyBytes.size(),
            ivBytes.data(), ivBytes.size(),
            aad.data(), aad.size(),
            dataWithTag.data(), cipherLen,
            out.data(),
            dataWithTag.data() + cipherLen, tagLen);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "AES-GCM decryption failed (auth tag mismatch or invalid data)");
        }
        return makeUint8Array(runtime, std::move(out));
#else
        throw facebook::jsi::JSError(runtime, "AES-GCM not yet supported on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactAesGcmDecrypt", std::move(aesGcmDecFn));

#if !defined(EXACT_NO_OPENSSL)
  // __exactEvpCipherEncrypt(algorithm, key, iv, data) -> Uint8Array
  // Generic EVP cipher encrypt for DES, 3DES, Blowfish, ChaCha20-Poly1305, etc.
  auto evpCipherEncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEvpCipherEncrypt"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4) throw facebook::jsi::JSError(runtime, "algorithm, key, iv, data required");
        auto algo = args[0].asString(runtime).utf8(runtime);
        auto keyBytes = extractBytes(runtime, args[1]);
        auto ivBytes = extractBytes(runtime, args[2]);
        auto data = extractBytes(runtime, args[3]);

        const EVP_CIPHER* cipher = EVP_get_cipherbyname(algo.c_str());
        if (!cipher) {
          throw facebook::jsi::JSError(runtime, "Unsupported cipher: " + algo);
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw facebook::jsi::JSError(runtime, "Failed to create cipher context");

        int outLen = 0;
        int finalLen = 0;
        bool isAEAD = (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0;

        // Output buffer: data + block size + possible tag
        int blockSize = EVP_CIPHER_block_size(cipher);
        std::vector<uint8_t> out(data.size() + blockSize + (isAEAD ? 16 : 0));

        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher init failed");
        }

        // Set key and IV lengths if needed
        if ((int)ivBytes.size() != EVP_CIPHER_CTX_iv_length(ctx)) {
          EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivBytes.size(), nullptr);
        }

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, keyBytes.data(), ivBytes.data()) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher key/iv init failed");
        }

        if (EVP_EncryptUpdate(ctx, out.data(), &outLen, data.data(), data.size()) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher encrypt update failed");
        }

        if (EVP_EncryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher encrypt final failed");
        }

        int totalLen = outLen + finalLen;

        // For AEAD ciphers, append the auth tag
        if (isAEAD) {
          uint8_t tag[16];
          if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "Failed to get auth tag");
          }
          memcpy(out.data() + totalLen, tag, 16);
          totalLen += 16;
        }

        EVP_CIPHER_CTX_free(ctx);
        out.resize(totalLen);
        return makeUint8Array(runtime, std::move(out));
      });
  rt.global().setProperty(rt, "__exactEvpCipherEncrypt", std::move(evpCipherEncFn));
#endif // !EXACT_NO_OPENSSL

#if !defined(EXACT_NO_OPENSSL)
  // __exactEvpCipherDecrypt(algorithm, key, iv, data, authTag?) -> Uint8Array
  // Generic EVP cipher decrypt for DES, 3DES, Blowfish, ChaCha20-Poly1305, etc.
  auto evpCipherDecFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEvpCipherDecrypt"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4) throw facebook::jsi::JSError(runtime, "algorithm, key, iv, data required");
        auto algo = args[0].asString(runtime).utf8(runtime);
        auto keyBytes = extractBytes(runtime, args[1]);
        auto ivBytes = extractBytes(runtime, args[2]);
        auto data = extractBytes(runtime, args[3]);

        const EVP_CIPHER* cipher = EVP_get_cipherbyname(algo.c_str());
        if (!cipher) {
          throw facebook::jsi::JSError(runtime, "Unsupported cipher: " + algo);
        }

        bool isAEAD = (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw facebook::jsi::JSError(runtime, "Failed to create cipher context");

        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher init failed");
        }

        // Set IV length if needed
        if ((int)ivBytes.size() != EVP_CIPHER_CTX_iv_length(ctx)) {
          EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivBytes.size(), nullptr);
        }

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, keyBytes.data(), ivBytes.data()) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher key/iv init failed");
        }

        // For AEAD ciphers, set the auth tag (from arg 4 or last 16 bytes of data)
        if (isAEAD) {
          if (count >= 5 && !args[4].isUndefined() && !args[4].isNull()) {
            auto tag = extractBytes(runtime, args[4]);
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag.size(), tag.data()) != 1) {
              EVP_CIPHER_CTX_free(ctx);
              throw facebook::jsi::JSError(runtime, "Failed to set auth tag");
            }
          } else if (data.size() >= 16) {
            // Tag appended to end of data
            uint8_t tag[16];
            memcpy(tag, data.data() + data.size() - 16, 16);
            data.resize(data.size() - 16);
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1) {
              EVP_CIPHER_CTX_free(ctx);
              throw facebook::jsi::JSError(runtime, "Failed to set auth tag");
            }
          }
        }

        int blockSize = EVP_CIPHER_block_size(cipher);
        std::vector<uint8_t> out(data.size() + blockSize);
        int outLen = 0;
        int finalLen = 0;

        if (EVP_DecryptUpdate(ctx, out.data(), &outLen, data.data(), data.size()) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher decrypt update failed");
        }

        if (EVP_DecryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) {
          EVP_CIPHER_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "Cipher decrypt final failed (auth tag mismatch or bad padding)");
        }

        EVP_CIPHER_CTX_free(ctx);
        out.resize(outLen + finalLen);
        return makeUint8Array(runtime, std::move(out));
      });
  rt.global().setProperty(rt, "__exactEvpCipherDecrypt", std::move(evpCipherDecFn));
#endif // !EXACT_NO_OPENSSL

  // __exactPbkdf2(password, salt, iterations, keyLength, hashAlgo) -> Uint8Array
  auto pbkdf2Fn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactPbkdf2"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 5) throw facebook::jsi::JSError(runtime, "password, salt, iterations, keyLength, hash required");
        auto password = extractBytes(runtime, args[0]);
        auto salt = extractBytes(runtime, args[1]);
        auto iterations = static_cast<unsigned int>(args[2].asNumber());
        auto keyLength = static_cast<size_t>(args[3].asNumber());
        auto hash = args[4].asString(runtime).utf8(runtime);
#if defined(__APPLE__)
        CCPseudoRandomAlgorithm prf;
        if (hash == "SHA-1" || hash == "sha1") prf = kCCPRFHmacAlgSHA1;
        else if (hash == "SHA-256" || hash == "sha256") prf = kCCPRFHmacAlgSHA256;
        else if (hash == "SHA-384" || hash == "sha384") prf = kCCPRFHmacAlgSHA384;
        else if (hash == "SHA-512" || hash == "sha512") prf = kCCPRFHmacAlgSHA512;
        else throw facebook::jsi::JSError(runtime, "Unsupported PBKDF2 hash: " + hash);
        std::vector<uint8_t> derivedKey(keyLength);
        CCCryptorStatus status = CCKeyDerivationPBKDF(
            kCCPBKDF2,
            reinterpret_cast<const char*>(password.data()), password.size(),
            salt.data(), salt.size(),
            prf, iterations,
            derivedKey.data(), keyLength);
        if (status != kCCSuccess) {
          throw facebook::jsi::JSError(runtime, "PBKDF2 derivation failed");
        }
        return makeUint8Array(runtime, std::move(derivedKey));
#else
        throw facebook::jsi::JSError(runtime, "PBKDF2 not yet supported on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactPbkdf2", std::move(pbkdf2Fn));

  // __exactScryptSync(password, salt, N, r, p, keylen) -> Uint8Array
  // Real scrypt implementation using Salsa20/8 core + PBKDF2-HMAC-SHA256
  auto scryptFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactScryptSync"),
      6,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 6) throw facebook::jsi::JSError(runtime, "password, salt, N, r, p, keylen required");
        auto password = extractBytes(runtime, args[0]);
        auto salt = extractBytes(runtime, args[1]);
        uint64_t N = static_cast<uint64_t>(args[2].asNumber());
        uint32_t r = static_cast<uint32_t>(args[3].asNumber());
        uint32_t p = static_cast<uint32_t>(args[4].asNumber());
        size_t keylen = static_cast<size_t>(args[5].asNumber());

        // Validate parameters
        if (N == 0 || (N & (N - 1)) != 0) {
          throw facebook::jsi::JSError(runtime, "scrypt: N must be a power of 2");
        }
        if (r == 0) throw facebook::jsi::JSError(runtime, "scrypt: r must be > 0");
        if (p == 0) throw facebook::jsi::JSError(runtime, "scrypt: p must be > 0");
        // Check for overflow: p * 128 * r
        if (p > 0 && r > 0 && static_cast<uint64_t>(p) * 128 * r > 1073741824ULL) {
          throw facebook::jsi::JSError(runtime, "scrypt: parameters too large");
        }

#if defined(__APPLE__)
        // Helper lambdas for scrypt algorithm

        // Salsa20/8 core: applies 8 rounds of Salsa20 quarter-round in place
        // Input/output: 16 uint32_t words (64 bytes)
        auto salsa20_8 = [](uint32_t B[16]) {
          uint32_t x[16];
          std::memcpy(x, B, 64);

          #define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
          for (int i = 0; i < 8; i += 2) {
            // Column round
            x[ 4] ^= ROTL32(x[ 0] + x[12],  7);
            x[ 8] ^= ROTL32(x[ 4] + x[ 0],  9);
            x[12] ^= ROTL32(x[ 8] + x[ 4], 13);
            x[ 0] ^= ROTL32(x[12] + x[ 8], 18);
            x[ 9] ^= ROTL32(x[ 5] + x[ 1],  7);
            x[13] ^= ROTL32(x[ 9] + x[ 5],  9);
            x[ 1] ^= ROTL32(x[13] + x[ 9], 13);
            x[ 5] ^= ROTL32(x[ 1] + x[13], 18);
            x[14] ^= ROTL32(x[10] + x[ 6],  7);
            x[ 2] ^= ROTL32(x[14] + x[10],  9);
            x[ 6] ^= ROTL32(x[ 2] + x[14], 13);
            x[10] ^= ROTL32(x[ 6] + x[ 2], 18);
            x[ 3] ^= ROTL32(x[15] + x[11],  7);
            x[ 7] ^= ROTL32(x[ 3] + x[15],  9);
            x[11] ^= ROTL32(x[ 7] + x[ 3], 13);
            x[15] ^= ROTL32(x[11] + x[ 7], 18);
            // Row round
            x[ 1] ^= ROTL32(x[ 0] + x[ 3],  7);
            x[ 2] ^= ROTL32(x[ 1] + x[ 0],  9);
            x[ 3] ^= ROTL32(x[ 2] + x[ 1], 13);
            x[ 0] ^= ROTL32(x[ 3] + x[ 2], 18);
            x[ 6] ^= ROTL32(x[ 5] + x[ 4],  7);
            x[ 7] ^= ROTL32(x[ 6] + x[ 5],  9);
            x[ 4] ^= ROTL32(x[ 7] + x[ 6], 13);
            x[ 5] ^= ROTL32(x[ 4] + x[ 7], 18);
            x[11] ^= ROTL32(x[10] + x[ 9],  7);
            x[ 8] ^= ROTL32(x[11] + x[10],  9);
            x[ 9] ^= ROTL32(x[ 8] + x[11], 13);
            x[10] ^= ROTL32(x[ 9] + x[ 8], 18);
            x[12] ^= ROTL32(x[15] + x[14],  7);
            x[13] ^= ROTL32(x[12] + x[15],  9);
            x[14] ^= ROTL32(x[13] + x[12], 13);
            x[15] ^= ROTL32(x[14] + x[13], 18);
          }
          #undef ROTL32

          for (int i = 0; i < 16; i++) {
            B[i] += x[i];
          }
        };

        // scryptBlockMix: mixes 2*r 64-byte blocks
        // B is 2*r*16 uint32_t words (2*r * 64 bytes)
        // Output Y is same size, with even blocks then odd blocks
        auto blockMix = [&salsa20_8](uint32_t* B, uint32_t* Y, uint32_t r) {
          uint32_t blockCount = 2 * r;
          // X = B[2r-1] (last 64-byte block)
          uint32_t X[16];
          std::memcpy(X, &B[(blockCount - 1) * 16], 64);

          // Temporary arrays for even and odd blocks
          for (uint32_t i = 0; i < blockCount; i++) {
            // X = X xor B[i]
            for (int k = 0; k < 16; k++) {
              X[k] ^= B[i * 16 + k];
            }
            salsa20_8(X);
            // Copy result to Y
            std::memcpy(&Y[i * 16], X, 64);
          }

          // Rearrange: even blocks first, then odd blocks
          // Y currently has blocks in order 0,1,2,...,2r-1
          // We need: 0,2,4,...,2r-2, 1,3,5,...,2r-1
          std::vector<uint32_t> tmp(blockCount * 16);
          uint32_t half = 0;
          for (uint32_t i = 0; i < blockCount; i += 2) {
            std::memcpy(&tmp[half * 16], &Y[i * 16], 64);
            half++;
          }
          for (uint32_t i = 1; i < blockCount; i += 2) {
            std::memcpy(&tmp[half * 16], &Y[i * 16], 64);
            half++;
          }
          std::memcpy(Y, tmp.data(), blockCount * 64);
        };

        // scryptROMix: memory-hard function
        // B is 2*r*16 uint32_t words
        auto roMix = [&blockMix](uint32_t* B, uint64_t N, uint32_t r) {
          size_t blockWords = 2 * static_cast<size_t>(r) * 16; // words per block (each word is 4 bytes)
          size_t blockBytes = blockWords * 4;

          // Allocate V: N blocks
          std::vector<uint32_t> V(N * blockWords);
          std::vector<uint32_t> Y(blockWords);

          // Step 1: Build V
          for (uint64_t i = 0; i < N; i++) {
            std::memcpy(&V[i * blockWords], B, blockBytes);
            blockMix(B, Y.data(), r);
            std::memcpy(B, Y.data(), blockBytes);
          }

          // Step 2: Mix
          for (uint64_t i = 0; i < N; i++) {
            // Integerify: take last 64-byte block of B, interpret first 4 bytes as LE uint32
            uint32_t lastBlockStart = (2 * r - 1) * 16;
            uint64_t j = B[lastBlockStart] % N;

            // X = X xor V[j]
            for (size_t k = 0; k < blockWords; k++) {
              B[k] ^= V[j * blockWords + k];
            }
            blockMix(B, Y.data(), r);
            std::memcpy(B, Y.data(), blockBytes);
          }
        };

        // PBKDF2-HMAC-SHA256 implemented manually using CCHmac
        // (CommonCrypto's CCKeyDerivationPBKDF fails with empty password/salt)
        auto pbkdf2_sha256 = [](const uint8_t* pass, size_t passLen,
                                const uint8_t* saltData, size_t saltLen,
                                uint32_t iterations,
                                uint8_t* out, size_t outLen) {
          const size_t hLen = CC_SHA256_DIGEST_LENGTH; // 32
          uint32_t blockCount = static_cast<uint32_t>((outLen + hLen - 1) / hLen);

          for (uint32_t blockIdx = 1; blockIdx <= blockCount; blockIdx++) {
            // U_1 = HMAC-SHA256(pass, salt || INT_32_BE(blockIdx))
            // Prepare salt || INT_32_BE(blockIdx)
            std::vector<uint8_t> saltBlock(saltLen + 4);
            if (saltLen > 0) std::memcpy(saltBlock.data(), saltData, saltLen);
            saltBlock[saltLen + 0] = static_cast<uint8_t>((blockIdx >> 24) & 0xFF);
            saltBlock[saltLen + 1] = static_cast<uint8_t>((blockIdx >> 16) & 0xFF);
            saltBlock[saltLen + 2] = static_cast<uint8_t>((blockIdx >> 8) & 0xFF);
            saltBlock[saltLen + 3] = static_cast<uint8_t>(blockIdx & 0xFF);

            uint8_t U[CC_SHA256_DIGEST_LENGTH];
            uint8_t T[CC_SHA256_DIGEST_LENGTH];

            // U_1
            CCHmac(kCCHmacAlgSHA256, pass, passLen,
                   saltBlock.data(), saltBlock.size(), U);
            std::memcpy(T, U, hLen);

            // U_2 .. U_c
            for (uint32_t iter = 1; iter < iterations; iter++) {
              CCHmac(kCCHmacAlgSHA256, pass, passLen, U, hLen, U);
              for (size_t k = 0; k < hLen; k++) {
                T[k] ^= U[k];
              }
            }

            // Copy T to output
            size_t offset = static_cast<size_t>(blockIdx - 1) * hLen;
            size_t copyLen = (offset + hLen <= outLen) ? hLen : (outLen - offset);
            std::memcpy(out + offset, T, copyLen);
          }
        };

        // === Main scrypt algorithm ===
        size_t BLen = static_cast<size_t>(128) * r * p;
        std::vector<uint8_t> B(BLen);

        // Step 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r)
        pbkdf2_sha256(password.data(), password.size(),
                      salt.data(), salt.size(),
                      1, B.data(), BLen);

        // Step 2: For each block i in 0..p, apply ROMix
        for (uint32_t i = 0; i < p; i++) {
          // Interpret B[i*128*r .. (i+1)*128*r] as uint32_t array (little-endian)
          uint32_t* block = reinterpret_cast<uint32_t*>(&B[static_cast<size_t>(i) * 128 * r]);
          // Note: On little-endian systems (x86/ARM), this is correct.
          // The scrypt spec defines the data as little-endian uint32 words.
          roMix(block, N, r);
        }

        // Step 3: Output = PBKDF2-HMAC-SHA256(password, B, 1, keylen)
        std::vector<uint8_t> derivedKey(keylen);
        pbkdf2_sha256(password.data(), password.size(),
                      B.data(), B.size(),
                      1, derivedKey.data(), keylen);

        return makeUint8Array(runtime, std::move(derivedKey));
#else
        throw facebook::jsi::JSError(runtime, "scrypt not yet supported on this platform");
#endif
      });
  rt.global().setProperty(rt, "__exactScryptSync", std::move(scryptFn));

#if defined(__APPLE__)
#if !defined(EXACT_PLATFORM_IOS)
  auto signFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSignSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isString() || !args[1].isString() || !args[2].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: algorithm, data, and key required");
        }

        auto rawAlgorithm = args[0].asString(runtime).utf8(runtime);
        auto hashName = normalizeHashForNodeCrypto(rawAlgorithm);
        auto dataText = args[1].asString(runtime).utf8(runtime);
        auto keyText = args[2].asString(runtime).utf8(runtime);
        auto key = importPemKey(keyText, kSecItemTypePrivateKey);
        if (!key) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: invalid PEM private key");
        }

        auto isRsa = isRsaSecKey(key);
        auto algorithm = pickSecKeySignAlgorithm(hashName, isRsa);
        if (!algorithm) {
          CFRelease(key);
          throw facebook::jsi::JSError(runtime, "__exactSignSync: unsupported algorithm " + rawAlgorithm);
        }

        auto dataBytes = std::vector<uint8_t>(dataText.begin(), dataText.end());
        auto dataRef = CFDataCreate(kCFAllocatorDefault, dataBytes.data(), static_cast<CFIndex>(dataBytes.size()));
        if (!dataRef) {
          CFRelease(key);
          throw facebook::jsi::JSError(runtime, "__exactSignSync: failed to allocate data");
        }

        CFErrorRef error = nullptr;
        auto signatureRef = SecKeyCreateSignature(key, algorithm, dataRef, &error);
        CFRelease(dataRef);
        CFRelease(key);
        if (!signatureRef) {
          if (error) {
            CFRelease(error);
          }
          throw facebook::jsi::JSError(runtime, "__exactSignSync: signing failed");
        }

        auto signature = dataToString(signatureRef);
        CFRelease(signatureRef);
        return makeUint8Array(runtime, std::vector<uint8_t>(signature.begin(), signature.end()));
      });
  rt.global().setProperty(rt, "__exactSignSync", std::move(signFn));
#endif // !EXACT_PLATFORM_IOS

#if !defined(EXACT_PLATFORM_IOS)
  auto verifyFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactVerifySync"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4 || !args[0].isString() || !args[2].isString() || !args[3].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: algorithm, signature, data, and key required");
        }

        auto rawAlgorithm = args[0].asString(runtime).utf8(runtime);
        auto hashName = normalizeHashForNodeCrypto(rawAlgorithm);
        auto signatureBytes = extractBytes(runtime, args[1]);
        auto dataText = args[2].asString(runtime).utf8(runtime);
        auto keyText = args[3].asString(runtime).utf8(runtime);
        auto key = importPemKey(keyText, kSecItemTypePublicKey);
        if (!key) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: invalid PEM public key");
        }

        auto isRsa = isRsaSecKey(key);
        auto algorithm = pickSecKeySignAlgorithm(hashName, isRsa);
        if (!algorithm) {
          CFRelease(key);
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: unsupported algorithm " + rawAlgorithm);
        }

        auto dataBytes = std::vector<uint8_t>(dataText.begin(), dataText.end());
        auto signatureRef = CFDataCreate(kCFAllocatorDefault, signatureBytes.data(), static_cast<CFIndex>(signatureBytes.size()));
        auto dataRef = CFDataCreate(kCFAllocatorDefault, dataBytes.data(), static_cast<CFIndex>(dataBytes.size()));
        if (!dataRef || !signatureRef) {
          if (signatureRef) CFRelease(signatureRef);
          if (dataRef) CFRelease(dataRef);
          CFRelease(key);
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: failed to allocate data");
        }

        CFErrorRef error = nullptr;
        auto verified = SecKeyVerifySignature(key, algorithm, dataRef, signatureRef, &error);
        CFRelease(signatureRef);
        CFRelease(dataRef);
        CFRelease(key);
        if (error) {
          CFRelease(error);
        }
        return facebook::jsi::Value(static_cast<bool>(verified));
      });
  rt.global().setProperty(rt, "__exactVerifySync", std::move(verifyFn));
#endif // !EXACT_PLATFORM_IOS

  auto generateKeyPairSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGenerateKeyPairSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key type required");
        }
        auto keyType = args[0].asString(runtime).utf8(runtime);
        if (keyType != "rsa" && keyType != "ec" && keyType != "rsa-pss" &&
            keyType != "ecdsa" && keyType != "ed25519" && keyType != "x25519") {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported key type " + keyType);
        }

        uint32_t bits = 2048;
        uint32_t exponent = 65537;
        std::string namedCurve = "P-256";
        if (count >= 2 && args[1].isObject()) {
          auto options = args[1].asObject(runtime);
          if (options.hasProperty(runtime, "modulusLength")) {
            auto v = options.getProperty(runtime, "modulusLength");
            if (v.isNumber()) bits = static_cast<uint32_t>(v.asNumber());
          }
          if (options.hasProperty(runtime, "publicExponent")) {
            auto v = options.getProperty(runtime, "publicExponent");
            if (v.isNumber()) exponent = static_cast<uint32_t>(v.asNumber());
            else if (v.isString()) {
              exponent = static_cast<uint32_t>(std::stoul(v.asString(runtime).utf8(runtime)));
            }
          }
          if (options.hasProperty(runtime, "namedCurve")) {
            auto v = options.getProperty(runtime, "namedCurve");
            if (v.isString()) namedCurve = v.asString(runtime).utf8(runtime);
          }
        }

        // --- Ed25519 and X25519: use OpenSSL on macOS ---
        if (keyType == "ed25519" || keyType == "x25519") {
#if !defined(EXACT_NO_OPENSSL)
          int evpType = (keyType == "ed25519") ? EVP_PKEY_ED25519 : EVP_PKEY_X25519;
          EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(evpType, nullptr);
          if (!ctx) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to create context for " + keyType);
          }
          if (EVP_PKEY_keygen_init(ctx) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: keygen init failed for " + keyType);
          }
          EVP_PKEY* pkey = nullptr;
          if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key generation failed for " + keyType);
          }
          EVP_PKEY_CTX_free(ctx);

          // Export as PEM
          BIO* privateBio = BIO_new(BIO_s_mem());
          BIO* publicBio = BIO_new(BIO_s_mem());
          if (!privateBio || !publicBio) {
            if (privateBio) BIO_free(privateBio);
            if (publicBio) BIO_free(publicBio);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate PEM buffers");
          }
          if (PEM_write_bio_PrivateKey(privateBio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1 ||
              PEM_write_bio_PUBKEY(publicBio, pkey) != 1) {
            BIO_free(privateBio);
            BIO_free(publicBio);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to serialize PEM keys for " + keyType);
          }
          EVP_PKEY_free(pkey);

          char* privatePtr = nullptr;
          char* publicPtr = nullptr;
          auto privateLen = BIO_get_mem_data(privateBio, &privatePtr);
          auto publicLen = BIO_get_mem_data(publicBio, &publicPtr);
          std::string privatePem = privatePtr && privateLen > 0 ? std::string(privatePtr, static_cast<size_t>(privateLen)) : std::string();
          std::string publicPem = publicPtr && publicLen > 0 ? std::string(publicPtr, static_cast<size_t>(publicLen)) : std::string();
          BIO_free(privateBio);
          BIO_free(publicBio);

          facebook::jsi::Object result(runtime);
          result.setProperty(runtime, "privateKey", facebook::jsi::String::createFromUtf8(runtime, privatePem));
          result.setProperty(runtime, "publicKey", facebook::jsi::String::createFromUtf8(runtime, publicPem));
          return result;
#else
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: " + keyType + " key generation requires OpenSSL (not available on iOS)");
#endif // !EXACT_NO_OPENSSL
        }

        // --- ECDSA: use Security.framework on macOS ---
        if (keyType == "ec" || keyType == "ecdsa") {
          uint32_t ecBits = 256;
          if (namedCurve == "P-256" || namedCurve == "prime256v1") ecBits = 256;
          else if (namedCurve == "P-384" || namedCurve == "secp384r1") ecBits = 384;
          else if (namedCurve == "P-521" || namedCurve == "secp521r1") ecBits = 521;
          else {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported EC curve " + namedCurve);
          }

          auto ecBitsValue = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &ecBits);
          if (!ecBitsValue) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate EC options");
          }

          CFTypeRef ecKeys[2] = { kSecAttrKeyType, kSecAttrKeySizeInBits };
          CFTypeRef ecValues[2] = { kSecAttrKeyTypeECSECPrimeRandom, ecBitsValue };
          auto ecParams = CFDictionaryCreate(
              kCFAllocatorDefault, ecKeys, ecValues, 2,
              &kCFTypeDictionaryKeyCallBacks,
              &kCFTypeDictionaryValueCallBacks);
          if (!ecParams) {
            CFRelease(ecBitsValue);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate EC key params");
          }

          CFErrorRef ecError = nullptr;
          SecKeyRef ecPrivateKey = SecKeyCreateRandomKey(ecParams, &ecError);
          CFRelease(ecParams);
          CFRelease(ecBitsValue);
          if (!ecPrivateKey) {
            if (ecError) CFRelease(ecError);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: EC key generation failed");
          }
          if (ecError) CFRelease(ecError);
          SecKeyRef ecPublicKey = SecKeyCopyPublicKey(ecPrivateKey);
          if (!ecPublicKey) {
            CFRelease(ecPrivateKey);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: EC key generation failed");
          }

#if !defined(EXACT_PLATFORM_IOS)
          CFDataRef ecPrivateData = nullptr;
          CFDataRef ecPublicData = nullptr;
          auto ecExportStatus = SecItemExport(ecPrivateKey, kSecFormatOpenSSL, kSecItemPemArmour, nullptr, &ecPrivateData);
          if (ecExportStatus == errSecSuccess) {
            ecExportStatus = SecItemExport(ecPublicKey, kSecFormatOpenSSL, kSecItemPemArmour, nullptr, &ecPublicData);
          }
          CFRelease(ecPrivateKey);
          CFRelease(ecPublicKey);
          if (ecExportStatus != errSecSuccess || !ecPrivateData || !ecPublicData) {
            if (ecPrivateData) CFRelease(ecPrivateData);
            if (ecPublicData) CFRelease(ecPublicData);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to export EC PEM keys");
          }

          std::string privatePem = dataToString(ecPrivateData);
          std::string publicPem = dataToString(ecPublicData);
          CFRelease(ecPrivateData);
          CFRelease(ecPublicData);

          facebook::jsi::Object result(runtime);
          result.setProperty(runtime, "privateKey", facebook::jsi::String::createFromUtf8(runtime, privatePem));
          result.setProperty(runtime, "publicKey", facebook::jsi::String::createFromUtf8(runtime, publicPem));
          return result;
#else
          CFRelease(ecPrivateKey);
          CFRelease(ecPublicKey);
          throw facebook::jsi::JSError(runtime, "PEM key export not yet available on iOS");
#endif // !EXACT_PLATFORM_IOS
        }

        // --- RSA ---
        if (bits < 1024) bits = 1024;
        if (bits > 16384) bits = 16384;

        if (exponent != 65537) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported public exponent");
        }

        auto bitsValue = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &bits);
        if (!bitsValue) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate options");
        }

        CFTypeRef keys[2] = { kSecAttrKeyType, kSecAttrKeySizeInBits };
        CFTypeRef values[2] = { kSecAttrKeyTypeRSA, bitsValue };
        auto params = CFDictionaryCreate(
            kCFAllocatorDefault,
            keys,
            values,
            2,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        if (!params) {
          CFRelease(bitsValue);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate key params");
        }

        CFErrorRef rsaError = nullptr;
        SecKeyRef privateKey = SecKeyCreateRandomKey(params, &rsaError);
        CFRelease(params);
        CFRelease(bitsValue);
        if (!privateKey) {
          if (rsaError) CFRelease(rsaError);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key generation failed");
        }
        if (rsaError) CFRelease(rsaError);
        SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
        if (!publicKey) {
          CFRelease(privateKey);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key generation failed");
        }

#if !defined(EXACT_PLATFORM_IOS)
        CFDataRef privateData = nullptr;
        CFDataRef publicData = nullptr;
        auto exportStatus = SecItemExport(privateKey, kSecFormatOpenSSL, kSecItemPemArmour, nullptr, &privateData);
        if (exportStatus == errSecSuccess) {
          exportStatus = SecItemExport(publicKey, kSecFormatOpenSSL, kSecItemPemArmour, nullptr, &publicData);
        }
        CFRelease(privateKey);
        CFRelease(publicKey);
        if (exportStatus != errSecSuccess || !privateData || !publicData) {
          if (privateData) CFRelease(privateData);
          if (publicData) CFRelease(publicData);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to export PEM keys");
        }

        std::string privatePem = dataToString(privateData);
        std::string publicPem = dataToString(publicData);
        CFRelease(privateData);
        CFRelease(publicData);

        facebook::jsi::Object result(runtime);
        result.setProperty(runtime, "privateKey", facebook::jsi::String::createFromUtf8(runtime, privatePem));
        result.setProperty(runtime, "publicKey", facebook::jsi::String::createFromUtf8(runtime, publicPem));
        return result;
#else
        CFRelease(privateKey);
        CFRelease(publicKey);
        throw facebook::jsi::JSError(runtime, "PEM key export not yet available on iOS");
#endif // !EXACT_PLATFORM_IOS
      });
  rt.global().setProperty(rt, "__exactGenerateKeyPairSync", std::move(generateKeyPairSyncFn));
#else
  auto signFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSignSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isString() || !args[1].isString() || !args[2].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: algorithm, data, and key required");
        }

        auto rawAlgorithm = args[0].asString(runtime).utf8(runtime);
        auto hashName = digestAlgorithmFromNodeCrypto(rawAlgorithm);
        const EVP_MD* md = selectDigestForCryptoAlgo(hashName);
        if (!md) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: unsupported algorithm " + rawAlgorithm);
        }

        auto dataText = args[1].asString(runtime).utf8(runtime);
        auto keyText = args[2].asString(runtime).utf8(runtime);
        std::vector<uint8_t> data(dataText.begin(), dataText.end());
        std::vector<uint8_t> keyBytes(keyText.begin(), keyText.end());

        std::vector<uint8_t> signature;
        BIO* keyBio = BIO_new_mem_buf(keyBytes.data(), static_cast<int>(keyBytes.size()));
        if (!keyBio) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: failed to allocate key BIO");
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
        BIO_free(keyBio);
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactSignSync: invalid PEM private key");
        }

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactSignSync: failed to allocate digest context");
        }

        if (EVP_DigestSignInit(mdCtx, nullptr, md, nullptr, pkey) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactSignSync: EVP_DigestSignInit failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        if (EVP_DigestSignUpdate(mdCtx, data.data(), data.size()) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactSignSync: EVP_DigestSignUpdate failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        size_t sigLen = 0;
        if (EVP_DigestSignFinal(mdCtx, nullptr, &sigLen) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactSignSync: EVP_DigestSignFinal failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        signature.resize(sigLen);
        if (EVP_DigestSignFinal(mdCtx, signature.data(), &sigLen) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactSignSync: signing failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        signature.resize(sigLen);

        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);

        return makeUint8Array(runtime, std::move(signature));
      });
  rt.global().setProperty(rt, "__exactSignSync", std::move(signFn));

  auto verifyFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactVerifySync"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4 || !args[0].isString() || !args[2].isString() || !args[3].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: algorithm, signature, data, and key required");
        }

        auto rawAlgorithm = args[0].asString(runtime).utf8(runtime);
        auto hashName = digestAlgorithmFromNodeCrypto(rawAlgorithm);
        const EVP_MD* md = selectDigestForCryptoAlgo(hashName);
        if (!md) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: unsupported algorithm " + rawAlgorithm);
        }

        auto signatureBytes = extractBytes(runtime, args[1]);
        auto dataText = args[2].asString(runtime).utf8(runtime);
        auto keyText = args[3].asString(runtime).utf8(runtime);
        std::vector<uint8_t> data(dataText.begin(), dataText.end());
        std::vector<uint8_t> keyBytes(keyText.begin(), keyText.end());

        BIO* keyBio = BIO_new_mem_buf(keyBytes.data(), static_cast<int>(keyBytes.size()));
        if (!keyBio) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: failed to allocate key BIO");
        }

        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(keyBio, nullptr, nullptr, nullptr);
        BIO_free(keyBio);
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: invalid PEM public key");
        }

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: failed to allocate digest context");
        }

        if (EVP_DigestVerifyInit(mdCtx, nullptr, md, nullptr, pkey) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: EVP_DigestVerifyInit failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        if (EVP_DigestVerifyUpdate(mdCtx, data.data(), data.size()) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: EVP_DigestVerifyUpdate failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        auto result = EVP_DigestVerifyFinal(mdCtx, signatureBytes.data(), signatureBytes.size());
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        if (result != 1 && result != 0) {
          throw facebook::jsi::JSError(runtime, "__exactVerifySync: verify failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        return facebook::jsi::Value(static_cast<bool>(result == 1));
      });
  rt.global().setProperty(rt, "__exactVerifySync", std::move(verifyFn));

  auto generateKeyPairSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGenerateKeyPairSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key type required");
        }
        auto keyType = args[0].asString(runtime).utf8(runtime);
        if (keyType != "rsa" && keyType != "ec" && keyType != "rsa-pss" &&
            keyType != "ecdsa" && keyType != "ed25519" && keyType != "x25519") {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported key type " + keyType);
        }

        uint32_t bits = 2048;
        uint32_t exponent = 65537;
        std::string namedCurve = "P-256";
        if (count >= 2 && args[1].isObject()) {
          auto options = args[1].asObject(runtime);
          if (options.hasProperty(runtime, "modulusLength")) {
            auto v = options.getProperty(runtime, "modulusLength");
            if (v.isNumber()) bits = static_cast<uint32_t>(v.asNumber());
          }
          if (options.hasProperty(runtime, "publicExponent")) {
            auto v = options.getProperty(runtime, "publicExponent");
            if (v.isNumber()) exponent = static_cast<uint32_t>(v.asNumber());
            else if (v.isString()) {
              exponent = static_cast<uint32_t>(std::stoul(v.asString(runtime).utf8(runtime)));
            }
          }
          if (options.hasProperty(runtime, "namedCurve")) {
            auto v = options.getProperty(runtime, "namedCurve");
            if (v.isString()) namedCurve = v.asString(runtime).utf8(runtime);
          }
        }

        // Helper lambda: generate EVP_PKEY and serialize to PEM
        auto serializeKeyPairToPem = [&](EVP_PKEY* pkey) -> facebook::jsi::Value {
          BIO* privateBio = BIO_new(BIO_s_mem());
          BIO* publicBio = BIO_new(BIO_s_mem());
          if (!privateBio || !publicBio) {
            if (privateBio) BIO_free(privateBio);
            if (publicBio) BIO_free(publicBio);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate PEM buffers");
          }
          if (PEM_write_bio_PrivateKey(privateBio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1 ||
              PEM_write_bio_PUBKEY(publicBio, pkey) != 1) {
            BIO_free(privateBio);
            BIO_free(publicBio);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to serialize PEM keys");
          }
          EVP_PKEY_free(pkey);

          char* privatePtr = nullptr;
          char* publicPtr = nullptr;
          auto privateLen = BIO_get_mem_data(privateBio, &privatePtr);
          auto publicLen = BIO_get_mem_data(publicBio, &publicPtr);
          std::string privatePem = privatePtr && privateLen > 0 ? std::string(privatePtr, static_cast<size_t>(privateLen)) : std::string();
          std::string publicPem = publicPtr && publicLen > 0 ? std::string(publicPtr, static_cast<size_t>(publicLen)) : std::string();
          BIO_free(privateBio);
          BIO_free(publicBio);

          facebook::jsi::Object result(runtime);
          result.setProperty(runtime, "privateKey", facebook::jsi::String::createFromUtf8(runtime, privatePem));
          result.setProperty(runtime, "publicKey", facebook::jsi::String::createFromUtf8(runtime, publicPem));
          return result;
        };

        // --- Ed25519 and X25519 ---
        if (keyType == "ed25519" || keyType == "x25519") {
          int evpType = (keyType == "ed25519") ? EVP_PKEY_ED25519 : EVP_PKEY_X25519;
          EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(evpType, nullptr);
          if (!ctx) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to create context for " + keyType);
          }
          if (EVP_PKEY_keygen_init(ctx) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: keygen init failed for " + keyType);
          }
          EVP_PKEY* pkey = nullptr;
          if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key generation failed for " + keyType);
          }
          EVP_PKEY_CTX_free(ctx);
          return serializeKeyPairToPem(pkey);
        }

        // --- ECDSA ---
        if (keyType == "ec" || keyType == "ecdsa") {
          int nid = NID_X9_62_prime256v1;
          if (namedCurve == "P-256" || namedCurve == "prime256v1") nid = NID_X9_62_prime256v1;
          else if (namedCurve == "P-384" || namedCurve == "secp384r1") nid = NID_secp384r1;
          else if (namedCurve == "P-521" || namedCurve == "secp521r1") nid = NID_secp521r1;
          else {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported EC curve " + namedCurve);
          }

          EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
          if (!ctx) {
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to create EC context");
          }
          if (EVP_PKEY_keygen_init(ctx) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: EC keygen init failed");
          }
          if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to set EC curve");
          }
          EVP_PKEY* pkey = nullptr;
          if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: EC key generation failed");
          }
          EVP_PKEY_CTX_free(ctx);
          return serializeKeyPairToPem(pkey);
        }

        // --- RSA ---
        if (bits < 1024) bits = 1024;
        if (bits > 16384) bits = 16384;
        if (exponent != 65537) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: unsupported public exponent");
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to allocate key context");
        }
        if (EVP_PKEY_keygen_init(ctx) != 1) {
          EVP_PKEY_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: keygen init failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to set RSA key length");
        }

        BIGNUM* exp = nullptr;
        if (exponent == 0) {
          exponent = 65537;
        }
        exp = BN_new();
        if (!exp || !BN_set_word(exp, exponent) || EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, exp) <= 0) {
          if (exp) BN_clear_free(exp);
          EVP_PKEY_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: failed to set public exponent");
        }
        // Note: after successful EVP_PKEY_CTX_set_rsa_keygen_pubexp, ownership of exp transfers
        // Do NOT free exp here

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
          EVP_PKEY_CTX_free(ctx);
          throw facebook::jsi::JSError(runtime, "__exactGenerateKeyPairSync: key generation failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        EVP_PKEY_CTX_free(ctx);
        return serializeKeyPairToPem(pkey);
      });
  rt.global().setProperty(rt, "__exactGenerateKeyPairSync", std::move(generateKeyPairSyncFn));
#endif

#if !defined(EXACT_NO_OPENSSL)
  // --- Ed25519 Sign ---
  // __exactEd25519Sign(privateKeyBytes, data) -> Uint8Array (64-byte signature)
  auto ed25519SignFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEd25519Sign"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: privateKey and data required");
        }
        auto privKeyBytes = extractBytes(runtime, args[0]);
        auto data = extractBytes(runtime, args[1]);

        // Import the private key - try raw 32-byte key first, then PEM/PKCS8
        EVP_PKEY* pkey = nullptr;
        if (privKeyBytes.size() == 32) {
          // Raw 32-byte Ed25519 private key seed
          pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, privKeyBytes.data(), privKeyBytes.size());
        }
        if (!pkey) {
          // Try PEM format
          BIO* bio = BIO_new_mem_buf(privKeyBytes.data(), static_cast<int>(privKeyBytes.size()));
          if (bio) {
            pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          // Try DER/PKCS8 format
          const unsigned char* p = privKeyBytes.data();
          pkey = d2i_PrivateKey(EVP_PKEY_ED25519, nullptr, &p, static_cast<long>(privKeyBytes.size()));
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: failed to import Ed25519 private key");
        }

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: failed to allocate context");
        }

        // Ed25519 uses NULL as the digest (it does its own hashing)
        if (EVP_DigestSignInit(mdCtx, nullptr, nullptr, nullptr, pkey) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: EVP_DigestSignInit failed");
        }

        size_t sigLen = 0;
        if (EVP_DigestSign(mdCtx, nullptr, &sigLen, data.data(), data.size()) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: failed to get signature length");
        }
        std::vector<uint8_t> signature(sigLen);
        if (EVP_DigestSign(mdCtx, signature.data(), &sigLen, data.data(), data.size()) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Sign: signing failed");
        }
        signature.resize(sigLen);

        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return makeUint8Array(runtime, std::move(signature));
      });
  rt.global().setProperty(rt, "__exactEd25519Sign", std::move(ed25519SignFn));

  // --- Ed25519 Verify ---
  // __exactEd25519Verify(publicKeyBytes, signature, data) -> boolean
  auto ed25519VerifyFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEd25519Verify"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactEd25519Verify: publicKey, signature, and data required");
        }
        auto pubKeyBytes = extractBytes(runtime, args[0]);
        auto sigBytes = extractBytes(runtime, args[1]);
        auto data = extractBytes(runtime, args[2]);

        // Import the public key - try raw 32-byte key first, then PEM/SPKI
        EVP_PKEY* pkey = nullptr;
        if (pubKeyBytes.size() == 32) {
          pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubKeyBytes.data(), pubKeyBytes.size());
        }
        if (!pkey) {
          // Try PEM format
          BIO* bio = BIO_new_mem_buf(pubKeyBytes.data(), static_cast<int>(pubKeyBytes.size()));
          if (bio) {
            pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          // Try DER/SPKI format
          const unsigned char* p = pubKeyBytes.data();
          pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(pubKeyBytes.size()));
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactEd25519Verify: failed to import Ed25519 public key");
        }

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Verify: failed to allocate context");
        }

        if (EVP_DigestVerifyInit(mdCtx, nullptr, nullptr, nullptr, pkey) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEd25519Verify: EVP_DigestVerifyInit failed");
        }

        auto result = EVP_DigestVerify(mdCtx, sigBytes.data(), sigBytes.size(), data.data(), data.size());
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);

        return facebook::jsi::Value(result == 1);
      });
  rt.global().setProperty(rt, "__exactEd25519Verify", std::move(ed25519VerifyFn));

  // --- ECDSA Sign ---
  // __exactEcdsaSign(curve, hash, privateKeyBytes, data) -> Uint8Array (DER-encoded signature)
  auto ecdsaSignFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEcdsaSign"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4) {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: curve, hash, privateKey, and data required");
        }
        auto curve = args[0].asString(runtime).utf8(runtime);
        auto hash = args[1].asString(runtime).utf8(runtime);
        auto privKeyBytes = extractBytes(runtime, args[2]);
        auto data = extractBytes(runtime, args[3]);

        // Select digest
        const EVP_MD* md = nullptr;
        if (hash == "SHA-256" || hash == "sha256" || hash == "sha-256") md = EVP_sha256();
        else if (hash == "SHA-384" || hash == "sha384" || hash == "sha-384") md = EVP_sha384();
        else if (hash == "SHA-512" || hash == "sha512" || hash == "sha-512") md = EVP_sha512();
        else if (hash == "SHA-1" || hash == "sha1" || hash == "sha-1") md = EVP_sha1();
        else {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: unsupported hash algorithm " + hash);
        }

        // Import private key - try PEM first, then DER/PKCS8
        EVP_PKEY* pkey = nullptr;
        {
          BIO* bio = BIO_new_mem_buf(privKeyBytes.data(), static_cast<int>(privKeyBytes.size()));
          if (bio) {
            pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          const unsigned char* p = privKeyBytes.data();
          pkey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, static_cast<long>(privKeyBytes.size()));
        }
        if (!pkey) {
          // Try as PKCS8 DER
          const unsigned char* p = privKeyBytes.data();
          PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, static_cast<long>(privKeyBytes.size()));
          if (p8) {
            pkey = EVP_PKCS82PKEY(p8);
            PKCS8_PRIV_KEY_INFO_free(p8);
          }
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: failed to import EC private key");
        }

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: failed to allocate context");
        }

        if (EVP_DigestSignInit(mdCtx, nullptr, md, nullptr, pkey) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: EVP_DigestSignInit failed");
        }
        if (EVP_DigestSignUpdate(mdCtx, data.data(), data.size()) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: EVP_DigestSignUpdate failed");
        }

        size_t sigLen = 0;
        if (EVP_DigestSignFinal(mdCtx, nullptr, &sigLen) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: failed to get signature length");
        }
        std::vector<uint8_t> signature(sigLen);
        if (EVP_DigestSignFinal(mdCtx, signature.data(), &sigLen) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaSign: signing failed");
        }
        signature.resize(sigLen);

        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);
        return makeUint8Array(runtime, std::move(signature));
      });
  rt.global().setProperty(rt, "__exactEcdsaSign", std::move(ecdsaSignFn));

  // --- ECDSA Verify ---
  // __exactEcdsaVerify(curve, hash, publicKeyBytes, signature, data) -> boolean
  auto ecdsaVerifyFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEcdsaVerify"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 5) {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: curve, hash, publicKey, signature, and data required");
        }
        auto curve = args[0].asString(runtime).utf8(runtime);
        auto hash = args[1].asString(runtime).utf8(runtime);
        auto pubKeyBytes = extractBytes(runtime, args[2]);
        auto sigBytes = extractBytes(runtime, args[3]);
        auto data = extractBytes(runtime, args[4]);

        const EVP_MD* md = nullptr;
        if (hash == "SHA-256" || hash == "sha256" || hash == "sha-256") md = EVP_sha256();
        else if (hash == "SHA-384" || hash == "sha384" || hash == "sha-384") md = EVP_sha384();
        else if (hash == "SHA-512" || hash == "sha512" || hash == "sha-512") md = EVP_sha512();
        else if (hash == "SHA-1" || hash == "sha1" || hash == "sha-1") md = EVP_sha1();
        else {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: unsupported hash algorithm " + hash);
        }

        // Import public key - try PEM first, then DER/SPKI
        EVP_PKEY* pkey = nullptr;
        {
          BIO* bio = BIO_new_mem_buf(pubKeyBytes.data(), static_cast<int>(pubKeyBytes.size()));
          if (bio) {
            pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          const unsigned char* p = pubKeyBytes.data();
          pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(pubKeyBytes.size()));
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: failed to import EC public key");
        }

        EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
        if (!mdCtx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: failed to allocate context");
        }

        if (EVP_DigestVerifyInit(mdCtx, nullptr, md, nullptr, pkey) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: EVP_DigestVerifyInit failed");
        }
        if (EVP_DigestVerifyUpdate(mdCtx, data.data(), data.size()) != 1) {
          EVP_MD_CTX_free(mdCtx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: EVP_DigestVerifyUpdate failed");
        }

        auto result = EVP_DigestVerifyFinal(mdCtx, sigBytes.data(), sigBytes.size());
        EVP_MD_CTX_free(mdCtx);
        EVP_PKEY_free(pkey);

        if (result != 1 && result != 0) {
          throw facebook::jsi::JSError(runtime, "__exactEcdsaVerify: verification error");
        }
        return facebook::jsi::Value(result == 1);
      });
  rt.global().setProperty(rt, "__exactEcdsaVerify", std::move(ecdsaVerifyFn));

  // --- X25519 Derive Bits (ECDH with Curve25519) ---
  // __exactX25519DeriveBits(privateKeyBytes, publicKeyBytes) -> Uint8Array (32-byte shared secret)
  auto x25519DeriveFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactX25519DeriveBits"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: privateKey and publicKey required");
        }
        auto privKeyBytes = extractBytes(runtime, args[0]);
        auto pubKeyBytes = extractBytes(runtime, args[1]);

        // Import private key
        EVP_PKEY* privKey = nullptr;
        if (privKeyBytes.size() == 32) {
          privKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privKeyBytes.data(), privKeyBytes.size());
        }
        if (!privKey) {
          BIO* bio = BIO_new_mem_buf(privKeyBytes.data(), static_cast<int>(privKeyBytes.size()));
          if (bio) {
            privKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!privKey) {
          const unsigned char* p = privKeyBytes.data();
          privKey = d2i_PrivateKey(EVP_PKEY_X25519, nullptr, &p, static_cast<long>(privKeyBytes.size()));
        }
        if (!privKey) {
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: failed to import X25519 private key");
        }

        // Import public key
        EVP_PKEY* pubKey = nullptr;
        if (pubKeyBytes.size() == 32) {
          pubKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pubKeyBytes.data(), pubKeyBytes.size());
        }
        if (!pubKey) {
          BIO* bio = BIO_new_mem_buf(pubKeyBytes.data(), static_cast<int>(pubKeyBytes.size()));
          if (bio) {
            pubKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pubKey) {
          const unsigned char* p = pubKeyBytes.data();
          pubKey = d2i_PUBKEY(nullptr, &p, static_cast<long>(pubKeyBytes.size()));
        }
        if (!pubKey) {
          EVP_PKEY_free(privKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: failed to import X25519 public key");
        }

        // Derive shared secret
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, nullptr);
        if (!ctx) {
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: failed to create derive context");
        }

        if (EVP_PKEY_derive_init(ctx) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: derive init failed");
        }

        if (EVP_PKEY_derive_set_peer(ctx, pubKey) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: failed to set peer key");
        }

        size_t secretLen = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secretLen) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: failed to get secret length");
        }

        std::vector<uint8_t> secret(secretLen);
        if (EVP_PKEY_derive(ctx, secret.data(), &secretLen) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactX25519DeriveBits: key derivation failed");
        }
        secret.resize(secretLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        return makeUint8Array(runtime, std::move(secret));
      });
  rt.global().setProperty(rt, "__exactX25519DeriveBits", std::move(x25519DeriveFn));

  // --- Export Key to SPKI (SubjectPublicKeyInfo DER) ---
  // __exactExportKeySpki(keyType, keyData) -> Uint8Array (DER-encoded SPKI)
  auto exportSpkiFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactExportKeySpki"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactExportKeySpki: keyType and keyData required");
        }
        auto keyType = args[0].asString(runtime).utf8(runtime);
        auto keyData = extractBytes(runtime, args[1]);

        EVP_PKEY* pkey = nullptr;

        // Try to import the key based on type
        if (keyType == "ed25519" && keyData.size() == 32) {
          pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, keyData.data(), keyData.size());
        } else if (keyType == "x25519" && keyData.size() == 32) {
          pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, keyData.data(), keyData.size());
        }

        if (!pkey) {
          // Try PEM format
          BIO* bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.size()));
          if (bio) {
            pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          // Try DER SPKI format (already SPKI - just pass through)
          const unsigned char* p = keyData.data();
          pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(keyData.size()));
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactExportKeySpki: failed to import public key");
        }

        // Export to DER SPKI
        unsigned char* der = nullptr;
        int derLen = i2d_PUBKEY(pkey, &der);
        EVP_PKEY_free(pkey);
        if (derLen <= 0 || !der) {
          if (der) OPENSSL_free(der);
          throw facebook::jsi::JSError(runtime, "__exactExportKeySpki: failed to export SPKI");
        }

        std::vector<uint8_t> result(der, der + derLen);
        OPENSSL_free(der);
        return makeUint8Array(runtime, std::move(result));
      });
  rt.global().setProperty(rt, "__exactExportKeySpki", std::move(exportSpkiFn));

  // --- Export Key to PKCS8 (PrivateKeyInfo DER) ---
  // __exactExportKeyPkcs8(keyType, keyData) -> Uint8Array (DER-encoded PKCS8)
  auto exportPkcs8Fn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactExportKeyPkcs8"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactExportKeyPkcs8: keyType and keyData required");
        }
        auto keyType = args[0].asString(runtime).utf8(runtime);
        auto keyData = extractBytes(runtime, args[1]);

        EVP_PKEY* pkey = nullptr;

        // Try raw key import for Ed25519/X25519
        if (keyType == "ed25519" && keyData.size() == 32) {
          pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, keyData.data(), keyData.size());
        } else if (keyType == "x25519" && keyData.size() == 32) {
          pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, keyData.data(), keyData.size());
        }

        if (!pkey) {
          // Try PEM format
          BIO* bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.size()));
          if (bio) {
            pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          // Try DER PKCS8 format
          const unsigned char* p = keyData.data();
          PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, static_cast<long>(keyData.size()));
          if (p8) {
            pkey = EVP_PKCS82PKEY(p8);
            PKCS8_PRIV_KEY_INFO_free(p8);
          }
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactExportKeyPkcs8: failed to import private key");
        }

        // Export to PKCS8 DER
        PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(pkey);
        EVP_PKEY_free(pkey);
        if (!p8) {
          throw facebook::jsi::JSError(runtime, "__exactExportKeyPkcs8: failed to create PKCS8 structure");
        }

        unsigned char* der = nullptr;
        int derLen = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
        PKCS8_PRIV_KEY_INFO_free(p8);
        if (derLen <= 0 || !der) {
          if (der) OPENSSL_free(der);
          throw facebook::jsi::JSError(runtime, "__exactExportKeyPkcs8: failed to export PKCS8");
        }

        std::vector<uint8_t> result(der, der + derLen);
        OPENSSL_free(der);
        return makeUint8Array(runtime, std::move(result));
      });
  rt.global().setProperty(rt, "__exactExportKeyPkcs8", std::move(exportPkcs8Fn));

  // --- Import Key from SPKI (SubjectPublicKeyInfo DER) ---
  // __exactImportKeySpki(keyData) -> { keyType: string, rawKeyData: Uint8Array }
  auto importSpkiFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactImportKeySpki"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1) {
          throw facebook::jsi::JSError(runtime, "__exactImportKeySpki: keyData required");
        }
        auto keyData = extractBytes(runtime, args[0]);

        // Parse DER SPKI
        const unsigned char* p = keyData.data();
        EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(keyData.size()));
        if (!pkey) {
          // Try PEM
          BIO* bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.size()));
          if (bio) {
            pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactImportKeySpki: failed to parse SPKI key data");
        }

        // Determine key type
        std::string keyTypeStr;
        int pkeyType = EVP_PKEY_base_id(pkey);
        std::vector<uint8_t> rawKey;

        if (pkeyType == EVP_PKEY_ED25519) {
          keyTypeStr = "ed25519";
          size_t len = 32;
          rawKey.resize(len);
          if (EVP_PKEY_get_raw_public_key(pkey, rawKey.data(), &len) != 1) {
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactImportKeySpki: failed to extract Ed25519 public key");
          }
          rawKey.resize(len);
        } else if (pkeyType == EVP_PKEY_X25519) {
          keyTypeStr = "x25519";
          size_t len = 32;
          rawKey.resize(len);
          if (EVP_PKEY_get_raw_public_key(pkey, rawKey.data(), &len) != 1) {
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactImportKeySpki: failed to extract X25519 public key");
          }
          rawKey.resize(len);
        } else if (pkeyType == EVP_PKEY_EC) {
          keyTypeStr = "ec";
          // Export the full SPKI DER as rawKeyData (the caller can use it as-is)
          unsigned char* der = nullptr;
          int derLen = i2d_PUBKEY(pkey, &der);
          if (derLen > 0 && der) {
            rawKey.assign(der, der + derLen);
            OPENSSL_free(der);
          }
        } else if (pkeyType == EVP_PKEY_RSA) {
          keyTypeStr = "rsa";
          unsigned char* der = nullptr;
          int derLen = i2d_PUBKEY(pkey, &der);
          if (derLen > 0 && der) {
            rawKey.assign(der, der + derLen);
            OPENSSL_free(der);
          }
        } else {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactImportKeySpki: unsupported key type in SPKI");
        }

        EVP_PKEY_free(pkey);

        facebook::jsi::Object result(runtime);
        result.setProperty(runtime, "keyType", facebook::jsi::String::createFromUtf8(runtime, keyTypeStr));
        result.setProperty(runtime, "rawKeyData", makeUint8Array(runtime, std::move(rawKey)));
        return result;
      });
  rt.global().setProperty(rt, "__exactImportKeySpki", std::move(importSpkiFn));

  // --- Import Key from PKCS8 (PrivateKeyInfo DER) ---
  // __exactImportKeyPkcs8(keyData) -> { keyType: string, rawKeyData: Uint8Array }
  auto importPkcs8Fn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactImportKeyPkcs8"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1) {
          throw facebook::jsi::JSError(runtime, "__exactImportKeyPkcs8: keyData required");
        }
        auto keyData = extractBytes(runtime, args[0]);

        // Parse DER PKCS8
        EVP_PKEY* pkey = nullptr;
        {
          const unsigned char* p = keyData.data();
          PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, static_cast<long>(keyData.size()));
          if (p8) {
            pkey = EVP_PKCS82PKEY(p8);
            PKCS8_PRIV_KEY_INFO_free(p8);
          }
        }
        if (!pkey) {
          // Try PEM
          BIO* bio = BIO_new_mem_buf(keyData.data(), static_cast<int>(keyData.size()));
          if (bio) {
            pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactImportKeyPkcs8: failed to parse PKCS8 key data");
        }

        // Determine key type
        std::string keyTypeStr;
        int pkeyType = EVP_PKEY_base_id(pkey);
        std::vector<uint8_t> rawKey;

        if (pkeyType == EVP_PKEY_ED25519) {
          keyTypeStr = "ed25519";
          size_t len = 32;
          rawKey.resize(len);
          if (EVP_PKEY_get_raw_private_key(pkey, rawKey.data(), &len) != 1) {
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactImportKeyPkcs8: failed to extract Ed25519 private key");
          }
          rawKey.resize(len);
        } else if (pkeyType == EVP_PKEY_X25519) {
          keyTypeStr = "x25519";
          size_t len = 32;
          rawKey.resize(len);
          if (EVP_PKEY_get_raw_private_key(pkey, rawKey.data(), &len) != 1) {
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactImportKeyPkcs8: failed to extract X25519 private key");
          }
          rawKey.resize(len);
        } else if (pkeyType == EVP_PKEY_EC) {
          keyTypeStr = "ec";
          // Export as PKCS8 DER
          PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(pkey);
          if (p8) {
            unsigned char* der = nullptr;
            int derLen = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
            PKCS8_PRIV_KEY_INFO_free(p8);
            if (derLen > 0 && der) {
              rawKey.assign(der, der + derLen);
              OPENSSL_free(der);
            }
          }
        } else if (pkeyType == EVP_PKEY_RSA) {
          keyTypeStr = "rsa";
          PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(pkey);
          if (p8) {
            unsigned char* der = nullptr;
            int derLen = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
            PKCS8_PRIV_KEY_INFO_free(p8);
            if (derLen > 0 && der) {
              rawKey.assign(der, der + derLen);
              OPENSSL_free(der);
            }
          }
        } else {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactImportKeyPkcs8: unsupported key type in PKCS8");
        }

        EVP_PKEY_free(pkey);

        facebook::jsi::Object result(runtime);
        result.setProperty(runtime, "keyType", facebook::jsi::String::createFromUtf8(runtime, keyTypeStr));
        result.setProperty(runtime, "rawKeyData", makeUint8Array(runtime, std::move(rawKey)));
        return result;
      });
  rt.global().setProperty(rt, "__exactImportKeyPkcs8", std::move(importPkcs8Fn));
#endif // !EXACT_NO_OPENSSL

  // --- HKDF (RFC 5869) ---
  // __exactHkdf(hashAlgo, ikm, salt, info, length) -> Uint8Array
  auto hkdfFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactHkdf"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 5) throw facebook::jsi::JSError(runtime, "__exactHkdf: hashAlgo, ikm, salt, info, length required");
        auto hashAlgo = args[0].asString(runtime).utf8(runtime);
        auto ikm = extractBytes(runtime, args[1]);
        auto salt = extractBytes(runtime, args[2]);
        auto info = extractBytes(runtime, args[3]);
        auto length = static_cast<size_t>(args[4].asNumber());

#if defined(__APPLE__)
        CCHmacAlgorithm ccAlgo;
        size_t hashLen;
        if (hashAlgo == "SHA-256" || hashAlgo == "sha256" || hashAlgo == "sha-256") {
          ccAlgo = kCCHmacAlgSHA256; hashLen = CC_SHA256_DIGEST_LENGTH;
        } else if (hashAlgo == "SHA-1" || hashAlgo == "sha1" || hashAlgo == "sha-1") {
          ccAlgo = kCCHmacAlgSHA1; hashLen = CC_SHA1_DIGEST_LENGTH;
        } else if (hashAlgo == "SHA-384" || hashAlgo == "sha384" || hashAlgo == "sha-384") {
          ccAlgo = kCCHmacAlgSHA384; hashLen = CC_SHA384_DIGEST_LENGTH;
        } else if (hashAlgo == "SHA-512" || hashAlgo == "sha512" || hashAlgo == "sha-512") {
          ccAlgo = kCCHmacAlgSHA512; hashLen = CC_SHA512_DIGEST_LENGTH;
        } else {
          throw facebook::jsi::JSError(runtime, "__exactHkdf: unsupported hash algorithm: " + hashAlgo);
        }

        // If salt is empty, use a hash-length block of zeros
        std::vector<uint8_t> actualSalt;
        if (salt.empty()) {
          actualSalt.resize(hashLen, 0);
        } else {
          actualSalt = std::move(salt);
        }

        // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
        std::vector<uint8_t> prk(hashLen);
        CCHmac(ccAlgo, actualSalt.data(), actualSalt.size(),
               ikm.data(), ikm.size(), prk.data());

        // HKDF-Expand
        size_t n = (length + hashLen - 1) / hashLen;
        std::vector<uint8_t> okm;
        okm.reserve(n * hashLen);
        std::vector<uint8_t> prev;

        for (size_t i = 1; i <= n; i++) {
          // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
          std::vector<uint8_t> input;
          input.insert(input.end(), prev.begin(), prev.end());
          input.insert(input.end(), info.begin(), info.end());
          input.push_back(static_cast<uint8_t>(i));

          prev.resize(hashLen);
          CCHmac(ccAlgo, prk.data(), prk.size(),
                 input.data(), input.size(), prev.data());
          okm.insert(okm.end(), prev.begin(), prev.end());
        }
        okm.resize(length);
        return makeUint8Array(runtime, std::move(okm));
#else
        // OpenSSL path
        const EVP_MD* md = nullptr;
        if (hashAlgo == "SHA-256" || hashAlgo == "sha256" || hashAlgo == "sha-256") md = EVP_sha256();
        else if (hashAlgo == "SHA-1" || hashAlgo == "sha1" || hashAlgo == "sha-1") md = EVP_sha1();
        else if (hashAlgo == "SHA-384" || hashAlgo == "sha384" || hashAlgo == "sha-384") md = EVP_sha384();
        else if (hashAlgo == "SHA-512" || hashAlgo == "sha512" || hashAlgo == "sha-512") md = EVP_sha512();
        else throw facebook::jsi::JSError(runtime, "__exactHkdf: unsupported hash algorithm: " + hashAlgo);

        size_t hashLen = static_cast<size_t>(EVP_MD_size(md));

        std::vector<uint8_t> actualSalt;
        if (salt.empty()) {
          actualSalt.resize(hashLen, 0);
        } else {
          actualSalt = std::move(salt);
        }

        // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
        unsigned int prkLen = 0;
        std::vector<uint8_t> prk(EVP_MAX_MD_SIZE);
        HMAC(md, actualSalt.data(), actualSalt.size(),
             ikm.data(), ikm.size(), prk.data(), &prkLen);
        prk.resize(prkLen);

        // HKDF-Expand
        size_t n = (length + hashLen - 1) / hashLen;
        std::vector<uint8_t> okm;
        okm.reserve(n * hashLen);
        std::vector<uint8_t> prev;

        for (size_t i = 1; i <= n; i++) {
          std::vector<uint8_t> input;
          input.insert(input.end(), prev.begin(), prev.end());
          input.insert(input.end(), info.begin(), info.end());
          input.push_back(static_cast<uint8_t>(i));

          unsigned int tLen = 0;
          prev.resize(EVP_MAX_MD_SIZE);
          HMAC(md, prk.data(), prk.size(),
               input.data(), input.size(), prev.data(), &tLen);
          prev.resize(tLen);
          okm.insert(okm.end(), prev.begin(), prev.end());
        }
        okm.resize(length);
        return makeUint8Array(runtime, std::move(okm));
#endif
      });
  rt.global().setProperty(rt, "__exactHkdf", std::move(hkdfFn));

#if !defined(EXACT_NO_OPENSSL)
  // --- ECDH DeriveBits for NIST curves ---
  // __exactEcdhDeriveBits(curve, privateKeyBytes, publicKeyBytes) -> Uint8Array
  auto ecdhDeriveFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactEcdhDeriveBits"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3) {
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: curve, privateKey, and publicKey required");
        }
        auto curve = args[0].asString(runtime).utf8(runtime);
        auto privKeyBytes = extractBytes(runtime, args[1]);
        auto pubKeyBytes = extractBytes(runtime, args[2]);

        // Map curve name to NID
        int nid = 0;
        if (curve == "P-256" || curve == "prime256v1") nid = NID_X9_62_prime256v1;
        else if (curve == "P-384" || curve == "secp384r1") nid = NID_secp384r1;
        else if (curve == "P-521" || curve == "secp521r1") nid = NID_secp521r1;
        else {
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: unsupported curve " + curve);
        }

        // Import private key - try PEM first, then raw DER
        EVP_PKEY* privKey = nullptr;
        {
          BIO* bio = BIO_new_mem_buf(privKeyBytes.data(), static_cast<int>(privKeyBytes.size()));
          if (bio) {
            privKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!privKey) {
          // Try DER
          const unsigned char* p = privKeyBytes.data();
          privKey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, static_cast<long>(privKeyBytes.size()));
        }
        if (!privKey) {
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: failed to import EC private key");
        }

        // Import public key - try PEM first, then raw uncompressed point, then DER
        EVP_PKEY* pubKey = nullptr;
        {
          BIO* bio = BIO_new_mem_buf(pubKeyBytes.data(), static_cast<int>(pubKeyBytes.size()));
          if (bio) {
            pubKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
          }
        }
        if (!pubKey) {
          // Try DER/SPKI
          const unsigned char* p = pubKeyBytes.data();
          pubKey = d2i_PUBKEY(nullptr, &p, static_cast<long>(pubKeyBytes.size()));
        }
        if (!pubKey && pubKeyBytes.size() > 0 && pubKeyBytes[0] == 0x04) {
          // Try as raw uncompressed point using modern EVP_PKEY_fromdata API
          const char* groupName = nullptr;
          if (nid == NID_X9_62_prime256v1) groupName = "P-256";
          else if (nid == NID_secp384r1) groupName = "P-384";
          else if (nid == NID_secp521r1) groupName = "P-521";
          if (groupName) {
            OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
            if (bld) {
              OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, groupName, 0);
              OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                  pubKeyBytes.data(), pubKeyBytes.size());
              OSSL_PARAM* osslParams = OSSL_PARAM_BLD_to_param(bld);
              if (osslParams) {
                EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
                if (pctx) {
                  EVP_PKEY_fromdata_init(pctx);
                  EVP_PKEY_fromdata(pctx, &pubKey, EVP_PKEY_PUBLIC_KEY, osslParams);
                  EVP_PKEY_CTX_free(pctx);
                }
                OSSL_PARAM_free(osslParams);
              }
              OSSL_PARAM_BLD_free(bld);
            }
          }
        }
        if (!pubKey) {
          EVP_PKEY_free(privKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: failed to import EC public key");
        }

        // Derive shared secret
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, nullptr);
        if (!ctx) {
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: failed to create derive context");
        }

        if (EVP_PKEY_derive_init(ctx) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: derive init failed");
        }

        if (EVP_PKEY_derive_set_peer(ctx, pubKey) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: failed to set peer key");
        }

        size_t secretLen = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secretLen) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: failed to get secret length");
        }

        std::vector<uint8_t> secret(secretLen);
        if (EVP_PKEY_derive(ctx, secret.data(), &secretLen) != 1) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(privKey);
          EVP_PKEY_free(pubKey);
          throw facebook::jsi::JSError(runtime, "__exactEcdhDeriveBits: key derivation failed");
        }
        secret.resize(secretLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(pubKey);
        return makeUint8Array(runtime, std::move(secret));
      });
  rt.global().setProperty(rt, "__exactEcdhDeriveBits", std::move(ecdhDeriveFn));

  // --- RSA-OAEP Encrypt ---
  // __exactRsaOaepEncrypt(publicKeyData, hashAlgorithm, label, plaintext) -> Uint8Array (ciphertext)
  auto rsaOaepEncryptFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRsaOaepEncrypt"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: publicKeyData, hashAlgorithm, label, and plaintext required");
        }

        auto keyBytes = extractBytes(runtime, args[0]);
        auto hashAlgorithm = args[1].asString(runtime).utf8(runtime);
        auto labelBytes = extractBytes(runtime, args[2]);
        auto plaintext = extractBytes(runtime, args[3]);

        // Select hash algorithm for OAEP (Web Crypto style names: SHA-1, SHA-256, SHA-384, SHA-512)
        const EVP_MD* md = nullptr;
        if (hashAlgorithm == "SHA-1" || hashAlgorithm == "sha-1" || hashAlgorithm == "sha1") md = EVP_sha1();
        else if (hashAlgorithm == "SHA-256" || hashAlgorithm == "sha-256" || hashAlgorithm == "sha256") md = EVP_sha256();
        else if (hashAlgorithm == "SHA-384" || hashAlgorithm == "sha-384" || hashAlgorithm == "sha384") md = EVP_sha384();
        else if (hashAlgorithm == "SHA-512" || hashAlgorithm == "sha-512" || hashAlgorithm == "sha512") md = EVP_sha512();
        if (!md) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: unsupported hash algorithm " + hashAlgorithm);
        }

        // Import public key from PEM
        BIO* keyBio = BIO_new_mem_buf(keyBytes.data(), static_cast<int>(keyBytes.size()));
        if (!keyBio) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to allocate key BIO");
        }
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(keyBio, nullptr, nullptr, nullptr);
        BIO_free(keyBio);
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: invalid PEM public key");
        }

        // Create encryption context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to create context");
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: EVP_PKEY_encrypt_init failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to set OAEP padding: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to set OAEP hash: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        // Set MGF1 hash to match OAEP hash (Web Crypto spec requires this)
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to set MGF1 hash: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        // Set OAEP label if provided
        if (!labelBytes.empty()) {
          // OpenSSL takes ownership of the label buffer, so we must allocate with OPENSSL_malloc
          unsigned char* labelCopy = static_cast<unsigned char*>(OPENSSL_malloc(labelBytes.size()));
          if (!labelCopy) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to allocate label");
          }
          memcpy(labelCopy, labelBytes.data(), labelBytes.size());
          if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, labelCopy, static_cast<int>(labelBytes.size())) <= 0) {
            OPENSSL_free(labelCopy);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to set OAEP label: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
          }
          // labelCopy ownership transferred to ctx - do NOT free
        }

        // Determine output size
        size_t outLen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, plaintext.data(), plaintext.size()) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: failed to get output size: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        std::vector<uint8_t> ciphertext(outLen);
        if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outLen, plaintext.data(), plaintext.size()) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepEncrypt: encryption failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        ciphertext.resize(outLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return makeUint8Array(runtime, std::move(ciphertext));
      });
  rt.global().setProperty(rt, "__exactRsaOaepEncrypt", std::move(rsaOaepEncryptFn));

  // --- RSA-OAEP Decrypt ---
  // __exactRsaOaepDecrypt(privateKeyData, hashAlgorithm, label, ciphertext) -> Uint8Array (plaintext)
  auto rsaOaepDecryptFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRsaOaepDecrypt"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 4) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: privateKeyData, hashAlgorithm, label, and ciphertext required");
        }

        auto keyBytes = extractBytes(runtime, args[0]);
        auto hashAlgorithm = args[1].asString(runtime).utf8(runtime);
        auto labelBytes = extractBytes(runtime, args[2]);
        auto ciphertext = extractBytes(runtime, args[3]);

        // Select hash algorithm for OAEP (Web Crypto style names: SHA-1, SHA-256, SHA-384, SHA-512)
        const EVP_MD* md = nullptr;
        if (hashAlgorithm == "SHA-1" || hashAlgorithm == "sha-1" || hashAlgorithm == "sha1") md = EVP_sha1();
        else if (hashAlgorithm == "SHA-256" || hashAlgorithm == "sha-256" || hashAlgorithm == "sha256") md = EVP_sha256();
        else if (hashAlgorithm == "SHA-384" || hashAlgorithm == "sha-384" || hashAlgorithm == "sha384") md = EVP_sha384();
        else if (hashAlgorithm == "SHA-512" || hashAlgorithm == "sha-512" || hashAlgorithm == "sha512") md = EVP_sha512();
        if (!md) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: unsupported hash algorithm " + hashAlgorithm);
        }

        // Import private key from PEM
        BIO* keyBio = BIO_new_mem_buf(keyBytes.data(), static_cast<int>(keyBytes.size()));
        if (!keyBio) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to allocate key BIO");
        }
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
        BIO_free(keyBio);
        if (!pkey) {
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: invalid PEM private key");
        }

        // Create decryption context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) {
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to create context");
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: EVP_PKEY_decrypt_init failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to set OAEP padding: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to set OAEP hash: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        // Set MGF1 hash to match OAEP hash (Web Crypto spec requires this)
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to set MGF1 hash: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        // Set OAEP label if provided
        if (!labelBytes.empty()) {
          // OpenSSL takes ownership of the label buffer, so we must allocate with OPENSSL_malloc
          unsigned char* labelCopy = static_cast<unsigned char*>(OPENSSL_malloc(labelBytes.size()));
          if (!labelCopy) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to allocate label");
          }
          memcpy(labelCopy, labelBytes.data(), labelBytes.size());
          if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, labelCopy, static_cast<int>(labelBytes.size())) <= 0) {
            OPENSSL_free(labelCopy);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to set OAEP label: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
          }
          // labelCopy ownership transferred to ctx - do NOT free
        }

        // Determine output size
        size_t outLen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, ciphertext.data(), ciphertext.size()) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: failed to get output size: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }

        std::vector<uint8_t> plaintext(outLen);
        if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outLen, ciphertext.data(), ciphertext.size()) <= 0) {
          EVP_PKEY_CTX_free(ctx);
          EVP_PKEY_free(pkey);
          throw facebook::jsi::JSError(runtime, "__exactRsaOaepDecrypt: decryption failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
        }
        plaintext.resize(outLen);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return makeUint8Array(runtime, std::move(plaintext));
      });
  rt.global().setProperty(rt, "__exactRsaOaepDecrypt", std::move(rsaOaepDecryptFn));
#endif // !EXACT_NO_OPENSSL

  // --- Zlib: sync compress/decompress ---
  // __exactDeflateSync(data, level, mode) -> Uint8Array
  // mode: 0 = deflate (zlib header, windowBits=15), 1 = gzip (windowBits=15+16), 2 = raw (windowBits=-15)
  auto deflateSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDeflateSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, "__exactDeflateSync: data required");
        }

        auto input = extractBytes(runtime, args[0]);

        int level = Z_DEFAULT_COMPRESSION;
        if (count > 1 && args[1].isNumber()) {
          level = static_cast<int>(args[1].asNumber());
        }
        int mode = 0; // 0=deflate, 1=gzip, 2=raw
        if (count > 2 && args[2].isNumber()) {
          mode = static_cast<int>(args[2].asNumber());
        }

        // deflate
        z_stream strm = {};
        int windowBits;
        if (mode == 2) {
          windowBits = -15; // raw deflate: no header, no checksum
        } else if (mode == 1) {
          windowBits = 15 + 16; // gzip header
        } else {
          windowBits = 15; // zlib header (default)
        }
        if (deflateInit2(&strm, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
          throw facebook::jsi::JSError(runtime, "deflateInit2 failed");
        }

        strm.next_in = input.data();
        strm.avail_in = static_cast<uInt>(input.size());

        std::vector<uint8_t> output;
        uint8_t outBuf[32768];
        do {
          strm.next_out = outBuf;
          strm.avail_out = sizeof(outBuf);
          deflate(&strm, Z_FINISH);
          size_t have = sizeof(outBuf) - strm.avail_out;
          output.insert(output.end(), outBuf, outBuf + have);
        } while (strm.avail_out == 0);
        deflateEnd(&strm);

        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactDeflateSync", std::move(deflateSyncFn));

  // __exactInflateSync(data, mode) -> Uint8Array
  // mode: 0 = deflate (zlib header, windowBits=15), 1 = gzip (windowBits=15+32), 2 = raw (windowBits=-15)
  auto inflateSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactInflateSync"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, "__exactInflateSync: data required");
        }

        auto input = extractBytes(runtime, args[0]);

        int mode = 0; // 0=deflate, 1=gzip, 2=raw
        if (count > 1 && args[1].isNumber()) {
          mode = static_cast<int>(args[1].asNumber());
        }

        z_stream strm = {};
        int windowBits;
        if (mode == 2) {
          windowBits = -15; // raw inflate: no header expected
        } else if (mode == 1) {
          windowBits = 15 + 32; // auto-detect gzip/deflate
        } else {
          windowBits = 15; // zlib header (default)
        }
        if (inflateInit2(&strm, windowBits) != Z_OK) {
          throw facebook::jsi::JSError(runtime, "inflateInit2 failed");
        }

        strm.next_in = input.data();
        strm.avail_in = static_cast<uInt>(input.size());

        std::vector<uint8_t> output;
        uint8_t outBuf[32768];
        int ret;
        do {
          strm.next_out = outBuf;
          strm.avail_out = sizeof(outBuf);
          ret = inflate(&strm, Z_NO_FLUSH);
          if (ret == Z_MEM_ERROR || ret == Z_DATA_ERROR) {
            inflateEnd(&strm);
            throw facebook::jsi::JSError(runtime, "inflate failed: data error");
          }
          size_t have = sizeof(outBuf) - strm.avail_out;
          output.insert(output.end(), outBuf, outBuf + have);
        } while (ret != Z_STREAM_END && strm.avail_out == 0);
        inflateEnd(&strm);

        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactInflateSync", std::move(inflateSyncFn));

#if !defined(EXACT_NO_BROTLI)
  // --- Brotli: sync compress/decompress ---
  // __exactBrotliCompressSync(data, quality) -> Uint8Array
  // quality: 0-11, default BROTLI_DEFAULT_QUALITY (11)
  auto brotliCompressSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactBrotliCompressSync"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, "__exactBrotliCompressSync: data required");
        }

        auto input = extractBytes(runtime, args[0]);

        int quality = BROTLI_DEFAULT_QUALITY;
        if (count > 1 && args[1].isNumber()) {
          quality = static_cast<int>(args[1].asNumber());
          if (quality < BROTLI_MIN_QUALITY) quality = BROTLI_MIN_QUALITY;
          if (quality > BROTLI_MAX_QUALITY) quality = BROTLI_MAX_QUALITY;
        }

        size_t maxSize = BrotliEncoderMaxCompressedSize(input.size());
        if (maxSize == 0) {
          // BrotliEncoderMaxCompressedSize returns 0 for very large inputs;
          // use a generous estimate
          maxSize = input.size() + (input.size() >> 2) + 1024;
        }
        std::vector<uint8_t> output(maxSize);
        size_t encodedSize = maxSize;

        BROTLI_BOOL ok = BrotliEncoderCompress(
            quality,
            BROTLI_DEFAULT_WINDOW,
            BROTLI_DEFAULT_MODE,
            input.size(),
            input.data(),
            &encodedSize,
            output.data());

        if (!ok) {
          throw facebook::jsi::JSError(runtime, "BrotliEncoderCompress failed");
        }

        output.resize(encodedSize);
        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactBrotliCompressSync", std::move(brotliCompressSyncFn));

  // __exactBrotliDecompressSync(data) -> Uint8Array
  auto brotliDecompressSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactBrotliDecompressSync"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, "__exactBrotliDecompressSync: data required");
        }

        auto input = extractBytes(runtime, args[0]);

        // Use streaming decoder for unknown output size
        BrotliDecoderState* state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
        if (!state) {
          throw facebook::jsi::JSError(runtime, "BrotliDecoderCreateInstance failed");
        }

        std::vector<uint8_t> output;
        const uint8_t* nextIn = input.data();
        size_t availableIn = input.size();
        BrotliDecoderResult result;

        do {
          uint8_t outBuf[32768];
          uint8_t* nextOut = outBuf;
          size_t availableOut = sizeof(outBuf);

          result = BrotliDecoderDecompressStream(
              state,
              &availableIn,
              &nextIn,
              &availableOut,
              &nextOut,
              nullptr);

          size_t have = sizeof(outBuf) - availableOut;
          output.insert(output.end(), outBuf, outBuf + have);

          if (result == BROTLI_DECODER_RESULT_ERROR) {
            BrotliDecoderDestroyInstance(state);
            throw facebook::jsi::JSError(runtime, "BrotliDecoderDecompressStream failed: corrupt data");
          }
        } while (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);

        BrotliDecoderDestroyInstance(state);

        if (result != BROTLI_DECODER_RESULT_SUCCESS) {
          throw facebook::jsi::JSError(runtime, "Brotli decompression failed: incomplete data");
        }

        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactBrotliDecompressSync", std::move(brotliDecompressSyncFn));
#endif // !EXACT_NO_BROTLI

  // --- Signal handling setup ---
  // __exactPollSignal() -> signal number or 0
  auto pollSignalFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactPollSignal"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        int sig = g_pending_signal.exchange(0, std::memory_order_relaxed);
        return facebook::jsi::Value(sig);
      });
  rt.global().setProperty(rt, "__exactPollSignal", std::move(pollSignalFn));

  // __exactTrapSignal(signalNumber) -> void
  auto trapSignalFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTrapSignal"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTrapSignal: signal number required");
        }
        int sig = static_cast<int>(args[0].asNumber());
        struct sigaction sa = {};
        sa.sa_handler = signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        sigaction(sig, &sa, nullptr);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactTrapSignal", std::move(trapSignalFn));

  // __exactResetSignal(signalNumber) -> void (restore default handler)
  auto resetSignalFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactResetSignal"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactResetSignal: signal number required");
        }
        int sig = static_cast<int>(args[0].asNumber());
        struct sigaction sa = {};
        sa.sa_handler = SIG_DFL;
        sigemptyset(&sa.sa_mask);
        sigaction(sig, &sa, nullptr);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactResetSignal", std::move(resetSignalFn));

  // --- Stdin reading ---
  // __exactStdinRead(maxBytes) -> string or null (EOF/no data)
  // Non-blocking read from fd 0. Returns null when no data available or EOF.
  auto stdinReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactStdinRead"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        size_t maxBytes = 4096;
        if (count > 0 && args[0].isNumber()) {
          maxBytes = static_cast<size_t>(args[0].asNumber());
          if (maxBytes == 0) maxBytes = 4096;
          if (maxBytes > 65536) maxBytes = 65536;
        }

        // Set stdin to non-blocking
        int flags = fcntl(0, F_GETFL, 0);
        if (flags == -1) return facebook::jsi::Value::null();
        fcntl(0, F_SETFL, flags | O_NONBLOCK);

        std::vector<char> buf(maxBytes);
        ssize_t nread = ::read(0, buf.data(), maxBytes);

        // Restore blocking mode
        fcntl(0, F_SETFL, flags);

        if (nread < 0) {
          // EAGAIN/EWOULDBLOCK means no data available (not an error)
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return facebook::jsi::Value::null();
          }
          // Real error
          return facebook::jsi::Value::null();
        }
        if (nread == 0) {
          // EOF — return empty string to distinguish from "no data"
          return facebook::jsi::String::createFromUtf8(runtime, "");
        }

        return facebook::jsi::String::createFromUtf8(
            runtime, reinterpret_cast<const uint8_t*>(buf.data()), nread);
      });
  rt.global().setProperty(rt, "__exactStdinRead", std::move(stdinReadFn));

  // --- DNS lookup ---
  // __exactDnsLookup(hostname, family) -> JSON string { address, family }
  auto dnsLookupFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactDnsLookup"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactDnsLookup: hostname required");
        }
        auto hostname = args[0].asString(runtime).utf8(runtime);
        int family = 0; // 0 = any, 4 = IPv4, 6 = IPv6
        if (count > 1 && args[1].isNumber()) {
          family = static_cast<int>(args[1].asNumber());
        }

        struct addrinfo hints = {};
        hints.ai_socktype = SOCK_STREAM;
        if (family == 4) hints.ai_family = AF_INET;
        else if (family == 6) hints.ai_family = AF_INET6;
        else hints.ai_family = AF_UNSPEC;

        struct addrinfo* result = nullptr;
        int ret = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
        if (ret != 0 || !result) {
          if (result) freeaddrinfo(result);
          throw facebook::jsi::JSError(runtime,
              std::string("getaddrinfo failed for ") + hostname + ": " + gai_strerror(ret));
        }

        // Build JSON result
        std::string json = "[";
        bool first = true;
        for (struct addrinfo* p = result; p != nullptr; p = p->ai_next) {
          char addr[INET6_ADDRSTRLEN] = {};
          int fam = 4;
          if (p->ai_family == AF_INET) {
            struct sockaddr_in* sa = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
            inet_ntop(AF_INET, &sa->sin_addr, addr, sizeof(addr));
            fam = 4;
          } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6* sa = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
            inet_ntop(AF_INET6, &sa->sin6_addr, addr, sizeof(addr));
            fam = 6;
          } else {
            continue;
          }
          if (!first) json += ",";
          json += "{\"address\":\"" + std::string(addr) + "\",\"family\":" + std::to_string(fam) + "}";
          first = false;
        }
        json += "]";
        freeaddrinfo(result);

        return facebook::jsi::String::createFromUtf8(runtime, json);
      });
  rt.global().setProperty(rt, "__exactDnsLookup", std::move(dnsLookupFn));

  // __exactDnsResolve(hostname, rrtype) -> JSON array via res_query
  auto dnsResolveFn = facebook::jsi::Function::createFromHostFunction(rt, facebook::jsi::PropNameID::forAscii(rt, "__exactDnsResolve"), 2, [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&, const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
    if (count < 2 || !args[0].isString() || !args[1].isString()) throw facebook::jsi::JSError(runtime, "__exactDnsResolve requires hostname and rrtype");
    auto hostname = args[0].asString(runtime).utf8(runtime);
    auto rrtype = args[1].asString(runtime).utf8(runtime);
    int qtype = 0;
    if (rrtype == "MX") qtype = ns_t_mx;
    else if (rrtype == "TXT") qtype = ns_t_txt;
    else if (rrtype == "SRV") qtype = ns_t_srv;
    else if (rrtype == "NS") qtype = ns_t_ns;
    else if (rrtype == "CNAME") qtype = ns_t_cname;
    else if (rrtype == "SOA") qtype = ns_t_soa;
    else if (rrtype == "PTR") qtype = ns_t_ptr;
    else if (rrtype == "CAA") qtype = 257;
    else if (rrtype == "NAPTR") qtype = ns_t_naptr;
    else throw facebook::jsi::JSError(runtime, ("unsupported record type: " + rrtype).c_str());
    unsigned char answer[4096];
    int len = res_query(hostname.c_str(), ns_c_in, qtype, answer, sizeof(answer));
    if (len < 0) throw facebook::jsi::JSError(runtime, ("DNS query failed for " + hostname + " type " + rrtype).c_str());
    ns_msg msg;
    if (ns_initparse(answer, len, &msg) < 0) throw facebook::jsi::JSError(runtime, "Failed to parse DNS response");
    int rrCount = ns_msg_count(msg, ns_s_an);
    std::string json = "[";
    bool first = true;
    for (int i = 0; i < rrCount; i++) {
      ns_rr rr;
      if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) continue;
      if (ns_rr_type(rr) != qtype) continue;
      const unsigned char* rdata = ns_rr_rdata(rr);
      int rdlen = ns_rr_rdlen(rr);
      if (!first) json += ",";
      first = false;
      if (qtype == ns_t_mx) {
        if (rdlen < 3) { first = true; continue; }
        int prio = (rdata[0] << 8) | rdata[1];
        char ex[NS_MAXDNAME];
        if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata + 2, ex, sizeof(ex)) < 0) { first = true; continue; }
        std::string e(ex); if (!e.empty() && e.back() == '.') e.pop_back();
        json += "{\"priority\":" + std::to_string(prio) + ",\"exchange\":\"" + e + "\"}";
      } else if (qtype == ns_t_txt) {
        std::string ta = "["; bool ft = true; int p = 0;
        while (p < rdlen) { int sl = static_cast<unsigned char>(rdata[p]); p++; if (p+sl>rdlen) break; if (!ft) ta += ","; ft = false; std::string t; for (int j=0;j<sl;j++){char c=static_cast<char>(rdata[p+j]);if(c=='"')t+="\\\"";else if(c=='\\')t+="\\\\";else t+=c;} ta += "\"" + t + "\""; p += sl; }
        ta += "]"; json += ta;
      } else if (qtype == ns_t_srv) {
        if (rdlen < 7) { first = true; continue; }
        int prio = (rdata[0]<<8)|rdata[1]; int wt = (rdata[2]<<8)|rdata[3]; int pt = (rdata[4]<<8)|rdata[5];
        char tg[NS_MAXDNAME];
        if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata+6, tg, sizeof(tg)) < 0) { first = true; continue; }
        std::string tgt(tg); if (!tgt.empty() && tgt.back() == '.') tgt.pop_back();
        json += "{\"priority\":" + std::to_string(prio) + ",\"weight\":" + std::to_string(wt) + ",\"port\":" + std::to_string(pt) + ",\"name\":\"" + tgt + "\"}";
      } else if (qtype == ns_t_ns) {
        char n[NS_MAXDNAME];
        if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata, n, sizeof(n)) < 0) { first = true; continue; }
        std::string s(n); if (!s.empty() && s.back() == '.') s.pop_back();
        json += "\"" + s + "\"";
      } else if (qtype == ns_t_cname) {
        char cn[NS_MAXDNAME];
        if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata, cn, sizeof(cn)) < 0) { first = true; continue; }
        std::string s(cn); if (!s.empty() && s.back() == '.') s.pop_back();
        json += "\"" + s + "\"";
      } else if (qtype == ns_t_soa) {
        char mn[NS_MAXDNAME]; int o1 = ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata, mn, sizeof(mn));
        if (o1 < 0) { first = true; continue; }
        std::string m(mn); if (!m.empty() && m.back() == '.') m.pop_back();
        char rn[NS_MAXDNAME]; int o2 = ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata+o1, rn, sizeof(rn));
        if (o2 < 0) { first = true; continue; }
        std::string r(rn); if (!r.empty() && r.back() == '.') r.pop_back();
        const unsigned char* sd = rdata+o1+o2;
        if (o1+o2+20 > rdlen) { first = true; continue; }
        uint32_t ser = (uint32_t(sd[0])<<24)|(uint32_t(sd[1])<<16)|(uint32_t(sd[2])<<8)|sd[3];
        int32_t ref = (sd[4]<<24)|(sd[5]<<16)|(sd[6]<<8)|sd[7];
        int32_t rty = (sd[8]<<24)|(sd[9]<<16)|(sd[10]<<8)|sd[11];
        int32_t exp = (sd[12]<<24)|(sd[13]<<16)|(sd[14]<<8)|sd[15];
        uint32_t mnt = (uint32_t(sd[16])<<24)|(uint32_t(sd[17])<<16)|(uint32_t(sd[18])<<8)|sd[19];
        json += "{\"nsname\":\""+m+"\",\"hostmaster\":\""+r+"\",\"serial\":"+std::to_string(ser)+",\"refresh\":"+std::to_string(ref)+",\"retry\":"+std::to_string(rty)+",\"expire\":"+std::to_string(exp)+",\"minttl\":"+std::to_string(mnt)+"}";
      } else if (qtype == ns_t_ptr) {
        char pn[NS_MAXDNAME];
        if (ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg), rdata, pn, sizeof(pn)) < 0) { first = true; continue; }
        std::string s(pn); if (!s.empty() && s.back() == '.') s.pop_back();
        json += "\"" + s + "\"";
      } else if (qtype == 257) {
        if (rdlen < 2) { first = true; continue; }
        int fl = rdata[0]; int tl = rdata[1];
        if (2+tl > rdlen) { first = true; continue; }
        std::string tag(reinterpret_cast<const char*>(rdata+2), tl);
        std::string val(reinterpret_cast<const char*>(rdata+2+tl), rdlen-2-tl);
        std::string ev; for (size_t vi=0;vi<val.size();vi++){char c=val[vi];if(c=='"')ev+="\\\"";else if(c=='\\')ev+="\\\\";else ev+=c;}
        json += "{\"critical\":"+std::to_string(fl)+",\""+tag+"\":\""+ev+"\"}";
      }
    }
    json += "]";
    return facebook::jsi::String::createFromUtf8(runtime, json);
  });
  rt.global().setProperty(rt, "__exactDnsResolve", std::move(dnsResolveFn));

  // __exactDnsReverse(ip) -> JSON array of hostnames via getnameinfo
  auto dnsReverseFn = facebook::jsi::Function::createFromHostFunction(rt, facebook::jsi::PropNameID::forAscii(rt, "__exactDnsReverse"), 1, [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&, const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
    if (count == 0 || !args[0].isString()) throw facebook::jsi::JSError(runtime, "__exactDnsReverse: ip address required");
    auto ip = args[0].asString(runtime).utf8(runtime);
    struct sockaddr_storage sa; socklen_t salen; memset(&sa, 0, sizeof(sa));
    auto* sa4 = reinterpret_cast<struct sockaddr_in*>(&sa);
    auto* sa6 = reinterpret_cast<struct sockaddr_in6*>(&sa);
    if (inet_pton(AF_INET, ip.c_str(), &sa4->sin_addr) == 1) { sa4->sin_family = AF_INET; salen = sizeof(struct sockaddr_in); }
    else if (inet_pton(AF_INET6, ip.c_str(), &sa6->sin6_addr) == 1) { sa6->sin6_family = AF_INET6; salen = sizeof(struct sockaddr_in6); }
    else throw facebook::jsi::JSError(runtime, ("invalid IP address: " + ip).c_str());
    char host[NI_MAXHOST];
    int ret = getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), salen, host, sizeof(host), nullptr, 0, NI_NAMEREQD);
    if (ret != 0) throw facebook::jsi::JSError(runtime, ("getnameinfo failed for " + ip + ": " + gai_strerror(ret)).c_str());
    return facebook::jsi::String::createFromUtf8(runtime, "[\"" + std::string(host) + "\"]");
  });
  rt.global().setProperty(rt, "__exactDnsReverse", std::move(dnsReverseFn));

  // __exactGrantCapability(moduleId, capability) -> void
  auto grantCapabilityFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGrantCapability"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isString()) {
          return facebook::jsi::Value::undefined();
        }
        auto module_id = static_cast<uint64_t>(args[0].asNumber());
        auto capability = args[1].toString(runtime).utf8(runtime);
        ex_host_grant_capability(module_id, capability.c_str());
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactGrantCapability", std::move(grantCapabilityFn));

  auto readFileFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactReadFile"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          return facebook::jsi::Value::undefined();
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (!isAllowAll()) {
          std::string cap = "fs:read:" + path;
          if (!checkCapability(cap)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        }

        // Single FFI call: read entire file at once
        uint32_t len = 0;
        uint8_t* buf = ex_host_fs_read_file(path.c_str(), &len);
        if (!buf) {
          throw facebook::jsi::JSError(runtime, "Failed to open file");
        }

        // Move data into a vector and free the Rust buffer
        std::vector<uint8_t> data(buf, buf + len);
        ex_host_free_buffer(buf, len);
        return makeUint8Array(runtime, std::move(data));
      });
  rt.global().setProperty(rt, "__exactReadFile", std::move(readFileFn));

  // __exactWriteFile(path, data: Uint8Array) -> void (throws on error)
  auto writeFileFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWriteFile"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactWriteFile: path and data required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }

        // Extract bytes from Uint8Array
        auto obj = args[1].asObject(runtime);
        size_t length = 0;
        const uint8_t* dataPtr = nullptr;
        std::vector<uint8_t> dataCopy;

        if (obj.hasProperty(runtime, "buffer")) {
          auto bufVal = obj.getProperty(runtime, "buffer");
          if (bufVal.isObject()) {
            auto buf = bufVal.asObject(runtime).getArrayBuffer(runtime);
            auto offset = obj.hasProperty(runtime, "byteOffset")
                ? static_cast<size_t>(obj.getProperty(runtime, "byteOffset").asNumber())
                : 0;
            length = obj.hasProperty(runtime, "byteLength")
                ? static_cast<size_t>(obj.getProperty(runtime, "byteLength").asNumber())
                : buf.size(runtime) - offset;
            dataCopy.assign(buf.data(runtime) + offset, buf.data(runtime) + offset + length);
            dataPtr = dataCopy.data();
          }
        }

        void* handle = ex_host_fs_open(path.c_str(), EXACT_FS_WRITE | EXACT_FS_CREATE | EXACT_FS_TRUNCATE);
        if (!handle) {
          throw facebook::jsi::JSError(runtime, "Failed to open file for writing");
        }
        if (length > 0 && dataPtr) {
          int32_t written = ex_host_fs_write(handle, dataPtr, static_cast<uint32_t>(length));
          if (written < 0) {
            ex_host_fs_close(handle);
            throw facebook::jsi::JSError(runtime, "Failed to write file");
          }
        }
        ex_host_fs_close(handle);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactWriteFile", std::move(writeFileFn));

  // __exactAppendFile(path, data: Uint8Array) -> void
  auto appendFileFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAppendFile"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactAppendFile: path and data required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }

        auto obj = args[1].asObject(runtime);
        size_t length = 0;
        const uint8_t* dataPtr = nullptr;
        std::vector<uint8_t> dataCopy;

        if (obj.hasProperty(runtime, "buffer")) {
          auto bufVal = obj.getProperty(runtime, "buffer");
          if (bufVal.isObject()) {
            auto buf = bufVal.asObject(runtime).getArrayBuffer(runtime);
            auto offset = obj.hasProperty(runtime, "byteOffset")
                ? static_cast<size_t>(obj.getProperty(runtime, "byteOffset").asNumber())
                : 0;
            length = obj.hasProperty(runtime, "byteLength")
                ? static_cast<size_t>(obj.getProperty(runtime, "byteLength").asNumber())
                : buf.size(runtime) - offset;
            dataCopy.assign(buf.data(runtime) + offset, buf.data(runtime) + offset + length);
            dataPtr = dataCopy.data();
          }
        }

        if (length > 0 && dataPtr) {
          int32_t written = ex_host_fs_append(path.c_str(), dataPtr, static_cast<uint32_t>(length));
          if (written < 0) {
            throw facebook::jsi::JSError(runtime, "Failed to append to file");
          }
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactAppendFile", std::move(appendFileFn));

  // __exactStat(path) -> object {size, mtime_ms, is_dir, is_file, mode}
  auto statFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactStat"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactStat: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        char* json = ex_host_fs_stat(path.c_str());
        if (!json) {
          throw facebook::jsi::JSError(runtime, std::string("ENOENT: no such file or directory, stat '") + path + "'");
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactStat", std::move(statFn));

  // __exactLstat(path) -> JSON string
  auto lstatFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactLstat"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactLstat: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        char* json = ex_host_fs_lstat(path.c_str());
        if (!json) {
          throw facebook::jsi::JSError(runtime, std::string("ENOENT: no such file or directory, lstat '") + path + "'");
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactLstat", std::move(lstatFn));

  // __exactReaddir(path) -> JSON string (array of names)
  auto readdirFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactReaddir"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactReaddir: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        char* json = ex_host_fs_readdir(path.c_str());
        if (!json) {
          throw facebook::jsi::JSError(runtime, std::string("ENOENT: no such file or directory, readdir '") + path + "'");
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactReaddir", std::move(readdirFn));

  // __exactMkdir(path, recursive) -> void
  auto mkdirFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactMkdir"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactMkdir: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        int32_t recursive = 0;
        if (count > 1 && args[1].isBool()) {
          recursive = args[1].getBool() ? 1 : 0;
        } else if (count > 1 && args[1].isNumber()) {
          recursive = args[1].asNumber() != 0 ? 1 : 0;
        }
        if (ex_host_fs_mkdir(path.c_str(), recursive) != 0) {
          throw facebook::jsi::JSError(runtime, std::string("ENOENT: failed to create directory '") + path + "'");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactMkdir", std::move(mkdirFn));

  // __exactRmdir(path) -> void
  auto rmdirFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRmdir"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactRmdir: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (ex_host_fs_rmdir(path.c_str()) != 0) {
          throw facebook::jsi::JSError(runtime, std::string("ENOENT: failed to remove directory '") + path + "'");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactRmdir", std::move(rmdirFn));

  // __exactUnlink(path) -> void
  auto unlinkFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactUnlink"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactUnlink: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (ex_host_fs_unlink(path.c_str()) != 0) {
          throw facebook::jsi::JSError(runtime, std::string("ENOENT: no such file or directory, unlink '") + path + "'");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactUnlink", std::move(unlinkFn));

  // __exactRename(from, to) -> void
  auto renameFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRename"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactRename: from and to paths required");
        }
        auto from = args[0].toString(runtime).utf8(runtime);
        auto to = args[1].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + from;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (ex_host_fs_rename(from.c_str(), to.c_str()) != 0) {
          throw facebook::jsi::JSError(runtime, std::string("Failed to rename '") + from + "' to '" + to + "'");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactRename", std::move(renameFn));

  // __exactCopyFile(from, to) -> void
  auto copyFileFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactCopyFile"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactCopyFile: src and dest required");
        }
        auto from = args[0].toString(runtime).utf8(runtime);
        auto to = args[1].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + from;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        std::string wcap = "fs:write:" + to;
        if (!checkCapability(wcap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (ex_host_fs_copy(from.c_str(), to.c_str()) != 0) {
          throw facebook::jsi::JSError(runtime, std::string("Failed to copy '") + from + "' to '" + to + "'");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactCopyFile", std::move(copyFileFn));

  // __exactRealpath(path) -> string
  auto realpathFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRealpath"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactRealpath: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        char* resolved = ex_host_fs_realpath(path.c_str());
        if (!resolved) {
          throw facebook::jsi::JSError(runtime, std::string("ENOENT: no such file or directory, realpath '") + path + "'");
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, resolved);
        ex_host_free_string(resolved);
        return result;
      });
  rt.global().setProperty(rt, "__exactRealpath", std::move(realpathFn));

  // __exactAccess(path, mode) -> void (throws if not accessible)
  auto accessFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAccess"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactAccess: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        int32_t mode = 0;
        if (count > 1 && args[1].isNumber()) {
          mode = static_cast<int32_t>(args[1].asNumber());
        }
        if (ex_host_fs_access(path.c_str(), mode) != 0) {
          throw facebook::jsi::JSError(runtime, std::string("ENOENT: no such file or directory, access '") + path + "'");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactAccess", std::move(accessFn));

  // __exactChmod(path, mode) -> void
  auto chmodFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactChmod"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactChmod: path and mode required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        uint32_t mode = static_cast<uint32_t>(args[1].asNumber());
        if (ex_host_fs_chmod(path.c_str(), mode) != 0) {
          throw facebook::jsi::JSError(runtime, std::string("Failed to chmod '") + path + "'");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactChmod", std::move(chmodFn));

  // __exactMkdtemp(prefix) -> string (path of created temp directory)
  auto mkdtempFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactMkdtemp"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        std::string prefix = "tmp";
        if (count > 0 && args[0].isString()) {
          prefix = args[0].toString(runtime).utf8(runtime);
        }
        std::string cap = "fs:write:" + prefix;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        char* path = ex_host_fs_mkdtemp(prefix.c_str());
        if (!path) {
          throw facebook::jsi::JSError(runtime, "Failed to create temporary directory");
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, path);
        ex_host_free_string(path);
        return result;
      });
  rt.global().setProperty(rt, "__exactMkdtemp", std::move(mkdtempFn));

  // __exactFsOpen(path, flags, mode) -> integer fd
  auto fsOpenFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsOpen"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactFsOpen: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (!isAllowAll()) {
          std::string cap = "fs:read:" + path;
          if (!checkCapability(cap)) {
            std::string wcap = "fs:write:" + path;
            if (!checkCapability(wcap)) {
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
          }
        }

        // Parse flags string to POSIX flags
        int posixFlags = O_RDONLY;
        if (count > 1 && args[1].isString()) {
          auto flagStr = args[1].toString(runtime).utf8(runtime);
          if (flagStr == "r") posixFlags = O_RDONLY;
          else if (flagStr == "r+") posixFlags = O_RDWR;
          else if (flagStr == "rs+" || flagStr == "sr+") posixFlags = O_RDWR | O_SYNC;
          else if (flagStr == "w") posixFlags = O_WRONLY | O_CREAT | O_TRUNC;
          else if (flagStr == "wx" || flagStr == "xw") posixFlags = O_WRONLY | O_CREAT | O_TRUNC | O_EXCL;
          else if (flagStr == "w+") posixFlags = O_RDWR | O_CREAT | O_TRUNC;
          else if (flagStr == "wx+" || flagStr == "xw+") posixFlags = O_RDWR | O_CREAT | O_TRUNC | O_EXCL;
          else if (flagStr == "a") posixFlags = O_WRONLY | O_CREAT | O_APPEND;
          else if (flagStr == "ax" || flagStr == "xa") posixFlags = O_WRONLY | O_CREAT | O_APPEND | O_EXCL;
          else if (flagStr == "a+") posixFlags = O_RDWR | O_CREAT | O_APPEND;
          else if (flagStr == "ax+" || flagStr == "xa+") posixFlags = O_RDWR | O_CREAT | O_APPEND | O_EXCL;
          else {
            throw facebook::jsi::JSError(runtime, std::string("Unknown file flag: ") + flagStr);
          }
        } else if (count > 1 && args[1].isNumber()) {
          posixFlags = static_cast<int>(args[1].asNumber());
        }

        int mode = 0666;
        if (count > 2 && args[2].isNumber()) {
          mode = static_cast<int>(args[2].asNumber());
        }

        int fd = ::open(path.c_str(), posixFlags, mode);
        if (fd < 0) {
          throw facebook::jsi::JSError(runtime, std::string("ENOENT: no such file or directory, open '") + path + "'");
        }
        return facebook::jsi::Value(fd);
      });
  rt.global().setProperty(rt, "__exactFsOpen", std::move(fsOpenFn));

  // __exactFsClose(fd) -> void
  auto fsCloseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsClose"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsClose: fd required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        if (::close(fd) < 0) {
          throw facebook::jsi::JSError(runtime, std::string("EBADF: bad file descriptor, close fd ") + std::to_string(fd));
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsClose", std::move(fsCloseFn));

  // __exactFsRead(fd, length, position) -> Uint8Array (bytes read)
  // position = -1 means use current position
  auto fsReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsRead"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsRead: fd and length required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        size_t length = static_cast<size_t>(args[1].asNumber());

        // If position is provided and not -1 / null / undefined, seek first
        if (count > 2 && args[2].isNumber()) {
          double pos = args[2].asNumber();
          if (pos >= 0) {
            ::lseek(fd, static_cast<off_t>(pos), SEEK_SET);
          }
        }

        std::vector<uint8_t> data(length);
        ssize_t bytesRead = ::read(fd, data.data(), length);
        if (bytesRead < 0) {
          throw facebook::jsi::JSError(runtime, std::string("EIO: read error on fd ") + std::to_string(fd));
        }
        data.resize(static_cast<size_t>(bytesRead));
        return makeUint8Array(runtime, std::move(data));
      });
  rt.global().setProperty(rt, "__exactFsRead", std::move(fsReadFn));

  // __exactFsWrite(fd, data, position) -> number (bytes written)
  // data can be a string or Uint8Array; position = -1 means use current position
  auto fsWriteFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsWrite"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsWrite: fd and data required");
        }
        int fd = static_cast<int>(args[0].asNumber());

        // Extract data bytes
        auto dataBytes = extractBytes(runtime, args[1]);

        // If position is provided and not -1 / null / undefined, seek first
        if (count > 2 && args[2].isNumber()) {
          double pos = args[2].asNumber();
          if (pos >= 0) {
            ::lseek(fd, static_cast<off_t>(pos), SEEK_SET);
          }
        }

        ssize_t bytesWritten = ::write(fd, dataBytes.data(), dataBytes.size());
        if (bytesWritten < 0) {
          throw facebook::jsi::JSError(runtime, std::string("EIO: write error on fd ") + std::to_string(fd));
        }
        return facebook::jsi::Value(static_cast<int>(bytesWritten));
      });
  rt.global().setProperty(rt, "__exactFsWrite", std::move(fsWriteFn));

  auto randomBytesFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRandomBytes"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        if (!checkCapability("crypto:random")) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        auto len = static_cast<size_t>(args[0].asNumber());
        std::vector<uint8_t> data(len);
        if (len > 0) {
          if (ex_host_random_fill(data.data(), static_cast<uint32_t>(len)) != 0) {
            throw facebook::jsi::JSError(runtime, "Random fill failed");
          }
        }
        return makeUint8Array(runtime, std::move(data));
      });
  rt.global().setProperty(rt, "__exactRandomBytes", std::move(randomBytesFn));

  facebook::jsi::Object processObj(rt);
  if (rt.global().hasProperty(rt, "process")) {
    auto existing = rt.global().getProperty(rt, "process");
    if (existing.isObject()) {
      processObj = existing.asObject(rt);
    }
  }

  auto nextTickFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "nextTick"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() ||
            !args[0].asObject(runtime).isFunction(runtime)) {
          return facebook::jsi::Value::undefined();
        }
        auto callback = args[0].asObject(runtime).asFunction(runtime);
        handle->next_tick.push_back(std::move(callback));
        return facebook::jsi::Value::undefined();
      });

  processObj.setProperty(rt, "nextTick", std::move(nextTickFn));

  // Populate process.env from actual environment variables
  {
    facebook::jsi::Object envObj(rt);
#if defined(__APPLE__)
    char **envp = *_NSGetEnviron();
#else
    extern char **environ;
    char **envp = environ;
#endif
    if (envp) {
      for (char **ep = envp; *ep; ++ep) {
        std::string entry(*ep);
        auto eq = entry.find('=');
        if (eq != std::string::npos) {
          auto key = entry.substr(0, eq);
          auto val = entry.substr(eq + 1);
          envObj.setProperty(rt,
            facebook::jsi::PropNameID::forUtf8(rt, key),
            facebook::jsi::String::createFromUtf8(rt, val));
        }
      }
    }
    processObj.setProperty(rt, "env", std::move(envObj));
  }

  // Set process.platform and process.version
#if defined(__APPLE__)
  processObj.setProperty(rt, "platform",
    facebook::jsi::String::createFromUtf8(rt, "darwin"));
#elif defined(__linux__)
  processObj.setProperty(rt, "platform",
    facebook::jsi::String::createFromUtf8(rt, "linux"));
#elif defined(_WIN32)
  processObj.setProperty(rt, "platform",
    facebook::jsi::String::createFromUtf8(rt, "win32"));
#else
  processObj.setProperty(rt, "platform",
    facebook::jsi::String::createFromUtf8(rt, "unknown"));
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
  processObj.setProperty(rt, "arch",
    facebook::jsi::String::createFromUtf8(rt, "arm64"));
#elif defined(__x86_64__) || defined(_M_X64)
  processObj.setProperty(rt, "arch",
    facebook::jsi::String::createFromUtf8(rt, "x64"));
#else
  processObj.setProperty(rt, "arch",
    facebook::jsi::String::createFromUtf8(rt, "unknown"));
#endif

  processObj.setProperty(rt, "version",
    facebook::jsi::String::createFromUtf8(rt, "v21.0.0"));
  processObj.setProperty(rt, "versions",
    facebook::jsi::Object(rt));

  // process.cwd()
  auto cwdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "cwd"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        char buffer[PATH_MAX];
        if (getcwd(buffer, sizeof(buffer))) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, buffer));
        }
        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, "/"));
      });
  processObj.setProperty(rt, "cwd", std::move(cwdFn));

  auto chdirFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "chdir"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(
              runtime,
              "The first argument must be of type string");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (chdir(path.c_str()) != 0) {
          throw facebook::jsi::JSError(
              runtime,
              "Failed to change directory: " + std::string(strerror(errno)));
        }
        return facebook::jsi::Value::undefined();
      });
  processObj.setProperty(rt, "chdir", std::move(chdirFn));

  // process.exit()
  auto exitFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "exit"),
      1,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        int code = 0;
        if (count > 0 && args[0].isNumber()) {
          code = static_cast<int>(args[0].asNumber());
        }
        std::exit(code);
        return facebook::jsi::Value::undefined();
      });
  processObj.setProperty(rt, "exit", std::move(exitFn));

  // process.stdout and process.stderr — proper Writable stream-like objects
  auto makeStream = [&rt](int fd) {
    facebook::jsi::Object stream(rt);
    auto writeFn = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "write"),
        3,
        [fd](facebook::jsi::Runtime& runtime,
             const facebook::jsi::Value&,
             const facebook::jsi::Value* args,
             size_t count) -> facebook::jsi::Value {
          if (count > 0 && args[0].isString()) {
            auto str = args[0].asString(runtime).utf8(runtime);
            if (fd == 1) {
              fprintf(stdout, "%s", str.c_str());
              fflush(stdout);
            } else {
              fprintf(stderr, "%s", str.c_str());
              fflush(stderr);
            }
          }
          // If a callback is provided (2nd or 3rd arg), call it
          for (size_t i = 1; i < count; i++) {
            if (args[i].isObject() && args[i].asObject(runtime).isFunction(runtime)) {
              args[i].asObject(runtime).asFunction(runtime).call(runtime);
              break;
            }
          }
          return facebook::jsi::Value(true);
        });
    stream.setProperty(rt, "write", std::move(writeFn));

    // Real isTTY detection via isatty()
    bool isTTY = ::isatty(fd) != 0;
    stream.setProperty(rt, "isTTY", facebook::jsi::Value(isTTY));
    stream.setProperty(rt, "fd", facebook::jsi::Value(fd));

    // Terminal dimensions via ioctl(TIOCGWINSZ)
    if (isTTY) {
      struct winsize ws;
      if (::ioctl(fd, TIOCGWINSZ, &ws) == 0) {
        stream.setProperty(rt, "columns", facebook::jsi::Value(static_cast<int>(ws.ws_col)));
        stream.setProperty(rt, "rows", facebook::jsi::Value(static_cast<int>(ws.ws_row)));
      }
    }

    // Writable stream properties
    stream.setProperty(rt, "writable", facebook::jsi::Value(true));
    stream.setProperty(rt, "writableEnded", facebook::jsi::Value(false));
    stream.setProperty(rt, "writableFinished", facebook::jsi::Value(false));
    stream.setProperty(rt, "writableHighWaterMark", facebook::jsi::Value(16384));
    stream.setProperty(rt, "writableLength", facebook::jsi::Value(0));
    stream.setProperty(rt, "writableObjectMode", facebook::jsi::Value(false));
    stream.setProperty(rt, "destroyed", facebook::jsi::Value(false));

    return stream;
  };
  processObj.setProperty(rt, "stdout", makeStream(1));
  processObj.setProperty(rt, "stderr", makeStream(2));

  // process.stdin — minimal readable stream stub
  {
    facebook::jsi::Object stdinObj(rt);
    stdinObj.setProperty(rt, "readable", facebook::jsi::Value(true));
    stdinObj.setProperty(rt, "isTTY", facebook::jsi::Value(::isatty(0) != 0));
    stdinObj.setProperty(rt, "fd", facebook::jsi::Value(0));
    processObj.setProperty(rt, "stdin", std::move(stdinObj));
  }

  // process.pid and process.ppid
  processObj.setProperty(rt, "pid", facebook::jsi::Value(static_cast<int>(getpid())));
  processObj.setProperty(rt, "ppid", facebook::jsi::Value(static_cast<int>(getppid())));

  // process.execPath — path to the ex binary
  {
    std::string execPathStr;
#if defined(__APPLE__)
    char execPathBuf[PATH_MAX];
    uint32_t epSize = sizeof(execPathBuf);
    if (_NSGetExecutablePath(execPathBuf, &epSize) == 0) {
      char realExecPath[PATH_MAX];
      if (realpath(execPathBuf, realExecPath)) {
        execPathStr = realExecPath;
      } else {
        execPathStr = execPathBuf;
      }
    }
#elif defined(__linux__)
    char execPathBuf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", execPathBuf, sizeof(execPathBuf) - 1);
    if (len > 0) {
      execPathBuf[len] = '\0';
      execPathStr = execPathBuf;
    }
#endif
    if (execPathStr.empty()) {
      execPathStr = "ex";
    }
    processObj.setProperty(rt, "execPath",
        facebook::jsi::String::createFromUtf8(rt, execPathStr));
  }

  // process.title
  processObj.setProperty(rt, "title",
      facebook::jsi::String::createFromUtf8(rt, "ex"));

  // process.uptime() — seconds since process start
  auto uptimeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "uptime"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration<double>(now - g_process_start_time);
        return facebook::jsi::Value(elapsed.count());
      });
  processObj.setProperty(rt, "uptime", std::move(uptimeFn));

  // process.hrtime() and process.hrtime.bigint()
  {
    auto hrtimeFn = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "hrtime"),
        1,
        [](facebook::jsi::Runtime& runtime,
           const facebook::jsi::Value&,
           const facebook::jsi::Value* args,
           size_t count) -> facebook::jsi::Value {
          auto now = std::chrono::steady_clock::now().time_since_epoch();
          auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();

          int64_t prevSec = 0, prevNs = 0;
          if (count > 0 && args[0].isObject()) {
            auto arr = args[0].asObject(runtime).asArray(runtime);
            auto sVal = arr.getValueAtIndex(runtime, 0);
            auto nVal = arr.getValueAtIndex(runtime, 1);
            if (sVal.isNumber()) prevSec = static_cast<int64_t>(sVal.asNumber());
            if (nVal.isNumber()) prevNs = static_cast<int64_t>(nVal.asNumber());
          }

          int64_t sec = ns / 1000000000LL;
          int64_t rem = ns % 1000000000LL;

          if (count > 0 && args[0].isObject()) {
            sec -= prevSec;
            rem -= prevNs;
            if (rem < 0) {
              sec -= 1;
              rem += 1000000000LL;
            }
          }

          auto result = facebook::jsi::Array(runtime, 2);
          result.setValueAtIndex(runtime, 0, facebook::jsi::Value(static_cast<double>(sec)));
          result.setValueAtIndex(runtime, 1, facebook::jsi::Value(static_cast<double>(rem)));
          return result;
        });

    // hrtime.bigint() — returns nanoseconds as a number (Hermes lacks BigInt)
    auto hrtimeBigintFn = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "bigint"),
        0,
        [](facebook::jsi::Runtime&,
           const facebook::jsi::Value&,
           const facebook::jsi::Value*,
           size_t) -> facebook::jsi::Value {
          auto now = std::chrono::steady_clock::now().time_since_epoch();
          auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
          return facebook::jsi::Value(static_cast<double>(ns));
        });

    // Attach bigint as a property of the hrtime function object
    hrtimeFn.setProperty(rt, "bigint", std::move(hrtimeBigintFn));
    processObj.setProperty(rt, "hrtime", std::move(hrtimeFn));
  }

  // process.memoryUsage()
  auto memoryUsageFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "memoryUsage"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        facebook::jsi::Object result(runtime);
        size_t rss = 0;
#if defined(__APPLE__)
        struct mach_task_basic_info info;
        mach_msg_type_number_t infoCount = MACH_TASK_BASIC_INFO_COUNT;
        if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                      (task_info_t)&info, &infoCount) == KERN_SUCCESS) {
          rss = info.resident_size;
        }
#elif defined(__linux__)
        struct rusage usage;
        if (getrusage(RUSAGE_SELF, &usage) == 0) {
          rss = static_cast<size_t>(usage.ru_maxrss) * 1024; // Linux reports in KB
        }
#endif
        result.setProperty(runtime, "rss", facebook::jsi::Value(static_cast<double>(rss)));
        result.setProperty(runtime, "heapTotal", facebook::jsi::Value(0.0));
        result.setProperty(runtime, "heapUsed", facebook::jsi::Value(0.0));
        result.setProperty(runtime, "external", facebook::jsi::Value(0.0));
        result.setProperty(runtime, "arrayBuffers", facebook::jsi::Value(0.0));
        return result;
      });
  processObj.setProperty(rt, "memoryUsage", std::move(memoryUsageFn));

  // process.cpuUsage()
  auto cpuUsageFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "cpuUsage"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        struct rusage usage;
        getrusage(RUSAGE_SELF, &usage);
        int64_t userUsec = static_cast<int64_t>(usage.ru_utime.tv_sec) * 1000000LL
                         + usage.ru_utime.tv_usec;
        int64_t sysUsec  = static_cast<int64_t>(usage.ru_stime.tv_sec) * 1000000LL
                         + usage.ru_stime.tv_usec;

        // If a previous value is passed, return the difference
        if (count > 0 && args[0].isObject()) {
          auto prev = args[0].asObject(runtime);
          auto prevUser = prev.getProperty(runtime, "user");
          auto prevSystem = prev.getProperty(runtime, "system");
          if (prevUser.isNumber()) {
            userUsec -= static_cast<int64_t>(prevUser.asNumber());
          }
          if (prevSystem.isNumber()) {
            sysUsec -= static_cast<int64_t>(prevSystem.asNumber());
          }
        }

        facebook::jsi::Object result(runtime);
        result.setProperty(runtime, "user", facebook::jsi::Value(static_cast<double>(userUsec)));
        result.setProperty(runtime, "system", facebook::jsi::Value(static_cast<double>(sysUsec)));
        return result;
      });
  processObj.setProperty(rt, "cpuUsage", std::move(cpuUsageFn));

  // process.getuid() and process.getgid()
  auto getuidFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getuid"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(static_cast<int>(getuid()));
      });
  processObj.setProperty(rt, "getuid", std::move(getuidFn));

  auto getgidFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getgid"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(static_cast<int>(getgid()));
      });
  processObj.setProperty(rt, "getgid", std::move(getgidFn));

  // process.kill(pid, signal)
  auto killFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "kill"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "process.kill requires a pid");
        }
        pid_t targetPid = static_cast<pid_t>(args[0].asNumber());
        int sig = SIGTERM; // default signal
        if (count > 1) {
          if (args[1].isNumber()) {
            sig = static_cast<int>(args[1].asNumber());
          } else if (args[1].isString()) {
            auto sigName = args[1].asString(runtime).utf8(runtime);
            if (sigName == "SIGTERM") sig = SIGTERM;
            else if (sigName == "SIGKILL") sig = SIGKILL;
            else if (sigName == "SIGINT") sig = SIGINT;
            else if (sigName == "SIGHUP") sig = SIGHUP;
            else if (sigName == "SIGUSR1") sig = SIGUSR1;
            else if (sigName == "SIGUSR2") sig = SIGUSR2;
            else if (sigName == "SIGSTOP") sig = SIGSTOP;
            else if (sigName == "SIGCONT") sig = SIGCONT;
            else if (sigName == "SIGQUIT") sig = SIGQUIT;
            else {
              throw facebook::jsi::JSError(runtime,
                  std::string("Unknown signal: ") + sigName);
            }
          }
        }
        int result = kill(targetPid, sig);
        if (result != 0) {
          throw facebook::jsi::JSError(runtime,
              std::string("kill failed: ") + strerror(errno));
        }
        return facebook::jsi::Value(true);
      });
  processObj.setProperty(rt, "kill", std::move(killFn));

  // process.release
  {
    facebook::jsi::Object releaseObj(rt);
    releaseObj.setProperty(rt, "name",
        facebook::jsi::String::createFromUtf8(rt, "ex"));
    processObj.setProperty(rt, "release", std::move(releaseObj));
  }

  rt.global().setProperty(rt, "process", std::move(processObj));

  // Enhance process.stdout, process.stderr, and process.stdin with JS-level methods
  // (event emitter, end(), cork/uncork, TTY methods, color detection, etc.)
  {
    static const char* streamEnhanceJS = R"JS(
(function() {
  'use strict';
  var p = globalThis.process;
  if (!p) return;

  // --- Minimal EventEmitter mixin ---
  function addEventEmitter(obj) {
    var listeners = {};
    obj.on = function(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].push({ fn: fn, once: false });
      return obj;
    };
    obj.addListener = obj.on;
    obj.once = function(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].push({ fn: fn, once: true });
      return obj;
    };
    obj.emit = function(event) {
      var args = [];
      for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
      var list = listeners[event];
      if (!list) return false;
      var keep = [];
      for (var j = 0; j < list.length; j++) {
        list[j].fn.apply(obj, args);
        if (!list[j].once) keep.push(list[j]);
      }
      listeners[event] = keep;
      return true;
    };
    obj.removeListener = function(event, fn) {
      var list = listeners[event];
      if (!list) return obj;
      var keep = [];
      for (var j = 0; j < list.length; j++) {
        if (list[j].fn !== fn) keep.push(list[j]);
      }
      listeners[event] = keep;
      return obj;
    };
    obj.off = obj.removeListener;
    obj.removeAllListeners = function(event) {
      if (event) { listeners[event] = []; } else { listeners = {}; }
      return obj;
    };
    obj.listenerCount = function(event) {
      return listeners[event] ? listeners[event].length : 0;
    };
    obj.listeners = function(event) {
      var list = listeners[event] || [];
      var result = [];
      for (var j = 0; j < list.length; j++) result.push(list[j].fn);
      return result;
    };
    obj.prependListener = function(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].unshift({ fn: fn, once: false });
      return obj;
    };
    obj.prependOnceListener = function(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].unshift({ fn: fn, once: true });
      return obj;
    };
    obj.rawListeners = obj.listeners;
    obj.eventNames = function() {
      var names = [];
      for (var k in listeners) {
        if (listeners[k] && listeners[k].length > 0) names.push(k);
      }
      return names;
    };
    obj.setMaxListeners = function() { return obj; };
    obj.getMaxListeners = function() { return 10; };
  }

  // --- Color depth detection ---
  function getColorDepth(env) {
    env = env || p.env || {};
    if (env.FORCE_COLOR !== undefined) {
      var fc = env.FORCE_COLOR;
      if (fc === '0' || fc === 'false') return 1;
      if (fc === '1' || fc === 'true' || fc === '') return 4;
      if (fc === '2') return 8;
      if (fc === '3') return 24;
    }
    if (env.NO_COLOR !== undefined) return 1;
    if (env.COLORTERM === 'truecolor' || env.COLORTERM === '24bit') return 24;
    if (env.TERM === 'xterm-256color' || env.TERM === 'screen-256color') return 8;
    var term = env.TERM || '';
    if (term === 'dumb') return 1;
    if (term.indexOf('color') !== -1 || term.indexOf('ansi') !== -1 ||
        term.indexOf('xterm') !== -1 || term.indexOf('screen') !== -1 ||
        term.indexOf('vt100') !== -1 || term.indexOf('rxvt') !== -1 ||
        env.COLORTERM) return 4;
    return 1;
  }

  function hasColors(count, env) {
    if (typeof count === 'object' && count !== null) {
      env = count;
      count = 16;
    }
    if (count === undefined) count = 16;
    var depth = getColorDepth(env);
    return Math.pow(2, depth) >= count;
  }

  // --- Enhance writable streams (stdout, stderr) ---
  function enhanceWritable(stream) {
    if (!stream) return;
    var origWrite = stream.write;
    addEventEmitter(stream);

    // Wrap native write to ensure callback support and coerce non-strings
    stream.write = function(chunk, encoding, callback) {
      if (typeof encoding === 'function') {
        callback = encoding;
        encoding = undefined;
      }
      if (typeof chunk !== 'string' && chunk != null) {
        chunk = String(chunk);
      }
      var result = origWrite.call(stream, chunk, encoding, callback);
      return result;
    };

    stream.end = function(chunk, encoding, callback) {
      if (typeof chunk === 'function') {
        callback = chunk;
        chunk = undefined;
        encoding = undefined;
      } else if (typeof encoding === 'function') {
        callback = encoding;
        encoding = undefined;
      }
      if (chunk != null) {
        stream.write(chunk, encoding);
      }
      stream.writable = false;
      stream.writableEnded = true;
      stream.writableFinished = true;
      stream.emit('finish');
      stream.emit('close');
      if (typeof callback === 'function') callback();
      return stream;
    };

    stream._write = function(chunk, encoding, callback) {
      return stream.write(chunk, encoding, callback);
    };

    stream.cork = function() {};
    stream.uncork = function() {};
    stream.setDefaultEncoding = function() { return stream; };

    stream.destroy = function(err) {
      stream.destroyed = true;
      stream.writable = false;
      if (err) stream.emit('error', err);
      stream.emit('close');
      return stream;
    };

    stream.pipe = function() {
      throw new Error('process.stdout cannot be piped to');
    };

    // TTY methods (functional stubs for compatibility)
    stream.clearLine = function(dir, callback) {
      if (typeof callback === 'function') callback();
      return true;
    };
    stream.clearScreenDown = function(callback) {
      if (typeof callback === 'function') callback();
      return true;
    };
    stream.cursorTo = function(x, y, callback) {
      if (typeof y === 'function') { callback = y; }
      if (typeof callback === 'function') callback();
      return true;
    };
    stream.moveCursor = function(dx, dy, callback) {
      if (typeof callback === 'function') callback();
      return true;
    };

    stream.getWindowSize = function() {
      return [stream.columns || 80, stream.rows || 24];
    };

    stream.getColorDepth = function(env) {
      if (!stream.isTTY) return 1;
      return getColorDepth(env);
    };

    stream.hasColors = function(count, env) {
      if (!stream.isTTY) return false;
      return hasColors(count, env);
    };

    // Constructor name for duck-typing checks
    stream.constructor = { name: 'WriteStream' };
  }

  // --- Enhance readable stream (stdin) ---
  function enhanceReadable(stream) {
    if (!stream) return;
    addEventEmitter(stream);

    stream._encoding = null;
    stream._paused = true;
    stream._ended = false;
    stream._pollTimer = 0;

    stream.setEncoding = function(enc) {
      stream._encoding = enc;
      return stream;
    };

    stream.resume = function() {
      stream.readable = true;
      stream._paused = false;
      stream.readableFlowing = true;
      // Start polling for stdin data if we have __exactStdinRead
      if (!stream._ended && typeof __exactStdinRead === 'function' && !stream._pollTimer) {
        (function pollStdin() {
          if (stream._paused || stream._ended || stream.destroyed) return;
          var data = __exactStdinRead(4096);
          if (data === null) {
            // No data available, poll again
            stream._pollTimer = setTimeout(pollStdin, 50);
          } else if (data === '') {
            // EOF
            stream._ended = true;
            stream._pollTimer = 0;
            stream.readableEnded = true;
            stream.emit('end');
            stream.emit('close');
          } else {
            // Got data
            stream.readableLength += data.length;
            stream.emit('data', data);
            stream.readableLength = 0;
            if (!stream._paused && !stream._ended) {
              stream._pollTimer = setTimeout(pollStdin, 10);
            }
          }
        })();
      }
      return stream;
    };

    stream.pause = function() {
      stream._paused = true;
      stream.readableFlowing = false;
      if (stream._pollTimer) {
        clearTimeout(stream._pollTimer);
        stream._pollTimer = 0;
      }
      return stream;
    };

    stream.read = function(size) {
      if (typeof __exactStdinRead === 'function') {
        var data = __exactStdinRead(size || 4096);
        if (data === '') return null; // EOF
        return data;
      }
      return null;
    };

    stream.pipe = function(dest) {
      stream.on('data', function(chunk) {
        if (dest && typeof dest.write === 'function') {
          var ok = dest.write(chunk);
          if (ok === false) {
            stream.pause();
            dest.once('drain', function() { stream.resume(); });
          }
        }
      });
      stream.on('end', function() {
        if (dest && typeof dest.end === 'function') dest.end();
      });
      return dest;
    };

    stream.unpipe = function() { return stream; };
    stream.unshift = function() {};
    stream.wrap = function() { return stream; };
    stream.destroy = function() {
      stream.readable = false;
      stream.destroyed = true;
      stream._paused = true;
      if (stream._pollTimer) {
        clearTimeout(stream._pollTimer);
        stream._pollTimer = 0;
      }
      stream.emit('close');
      return stream;
    };
    stream.destroyed = false;
    stream.readableEncoding = null;
    stream.readableEnded = false;
    stream.readableFlowing = null;
    stream.readableHighWaterMark = 16384;
    stream.readableLength = 0;
    stream.readableObjectMode = false;

    stream.constructor = { name: 'ReadStream' };

    // Auto-start polling when 'data' listener is added
    var _origStdinOn = stream.on;
    stream.on = function(event, fn) {
      _origStdinOn.call(stream, event, fn);
      if (event === 'data' && !stream._ended && stream._paused) {
        stream.resume();
      }
      return stream;
    };
    stream.addListener = stream.on;
  }

  enhanceWritable(p.stdout);
  enhanceWritable(p.stderr);
  enhanceReadable(p.stdin);

  // --- Make process itself an EventEmitter ---
  addEventEmitter(p);

  // process.on('exit') — fire exit hooks before process exits
  var origExit = p.exit;
  p.exit = function(code) {
    if (code === undefined) code = p.exitCode || 0;
    try { p.emit('exit', code); } catch(e) {}
    if (origExit) origExit(code);
  };

  // process.exitCode — settable exit code
  if (p.exitCode === undefined) p.exitCode = 0;

  // process.abort()
  p.abort = function() {
    p.exit(134);
  };

  // process.emitWarning()
  p.emitWarning = function(warning, options) {
    var name = 'Warning';
    if (typeof options === 'string') name = options;
    else if (options && options.type) name = options.type;
    var msg = (typeof warning === 'string') ? warning : String(warning);
    p.stderr.write('(' + name + ') ' + msg + '\n');
    p.emit('warning', warning);
  };

  // --- uncaughtException / unhandledRejection support ---
  // Store a global error handler that the native side can call into
  p._uncaughtExceptionHandler = function(err) {
    if (p.listenerCount('uncaughtException') > 0) {
      try {
        p.emit('uncaughtException', err);
        return true; // handled
      } catch (e) {
        // Handler itself threw - fall through to crash
        return false;
      }
    }
    return false; // not handled
  };
  // Expose globally so the native runtime can call it
  globalThis.__exactUncaughtExceptionHandler = p._uncaughtExceptionHandler;

  // unhandledRejection support via Promise rejection tracking
  p._unhandledRejectionHandler = function(reason, promise) {
    if (p.listenerCount('unhandledRejection') > 0) {
      try {
        p.emit('unhandledRejection', reason, promise);
        return true;
      } catch (e) {
        return false;
      }
    }
    return false;
  };
  globalThis.__exactUnhandledRejectionHandler = p._unhandledRejectionHandler;

  // --- Signal handling ---
  // Map signal names to numbers
  var _signals = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGTERM: 15, SIGUSR1: 10, SIGUSR2: 12 };
  var _trappedSignals = {};
  var _signalNames = {};
  var _signalPollEnabled = typeof __exactPollSignal === 'function';
  var _signalPollActive = false;
  var _signalPollTimer = 0;

  if (_signalPollEnabled) {
    for (var _sk in _signals) {
      _signalNames[_signals[_sk]] = _sk;
    }
  }

  function _startSignalPolling() {
    if (!_signalPollEnabled || _signalPollActive) {
      return;
    }

    _signalPollActive = true;

    (function pollSignals() {
      var sig = __exactPollSignal();
      if (sig > 0 && _signalNames[sig]) {
        var name = _signalNames[sig];
        if (p.listenerCount(name) > 0) {
          p.emit(name);
        } else {
          // No listeners, restore default behavior
          if (typeof __exactResetSignal === 'function') {
            __exactResetSignal(sig);
          }
          // Re-raise the signal
          if (p.kill) p.kill(p.pid, sig);
        }
      }

      if (_signalPollActive) {
        _signalPollTimer = setTimeout(pollSignals, 100);
      }
    })();
  }

  var _origOn = p.on;
  p.on = function(event, fn) {
    _origOn.call(p, event, fn);
    // Auto-trap OS signal when first listener is added
    if (_signals[event] && !_trappedSignals[event]) {
      _trappedSignals[event] = true;
      if (typeof __exactTrapSignal === 'function') {
        __exactTrapSignal(_signals[event]);
      }
      if (_signalPollEnabled) {
        _startSignalPolling();
      }
    }
    return p;
  };
  p.addListener = p.on;

  // process.channel — not applicable (no IPC), but stub for compatibility
  p.channel = undefined;
  p.connected = false;
  p.disconnect = function() {};
  p.send = function() { return false; };

  // process.versions — many packages check process.versions.node
  if (!p.versions || !p.versions.node) {
    p.versions = {
      node: '22.0.0',
      v8: '0.0.0',
      uv: '0.0.0',
      zlib: '1.3.1',
      brotli: '0.0.0',
      ares: '0.0.0',
      modules: '127',
      nghttp2: '0.0.0',
      napi: '9',
      llhttp: '0.0.0',
      uvwasi: '0.0.0',
      unicode: '15.1',
      openssl: '0.0.0',
      hermes: '0.12.0',
      exact: '0.1.0'
    };
  }

  // process.version
  if (!p.version) p.version = 'v22.0.0';

  // process.execArgv — empty by default
  if (!p.execArgv) p.execArgv = [];

  // process.config stub
  if (!p.config) {
    p.config = { target_defaults: {}, variables: {} };
  }

  // process.features stub
  if (!p.features) {
    p.features = { inspector: true, debug: false, uv: false, ipv6: true, tls_alpn: false, tls_sni: false, tls_ocsp: false, tls: false };
  }

  // process.mainModule (deprecated but still used)
  p.mainModule = undefined;

  // process.binding — stub (deprecated but some old packages use it)
  if (!p.binding) {
    p.binding = function(name) {
      throw new Error("process.binding('" + name + "') is not supported in Exact");
    };
  }

  // process.emitWarning
  if (!p.emitWarning) {
    p.emitWarning = function(warning, type) {
      console.warn((type || 'Warning') + ': ' + warning);
    };
  }
})();
)JS";

    try {
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(streamEnhanceJS);
      rt.evaluateJavaScript(buffer, "<stream-enhance>");
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, (std::string("Stream enhance error: ") + err.getMessage()).c_str());
    } catch (const std::exception& err) {
      ex_host_console_log(1, (std::string("Stream enhance error: ") + err.what()).c_str());
    }
  }

  // --- Web Crypto API (globalThis.crypto) ---
  {
    static const char* webCryptoJS = R"JS(
(function() {
  'use strict';

  // getRandomValues - fills typed array with crypto-random values
  function getRandomValues(typedArray) {
    if (!typedArray || typeof typedArray.length !== 'number') {
      throw new TypeError('Expected a TypedArray');
    }
    if (typedArray.byteLength > 65536) {
      throw new DOMException('Quota exceeded', 'QuotaExceededError');
    }
    if (typeof __exactRandomBytes === 'function') {
      var bytes = __exactRandomBytes(typedArray.byteLength);
      var u8 = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
      for (var i = 0; i < bytes.length; i++) u8[i] = bytes[i];
    }
    return typedArray;
  }

  // randomUUID - generate a v4 UUID
  function randomUUID() {
    var bytes = new Uint8Array(16);
    getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 1
    var hex = '';
    for (var i = 0; i < 16; i++) {
      var h = bytes[i].toString(16);
      if (h.length === 1) h = '0' + h;
      hex += h;
      if (i === 3 || i === 5 || i === 7 || i === 9) hex += '-';
    }
    return hex;
  }

  // --- SubtleCrypto ---
  function normalizeAlgo(algo) {
    if (typeof algo === 'string') return { name: algo.toUpperCase() };
    if (algo && algo.name) return { name: algo.name.toUpperCase(), length: algo.length, hash: algo.hash, iv: algo.iv, counter: algo.counter, additionalData: algo.additionalData, tagLength: algo.tagLength, salt: algo.salt, iterations: algo.iterations, info: algo.info };
    throw new TypeError('Invalid algorithm');
  }

  function toBytes(data) {
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (data instanceof Uint8Array) return data;
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    throw new TypeError('Expected BufferSource');
  }

  function CryptoKey(type, extractable, algorithm, usages, keyData) {
    this.type = type;
    this.extractable = extractable;
    this.algorithm = algorithm;
    this.usages = usages;
    this._keyData = keyData;
  }

  var subtle = {};

  // subtle.digest(algorithm, data) -> ArrayBuffer
  subtle.digest = function(algorithm, data) {
    var algo = normalizeAlgo(algorithm);
    var nameMap = { 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' };
    var hashName = nameMap[algo.name];
    if (!hashName) return Promise.reject(new Error('Unsupported digest algorithm: ' + algo.name));
    var bytes = toBytes(data);
    // Convert to string for native bridge
    var str = '';
    for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    if (typeof __exactHashRaw === 'function') {
      var result = __exactHashRaw(hashName, str);
      return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
    }
    return Promise.reject(new Error('Native hash not available'));
  };

  // subtle.generateKey(algorithm, extractable, keyUsages) -> CryptoKey or CryptoKeyPair
  subtle.generateKey = function(algorithm, extractable, keyUsages) {
    var algo = normalizeAlgo(algorithm);
    if (algo.name === 'AES-GCM' || algo.name === 'AES-CBC' || algo.name === 'AES-CTR') {
      var length = algo.length || 256;
      if (length !== 128 && length !== 192 && length !== 256) {
        return Promise.reject(new Error('Invalid key length: ' + length));
      }
      var keyBytes = new Uint8Array(length / 8);
      getRandomValues(keyBytes);
      var key = new CryptoKey('secret', extractable, { name: algo.name, length: length }, keyUsages, keyBytes);
      return Promise.resolve(key);
    }
    if (algo.name === 'HMAC') {
      var hashAlgo = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
      var hlen = { 'SHA-1': 20, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 };
      var klen = algo.length ? (algo.length / 8) : (hlen[hashAlgo.toUpperCase()] || 32);
      var hmacKey = new Uint8Array(klen);
      getRandomValues(hmacKey);
      var key = new CryptoKey('secret', extractable, { name: 'HMAC', hash: { name: hashAlgo.toUpperCase() }, length: klen * 8 }, keyUsages, hmacKey);
      return Promise.resolve(key);
    }
    return Promise.reject(new Error('Unsupported algorithm for generateKey: ' + algo.name));
  };

  // subtle.importKey(format, keyData, algorithm, extractable, keyUsages) -> CryptoKey
  subtle.importKey = function(format, keyData, algorithm, extractable, keyUsages) {
    var algo = normalizeAlgo(algorithm);
    if (format === 'raw') {
      var raw = toBytes(keyData);
      var keyAlgo = algo;
      if (algo.name === 'HMAC') {
        var hashAlgo = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
        keyAlgo = { name: 'HMAC', hash: { name: hashAlgo.toUpperCase() }, length: raw.length * 8 };
      } else if (algo.name === 'PBKDF2' || algo.name === 'HKDF') {
        keyAlgo = { name: algo.name };
      }
      var key = new CryptoKey('secret', extractable, keyAlgo, keyUsages, new Uint8Array(raw));
      return Promise.resolve(key);
    }
    if (format === 'jwk') {
      var jwk = keyData;
      if (jwk.kty === 'oct' && jwk.k) {
        var raw = base64urlDecode(jwk.k);
        var keyAlgo = algo;
        if (algo.name === 'HMAC') {
          var hashAlgo = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
          keyAlgo = { name: 'HMAC', hash: { name: hashAlgo.toUpperCase() }, length: raw.length * 8 };
        }
        var key = new CryptoKey('secret', extractable, keyAlgo, keyUsages, raw);
        return Promise.resolve(key);
      }
      return Promise.reject(new Error('Unsupported JWK key type: ' + jwk.kty));
    }
    return Promise.reject(new Error('Unsupported key format: ' + format));
  };

  // Base64url encode/decode helpers for JWK
  function base64urlEncode(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    var b64 = btoa(binary);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function base64urlDecode(str) {
    var padded = str.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) padded += '=';
    var binary = atob(padded);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  // subtle.exportKey(format, key) -> ArrayBuffer or JsonWebKey
  subtle.exportKey = function(format, key) {
    if (!key.extractable) return Promise.reject(new Error('Key is not extractable'));
    if (format === 'raw') {
      return Promise.resolve(key._keyData.buffer.slice(key._keyData.byteOffset, key._keyData.byteOffset + key._keyData.byteLength));
    }
    if (format === 'jwk') {
      var algName = key.algorithm && key.algorithm.name ? key.algorithm.name.toUpperCase() : '';
      var jwk = { kty: 'oct', k: base64urlEncode(key._keyData), ext: key.extractable, key_ops: key.usages };
      if (algName === 'AES-GCM') { jwk.alg = 'A' + key.algorithm.length + 'GCM'; }
      else if (algName === 'AES-CBC') { jwk.alg = 'A' + key.algorithm.length + 'CBC'; }
      else if (algName === 'AES-CTR') { jwk.alg = 'A' + key.algorithm.length + 'CTR'; }
      else if (algName === 'HMAC') {
        var hashName = key.algorithm.hash && typeof key.algorithm.hash === 'object' ? key.algorithm.hash.name : (key.algorithm.hash || 'SHA-256');
        var hmacAlgMap = { 'SHA-1': 'HS1', 'SHA-256': 'HS256', 'SHA-384': 'HS384', 'SHA-512': 'HS512' };
        jwk.alg = hmacAlgMap[hashName] || 'HS256';
      }
      return Promise.resolve(jwk);
    }
    return Promise.reject(new Error('Unsupported export format: ' + format));
  };

  // subtle.encrypt(algorithm, key, data) -> ArrayBuffer
  subtle.encrypt = function(algorithm, key, data) {
    var algo = normalizeAlgo(algorithm);
    var plaintext = toBytes(data);
    if (algo.name === 'AES-CBC') {
      if (!algo.iv) return Promise.reject(new Error('AES-CBC requires iv'));
      var iv = toBytes(algo.iv);
      if (typeof __exactAesCbcEncrypt !== 'function') return Promise.reject(new Error('AES-CBC not available'));
      try {
        var result = __exactAesCbcEncrypt(key._keyData, iv, plaintext);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(e); }
    }
    if (algo.name === 'AES-CTR') {
      if (!algo.counter) return Promise.reject(new Error('AES-CTR requires counter'));
      var counter = toBytes(algo.counter);
      if (typeof __exactAesCtrEncrypt !== 'function') return Promise.reject(new Error('AES-CTR not available'));
      try {
        var result = __exactAesCtrEncrypt(key._keyData, counter, plaintext);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(e); }
    }
    if (algo.name === 'AES-GCM') {
      if (!algo.iv) return Promise.reject(new Error('AES-GCM requires iv'));
      var iv = toBytes(algo.iv);
      var aad = algo.additionalData ? toBytes(algo.additionalData) : undefined;
      var tagLength = algo.tagLength || 128;
      if (typeof __exactAesGcmEncrypt !== 'function') return Promise.reject(new Error('AES-GCM not available'));
      try {
        var result = __exactAesGcmEncrypt(key._keyData, iv, plaintext, aad, tagLength);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(e); }
    }
    return Promise.reject(new Error('Unsupported encrypt algorithm: ' + algo.name));
  };

  // subtle.decrypt(algorithm, key, data) -> ArrayBuffer
  subtle.decrypt = function(algorithm, key, data) {
    var algo = normalizeAlgo(algorithm);
    var ciphertext = toBytes(data);
    if (algo.name === 'AES-CBC') {
      if (!algo.iv) return Promise.reject(new Error('AES-CBC requires iv'));
      var iv = toBytes(algo.iv);
      if (typeof __exactAesCbcDecrypt !== 'function') return Promise.reject(new Error('AES-CBC not available'));
      try {
        var result = __exactAesCbcDecrypt(key._keyData, iv, ciphertext);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(e); }
    }
    if (algo.name === 'AES-CTR') {
      if (!algo.counter) return Promise.reject(new Error('AES-CTR requires counter'));
      var counter = toBytes(algo.counter);
      if (typeof __exactAesCtrEncrypt !== 'function') return Promise.reject(new Error('AES-CTR not available'));
      try {
        // CTR mode encrypt and decrypt are the same operation
        var result = __exactAesCtrEncrypt(key._keyData, counter, ciphertext);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(e); }
    }
    if (algo.name === 'AES-GCM') {
      if (!algo.iv) return Promise.reject(new Error('AES-GCM requires iv'));
      var iv = toBytes(algo.iv);
      var aad = algo.additionalData ? toBytes(algo.additionalData) : undefined;
      var tagLength = algo.tagLength || 128;
      if (typeof __exactAesGcmDecrypt !== 'function') return Promise.reject(new Error('AES-GCM not available'));
      try {
        var result = __exactAesGcmDecrypt(key._keyData, iv, ciphertext, aad, tagLength);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(e); }
    }
    return Promise.reject(new Error('Unsupported decrypt algorithm: ' + algo.name));
  };

  // subtle.sign(algorithm, key, data) -> ArrayBuffer
  subtle.sign = function(algorithm, key, data) {
    var algo = normalizeAlgo(algorithm);
    if (algo.name === 'HMAC') {
      var rawHash = key.algorithm && key.algorithm.hash ? key.algorithm.hash : null;
      var hashAlgo = typeof rawHash === 'string' ? rawHash : (rawHash && rawHash.name ? rawHash.name : 'SHA-256');
      var nameMap = { 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' };
      var hashName = nameMap[hashAlgo.toUpperCase()];
      if (!hashName) return Promise.reject(new Error('Unsupported hash: ' + hashAlgo));
      var bytes = toBytes(data);
      // Convert to strings for native bridge
      var dataStr = '';
      for (var i = 0; i < bytes.length; i++) dataStr += String.fromCharCode(bytes[i]);
      var keyStr = '';
      for (var j = 0; j < key._keyData.length; j++) keyStr += String.fromCharCode(key._keyData[j]);
      if (typeof __exactHmacSync !== 'function') return Promise.reject(new Error('HMAC not available'));
      var hex = __exactHmacSync(hashName, keyStr, dataStr);
      var result = new Uint8Array(hex.length / 2);
      for (var k = 0; k < hex.length; k += 2) {
        result[k / 2] = parseInt(hex.substr(k, 2), 16);
      }
      return Promise.resolve(result.buffer);
    }
    return Promise.reject(new Error('Unsupported sign algorithm: ' + algo.name));
  };

  // subtle.verify(algorithm, key, signature, data) -> boolean
  subtle.verify = function(algorithm, key, signature, data) {
    return subtle.sign(algorithm, key, data).then(function(computed) {
      var sig = toBytes(signature);
      var comp = new Uint8Array(computed);
      if (sig.length !== comp.length) return false;
      var diff = 0;
      for (var i = 0; i < sig.length; i++) diff |= sig[i] ^ comp[i];
      return diff === 0;
    });
  };

  // subtle.deriveBits(algorithm, baseKey, length) -> ArrayBuffer
  subtle.deriveBits = function(algorithm, baseKey, length) {
    var algo = normalizeAlgo(algorithm);
    if (algo.name === 'PBKDF2') {
      if (!algo.salt || !algo.iterations) return Promise.reject(new Error('PBKDF2 requires salt and iterations'));
      var salt = toBytes(algo.salt);
      var hashName = typeof algo.hash === 'string' ? algo.hash : (algo.hash && algo.hash.name ? algo.hash.name : 'SHA-256');
      if (typeof __exactPbkdf2 !== 'function') return Promise.reject(new Error('PBKDF2 not available'));
      try {
        var result = __exactPbkdf2(baseKey._keyData, salt, algo.iterations, length / 8, hashName);
        return Promise.resolve(result.buffer.slice(result.byteOffset, result.byteOffset + result.byteLength));
      } catch(e) { return Promise.reject(e); }
    }
    return Promise.reject(new Error('Unsupported deriveBits algorithm: ' + algo.name));
  };

  // subtle.deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages) -> CryptoKey
  subtle.deriveKey = function(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages) {
    var derived = normalizeAlgo(derivedKeyAlgorithm);
    var length = derived.length || 256;
    return subtle.deriveBits(algorithm, baseKey, length).then(function(bits) {
      return subtle.importKey('raw', bits, derivedKeyAlgorithm, extractable, keyUsages);
    });
  };

  // subtle.wrapKey(format, key, wrappingKey, wrapAlgorithm) -> ArrayBuffer
  subtle.wrapKey = function(format, key, wrappingKey, wrapAlgorithm) {
    return subtle.exportKey(format, key).then(function(exported) {
      return subtle.encrypt(wrapAlgorithm, wrappingKey, exported);
    });
  };

  // subtle.unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages)
  subtle.unwrapKey = function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
    return subtle.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey).then(function(rawKey) {
      return subtle.importKey(format, rawKey, unwrappedKeyAlgorithm, extractable, keyUsages);
    });
  };

  // Set globalThis.crypto
  globalThis.crypto = {
    getRandomValues: getRandomValues,
    randomUUID: randomUUID,
    subtle: subtle
  };
})();
)JS";

    try {
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(webCryptoJS);
      rt.evaluateJavaScript(buffer, "<web-crypto>");
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, (std::string("Web Crypto setup error: ") + err.getMessage()).c_str());
    } catch (const std::exception& err) {
      ex_host_console_log(1, (std::string("Web Crypto setup error: ") + err.what()).c_str());
    }
  }

  // --- localStorage / sessionStorage (file-backed) ---
  {
    static const char* storageJS = R"JS(
(function() {
  'use strict';
  var _homedir = typeof process !== 'undefined' && process.env && process.env.HOME ? process.env.HOME : '/tmp';
  var _storePath = _homedir + '/.exact/localStorage.json';
  var _mkdirPath = _homedir + '/.exact';

  function _load() {
    try {
      if (typeof __exactReadFile === 'function') {
        var bytes = __exactReadFile(_storePath);
        if (bytes && bytes.length > 0) {
          var str = '';
          for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
          return JSON.parse(str);
        }
      }
    } catch(e) {}
    return {};
  }

  function _save(data) {
    try {
      if (typeof __exactWriteFile === 'function' && typeof __exactMkdir === 'function') {
        try { __exactMkdir(_mkdirPath); } catch(e) {}
        var json = JSON.stringify(data);
        var bytes = new Uint8Array(json.length);
        for (var i = 0; i < json.length; i++) bytes[i] = json.charCodeAt(i);
        __exactWriteFile(_storePath, bytes);
      }
    } catch(e) {}
  }

  function StorageImpl(persistent) {
    this._data = persistent ? _load() : {};
    this._persistent = persistent;
  }
  Object.defineProperty(StorageImpl.prototype, 'length', {
    get: function() {
      return Object.keys(this._data).length;
    }
  });
  StorageImpl.prototype.key = function(index) {
    var keys = Object.keys(this._data);
    return index >= 0 && index < keys.length ? keys[index] : null;
  };
  StorageImpl.prototype.getItem = function(key) {
    var k = String(key);
    return this._data.hasOwnProperty(k) ? this._data[k] : null;
  };
  StorageImpl.prototype.setItem = function(key, value) {
    this._data[String(key)] = String(value);
    if (this._persistent) _save(this._data);
  };
  StorageImpl.prototype.removeItem = function(key) {
    delete this._data[String(key)];
    if (this._persistent) _save(this._data);
  };
  StorageImpl.prototype.clear = function() {
    this._data = {};
    if (this._persistent) _save(this._data);
  };

  globalThis.localStorage = new StorageImpl(true);
  globalThis.sessionStorage = new StorageImpl(false);
})();
)JS";

    try {
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(storageJS);
      rt.evaluateJavaScript(buffer, "<web-storage>");
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, (std::string("Storage setup error: ") + err.getMessage()).c_str());
    } catch (const std::exception& err) {
      ex_host_console_log(1, (std::string("Storage setup error: ") + err.what()).c_str());
    }
  }

  // --- WebSocket native bridge ---
  // Register __exactWsConnect, __exactWsSend, __exactWsClose BEFORE the JS bootstrap
  auto wsConnectFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWsConnect"),
      3,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactWsConnect: url, protocols, wsInstance required");
        }
        auto url = args[0].toString(runtime).utf8(runtime);
        auto protocols = args[1].isString() ? args[1].toString(runtime).utf8(runtime) : std::string("");
        auto wsInstance = std::make_shared<facebook::jsi::Object>(args[2].asObject(runtime));
        ExactHermesRuntime* rtHandle = handle;

        auto wsId = native_ws_connect(
            url.c_str(),
            protocols.empty() ? nullptr : protocols.c_str(),
            // open callback - receives protocol and extensions from native
            [](uint32_t, const char* protocol, const char* extensions, void* ctx) {
                auto* info = static_cast<std::pair<ExactHermesRuntime*, std::shared_ptr<facebook::jsi::Object>>*>(ctx);
                auto protoCopy = std::string(protocol ? protocol : "");
                auto extCopy = std::string(extensions ? extensions : "");
                auto wsObj = info->second;
                pushRuntimeCallback(info->first, [wsObj, protoCopy, extCopy](facebook::jsi::Runtime& rt) {
                    auto fn = wsObj->getPropertyAsFunction(rt, "_handleOpen");
                    fn.call(rt,
                        facebook::jsi::String::createFromUtf8(rt, protoCopy),
                        facebook::jsi::String::createFromUtf8(rt, extCopy));
                });
            },
            [](uint32_t, const uint8_t* data, size_t length, int is_text, void* ctx) {
                auto* info = static_cast<std::pair<ExactHermesRuntime*, std::shared_ptr<facebook::jsi::Object>>*>(ctx);
                auto wsObj = info->second;
                if (is_text) {
                    auto textCopy = std::string(reinterpret_cast<const char*>(data), length);
                    pushRuntimeCallback(info->first, [wsObj, textCopy](facebook::jsi::Runtime& rt) {
                        auto fn = wsObj->getPropertyAsFunction(rt, "_handleMessage");
                        fn.call(rt, facebook::jsi::String::createFromUtf8(rt, textCopy));
                    });
                } else {
                    auto dataCopy = std::make_shared<std::vector<uint8_t>>(data, data + length);
                    pushRuntimeCallback(info->first, [wsObj, dataCopy](facebook::jsi::Runtime& rt) {
                        auto ab = rt.global()
                            .getPropertyAsFunction(rt, "ArrayBuffer")
                            .callAsConstructor(rt, static_cast<int>(dataCopy->size()))
                            .asObject(rt)
                            .getArrayBuffer(rt);
                        memcpy(ab.data(rt), dataCopy->data(), dataCopy->size());
                        auto fn = wsObj->getPropertyAsFunction(rt, "_handleMessage");
                        fn.call(rt, std::move(ab));
                    });
                }
            },
            [](uint32_t, uint16_t code, const char* reason, int was_clean, void* ctx) {
                auto* info = static_cast<std::pair<ExactHermesRuntime*, std::shared_ptr<facebook::jsi::Object>>*>(ctx);
                auto reasonCopy = std::string(reason ? reason : "");
                auto wsObj = info->second;
                auto codeCopy = code;
                auto cleanCopy = was_clean;
                pushRuntimeCallback(info->first, [wsObj, codeCopy, reasonCopy, cleanCopy](facebook::jsi::Runtime& rt) {
                    auto fn = wsObj->getPropertyAsFunction(rt, "_handleClose");
                    fn.call(rt,
                        facebook::jsi::Value(static_cast<int>(codeCopy)),
                        facebook::jsi::String::createFromUtf8(rt, reasonCopy),
                        facebook::jsi::Value(cleanCopy != 0));
                });
            },
            // error callback
            [](uint32_t, const char* message, void* ctx) {
                auto* info = static_cast<std::pair<ExactHermesRuntime*, std::shared_ptr<facebook::jsi::Object>>*>(ctx);
                auto msgCopy = std::string(message ? message : "Unknown error");
                auto wsObj = info->second;
                pushRuntimeCallback(info->first, [wsObj, msgCopy](facebook::jsi::Runtime& rt) {
                    auto fn = wsObj->getPropertyAsFunction(rt, "_handleError");
                    fn.call(rt, facebook::jsi::String::createFromUtf8(rt, msgCopy));
                });
            },
            // bytes_sent callback - decrements bufferedAmount on JS side
            [](uint32_t, size_t bytes_sent, void* ctx) {
                auto* info = static_cast<std::pair<ExactHermesRuntime*, std::shared_ptr<facebook::jsi::Object>>*>(ctx);
                auto wsObj = info->second;
                auto sentCopy = bytes_sent;
                pushRuntimeCallback(info->first, [wsObj, sentCopy](facebook::jsi::Runtime& rt) {
                    auto fn = wsObj->getPropertyAsFunction(rt, "_handleBytesSent");
                    fn.call(rt, facebook::jsi::Value(static_cast<int>(sentCopy)));
                });
            },
            new std::pair<ExactHermesRuntime*, std::shared_ptr<facebook::jsi::Object>>(rtHandle, wsInstance)
        );
        return facebook::jsi::Value(static_cast<int>(wsId));
      });
  rt.global().setProperty(rt, "__exactWsConnect", std::move(wsConnectFn));

  auto wsSendFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWsSend"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) return facebook::jsi::Value::undefined();
        uint32_t ws_id = static_cast<uint32_t>(args[0].asNumber());
        if (args[1].isString()) {
          auto text = args[1].toString(runtime).utf8(runtime);
          native_ws_send(ws_id, reinterpret_cast<const uint8_t*>(text.c_str()), text.size(), 1);
        } else if (args[1].isObject()) {
          auto obj = args[1].asObject(runtime);
          if (obj.isArrayBuffer(runtime)) {
            auto ab = obj.getArrayBuffer(runtime);
            native_ws_send(ws_id, ab.data(runtime), ab.size(runtime), 0);
          } else {
            auto val = facebook::jsi::Value(runtime, std::move(obj));
            auto bytes = extractBytes(runtime, val);
            if (!bytes.empty()) native_ws_send(ws_id, bytes.data(), bytes.size(), 0);
          }
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactWsSend", std::move(wsSendFn));

  auto wsCloseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWsClose"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::undefined();
        uint32_t ws_id = static_cast<uint32_t>(args[0].asNumber());
        uint16_t code = count > 1 && args[1].isNumber() ? static_cast<uint16_t>(args[1].asNumber()) : 1000;
        std::string reason = count > 2 && args[2].isString() ? args[2].toString(runtime).utf8(runtime) : "";
        native_ws_close(ws_id, code, reason.c_str());
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactWsClose", std::move(wsCloseFn));

  // --- WebSocket JS class ---
  // NOTE: The C++ inline WebSocket class that was previously here has been removed.
  // The JS bootstrap (WebSocket.ts via defineLazyGlobal) now provides the spec-compliant
  // WebSocket class with proper EventTarget support, bufferedAmount tracking,
  // binaryType handling, and addEventListener. The __exactWsConnect/__exactWsSend/__exactWsClose
  // bridge functions above are still registered for the JS class to use internally.

  // --- FormData (globalThis.FormData) + multipart parser ---
  {
    static const char* formDataJS = R"JS(
(function() {
  function FormData() {
    this._entries = [];
  }
  FormData.prototype.append = function(name, value, filename) {
    this._entries.push({ name: String(name), value: value, filename: filename });
  };
  FormData.prototype.set = function(name, value, filename) {
    this.delete(name);
    this.append(name, value, filename);
  };
  FormData.prototype.get = function(name) {
    for (var i = 0; i < this._entries.length; i++) {
      if (this._entries[i].name === name) return this._entries[i].value;
    }
    return null;
  };
  FormData.prototype.getAll = function(name) {
    var result = [];
    for (var i = 0; i < this._entries.length; i++) {
      if (this._entries[i].name === name) result.push(this._entries[i].value);
    }
    return result;
  };
  FormData.prototype.has = function(name) {
    for (var i = 0; i < this._entries.length; i++) {
      if (this._entries[i].name === name) return true;
    }
    return false;
  };
  FormData.prototype.delete = function(name) {
    this._entries = this._entries.filter(function(e) { return e.name !== name; });
  };
  FormData.prototype.keys = function() {
    var keys = [];
    for (var i = 0; i < this._entries.length; i++) keys.push(this._entries[i].name);
    return keys[Symbol.iterator] ? keys[Symbol.iterator]() : { _i: 0, _a: keys, next: function() {
      return this._i < this._a.length ? { value: this._a[this._i++], done: false } : { done: true };
    }};
  };
  FormData.prototype.values = function() {
    var vals = [];
    for (var i = 0; i < this._entries.length; i++) vals.push(this._entries[i].value);
    return vals[Symbol.iterator] ? vals[Symbol.iterator]() : { _i: 0, _a: vals, next: function() {
      return this._i < this._a.length ? { value: this._a[this._i++], done: false } : { done: true };
    }};
  };
  FormData.prototype.entries = function() {
    var ents = [];
    for (var i = 0; i < this._entries.length; i++) {
      ents.push([this._entries[i].name, this._entries[i].value]);
    }
    return ents[Symbol.iterator] ? ents[Symbol.iterator]() : { _i: 0, _a: ents, next: function() {
      return this._i < this._a.length ? { value: this._a[this._i++], done: false } : { done: true };
    }};
  };
  FormData.prototype.forEach = function(callback, thisArg) {
    for (var i = 0; i < this._entries.length; i++) {
      callback.call(thisArg, this._entries[i].value, this._entries[i].name, this);
    }
  };
  FormData.prototype[Symbol.iterator] = FormData.prototype.entries;

  // Parse multipart/form-data body
  FormData._parseMultipart = function(body, boundary) {
    var fd = new FormData();
    if (!body || !boundary) return fd;
    var bodyStr = typeof body === 'string' ? body :
      (typeof TextDecoder === 'function' ? new TextDecoder().decode(body) : String(body));
    var parts = bodyStr.split('--' + boundary);
    for (var i = 1; i < parts.length; i++) {
      var part = parts[i];
      if (part.indexOf('--') === 0) break; // end boundary
      var headerEnd = part.indexOf('\r\n\r\n');
      if (headerEnd < 0) headerEnd = part.indexOf('\n\n');
      if (headerEnd < 0) continue;
      var sep = part.indexOf('\r\n\r\n') >= 0 ? '\r\n\r\n' : '\n\n';
      var headerSection = part.substring(0, headerEnd);
      var value = part.substring(headerEnd + sep.length);
      // Trim trailing \r\n
      if (value.endsWith('\r\n')) value = value.slice(0, -2);
      else if (value.endsWith('\n')) value = value.slice(0, -1);
      // Parse Content-Disposition
      var nameMatch = headerSection.match(/name="([^"]+)"/);
      var filenameMatch = headerSection.match(/filename="([^"]+)"/);
      if (nameMatch) {
        fd.append(nameMatch[1], value, filenameMatch ? filenameMatch[1] : undefined);
      }
    }
    return fd;
  };

  globalThis.FormData = FormData;
})();
)JS";

    try {
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(formDataJS);
      rt.evaluateJavaScript(buffer, "<form-data>");
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, (std::string("FormData setup error: ") + err.getMessage()).c_str());
    } catch (const std::exception& err) {
      ex_host_console_log(1, (std::string("FormData setup error: ") + err.what()).c_str());
    }
  }

  auto resolveModuleFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactModuleResolve"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          return facebook::jsi::Value::null();
        }
        auto spec = args[0].toString(runtime).utf8(runtime);
        std::string referrer;
        if (count > 1 && args[1].isString()) {
          referrer = args[1].toString(runtime).utf8(runtime);
        }
        char* json = ex_host_module_resolve(
            spec.c_str(),
            referrer.empty() ? nullptr : referrer.c_str());
        if (!json) {
          return facebook::jsi::Value::null();
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactModuleResolve", std::move(resolveModuleFn));

  // __nativeFetch(url, init, body) -> Promise<NativeResponse>
  // Uses native NSURLSession via native_fetch_macos.mm
  // Pattern matches the iOS bridge (ExactHermesBridge.cpp installNativeFetch)
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

        // Check capability
        if (!checkCapability("network:fetch")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: network:fetch capability required");
        }

        // Parse URL
        std::string url = args[0].toString(runtime).utf8(runtime);

        // Parse init object
        auto init = args[1].asObject(runtime);
        std::string method = "GET";
        if (init.hasProperty(runtime, "method")) {
          auto methodVal = init.getProperty(runtime, "method");
          if (methodVal.isString()) {
            method = methodVal.toString(runtime).utf8(runtime);
          }
        }

        // Parse headers from [[name, value], ...] format to "Key: Value\r\n" string
        std::string headers;
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

        // Parse body (Uint8Array or null)
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

        // Allocate request ID
        uint32_t requestId;
        {
          std::lock_guard<std::mutex> lock(handle->fetchMutex);
          requestId = handle->nextFetchId++;
        }

        // Create Promise
        auto promiseCtor = runtime.global().getPropertyAsFunction(runtime, "Promise");

        auto methodCopy = std::make_shared<std::string>(method);
        auto urlCopy = std::make_shared<std::string>(url);
        auto headersCopy = std::make_shared<std::string>(headers);
        auto bodyCopy = std::make_shared<std::vector<uint8_t>>(body);

        auto executor = facebook::jsi::Function::createFromHostFunction(
            runtime,
            facebook::jsi::PropNameID::forAscii(runtime, "executor"),
            2,
            [handle, requestId, methodCopy, urlCopy, headersCopy, bodyCopy](
                facebook::jsi::Runtime& rt,
                const facebook::jsi::Value&,
                const facebook::jsi::Value* args,
                size_t count) -> facebook::jsi::Value {
              if (count >= 2 && args[0].isObject() && args[1].isObject()) {
                auto resolve = std::make_shared<facebook::jsi::Function>(
                    args[0].asObject(rt).asFunction(rt));
                auto reject = std::make_shared<facebook::jsi::Function>(
                    args[1].asObject(rt).asFunction(rt));

                {
                  std::lock_guard<std::mutex> lock(handle->fetchMutex);
                  handle->fetchCallbacks[requestId] = std::make_tuple(resolve, reject, *urlCopy);
                }

                // Call native fetch (NSURLSession)
                native_fetch_perform(
                    requestId,
                    methodCopy->c_str(),
                    urlCopy->c_str(),
                    headersCopy->empty() ? nullptr : headersCopy->c_str(),
                    bodyCopy->empty() ? nullptr : bodyCopy->data(),
                    bodyCopy->size(),
                    // Response callback - called when NSURLSession completes
                    [](uint32_t req_id, int status, const char* status_text,
                       const char* resp_headers, const uint8_t* resp_body,
                       size_t resp_body_length, void* ctx) {
                      auto* wrapper = static_cast<ExactHermesRuntime*>(ctx);
                      if (!wrapper || !wrapper->runtime) return;

                      // Find and remove callbacks
                      std::shared_ptr<facebook::jsi::Function> resolve;
                      std::shared_ptr<facebook::jsi::Function> reject;
                      std::string requestUrl;
                      {
                        std::lock_guard<std::mutex> lock(wrapper->fetchMutex);
                        auto it = wrapper->fetchCallbacks.find(req_id);
                        if (it == wrapper->fetchCallbacks.end()) return;
                        resolve = std::get<0>(it->second);
                        reject = std::get<1>(it->second);
                        requestUrl = std::get<2>(it->second);
                        wrapper->fetchCallbacks.erase(it);
                      }

                      auto& rt = *wrapper->runtime;

                      try {
                        if (status == 0) {
                          reject->call(rt, facebook::jsi::JSError(rt,
                              status_text ? status_text : "Network error").value());
                          return;
                        }

                        // Build NativeResponse object
                        facebook::jsi::Object response(rt);
                        response.setProperty(rt, "status", facebook::jsi::Value(status));
                        response.setProperty(rt, "statusText",
                            facebook::jsi::String::createFromUtf8(rt,
                                status_text ? status_text : ""));
                        response.setProperty(rt, "url",
                            facebook::jsi::String::createFromUtf8(rt, requestUrl));
                        response.setProperty(rt, "redirected", facebook::jsi::Value(false));

                        // Parse response headers from "Key: Value\r\n" to [[name, value], ...]
                        facebook::jsi::Array headersArray(rt, 0);
                        if (resp_headers) {
                          std::vector<std::pair<std::string, std::string>> headerPairs;
                          std::string headersStr(resp_headers);
                          size_t pos = 0;
                          while (pos < headersStr.size()) {
                            size_t lineEnd = headersStr.find("\r\n", pos);
                            if (lineEnd == std::string::npos) lineEnd = headersStr.size();
                            std::string line = headersStr.substr(pos, lineEnd - pos);
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
                            tuple.setValueAtIndex(rt, 0,
                                facebook::jsi::String::createFromUtf8(rt, headerPairs[i].first));
                            tuple.setValueAtIndex(rt, 1,
                                facebook::jsi::String::createFromUtf8(rt, headerPairs[i].second));
                            headersArray.setValueAtIndex(rt, i, tuple);
                          }
                        }
                        response.setProperty(rt, "headers", headersArray);

                        // Body as ArrayBuffer
                        if (resp_body && resp_body_length > 0) {
                          auto arrayBufferCtor = rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
                          auto arrayBuffer = arrayBufferCtor
                              .callAsConstructor(rt, static_cast<double>(resp_body_length))
                              .getObject(rt);
                          auto ab = arrayBuffer.getArrayBuffer(rt);
                          memcpy(ab.data(rt), resp_body, resp_body_length);
                          response.setProperty(rt, "body", arrayBuffer);
                        } else {
                          response.setProperty(rt, "body", facebook::jsi::Value::null());
                        }

                        resolve->call(rt, response);
                      } catch (const std::exception& e) {
                        reject->call(rt, facebook::jsi::JSError(rt, e.what()).value());
                      } catch (...) {}
                    },
                    handle  // context pointer
                );
              }
              return facebook::jsi::Value::undefined();
            }
        );

        return promiseCtor.callAsConstructor(runtime, executor);
      });
  rt.global().setProperty(rt, "__nativeFetch", std::move(nativeFetchFn));

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
        std::string hostname = "0.0.0.0";
        if (count > 1 && args[1].isString()) {
          hostname = args[1].toString(runtime).utf8(runtime);
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
  // Item 5: Uses a persistent waiter thread pool instead of spawning a
  // detached thread per call. Tasks are submitted to a shared pool.
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

              // Item 5: Use persistent waiter thread pool.
              // We use a static thread pool with a work queue instead of
              // creating/destroying a thread per wait call.
              struct WaitTask {
                ExactHermesRuntime* handle;
                uint32_t server_id;
                uint32_t timeout_ms;
                std::shared_ptr<facebook::jsi::Function> resolve;
                std::shared_ptr<facebook::jsi::Function> reject;
              };

              static std::mutex poolMutex;
              static std::condition_variable poolCv;
              static std::deque<WaitTask> poolQueue;
              static bool poolInitialized = false;
              static constexpr int POOL_SIZE = 4;

              auto task = WaitTask{handle, server_id, timeout_ms, resolve, reject};

              {
                std::lock_guard<std::mutex> lock(poolMutex);
                if (!poolInitialized) {
                  poolInitialized = true;
                  for (int i = 0; i < POOL_SIZE; i++) {
                    std::thread([]() {
                      while (true) {
                        WaitTask t;
                        {
                          std::unique_lock<std::mutex> lock(poolMutex);
                          poolCv.wait(lock, []{ return !poolQueue.empty(); });
                          t = std::move(poolQueue.front());
                          poolQueue.pop_front();
                        }

                        char* json = ex_host_http_wait(t.server_id, t.timeout_ms);
                        std::string payload;
                        bool has_payload = false;
                        if (json) {
                          payload = json;
                          has_payload = true;
                          ex_host_free_string(json);
                        }

                        pushRuntimeCallback(t.handle,
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
                }
                poolQueue.push_back(std::move(task));
              }
              poolCv.notify_one();

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

  // __exactSqliteOpen(path, options) -> numeric sqlite handle
  auto sqliteOpenFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteOpen"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteOpen: path required");
        }
        std::string path = args[0].toString(runtime).utf8(runtime);
        std::string optionsJson;
        const char* options = nullptr;
        if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
          optionsJson = stringifyValue(runtime, args[1]);
          options = optionsJson.c_str();
        }
        uint64_t handle = ex_host_sqlite_open(path.c_str(), options);
        if (handle == 0) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteOpen failed");
        }
        return facebook::jsi::Value(static_cast<double>(handle));
      });
  rt.global().setProperty(rt, "__exactSqliteOpen", std::move(sqliteOpenFn));

  // __exactSqliteClose(handle) -> 0/-1
  auto sqliteCloseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteClose"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteClose: handle required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        ex_host_sqlite_close(handle);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSqliteClose", std::move(sqliteCloseFn));

  // __exactSqlitePrepare(handle, sql) -> object {handle, ...}
  auto sqlitePrepareFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqlitePrepare"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isString()) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactSqlitePrepare: db handle and sql required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        auto sql = args[1].toString(runtime).utf8(runtime);
        char* json = ex_host_sqlite_prepare(handle, sql.c_str());
        if (!json) {
          throw facebook::jsi::JSError(runtime, "__exactSqlitePrepare failed");
        }
        auto value = parseJsonValue(runtime, json);
        ex_host_free_string(json);
        return value;
      });
  rt.global().setProperty(rt, "__exactSqlitePrepare", std::move(sqlitePrepareFn));

  // __exactSqliteFinalize(statementHandle) -> 0/-1
  auto sqliteFinalizeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteFinalize"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteFinalize: statement handle required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        ex_host_sqlite_finalize(handle);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSqliteFinalize", std::move(sqliteFinalizeFn));

  // __exactSqliteExpandedSql(statementHandle) -> string
  auto sqliteExpandedSqlFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteExpandedSql"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteExpandedSql: statement handle required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        char* expanded = ex_host_sqlite_expanded_sql(handle);
        if (!expanded) {
          return facebook::jsi::Value::null();
        }
        auto value = facebook::jsi::String::createFromUtf8(runtime, expanded);
        ex_host_free_string(expanded);
        return value;
      });
  rt.global().setProperty(rt, "__exactSqliteExpandedSql", std::move(sqliteExpandedSqlFn));

  // __exactSqliteInTransaction(handle) -> boolean
  auto sqliteInTransactionFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteInTransaction"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteInTransaction: handle required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        auto in_tx = ex_host_sqlite_in_transaction(handle);
        return facebook::jsi::Value(in_tx != 0);
      });
  rt.global().setProperty(rt, "__exactSqliteInTransaction", std::move(sqliteInTransactionFn));

  auto sqliteResultToValue = [](facebook::jsi::Runtime& runtime,
                               char* json,
                               const char* error_message) -> facebook::jsi::Value {
    if (!json) {
      throw facebook::jsi::JSError(runtime, error_message);
    }
    auto value = parseJsonValue(runtime, json);
    ex_host_free_string(json);
    return value;
  };

  // __exactSqliteAll(statementHandle, bindings) -> object {rows, columnTypes}
  auto sqliteAllFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteAll"),
      2,
      [sqliteResultToValue](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteAll: statement handle required");
        }
        auto statementHandle = static_cast<uint64_t>(args[0].asNumber());
        std::string bindingsJson;
        const char* bindings = nullptr;
        if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
          bindingsJson = stringifyValue(runtime, args[1]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_all(statementHandle, bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteAll failed");
      });
  rt.global().setProperty(rt, "__exactSqliteAll", std::move(sqliteAllFn));

  // __exactSqliteGet(statementHandle, bindings) -> object {row, columnTypes}
  auto sqliteGetFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteGet"),
      2,
      [sqliteResultToValue](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteGet: statement handle required");
        }
        auto statementHandle = static_cast<uint64_t>(args[0].asNumber());
        std::string bindingsJson;
        const char* bindings = nullptr;
        if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
          bindingsJson = stringifyValue(runtime, args[1]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_get(statementHandle, bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteGet failed");
      });
  rt.global().setProperty(rt, "__exactSqliteGet", std::move(sqliteGetFn));

  // __exactSqliteRun(statementHandle, bindings) -> object {changes, lastInsertRowid}
  auto sqliteRunFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteRun"),
      2,
      [sqliteResultToValue](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteRun: statement handle required");
        }
        auto statementHandle = static_cast<uint64_t>(args[0].asNumber());
        std::string bindingsJson;
        const char* bindings = nullptr;
        if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
          bindingsJson = stringifyValue(runtime, args[1]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_run(statementHandle, bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteRun failed");
      });
  rt.global().setProperty(rt, "__exactSqliteRun", std::move(sqliteRunFn));

  // __exactSqliteValues(statementHandle, bindings) -> object {rows, columnTypes}
  auto sqliteValuesFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteValues"),
      2,
      [sqliteResultToValue](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteValues: statement handle required");
        }
        auto statementHandle = static_cast<uint64_t>(args[0].asNumber());
        std::string bindingsJson;
        const char* bindings = nullptr;
        if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
          bindingsJson = stringifyValue(runtime, args[1]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_values(statementHandle, bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteValues failed");
      });
  rt.global().setProperty(rt, "__exactSqliteValues", std::move(sqliteValuesFn));

  // __exactSqliteExec(handle, sql, bindings) -> object {changes, lastInsertRowid}
  auto sqliteExecFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSqliteExec"),
      3,
      [sqliteResultToValue](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSqliteExec: db handle and sql required");
        }
        auto handle = static_cast<uint64_t>(args[0].asNumber());
        auto sql = args[1].toString(runtime).utf8(runtime);
        std::string bindingsJson;
        const char* bindings = nullptr;
        if (count > 2 && !args[2].isUndefined() && !args[2].isNull()) {
          bindingsJson = stringifyValue(runtime, args[2]);
          bindings = bindingsJson.c_str();
        }
        char* json = ex_host_sqlite_exec(handle, sql.c_str(), bindings);
        return sqliteResultToValue(runtime, json, "__exactSqliteExec failed");
      });
  rt.global().setProperty(rt, "__exactSqliteExec", std::move(sqliteExecFn));



  // __exactExecSync(command, optionsJSON) -> JSON string { stdout, stderr, status, error }
  // Executes a shell command synchronously using popen and returns result.
  auto execSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactExecSync"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("child_process")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: child_process capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactExecSync: command string required");
        }
        auto command = args[0].toString(runtime).utf8(runtime);

        // Parse options
        std::string cwd;
        uint32_t timeout_ms = 0;
        uint32_t max_buffer = 1024 * 1024; // 1MB default

        if (count > 1 && args[1].isString()) {
          auto optsJson = args[1].toString(runtime).utf8(runtime);
          auto cwdPos = optsJson.find("\"cwd\":\"");
          if (cwdPos != std::string::npos) {
            auto start = cwdPos + 7;
            auto end = optsJson.find("\"", start);
            if (end != std::string::npos) {
              cwd = optsJson.substr(start, end - start);
            }
          }
          auto timeoutPos = optsJson.find("\"timeout\":");
          if (timeoutPos != std::string::npos) {
            auto start = timeoutPos + 10;
            timeout_ms = static_cast<uint32_t>(std::stoul(optsJson.substr(start)));
          }
          auto maxBufPos = optsJson.find("\"maxBuffer\":");
          if (maxBufPos != std::string::npos) {
            auto start = maxBufPos + 12;
            max_buffer = static_cast<uint32_t>(std::stoul(optsJson.substr(start)));
          }
        }

        // Build the actual command: optionally prepend cd
        std::string fullCommand = command;
        if (!cwd.empty()) {
          fullCommand = "cd " + cwd + " && " + command;
        }

        // Redirect stderr to a temp file so we can capture it separately
        char stderrTmpPath[] = "/tmp/ex_stderr_XXXXXX";
        int stderrFd = mkstemp(stderrTmpPath);
        if (stderrFd < 0) {
          throw facebook::jsi::JSError(runtime, "Failed to create temp file for stderr");
        }
        close(stderrFd);

        std::string shellCmd = "( " + fullCommand + " ) 2>" + stderrTmpPath;

        std::atomic<bool> timedOut{false};

        FILE* fp = popen(shellCmd.c_str(), "r");
        if (!fp) {
          unlink(stderrTmpPath);
          throw facebook::jsi::JSError(runtime, "Failed to execute command");
        }

        // Start timeout thread if needed
        if (timeout_ms > 0) {
          std::thread([timeout_ms, &timedOut]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
            timedOut.store(true);
          }).detach();
        }

        // Read stdout
        std::string stdoutStr;
        char buf[4096];
        while (!timedOut.load()) {
          size_t bytesRead = fread(buf, 1, sizeof(buf), fp);
          if (bytesRead == 0) break;
          if (stdoutStr.size() + bytesRead > max_buffer) {
            stdoutStr.append(buf, max_buffer - stdoutStr.size());
            break;
          }
          stdoutStr.append(buf, bytesRead);
        }

        int pcloseResult = pclose(fp);
        int exitStatus = WIFEXITED(pcloseResult) ? WEXITSTATUS(pcloseResult) : -1;

        // Read stderr from temp file
        std::string stderrStr;
        FILE* stderrFile = fopen(stderrTmpPath, "r");
        if (stderrFile) {
          while (true) {
            size_t bytesRead = fread(buf, 1, sizeof(buf), stderrFile);
            if (bytesRead == 0) break;
            stderrStr.append(buf, bytesRead);
          }
          fclose(stderrFile);
        }
        unlink(stderrTmpPath);

        // JSON escape helper
        auto jsonEscape = [](const std::string& s) -> std::string {
          std::string result;
          result.reserve(s.size() + 16);
          for (char c : s) {
            switch (c) {
              case '"': result += "\\\""; break;
              case '\\': result += "\\\\"; break;
              case '\n': result += "\\n"; break;
              case '\r': result += "\\r"; break;
              case '\t': result += "\\t"; break;
              case '\b': result += "\\b"; break;
              case '\f': result += "\\f"; break;
              default:
                if (static_cast<unsigned char>(c) < 0x20) {
                  char hex[8];
                  snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned char>(c));
                  result += hex;
                } else {
                  result += c;
                }
                break;
            }
          }
          return result;
        };

        std::string errorStr = "";
        if (timedOut.load()) {
          errorStr = "Command timed out";
          exitStatus = -1;
        }

        std::string resultJson = "{\"stdout\":\"" + jsonEscape(stdoutStr)
            + "\",\"stderr\":\"" + jsonEscape(stderrStr)
            + "\",\"status\":" + std::to_string(exitStatus);
        if (!errorStr.empty()) {
          resultJson += ",\"error\":\"" + jsonEscape(errorStr) + "\"";
        }
        resultJson += "}";

        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, resultJson));
      });
  rt.global().setProperty(rt, "__exactExecSync", std::move(execSyncFn));

  // __exactSpawnSync(file, argsJSON, optionsJSON) -> JSON string { stdout, stderr, status, pid, error }
  // Spawns a process synchronously using fork/exec and returns result.
  auto spawnSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("child_process")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: child_process capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSpawnSync: file path required");
        }
        auto file = args[0].toString(runtime).utf8(runtime);

        // Parse args array from JSON
        std::vector<std::string> spawnArgs;
        if (count > 1 && args[1].isString()) {
          auto argsJson = args[1].toString(runtime).utf8(runtime);
          if (argsJson.size() > 2 && argsJson[0] == '[') {
            size_t pos = 1;
            while (pos < argsJson.size()) {
              while (pos < argsJson.size() && (argsJson[pos] == ' ' || argsJson[pos] == ',' || argsJson[pos] == '\n')) pos++;
              if (pos >= argsJson.size() || argsJson[pos] == ']') break;
              if (argsJson[pos] == '"') {
                pos++;
                std::string arg;
                while (pos < argsJson.size() && argsJson[pos] != '"') {
                  if (argsJson[pos] == '\\' && pos + 1 < argsJson.size()) {
                    pos++;
                    if (argsJson[pos] == 'n') arg += '\n';
                    else if (argsJson[pos] == 't') arg += '\t';
                    else if (argsJson[pos] == 'r') arg += '\r';
                    else arg += argsJson[pos];
                  } else {
                    arg += argsJson[pos];
                  }
                  pos++;
                }
                if (pos < argsJson.size()) pos++;
                spawnArgs.push_back(arg);
              } else {
                while (pos < argsJson.size() && argsJson[pos] != ',' && argsJson[pos] != ']') pos++;
              }
            }
          }
        }

        // Parse options
        std::string cwd;
        bool useShell = false;
        uint32_t timeout_ms = 0;
        uint32_t max_buffer = 1024 * 1024;

        if (count > 2 && args[2].isString()) {
          auto optsJson = args[2].toString(runtime).utf8(runtime);
          auto cwdPos = optsJson.find("\"cwd\":\"");
          if (cwdPos != std::string::npos) {
            auto start = cwdPos + 7;
            auto end = optsJson.find("\"", start);
            if (end != std::string::npos) {
              cwd = optsJson.substr(start, end - start);
            }
          }
          if (optsJson.find("\"shell\":true") != std::string::npos) {
            useShell = true;
          }
          auto shellPos = optsJson.find("\"shell\":\"");
          if (shellPos != std::string::npos) {
            useShell = true;
          }
          auto timeoutPos = optsJson.find("\"timeout\":");
          if (timeoutPos != std::string::npos) {
            auto start = timeoutPos + 10;
            timeout_ms = static_cast<uint32_t>(std::stoul(optsJson.substr(start)));
          }
          auto maxBufPos = optsJson.find("\"maxBuffer\":");
          if (maxBufPos != std::string::npos) {
            auto start = maxBufPos + 12;
            max_buffer = static_cast<uint32_t>(std::stoul(optsJson.substr(start)));
          }
        }

        // JSON escape helper
        auto jsonEscape = [](const std::string& s) -> std::string {
          std::string result;
          result.reserve(s.size() + 16);
          for (char c : s) {
            switch (c) {
              case '"': result += "\\\""; break;
              case '\\': result += "\\\\"; break;
              case '\n': result += "\\n"; break;
              case '\r': result += "\\r"; break;
              case '\t': result += "\\t"; break;
              case '\b': result += "\\b"; break;
              case '\f': result += "\\f"; break;
              default:
                if (static_cast<unsigned char>(c) < 0x20) {
                  char hex[8];
                  snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned char>(c));
                  result += hex;
                } else {
                  result += c;
                }
                break;
            }
          }
          return result;
        };

        // Create pipes for stdout and stderr
        int stdoutPipe[2], stderrPipe[2];
        if (pipe(stdoutPipe) != 0 || pipe(stderrPipe) != 0) {
          throw facebook::jsi::JSError(runtime, "Failed to create pipes");
        }

        pid_t pid = fork();
        if (pid < 0) {
          close(stdoutPipe[0]); close(stdoutPipe[1]);
          close(stderrPipe[0]); close(stderrPipe[1]);
          throw facebook::jsi::JSError(runtime, "Failed to fork process");
        }

        if (pid == 0) {
          // Child process
          close(stdoutPipe[0]);
          close(stderrPipe[0]);
          dup2(stdoutPipe[1], STDOUT_FILENO);
          dup2(stderrPipe[1], STDERR_FILENO);
          close(stdoutPipe[1]);
          close(stderrPipe[1]);

          if (!cwd.empty()) {
            if (chdir(cwd.c_str()) != 0) {
              _exit(127);
            }
          }

          if (useShell) {
            std::string fullCmd = file;
            for (auto& a : spawnArgs) {
              fullCmd += " " + a;
            }
            execl("/bin/sh", "sh", "-c", fullCmd.c_str(), nullptr);
          } else {
            std::vector<char*> argv;
            argv.push_back(const_cast<char*>(file.c_str()));
            for (auto& a : spawnArgs) {
              argv.push_back(const_cast<char*>(a.c_str()));
            }
            argv.push_back(nullptr);
            execvp(file.c_str(), argv.data());
          }
          _exit(127);
        }

        // Parent process
        close(stdoutPipe[1]);
        close(stderrPipe[1]);

        std::string stdoutStr, stderrStr;
        char buf[4096];
        std::atomic<bool> timedOut{false};

        if (timeout_ms > 0) {
          std::thread([timeout_ms, &timedOut, pid]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
            if (!timedOut.load()) {
              timedOut.store(true);
              kill(pid, SIGKILL);
            }
          }).detach();
        }

        // Read stdout
        while (true) {
          ssize_t bytesRead = read(stdoutPipe[0], buf, sizeof(buf));
          if (bytesRead <= 0) break;
          if (stdoutStr.size() + static_cast<size_t>(bytesRead) > max_buffer) {
            stdoutStr.append(buf, max_buffer - stdoutStr.size());
            break;
          }
          stdoutStr.append(buf, static_cast<size_t>(bytesRead));
        }
        close(stdoutPipe[0]);

        // Read stderr
        while (true) {
          ssize_t bytesRead = read(stderrPipe[0], buf, sizeof(buf));
          if (bytesRead <= 0) break;
          stderrStr.append(buf, static_cast<size_t>(bytesRead));
        }
        close(stderrPipe[0]);

        // Wait for child
        int status = 0;
        waitpid(pid, &status, 0);
        int exitStatus = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (WIFSIGNALED(status)) {
          exitStatus = -WTERMSIG(status);
        }

        std::string errorStr;
        if (timedOut.load()) {
          errorStr = "Command timed out";
        } else if (exitStatus == 127) {
          errorStr = "Command not found: " + file;
        }

        std::string resultJson = "{\"stdout\":\"" + jsonEscape(stdoutStr)
            + "\",\"stderr\":\"" + jsonEscape(stderrStr)
            + "\",\"status\":" + std::to_string(exitStatus)
            + ",\"pid\":" + std::to_string(static_cast<int>(pid));
        if (!errorStr.empty()) {
          resultJson += ",\"error\":\"" + jsonEscape(errorStr) + "\"";
        }
        resultJson += "}";

        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, resultJson));
      });
  rt.global().setProperty(rt, "__exactSpawnSync", std::move(spawnSyncFn));

  // --- Async spawn support ---
  // SpawnedProcess stores pipe fds and pid for async child processes.
  struct SpawnedProcess {
    pid_t pid;
    int stdinFd;   // parent writes to child's stdin
    int stdoutFd;  // parent reads from child's stdout
    int stderrFd;  // parent reads from child's stderr
    bool exited;
    int exitCode;
    int exitSignal; // 0 if exited normally, >0 if signaled
  };
  static std::unordered_map<int, SpawnedProcess> s_spawnedProcesses;
  static int s_nextSpawnHandle = 1;
  static std::mutex s_spawnMutex;

  // __exactSpawn(file, argsJSON, optionsJSON) -> JSON string {"handle":N,"pid":N} or {"error":"..."}
  auto spawnFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawn"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("child_process")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: child_process capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSpawn: file path required");
        }
        auto file = args[0].toString(runtime).utf8(runtime);

        // Parse args array from JSON
        std::vector<std::string> spawnArgs;
        if (count > 1 && args[1].isString()) {
          auto argsJson = args[1].toString(runtime).utf8(runtime);
          if (argsJson.size() > 2 && argsJson[0] == '[') {
            size_t pos = 1;
            while (pos < argsJson.size()) {
              while (pos < argsJson.size() && (argsJson[pos] == ' ' || argsJson[pos] == ',' || argsJson[pos] == '\n')) pos++;
              if (pos >= argsJson.size() || argsJson[pos] == ']') break;
              if (argsJson[pos] == '"') {
                pos++;
                std::string arg;
                while (pos < argsJson.size() && argsJson[pos] != '"') {
                  if (argsJson[pos] == '\\' && pos + 1 < argsJson.size()) {
                    pos++;
                    if (argsJson[pos] == 'n') arg += '\n';
                    else if (argsJson[pos] == 't') arg += '\t';
                    else if (argsJson[pos] == 'r') arg += '\r';
                    else arg += argsJson[pos];
                  } else {
                    arg += argsJson[pos];
                  }
                  pos++;
                }
                if (pos < argsJson.size()) pos++;
                spawnArgs.push_back(arg);
              } else {
                while (pos < argsJson.size() && argsJson[pos] != ',' && argsJson[pos] != ']') pos++;
              }
            }
          }
        }

        // Parse options
        std::string cwd;
        bool useShell = false;
        std::string stdioModes[3] = {"pipe", "pipe", "pipe"};

        auto skipJsonWhitespace = [](const std::string& value, size_t& pos) {
          while (pos < value.size()) {
            char ch = value[pos];
            if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') break;
            pos++;
          }
        };

        auto parseJsonString = [](const std::string& value, size_t& pos) {
          std::string out;
          if (pos >= value.size() || value[pos] != '"') return out;
          ++pos;
          while (pos < value.size()) {
            char ch = value[pos++];
            if (ch == '\\' && pos < value.size()) {
              char escaped = value[pos++];
              if (escaped == 'n') out.push_back('\n');
              else if (escaped == 't') out.push_back('\t');
              else if (escaped == 'r') out.push_back('\r');
              else if (escaped == '"') out.push_back('"');
              else if (escaped == '\\') out.push_back('\\');
              else out.push_back(escaped);
              continue;
            }
            if (ch == '"') break;
            out.push_back(ch);
          }
          return out;
        };

        auto normalizeStdioMode = [](const std::string& value) {
          if (value == "ignore") return std::string("ignore");
          if (value == "inherit") return std::string("inherit");
          if (value == "pipe") return std::string("pipe");
          if (value == "overlapped" || value == "ipc") return std::string("pipe");
          return std::string("pipe");
        };

        if (count > 2 && args[2].isString()) {
          auto optsJson = args[2].toString(runtime).utf8(runtime);
          auto cwdPos = optsJson.find("\"cwd\":\"");
          if (cwdPos != std::string::npos) {
            auto start = cwdPos + 7;
            auto end = optsJson.find("\"", start);
            if (end != std::string::npos) {
              cwd = optsJson.substr(start, end - start);
            }
          }
          if (optsJson.find("\"shell\":true") != std::string::npos) {
            useShell = true;
          }
          auto shellPos = optsJson.find("\"shell\":\"");
          if (shellPos != std::string::npos) {
            useShell = true;
          }

          auto stdioPos = optsJson.find("\"stdio\":");
          if (stdioPos != std::string::npos) {
            size_t modePos = stdioPos + 8;
            skipJsonWhitespace(optsJson, modePos);
            if (modePos < optsJson.size()) {
              if (optsJson[modePos] == '"') {
                auto parsed = parseJsonString(optsJson, modePos);
                auto normalized = normalizeStdioMode(parsed);
                stdioModes[0] = normalized;
                stdioModes[1] = normalized;
                stdioModes[2] = normalized;
              } else if (optsJson[modePos] == '[') {
                ++modePos;
                int slot = 0;
                while (modePos < optsJson.size() && slot < 3) {
                  skipJsonWhitespace(optsJson, modePos);
                  if (modePos >= optsJson.size() || optsJson[modePos] == ']') break;
                  std::string parsed;
                  if (optsJson[modePos] == '"') {
                    parsed = parseJsonString(optsJson, modePos);
                  } else {
                    if (optsJson.compare(modePos, 4, "null") == 0) {
                      modePos += 4;
                    } else {
                      while (modePos < optsJson.size() &&
                             optsJson[modePos] != ',' &&
                             optsJson[modePos] != ']') {
                        modePos++;
                      }
                    }
                  }
                  stdioModes[slot] = normalizeStdioMode(parsed);
                  slot++;
                  skipJsonWhitespace(optsJson, modePos);
                  if (modePos < optsJson.size() && optsJson[modePos] == ',') {
                    modePos++;
                  }
                }
              }
            }
          }
        }

        const bool stdinPipeRequested = stdioModes[0] == "pipe";
        const bool stdoutPipeRequested = stdioModes[1] == "pipe";
        const bool stderrPipeRequested = stdioModes[2] == "pipe";

        // Create pipes for stdin, stdout, stderr
        int stdinPipeFd[2] = {-1, -1};
        int stdoutPipeFd[2] = {-1, -1};
        int stderrPipeFd[2] = {-1, -1};

        if (stdinPipeRequested && pipe(stdinPipeFd) != 0) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create stdin pipe\"}"));
        }
        if (stdoutPipeRequested && pipe(stdoutPipeFd) != 0) {
          if (stdinPipeFd[0] >= 0) {
            close(stdinPipeFd[0]);
          }
          if (stdinPipeFd[1] >= 0) {
            close(stdinPipeFd[1]);
          }
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create stdout pipe\"}"));
        }
        if (stderrPipeRequested && pipe(stderrPipeFd) != 0) {
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create stderr pipe\"}"));
        }

        pid_t pid = fork();
        if (pid < 0) {
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
          if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to fork process\"}"));
        }

        if (pid == 0) {
          // Child process
          if (stdinPipeRequested) {
            close(stdinPipeFd[1]);
            dup2(stdinPipeFd[0], STDIN_FILENO);
            close(stdinPipeFd[0]);
          } else if (stdioModes[0] == "ignore") {
            int nullStdin = open("/dev/null", O_RDONLY);
            if (nullStdin >= 0) {
              dup2(nullStdin, STDIN_FILENO);
              close(nullStdin);
            }
          }

          if (stdoutPipeRequested) {
            close(stdoutPipeFd[0]);
            dup2(stdoutPipeFd[1], STDOUT_FILENO);
            close(stdoutPipeFd[1]);
          } else if (stdioModes[1] == "ignore") {
            int nullStdout = open("/dev/null", O_WRONLY);
            if (nullStdout >= 0) {
              dup2(nullStdout, STDOUT_FILENO);
              close(nullStdout);
            }
          }

          if (stderrPipeRequested) {
            close(stderrPipeFd[0]);
            dup2(stderrPipeFd[1], STDERR_FILENO);
            close(stderrPipeFd[1]);
          } else if (stdioModes[2] == "ignore") {
            int nullStderr = open("/dev/null", O_WRONLY);
            if (nullStderr >= 0) {
              dup2(nullStderr, STDERR_FILENO);
              close(nullStderr);
            }
          }

          if (!stdinPipeRequested) {
            if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
            if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          }
          if (!stdoutPipeRequested) {
            if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
            if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          }
          if (!stderrPipeRequested) {
            if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
            if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          }

          if (!cwd.empty()) {
            if (chdir(cwd.c_str()) != 0) {
              _exit(127);
            }
          }

          if (useShell) {
            std::string fullCmd = file;
            for (auto& a : spawnArgs) {
              fullCmd += " " + a;
            }
            execl("/bin/sh", "sh", "-c", fullCmd.c_str(), nullptr);
          } else {
            std::vector<char*> argv;
            argv.push_back(const_cast<char*>(file.c_str()));
            for (auto& a : spawnArgs) {
              argv.push_back(const_cast<char*>(a.c_str()));
            }
            argv.push_back(nullptr);
            execvp(file.c_str(), argv.data());
          }
          _exit(127);
        }

        // Parent process
        if (stdinPipeRequested) close(stdinPipeFd[0]);   // close read end of stdin pipe (child reads)
        if (stdoutPipeRequested) close(stdoutPipeFd[1]); // close write end of stdout pipe (child writes)
        if (stderrPipeRequested) close(stderrPipeFd[1]); // close write end of stderr pipe (child writes)

        if (stdoutPipeRequested) fcntl(stdoutPipeFd[0], F_SETFL, O_NONBLOCK);
        if (stderrPipeRequested) fcntl(stderrPipeFd[0], F_SETFL, O_NONBLOCK);

        // Store in map
        int handle;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          handle = s_nextSpawnHandle++;
          SpawnedProcess proc;
          proc.pid = pid;
          proc.stdinFd = stdinPipeRequested ? stdinPipeFd[1] : -1;
          proc.stdoutFd = stdoutPipeRequested ? stdoutPipeFd[0] : -1;
          proc.stderrFd = stderrPipeRequested ? stderrPipeFd[0] : -1;
          proc.exited = false;
          proc.exitCode = -1;
          proc.exitSignal = 0;
          s_spawnedProcesses[handle] = proc;
        }

        std::string resultJson = "{\"handle\":" + std::to_string(handle)
            + ",\"pid\":" + std::to_string(static_cast<int>(pid)) + "}";
        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, resultJson));
      });
  rt.global().setProperty(rt, "__exactSpawn", std::move(spawnFn));

  // __exactSpawnRead(handle, stream) -> string (data read, empty if nothing available)
  // stream is "stdout" or "stderr". Non-blocking read.
  auto spawnReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRead"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isString()) {
          return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(runtime, ""));
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto streamName = args[1].toString(runtime).utf8(runtime);

        int fd = -1;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it == s_spawnedProcesses.end()) {
            return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(runtime, ""));
          }
          if (streamName == "stdout") {
            fd = it->second.stdoutFd;
          } else if (streamName == "stderr") {
            fd = it->second.stderrFd;
          }
        }

        if (fd < 0) {
          return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(runtime, ""));
        }

        // Non-blocking read
        char buf[65536];
        std::string result;
        while (true) {
          ssize_t n = read(fd, buf, sizeof(buf));
          if (n > 0) {
            result.append(buf, static_cast<size_t>(n));
          } else {
            break;  // EAGAIN/EWOULDBLOCK or EOF
          }
        }

        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, result));
      });
  rt.global().setProperty(rt, "__exactSpawnRead", std::move(spawnReadFn));

  // __exactSpawnWrite(handle, data) -> boolean (success)
  auto spawnWriteFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnWrite"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isString()) {
          return facebook::jsi::Value(false);
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto data = args[1].toString(runtime).utf8(runtime);

        int fd = -1;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it == s_spawnedProcesses.end()) {
            return facebook::jsi::Value(false);
          }
          fd = it->second.stdinFd;
        }

        if (fd < 0) {
          return facebook::jsi::Value(false);
        }

        size_t totalWritten = 0;
        while (totalWritten < data.size()) {
          ssize_t n = write(fd, data.c_str() + totalWritten, data.size() - totalWritten);
          if (n < 0) {
            if (errno == EINTR) continue;
            return facebook::jsi::Value(false);
          }
          totalWritten += static_cast<size_t>(n);
        }
        return facebook::jsi::Value(true);
      });
  rt.global().setProperty(rt, "__exactSpawnWrite", std::move(spawnWriteFn));

  // __exactSpawnPoll(handle) -> JSON string {"exited":bool,"exitCode":N,"signal":N}
  // Uses waitpid with WNOHANG for non-blocking check.
  auto spawnPollFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnPoll"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":false,\"exitCode\":-1,\"signal\":0}"));
        }
        int handle = static_cast<int>(args[0].asNumber());

        std::lock_guard<std::mutex> lock(s_spawnMutex);
        auto it = s_spawnedProcesses.find(handle);
        if (it == s_spawnedProcesses.end()) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":true,\"exitCode\":-1,\"signal\":0}"));
        }

        auto& proc = it->second;
        if (proc.exited) {
          std::string json = "{\"exited\":true,\"exitCode\":" + std::to_string(proc.exitCode)
              + ",\"signal\":" + std::to_string(proc.exitSignal) + "}";
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, json));
        }

        int status = 0;
        pid_t result = waitpid(proc.pid, &status, WNOHANG);
        if (result == 0) {
          // Still running
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":false,\"exitCode\":-1,\"signal\":0}"));
        } else if (result > 0) {
          // Process exited
          proc.exited = true;
          if (WIFEXITED(status)) {
            proc.exitCode = WEXITSTATUS(status);
            proc.exitSignal = 0;
          } else if (WIFSIGNALED(status)) {
            proc.exitCode = -1;
            proc.exitSignal = WTERMSIG(status);
          }
          std::string json = "{\"exited\":true,\"exitCode\":" + std::to_string(proc.exitCode)
              + ",\"signal\":" + std::to_string(proc.exitSignal) + "}";
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, json));
        } else {
          // waitpid error
          proc.exited = true;
          proc.exitCode = -1;
          std::string json = "{\"exited\":true,\"exitCode\":-1,\"signal\":0}";
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, json));
        }
      });
  rt.global().setProperty(rt, "__exactSpawnPoll", std::move(spawnPollFn));

  // __exactSpawnKill(handle, signal) -> boolean (success)
  // signal: number (e.g. 15 for SIGTERM, 9 for SIGKILL)
  auto spawnKillFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnKill"),
      2,
      [](facebook::jsi::Runtime& /*runtime*/,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(false);
        }
        int handle = static_cast<int>(args[0].asNumber());
        int sig = SIGTERM; // default
        if (count > 1 && args[1].isNumber()) {
          sig = static_cast<int>(args[1].asNumber());
        }

        std::lock_guard<std::mutex> lock(s_spawnMutex);
        auto it = s_spawnedProcesses.find(handle);
        if (it == s_spawnedProcesses.end()) {
          return facebook::jsi::Value(false);
        }

        auto& proc = it->second;
        if (proc.exited) {
          return facebook::jsi::Value(false);
        }

        int killResult = kill(proc.pid, sig);
        return facebook::jsi::Value(killResult == 0);
      });
  rt.global().setProperty(rt, "__exactSpawnKill", std::move(spawnKillFn));

  // __exactSpawnCloseStdin(handle) -> void
  // Closes the stdin pipe so the child process sees EOF on its stdin.
  auto spawnCloseStdinFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnCloseStdin"),
      1,
      [](facebook::jsi::Runtime& /*runtime*/,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        int handle = static_cast<int>(args[0].asNumber());

        std::lock_guard<std::mutex> lock(s_spawnMutex);
        auto it = s_spawnedProcesses.find(handle);
        if (it == s_spawnedProcesses.end()) {
          return facebook::jsi::Value::undefined();
        }

        auto& proc = it->second;
        if (proc.stdinFd >= 0) {
          close(proc.stdinFd);
          proc.stdinFd = -1;
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSpawnCloseStdin", std::move(spawnCloseStdinFn));

  // __exactWhich(command) -> string path or null
  // Searches PATH for the given command, similar to the `which` utility.
  auto whichFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWhich"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          return facebook::jsi::Value::null();
        }
        auto command = args[0].asString(runtime).utf8(runtime);

        // If command contains a slash, check it directly
        if (command.find('/') != std::string::npos) {
          if (access(command.c_str(), X_OK) == 0) {
            return facebook::jsi::String::createFromUtf8(runtime, command);
          }
          return facebook::jsi::Value::null();
        }

        // Get PATH environment variable
        const char* pathEnv = getenv("PATH");
        if (!pathEnv) {
          return facebook::jsi::Value::null();
        }

        std::string pathStr(pathEnv);
        std::string::size_type start = 0;
        while (start < pathStr.size()) {
          auto end = pathStr.find(':', start);
          if (end == std::string::npos) end = pathStr.size();

          std::string dir = pathStr.substr(start, end - start);
          if (!dir.empty()) {
            std::string fullPath = dir + "/" + command;
            if (access(fullPath.c_str(), X_OK) == 0) {
              // Resolve to real path
              char resolved[PATH_MAX];
              if (realpath(fullPath.c_str(), resolved) != nullptr) {
                return facebook::jsi::String::createFromUtf8(runtime, std::string(resolved));
              }
              return facebook::jsi::String::createFromUtf8(runtime, fullPath);
            }
          }

          start = end + 1;
        }

        return facebook::jsi::Value::null();
      });
  rt.global().setProperty(rt, "__exactWhich", std::move(whichFn));

  // __StringBuffer: native string builder for O(1) amortized append
  // Avoids O(n^2) string concatenation in Hermes (no rope strings)
  rt.global().setProperty(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__StringBuffer"),
      facebook::jsi::Function::createFromHostFunction(
          rt,
          facebook::jsi::PropNameID::forAscii(rt, "__StringBuffer"),
          0,
          [](facebook::jsi::Runtime& rt, const facebook::jsi::Value&,
             const facebook::jsi::Value*, size_t) -> facebook::jsi::Value {
            auto obj = std::make_shared<StringBufferHostObject>();
            return facebook::jsi::Object::createFromHostObject(rt, obj);
          }
      )
  );

  // ============================================================
  // TCP Socket host functions for net module
  // ============================================================
  {
    static std::unordered_map<int, int> g_tcp_sockets;
    static int g_tcp_next_handle = 1;
    static std::mutex g_tcp_mutex;

    // __exactTcpConnect(host, port) -> handle or throws
    auto tcpConnectFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpConnect"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 2 || !args[0].isString() || !args[1].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactTcpConnect: host (string) and port (number) required");
          }
          std::string host = args[0].toString(runtime).utf8(runtime);
          int port = static_cast<int>(args[1].asNumber());
          struct addrinfo hints{}, *result = nullptr;
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_protocol = IPPROTO_TCP;
          std::string portStr = std::to_string(port);
          int gai_err = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result);
          if (gai_err != 0) {
            throw facebook::jsi::JSError(runtime,
                ("getaddrinfo failed for " + host + ":" + portStr + ": " + gai_strerror(gai_err)).c_str());
          }
          int fd = -1;
          for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == -1) continue;
            if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
            ::close(fd);
            fd = -1;
          }
          freeaddrinfo(result);
          if (fd == -1) {
            throw facebook::jsi::JSError(runtime,
                ("connect failed for " + host + ":" + portStr + ": " + strerror(errno)).c_str());
          }
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          int handle;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            handle = g_tcp_next_handle++;
            g_tcp_sockets[handle] = fd;
          }
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactTcpConnect", std::move(tcpConnectFn));

    // __exactTcpRead(handle, maxBytes) -> string (data), null (EOF), "" (EAGAIN)
    auto tcpReadFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpRead"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactTcpRead: handle required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          int maxBytes = 65536;
          if (count > 1 && args[1].isNumber()) {
            maxBytes = static_cast<int>(args[1].asNumber());
            if (maxBytes <= 0) maxBytes = 65536;
          }
          int fd;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            auto it = g_tcp_sockets.find(handle);
            if (it == g_tcp_sockets.end()) throw facebook::jsi::JSError(runtime, "__exactTcpRead: invalid handle");
            fd = it->second;
          }
          std::vector<char> buf(maxBytes);
          ssize_t n = ::read(fd, buf.data(), maxBytes);
          if (n > 0) {
            return facebook::jsi::String::createFromUtf8(runtime, reinterpret_cast<const uint8_t*>(buf.data()), n);
          } else if (n == 0) {
            return facebook::jsi::Value::null();
          } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              return facebook::jsi::String::createFromUtf8(runtime, "");
            }
            throw facebook::jsi::JSError(runtime, ("__exactTcpRead error: " + std::string(strerror(errno))).c_str());
          }
        });
    rt.global().setProperty(rt, "__exactTcpRead", std::move(tcpReadFn));

    // __exactTcpWrite(handle, data) -> bytes written
    auto tcpWriteFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpWrite"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 2 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactTcpWrite: handle and data required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          int fd;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            auto it = g_tcp_sockets.find(handle);
            if (it == g_tcp_sockets.end()) throw facebook::jsi::JSError(runtime, "__exactTcpWrite: invalid handle");
            fd = it->second;
          }
          std::string data;
          if (args[1].isString()) {
            data = args[1].toString(runtime).utf8(runtime);
          } else if (args[1].isObject()) {
            auto obj = args[1].asObject(runtime);
            if (obj.isArrayBuffer(runtime)) {
              auto ab = obj.getArrayBuffer(runtime);
              data.assign(reinterpret_cast<const char*>(ab.data(runtime)), ab.size(runtime));
            } else {
              auto bufProp = obj.getProperty(runtime, "buffer");
              auto byteLenProp = obj.getProperty(runtime, "byteLength");
              auto byteOffProp = obj.getProperty(runtime, "byteOffset");
              if (bufProp.isObject() && bufProp.asObject(runtime).isArrayBuffer(runtime)) {
                auto ab = bufProp.asObject(runtime).getArrayBuffer(runtime);
                size_t offset = byteOffProp.isNumber() ? static_cast<size_t>(byteOffProp.asNumber()) : 0;
                size_t len = byteLenProp.isNumber() ? static_cast<size_t>(byteLenProp.asNumber()) : ab.size(runtime) - offset;
                data.assign(reinterpret_cast<const char*>(ab.data(runtime) + offset), len);
              } else {
                data = args[1].toString(runtime).utf8(runtime);
              }
            }
          } else {
            data = args[1].toString(runtime).utf8(runtime);
          }
          ssize_t written = ::write(fd, data.data(), data.size());
          if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return facebook::jsi::Value(0);
            throw facebook::jsi::JSError(runtime, ("__exactTcpWrite error: " + std::string(strerror(errno))).c_str());
          }
          return facebook::jsi::Value(static_cast<int>(written));
        });
    rt.global().setProperty(rt, "__exactTcpWrite", std::move(tcpWriteFn));

    // __exactTcpClose(handle) -> 0
    auto tcpCloseFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpClose"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactTcpClose: handle required");
          int handle = static_cast<int>(args[0].asNumber());
          int fd;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            auto it = g_tcp_sockets.find(handle);
            if (it == g_tcp_sockets.end()) return facebook::jsi::Value(0);
            fd = it->second;
            g_tcp_sockets.erase(it);
          }
          ::close(fd);
          return facebook::jsi::Value(0);
        });
    rt.global().setProperty(rt, "__exactTcpClose", std::move(tcpCloseFn));

    // __exactTcpSetNoDelay(handle, enable) -> 0
    auto tcpSetNoDelayFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpSetNoDelay"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactTcpSetNoDelay: handle required");
          int handle = static_cast<int>(args[0].asNumber());
          int enable = (count > 1 && args[1].isNumber()) ? static_cast<int>(args[1].asNumber()) : 1;
          int fd;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            auto it = g_tcp_sockets.find(handle);
            if (it == g_tcp_sockets.end()) return facebook::jsi::Value(-1);
            fd = it->second;
          }
          int flag = enable ? 1 : 0;
          setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
          return facebook::jsi::Value(0);
        });
    rt.global().setProperty(rt, "__exactTcpSetNoDelay", std::move(tcpSetNoDelayFn));

    // __exactTcpSetKeepAlive(handle, enable) -> 0
    auto tcpSetKeepAliveFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpSetKeepAlive"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactTcpSetKeepAlive: handle required");
          int handle = static_cast<int>(args[0].asNumber());
          int enable = (count > 1 && args[1].isNumber()) ? static_cast<int>(args[1].asNumber()) : 1;
          int fd;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            auto it = g_tcp_sockets.find(handle);
            if (it == g_tcp_sockets.end()) return facebook::jsi::Value(-1);
            fd = it->second;
          }
          int flag = enable ? 1 : 0;
          setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
          return facebook::jsi::Value(0);
        });
    rt.global().setProperty(rt, "__exactTcpSetKeepAlive", std::move(tcpSetKeepAliveFn));

    // __exactTcpListen(host, port, backlog) -> handle or throws
    auto tcpListenFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpListen"), 3,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          std::string host = "0.0.0.0";
          if (count > 0 && args[0].isString()) host = args[0].toString(runtime).utf8(runtime);
          int port = 0;
          if (count > 1 && args[1].isNumber()) port = static_cast<int>(args[1].asNumber());
          int backlog = 128;
          if (count > 2 && args[2].isNumber()) backlog = static_cast<int>(args[2].asNumber());
          struct addrinfo hints{}, *result = nullptr;
          hints.ai_family = AF_INET;
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_protocol = IPPROTO_TCP;
          hints.ai_flags = AI_PASSIVE;
          std::string portStr = std::to_string(port);
          const char* nodeStr = host == "0.0.0.0" ? nullptr : host.c_str();
          int gai_err = getaddrinfo(nodeStr, portStr.c_str(), &hints, &result);
          if (gai_err != 0) {
            throw facebook::jsi::JSError(runtime, ("getaddrinfo failed: " + std::string(gai_strerror(gai_err))).c_str());
          }
          int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
          if (fd == -1) {
            freeaddrinfo(result);
            throw facebook::jsi::JSError(runtime, ("socket() failed: " + std::string(strerror(errno))).c_str());
          }
          int reuse = 1;
          setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
          if (::bind(fd, result->ai_addr, result->ai_addrlen) == -1) {
            freeaddrinfo(result);
            ::close(fd);
            throw facebook::jsi::JSError(runtime, ("bind() failed: " + std::string(strerror(errno))).c_str());
          }
          freeaddrinfo(result);
          if (::listen(fd, backlog) == -1) {
            ::close(fd);
            throw facebook::jsi::JSError(runtime, ("listen() failed: " + std::string(strerror(errno))).c_str());
          }
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          int handle;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            handle = g_tcp_next_handle++;
            g_tcp_sockets[handle] = fd;
          }
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactTcpListen", std::move(tcpListenFn));

    // __exactTcpAccept(handle) -> new handle or -1 (EAGAIN)
    auto tcpAcceptFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpAccept"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactTcpAccept: handle required");
          int handle = static_cast<int>(args[0].asNumber());
          int listenFd;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            auto it = g_tcp_sockets.find(handle);
            if (it == g_tcp_sockets.end()) throw facebook::jsi::JSError(runtime, "__exactTcpAccept: invalid handle");
            listenFd = it->second;
          }
          struct sockaddr_storage clientAddr;
          socklen_t clientLen = sizeof(clientAddr);
          int clientFd = ::accept(listenFd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
          if (clientFd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return facebook::jsi::Value(-1);
            throw facebook::jsi::JSError(runtime, ("__exactTcpAccept error: " + std::string(strerror(errno))).c_str());
          }
          int flags = fcntl(clientFd, F_GETFL, 0);
          if (flags != -1) fcntl(clientFd, F_SETFL, flags | O_NONBLOCK);
          int newHandle;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            newHandle = g_tcp_next_handle++;
            g_tcp_sockets[newHandle] = clientFd;
          }
          return facebook::jsi::Value(newHandle);
        });
    rt.global().setProperty(rt, "__exactTcpAccept", std::move(tcpAcceptFn));

    // __exactTcpLocalAddr(handle) -> JSON string or null
    auto tcpLocalAddrFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpLocalAddr"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::null();
          int handle = static_cast<int>(args[0].asNumber());
          int fd;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            auto it = g_tcp_sockets.find(handle);
            if (it == g_tcp_sockets.end()) return facebook::jsi::Value::null();
            fd = it->second;
          }
          struct sockaddr_storage addr;
          socklen_t addrLen = sizeof(addr);
          if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &addrLen) == -1) return facebook::jsi::Value::null();
          char ipStr[INET6_ADDRSTRLEN]; int port = 0; std::string family;
          if (addr.ss_family == AF_INET) {
            auto* sa = reinterpret_cast<struct sockaddr_in*>(&addr);
            inet_ntop(AF_INET, &sa->sin_addr, ipStr, sizeof(ipStr));
            port = ntohs(sa->sin_port); family = "IPv4";
          } else if (addr.ss_family == AF_INET6) {
            auto* sa = reinterpret_cast<struct sockaddr_in6*>(&addr);
            inet_ntop(AF_INET6, &sa->sin6_addr, ipStr, sizeof(ipStr));
            port = ntohs(sa->sin6_port); family = "IPv6";
          } else { return facebook::jsi::Value::null(); }
          std::string json = "{\"address\":\"" + std::string(ipStr) + "\",\"port\":" + std::to_string(port) + ",\"family\":\"" + family + "\"}";
          return facebook::jsi::String::createFromUtf8(runtime, json);
        });
    rt.global().setProperty(rt, "__exactTcpLocalAddr", std::move(tcpLocalAddrFn));

    // __exactTcpRemoteAddr(handle) -> JSON string or null
    auto tcpRemoteAddrFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpRemoteAddr"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::null();
          int handle = static_cast<int>(args[0].asNumber());
          int fd;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            auto it = g_tcp_sockets.find(handle);
            if (it == g_tcp_sockets.end()) return facebook::jsi::Value::null();
            fd = it->second;
          }
          struct sockaddr_storage addr;
          socklen_t addrLen = sizeof(addr);
          if (getpeername(fd, reinterpret_cast<struct sockaddr*>(&addr), &addrLen) == -1) return facebook::jsi::Value::null();
          char ipStr[INET6_ADDRSTRLEN]; int port = 0; std::string family;
          if (addr.ss_family == AF_INET) {
            auto* sa = reinterpret_cast<struct sockaddr_in*>(&addr);
            inet_ntop(AF_INET, &sa->sin_addr, ipStr, sizeof(ipStr));
            port = ntohs(sa->sin_port); family = "IPv4";
          } else if (addr.ss_family == AF_INET6) {
            auto* sa = reinterpret_cast<struct sockaddr_in6*>(&addr);
            inet_ntop(AF_INET6, &sa->sin6_addr, ipStr, sizeof(ipStr));
            port = ntohs(sa->sin6_port); family = "IPv6";
          } else { return facebook::jsi::Value::null(); }
          std::string json = "{\"address\":\"" + std::string(ipStr) + "\",\"port\":" + std::to_string(port) + ",\"family\":\"" + family + "\"}";
          return facebook::jsi::String::createFromUtf8(runtime, json);
        });
    rt.global().setProperty(rt, "__exactTcpRemoteAddr", std::move(tcpRemoteAddrFn));

    // ============================================================
    // Unix Domain Socket host functions
    // Reuses g_tcp_sockets/g_tcp_next_handle/g_tcp_mutex so that
    // __exactTcpRead, __exactTcpWrite, __exactTcpClose work on
    // Unix socket fds too (they all use the same fd-based I/O).
    // ============================================================

    // __exactUnixConnect(path) -> handle or throws
    auto unixConnectFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUnixConnect"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isString()) {
            throw facebook::jsi::JSError(runtime, "__exactUnixConnect: path (string) required");
          }
          std::string path = args[0].toString(runtime).utf8(runtime);
          if (path.size() >= sizeof(((struct sockaddr_un*)0)->sun_path)) {
            throw facebook::jsi::JSError(runtime, "__exactUnixConnect: path too long");
          }
          int fd = socket(AF_UNIX, SOCK_STREAM, 0);
          if (fd == -1) {
            throw facebook::jsi::JSError(runtime,
                ("socket(AF_UNIX) failed: " + std::string(strerror(errno))).c_str());
          }
          struct sockaddr_un addr;
          memset(&addr, 0, sizeof(addr));
          addr.sun_family = AF_UNIX;
          strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
          if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == -1) {
            int saved_errno = errno;
            ::close(fd);
            throw facebook::jsi::JSError(runtime,
                ("connect(AF_UNIX) failed for " + path + ": " + strerror(saved_errno)).c_str());
          }
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          int handle;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            handle = g_tcp_next_handle++;
            g_tcp_sockets[handle] = fd;
          }
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactUnixConnect", std::move(unixConnectFn));

    // __exactUnixListen(path, backlog) -> handle or throws
    auto unixListenFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUnixListen"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isString()) {
            throw facebook::jsi::JSError(runtime, "__exactUnixListen: path (string) required");
          }
          std::string path = args[0].toString(runtime).utf8(runtime);
          if (path.size() >= sizeof(((struct sockaddr_un*)0)->sun_path)) {
            throw facebook::jsi::JSError(runtime, "__exactUnixListen: path too long");
          }
          int backlog = 128;
          if (count > 1 && args[1].isNumber()) backlog = static_cast<int>(args[1].asNumber());
          // Unlink existing socket file (common pattern for Unix sockets)
          ::unlink(path.c_str());
          int fd = socket(AF_UNIX, SOCK_STREAM, 0);
          if (fd == -1) {
            throw facebook::jsi::JSError(runtime,
                ("socket(AF_UNIX) failed: " + std::string(strerror(errno))).c_str());
          }
          struct sockaddr_un addr;
          memset(&addr, 0, sizeof(addr));
          addr.sun_family = AF_UNIX;
          strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
          if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == -1) {
            int saved_errno = errno;
            ::close(fd);
            throw facebook::jsi::JSError(runtime,
                ("bind(AF_UNIX) failed for " + path + ": " + strerror(saved_errno)).c_str());
          }
          if (::listen(fd, backlog) == -1) {
            int saved_errno = errno;
            ::close(fd);
            ::unlink(path.c_str());
            throw facebook::jsi::JSError(runtime,
                ("listen(AF_UNIX) failed: " + std::string(strerror(saved_errno))).c_str());
          }
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          int handle;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            handle = g_tcp_next_handle++;
            g_tcp_sockets[handle] = fd;
          }
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactUnixListen", std::move(unixListenFn));

    // __exactUnixAccept(handle) -> new handle or -1 (EAGAIN)
    // Identical to __exactTcpAccept but kept separate for clarity
    auto unixAcceptFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUnixAccept"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactUnixAccept: handle required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          int listenFd;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            auto it = g_tcp_sockets.find(handle);
            if (it == g_tcp_sockets.end()) {
              throw facebook::jsi::JSError(runtime, "__exactUnixAccept: invalid handle");
            }
            listenFd = it->second;
          }
          struct sockaddr_un clientAddr;
          socklen_t clientLen = sizeof(clientAddr);
          int clientFd = ::accept(listenFd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
          if (clientFd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return facebook::jsi::Value(-1);
            throw facebook::jsi::JSError(runtime,
                ("__exactUnixAccept error: " + std::string(strerror(errno))).c_str());
          }
          int flags = fcntl(clientFd, F_GETFL, 0);
          if (flags != -1) fcntl(clientFd, F_SETFL, flags | O_NONBLOCK);
          int newHandle;
          {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            newHandle = g_tcp_next_handle++;
            g_tcp_sockets[newHandle] = clientFd;
          }
          return facebook::jsi::Value(newHandle);
        });
    rt.global().setProperty(rt, "__exactUnixAccept", std::move(unixAcceptFn));

  } // end TCP + Unix socket host functions

  installModuleLoader(handle);

  // Compatibility polyfills for modern ECMAScript APIs used by npm modules.
  {
    static const char* compatibilityPolyfillsJS = R"JS(
(function() {
  if (typeof Promise !== 'undefined' && typeof Promise.withResolvers !== 'function') {
    Promise.withResolvers = function() {
      var resolve;
      var reject;
      var promise = new Promise(function(res, rej) {
        resolve = res;
        reject = rej;
      });
      return {
        promise: promise,
        resolve: resolve,
        reject: reject
      };
    };
  }

  if (typeof Array.prototype.toSorted !== 'function') {
    Array.prototype.toSorted = function(compareFn) {
      var sorted = this.slice();
      return sorted.sort(compareFn);
    };
  }

  if (typeof Array.prototype.toReversed !== 'function') {
    Array.prototype.toReversed = function() {
      var result = [];
      for (var i = this.length - 1; i >= 0; i--) result.push(this[i]);
      return result;
    };
  }

  if (typeof FinalizationRegistry === 'undefined') {
    FinalizationRegistry = function(cleanupCallback) {
      if (!(this instanceof FinalizationRegistry)) {
        throw new TypeError('FinalizationRegistry must be called with new');
      }
      if (typeof cleanupCallback !== 'function') {
        throw new TypeError('FinalizationRegistry requires a callback');
      }
      this._entries = [];
      this._cleanup = cleanupCallback;
    };
    FinalizationRegistry.prototype.register = function(target, heldValue, unregisterToken) {
      if (!target || (typeof target !== 'object' && typeof target !== 'function')) {
        throw new TypeError('FinalizationRegistry target must be an object');
      }
      this._entries.push({
        target: target,
        heldValue: heldValue,
        token: unregisterToken
      });
      return true;
    };
    FinalizationRegistry.prototype.unregister = function(unregisterToken) {
      var removed = false;
      for (var i = this._entries.length - 1; i >= 0; i--) {
        if (this._entries[i].token === unregisterToken) {
          this._entries.splice(i, 1);
          removed = true;
        }
      }
      return removed;
    };
  }
})();
)JS";
    try {
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(compatibilityPolyfillsJS);
      rt.evaluateJavaScript(buffer, "<compat-polyfills>");
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, (std::string("Compatibility polyfill error: ") + err.getMessage()).c_str());
    } catch (const std::exception& err) {
      ex_host_console_log(1, (std::string("Compatibility polyfill error: ") + err.what()).c_str());
    }
  }

  // Install Exact global (with Bun alias) including Exact.file() and Exact.write()
  static const char* exactGlobalJS = R"JS(
(function() {
  var g = globalThis;
  var MIME = {
    '.txt':'text/plain;charset=utf-8','.html':'text/html;charset=utf-8','.htm':'text/html;charset=utf-8',
    '.css':'text/css;charset=utf-8','.js':'text/javascript;charset=utf-8','.mjs':'text/javascript;charset=utf-8',
    '.ts':'text/typescript;charset=utf-8','.tsx':'text/typescript;charset=utf-8','.jsx':'text/javascript;charset=utf-8',
    '.json':'application/json;charset=utf-8','.xml':'application/xml;charset=utf-8','.svg':'image/svg+xml;charset=utf-8',
    '.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.webp':'image/webp',
    '.pdf':'application/pdf','.zip':'application/zip','.gz':'application/gzip','.wasm':'application/wasm',
    '.mp3':'audio/mpeg','.mp4':'video/mp4','.webm':'video/webm','.ogg':'audio/ogg','.wav':'audio/wav',
    '.woff':'font/woff','.woff2':'font/woff2','.ttf':'font/ttf','.otf':'font/otf',
    '.md':'text/markdown;charset=utf-8','.yaml':'text/yaml;charset=utf-8','.yml':'text/yaml;charset=utf-8',
    '.toml':'text/toml;charset=utf-8','.csv':'text/csv;charset=utf-8','.sh':'application/x-sh','.sql':'application/sql'
  };
  function mimeType(p) {
    var i = p.lastIndexOf('.');
    return i === -1 ? 'application/octet-stream' : (MIME[p.slice(i).toLowerCase()] || 'application/octet-stream');
  }
  function decode(bytes) {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(bytes);
    var r = '';
    for (var i = 0; i < bytes.length; i++) r += String.fromCharCode(bytes[i]);
    return r;
  }
  function toBytes(data) {
    if (typeof data === 'string') {
      if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(data);
      var buf = new Uint8Array(data.length * 3), o = 0;
      for (var i = 0; i < data.length; i++) {
        var c = data.charCodeAt(i);
        if (c < 0x80) buf[o++] = c;
        else if (c < 0x800) { buf[o++] = 0xc0|(c>>6); buf[o++] = 0x80|(c&0x3f); }
        else { buf[o++] = 0xe0|(c>>12); buf[o++] = 0x80|((c>>6)&0x3f); buf[o++] = 0x80|(c&0x3f); }
      }
      return buf.slice(0, o);
    }
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(data))
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(data);
  }

  function ExactFile(path, opts) {
    this.name = path;
    this.type = (opts && opts.type) || mimeType(path);
  }
  Object.defineProperty(ExactFile.prototype, 'size', {
    get: function() {
      try { var s = JSON.parse(g.__exactStat(this.name)); return s.size; } catch(e) { return 0; }
    }
  });
  Object.defineProperty(ExactFile.prototype, 'lastModified', {
    get: function() {
      try { var s = JSON.parse(g.__exactStat(this.name)); return s.mtime_ms; } catch(e) { return 0; }
    }
  });
  ExactFile.prototype.text = function() {
    var n = this.name;
    return Promise.resolve().then(function() { return decode(g.__exactReadFile(n)); });
  };
  ExactFile.prototype.json = function() {
    var n = this.name;
    return Promise.resolve().then(function() { return JSON.parse(decode(g.__exactReadFile(n))); });
  };
  ExactFile.prototype.arrayBuffer = function() {
    var n = this.name;
    return Promise.resolve().then(function() {
      var b = g.__exactReadFile(n);
      return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    });
  };
  ExactFile.prototype.bytes = function() {
    var n = this.name;
    return Promise.resolve().then(function() { return g.__exactReadFile(n); });
  };
  ExactFile.prototype.exists = function() {
    var n = this.name;
    return Promise.resolve().then(function() {
      try { g.__exactAccess(n, 0); return true; } catch(e) { return false; }
    });
  };
  ExactFile.prototype.stat = function() {
    var n = this.name;
    return Promise.resolve().then(function() {
      try { return JSON.parse(g.__exactStat(n)); } catch(e) { return null; }
    });
  };
  ExactFile.prototype.slice = function(begin, end, type) {
    var b = g.__exactReadFile(this.name);
    var s = b.slice(begin || 0, end === undefined ? b.length : end);
    return new Blob([s], { type: type || this.type });
  };
  ExactFile.prototype.stream = function() {
    var n = this.name;
    return new ReadableStream({
      start: function(c) {
        try { c.enqueue(g.__exactReadFile(n)); c.close(); } catch(e) { c.error(e); }
      }
    });
  };
  ExactFile.prototype.writer = function() {
    var n = this.name, started = false;
    return {
      write: function(data) {
        var b = toBytes(data);
        if (!started) { g.__exactWriteFile(n, b); started = true; }
        else if (typeof g.__exactAppendFile === 'function') { g.__exactAppendFile(n, b); }
        return b.length;
      },
      end: function() {},
      flush: function() {}
    };
  };
  ExactFile.prototype.toString = function() { return 'ExactFile("' + this.name + '")'; };

  var E = g.Exact || {};
  function toModuleId(value) {
    if (typeof value === 'number' && isFinite(value) && value >= 0) {
      return value;
    }
    if (typeof value === 'string') {
      var parsed = Number(value);
      return isFinite(parsed) && parsed >= 0 ? parsed : 0;
    }
    return 0;
  }
  E.version = '0.1.0';
  E.platform = 'cli';
  E.file = function(path, opts) { return new ExactFile(path, opts); };
  E.write = function(dest, data) {
    var path = typeof dest === 'string' ? dest : dest.name;
    var b = toBytes(data);
    return Promise.resolve().then(function() { g.__exactWriteFile(path, b); return b.length; });
  };
  E.gc = function() {};
  E.env = (function() {
    var _store = {};
    return new Proxy(_store, {
      get: function(target, prop) {
        if (typeof prop === 'symbol') return undefined;
        if (prop === 'toJSON') {
          return function() {
            var all = {};
            var k;
            for (k in target) { if (Object.prototype.hasOwnProperty.call(target, k)) all[k] = target[k]; }
            if (typeof g.__exactGetAllEnv === 'function') {
              var native = g.__exactGetAllEnv();
              for (k in native) { if (Object.prototype.hasOwnProperty.call(native, k)) all[k] = native[k]; }
            }
            return all;
          };
        }
        if (prop === 'get') {
          return function(k) {
            if (typeof g.__exactGetEnv === 'function') { var v = g.__exactGetEnv(k); if (v !== undefined) return v; }
            return target[k];
          };
        }
        if (typeof g.__exactGetEnv === 'function') {
          var v = g.__exactGetEnv(prop);
          if (v !== undefined) return v;
        }
        return target[prop];
      },
      set: function(target, prop, value) {
        if (typeof prop === 'symbol') return false;
        target[prop] = String(value);
        return true;
      },
      has: function(target, prop) {
        if (typeof prop === 'symbol') return false;
        if (typeof g.__exactGetEnv === 'function') {
          if (g.__exactGetEnv(prop) !== undefined) return true;
        }
        return prop in target;
      },
      deleteProperty: function(target, prop) {
        if (typeof prop === 'symbol') return false;
        delete target[prop];
        return true;
      },
      ownKeys: function(target) {
        var keys = new Set(Object.keys(target));
        if (typeof g.__exactGetAllEnv === 'function') {
          var native = g.__exactGetAllEnv();
          Object.keys(native).forEach(function(k) { keys.add(k); });
        }
        return Array.from(keys);
      },
      getOwnPropertyDescriptor: function(target, prop) {
        if (typeof prop === 'symbol') return undefined;
        var val;
        if (typeof g.__exactGetEnv === 'function') {
          val = g.__exactGetEnv(prop);
          if (val !== undefined) return { value: val, writable: true, enumerable: true, configurable: true };
        }
        if (Object.prototype.hasOwnProperty.call(target, prop)) {
          return { value: target[prop], writable: true, enumerable: true, configurable: true };
        }
        return undefined;
      }
    });
  })();
  E.sleep = function(ms) { return new Promise(function(r) { setTimeout(r, ms || 0); }); };
  E.sleepSync = function() {};
  E.nanoseconds = function() { return Date.now() * 1e6; };
  E.escapeHTML = function(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
  };
  E.setModuleCapabilities = function(moduleId, capabilities) {
    var normalizedModuleId = toModuleId(moduleId);
    if (typeof g.__exactGrantCapability !== 'function') return;
    if (!capabilities) return;

    var caps = Array.isArray(capabilities) ? capabilities : [capabilities];
    for (var i = 0; i < caps.length; i++) {
      if (typeof caps[i] !== 'string') continue;
      g.__exactGrantCapability(normalizedModuleId, caps[i]);
    }
  };
  E.deepEquals = function deepEquals(a, b) {
    if (a === b) return true;
    if (a == null || b == null) return a === b;
    if (typeof a !== typeof b) return false;
    if (typeof a !== 'object') return a === b;
    if (Array.isArray(a) !== Array.isArray(b)) return false;
    if (Array.isArray(a)) {
      if (a.length !== b.length) return false;
      for (var i = 0; i < a.length; i++) if (!deepEquals(a[i], b[i])) return false;
      return true;
    }
    var ka = Object.keys(a), kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    for (var j = 0; j < ka.length; j++) {
      if (!Object.prototype.hasOwnProperty.call(b, ka[j])) return false;
      if (!deepEquals(a[ka[j]], b[ka[j]])) return false;
    }
    return true;
  };
  E.inspect = function(obj, opts) {
    var seen = new WeakSet(), depth = (opts && opts.depth) || 4;
    function iv(v, d) {
      if (d > depth) return '[...]';
      if (v === null) return 'null';
      if (v === undefined) return 'undefined';
      var t = typeof v;
      if (t === 'string') return JSON.stringify(v);
      if (t === 'number' || t === 'boolean') return String(v);
      if (t === 'function') return '[Function: ' + (v.name || 'anonymous') + ']';
      if (t === 'symbol') return v.toString();
      if (t !== 'object') return String(v);
      if (seen.has(v)) return '[Circular]';
      seen.add(v);
      if (Array.isArray(v)) return v.length ? '[ ' + v.map(function(x){return iv(x,d+1)}).join(', ') + ' ]' : '[]';
      var k = Object.keys(v);
      return k.length ? '{ ' + k.map(function(x){return x+': '+iv(v[x],d+1)}).join(', ') + ' }' : '{}';
    }
    return iv(obj, 0);
  };
  E.peek = function(p) {
    if (!(p instanceof Promise)) return { status: 'fulfilled', value: p };
    var s = 'pending', r;
    Promise.race([p.then(function(v){s='fulfilled';r=v},function(e){s='rejected';r=e}),Promise.resolve()]);
    return s === 'pending' ? { status: 'pending' } : s === 'fulfilled' ? { status: 'fulfilled', value: r } : { status: 'rejected', reason: r };
  };

  // --- Bun aliases ---
  E.fetch = (typeof fetch === 'function') ? fetch : undefined;
  E.resolve = function() {
    var path = require('path');
    return path.resolve.apply(path, arguments);
  };
  E.resolveSync = function() {
    return E.resolve.apply(E, arguments);
  };

  // Bun.password (stub for auth libraries)
  E.password = {
    hash: function(password, opts) {
      return Promise.reject(new Error('Bun.password.hash requires native bcrypt/argon2 support'));
    },
    hashSync: function(password, opts) {
      throw new Error('Bun.password.hashSync requires native bcrypt/argon2 support');
    },
    verify: function(password, hash) {
      return Promise.reject(new Error('Bun.password.verify requires native bcrypt/argon2 support'));
    },
    verifySync: function(password, hash) {
      throw new Error('Bun.password.verifySync requires native bcrypt/argon2 support');
    },
  };

  // Bun.color(name, format) - returns CSS color values for named colors
  E.color = function(name, format) {
    var colors = {
      red: [255,0,0], green: [0,128,0], blue: [0,0,255], white: [255,255,255],
      black: [0,0,0], yellow: [255,255,0], cyan: [0,255,255], magenta: [255,0,255],
      orange: [255,165,0], purple: [128,0,128], pink: [255,192,203],
      gray: [128,128,128], grey: [128,128,128],
    };
    var c = colors[name];
    if (!c) return null;
    if (format === 'css') return 'rgb(' + c[0] + ', ' + c[1] + ', ' + c[2] + ')';
    if (format === 'ansi') return '\x1b[38;2;' + c[0] + ';' + c[1] + ';' + c[2] + 'm';
    if (format === 'number') return (c[0] << 16) | (c[1] << 8) | c[2];
    if (format === 'rgba') return { r: c[0], g: c[1], b: c[2], a: 255 };
    return c;
  };

  // Bun.stringWidth(str) - approximate string display width
  E.stringWidth = function(str) {
    if (typeof str !== 'string') return 0;
    var width = 0;
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i);
      if (code === 0x1B) {
        while (i < str.length && str.charCodeAt(i) !== 0x6D) i++;
        continue;
      }
      if (code < 0x20 || (code >= 0x7F && code < 0xA0)) continue;
      if ((code >= 0x1100 && code <= 0x115F) ||
          (code >= 0x2E80 && code <= 0xA4CF && code !== 0x303F) ||
          (code >= 0xAC00 && code <= 0xD7A3) ||
          (code >= 0xF900 && code <= 0xFAFF) ||
          (code >= 0xFE10 && code <= 0xFE6F) ||
          (code >= 0xFF01 && code <= 0xFF60) ||
          (code >= 0xFFE0 && code <= 0xFFE6)) {
        width += 2;
      } else {
        width += 1;
      }
    }
    return width;
  };

  // Bun.pathToFileURL / Bun.fileURLToPath
  E.pathToFileURL = function(path) {
    return new URL('file://' + encodeURI(path.replace(/\\/g, '/')));
  };
  E.fileURLToPath = function(url) {
    var u = typeof url === 'string' ? new URL(url) : url;
    if (u.protocol !== 'file:') throw new TypeError('URL must be file: protocol');
    return decodeURIComponent(u.pathname);
  };

  // Bun.$ (shell template tag)
  E.$ = function(strings) {
    var cmd = '';
    for (var i = 0; i < strings.length; i++) {
      cmd += strings[i];
      if (i < arguments.length - 1) cmd += String(arguments[i + 1]);
    }
    var cp = require('child_process');
    var result = cp.execSync(cmd.trim(), { encoding: 'utf8' });
    return {
      text: function() { return result; },
      toString: function() { return result; },
      exitCode: 0,
    };
  };

  // Bun.semver (version comparison)
  E.semver = {
    satisfies: function(version, range) {
      try { var semver = require('semver'); return semver.satisfies(version, range); } catch(e) {}
      return true;
    },
    order: function(a, b) {
      var pa = a.split('.').map(Number);
      var pb = b.split('.').map(Number);
      for (var i = 0; i < 3; i++) {
        if ((pa[i] || 0) < (pb[i] || 0)) return -1;
        if ((pa[i] || 0) > (pb[i] || 0)) return 1;
      }
      return 0;
    },
  };

  // Bun.dns (DNS resolution wrapper)
  E.dns = {
    lookup: function(hostname, opts) {
      return new Promise(function(resolve, reject) {
        var dns = require('dns');
        dns.lookup(hostname, opts || {}, function(err, address, family) {
          if (err) return reject(err);
          resolve({ address: address, family: family });
        });
      });
    },
    resolve: function(hostname, type) {
      return new Promise(function(resolve, reject) {
        var dns = require('dns');
        dns.resolve(hostname, type || 'A', function(err, records) {
          if (err) return reject(err);
          resolve(records);
        });
      });
    },
  };

  // Metadata
  E.revision = '0000000';
  E.origin = '';
  E.enableANSIColors = true;
  E.Transpiler = function() { throw new Error('Bun.Transpiler is not available in Exact CLI mode'); };


  // --- Bun.spawn() and Bun.spawnSync() ---
  E.spawn = function(cmd, opts) {
    var args, options;
    if (Array.isArray(cmd)) {
      args = cmd;
      options = opts || {};
    } else if (cmd && typeof cmd === 'object') {
      args = cmd.cmd;
      options = {};
      for (var k in cmd) {
        if (k !== 'cmd') options[k] = cmd[k];
      }
      if (opts) {
        for (var k2 in opts) options[k2] = opts[k2];
      }
    } else {
      throw new TypeError('Bun.spawn: first argument must be an array or object with cmd property');
    }
    if (!args || !args.length) {
      throw new TypeError('Bun.spawn: command array must not be empty');
    }
    var cp = require('child_process');
    var proc = cp.spawn(args[0], args.slice(1), options);
    var result = {
      pid: proc.pid,
      stdin: proc.stdin || null,
      stdout: proc.stdout || null,
      stderr: proc.stderr || null,
      killed: false,
      exitCode: null,
      signalCode: null,
      kill: function(sig) { result.killed = true; return proc.kill(sig); },
      ref: function() { proc.ref(); return result; },
      unref: function() { proc.unref(); return result; }
    };
    result.exited = new Promise(function(resolve) {
      proc.on('close', function(code, signal) {
        result.exitCode = code;
        result.signalCode = signal || null;
        resolve(code);
      });
      proc.on('error', function() {
        result.exitCode = -1;
        result.killed = true;
        resolve(-1);
      });
    });
    return result;
  };

  E.spawnSync = function(cmd, opts) {
    var args, options;
    if (Array.isArray(cmd)) {
      args = cmd;
      options = opts || {};
    } else if (cmd && typeof cmd === 'object') {
      args = cmd.cmd;
      options = {};
      for (var k in cmd) {
        if (k !== 'cmd') options[k] = cmd[k];
      }
      if (opts) {
        for (var k2 in opts) options[k2] = opts[k2];
      }
    } else {
      throw new TypeError('Bun.spawnSync: first argument must be an array or object with cmd property');
    }
    if (!args || !args.length) {
      throw new TypeError('Bun.spawnSync: command array must not be empty');
    }
    var cp = require('child_process');
    var r = cp.spawnSync(args[0], args.slice(1), options);
    return {
      stdout: r.stdout || '',
      stderr: r.stderr || '',
      exitCode: r.status != null ? r.status : -1,
      success: r.status === 0
    };
  };

  // --- Bun.which() ---
  E.which = function(cmd) {
    if (typeof cmd !== 'string' || !cmd) return null;
    if (typeof g.__exactWhich === 'function') return g.__exactWhich(cmd);
    return null;
  };

  // --- Bun.hash() ---
  E.hash = function(data, seed) {
    if (typeof data === 'string') {
      var h = seed || 0;
      for (var i = 0; i < data.length; i++) {
        h = ((h << 5) - h + data.charCodeAt(i)) | 0;
      }
      return h >>> 0;
    }
    if (data && typeof data === 'object' && data.length !== undefined) {
      var h2 = seed || 0;
      for (var j = 0; j < data.length; j++) {
        h2 = ((h2 << 5) - h2 + (data[j] & 0xff)) | 0;
      }
      return h2 >>> 0;
    }
    return 0;
  };
  E.hash.wyhash = E.hash;
  E.hash.adler32 = function(data) {
    if (typeof data === 'string') {
      var a = 1, b = 0;
      for (var i = 0; i < data.length; i++) {
        a = (a + data.charCodeAt(i)) % 65521;
        b = (b + a) % 65521;
      }
      return ((b << 16) | a) >>> 0;
    }
    return 1;
  };
  E.hash.crc32 = function(data) {
    if (typeof data === 'string') {
      var crc = 0xFFFFFFFF;
      for (var i = 0; i < data.length; i++) {
        crc = crc ^ data.charCodeAt(i);
        for (var j = 0; j < 8; j++) {
          crc = (crc >>> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
      }
      return (crc ^ 0xFFFFFFFF) >>> 0;
    }
    return 0;
  };

  // --- Bun.sha() ---
  E.sha = function(data, encoding) {
    if (typeof g.__exactHashSync === 'function') {
      var input = typeof data === 'string' ? data : '';
      var hex = g.__exactHashSync('sha512', input);
      if (encoding === 'hex' || encoding === undefined) return hex;
      if (encoding === 'base64') {
        var bytes = [];
        for (var i = 0; i < hex.length; i += 2) {
          bytes.push(parseInt(hex.substr(i, 2), 16));
        }
        if (typeof btoa === 'function') {
          var str = '';
          for (var j = 0; j < bytes.length; j++) str += String.fromCharCode(bytes[j]);
          return btoa(str);
        }
        return hex;
      }
      return hex;
    }
    return '';
  };

  // --- Bun compression helpers ---
  E.gzipSync = function(data) {
    if (typeof g.__exactDeflateSync !== 'function') throw new Error('gzipSync not available');
    return g.__exactDeflateSync(toBytes(data), -1, 1);
  };
  E.gunzipSync = function(data) {
    if (typeof g.__exactInflateSync !== 'function') throw new Error('gunzipSync not available');
    return g.__exactInflateSync(toBytes(data), 1);
  };
  E.deflateSync = function(data, opts) {
    if (typeof g.__exactDeflateSync !== 'function') throw new Error('deflateSync not available');
    var level = (opts && opts.level !== undefined) ? opts.level : -1;
    return g.__exactDeflateSync(toBytes(data), level, 0);
  };
  E.inflateSync = function(data) {
    if (typeof g.__exactInflateSync !== 'function') throw new Error('inflateSync not available');
    return g.__exactInflateSync(toBytes(data), 0);
  };

  // --- Bun.readableStreamTo*() helpers ---
  E.readableStreamToText = function(stream) {
    if (typeof Response !== 'undefined') {
      return new Response(stream).text();
    }
    return new Promise(function(resolve, reject) {
      var chunks = [];
      var reader = stream.getReader();
      function pump() {
        reader.read().then(function(result) {
          if (result.done) { resolve(chunks.join('')); return; }
          chunks.push(typeof result.value === 'string' ? result.value : decode(result.value));
          pump();
        }, reject);
      }
      pump();
    });
  };
  E.readableStreamToArrayBuffer = function(stream) {
    if (typeof Response !== 'undefined') {
      return new Response(stream).arrayBuffer();
    }
    return new Promise(function(resolve, reject) {
      var chunks = [], totalLen = 0;
      var reader = stream.getReader();
      function pump() {
        reader.read().then(function(result) {
          if (result.done) {
            var out = new Uint8Array(totalLen), offset = 0;
            for (var i = 0; i < chunks.length; i++) { out.set(chunks[i], offset); offset += chunks[i].length; }
            resolve(out.buffer);
            return;
          }
          var chunk = result.value instanceof Uint8Array ? result.value : toBytes(result.value);
          chunks.push(chunk); totalLen += chunk.length;
          pump();
        }, reject);
      }
      pump();
    });
  };
  E.readableStreamToBlob = function(stream) {
    if (typeof Response !== 'undefined') {
      return new Response(stream).blob();
    }
    return E.readableStreamToArrayBuffer(stream).then(function(buf) {
      return new Blob([buf]);
    });
  };
  E.readableStreamToJSON = function(stream) {
    return E.readableStreamToText(stream).then(function(text) {
      return JSON.parse(text);
    });
  };

  // --- Bun.argv, Bun.main, Bun.isMainThread ---
  E.argv = (typeof process !== 'undefined' && process.argv) ? process.argv : [];
  E.main = (typeof process !== 'undefined' && process.argv && process.argv[1]) ? process.argv[1] : '';
  E.stdin = (typeof process !== 'undefined') ? process.stdin : null;
  E.stdout = (typeof process !== 'undefined') ? process.stdout : null;
  E.stderr = (typeof process !== 'undefined') ? process.stderr : null;
  E.isMainThread = false;

  // Bun.serve() implementation
  E.serve = function(options) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('Bun.serve() expects an options object');
    }
    var fetchHandler = options.fetch;
    if (typeof fetchHandler !== 'function') {
      throw new TypeError('Bun.serve() requires a fetch handler function');
    }
    var errorHandler = options.error || function(err) {
      return new Response('Internal Server Error: ' + (err && err.message ? err.message : String(err)), {
        status: 500, headers: { 'Content-Type': 'text/plain' }
      });
    };
    var port = options.port || 3000;
    var hostname = options.hostname || '0.0.0.0';

    if (typeof __exactHttpServe !== 'function') {
      throw new Error('HTTP server not available in this environment');
    }

    var resultJson = __exactHttpServe(port, hostname);
    var result;
    try { result = JSON.parse(resultJson); } catch(e) {
      throw new Error('Failed to start HTTP server');
    }
    if (result.error) throw new Error(result.error);

    var serverId = result.id;
    var actualPort = result.port || port;
    var closing = false;

    function buildRequest(data) {
      var method = data.method || 'GET';
      var url = data.url || '/';
      var fullUrl;
      if (url.indexOf('http://') === 0 || url.indexOf('https://') === 0) {
        fullUrl = url;
      } else {
        var h = hostname === '0.0.0.0' ? 'localhost' : hostname;
        fullUrl = 'http://' + h + ':' + actualPort + url;
      }
      var headers = new Headers();
      if (data.headers) {
        if (Array.isArray(data.headers)) {
          for (var i = 0; i < data.headers.length; i++) {
            var pair = data.headers[i];
            if (!pair || pair.length < 2) {
              continue;
            }
            headers.set(pair[0], pair[1]);
          }
        } else if (typeof data.headers === 'object') {
          for (var k in data.headers) {
            if (Object.prototype.hasOwnProperty.call(data.headers, k)) headers.set(k, data.headers[k]);
          }
        }
      }
      var init = { method: method, headers: headers };
      if (method !== 'GET' && method !== 'HEAD' && data.body) {
        try { init.body = atob(data.body); } catch(e) { init.body = data.body; }
      }
      return new Request(fullUrl, init);
    }

    function sendResponse(requestId, response) {
      var status = response.status || 200;
      var hdrs = [];
      if (response.headers) response.headers.forEach(function(val, key) { hdrs.push([key, val]); });
      var headersJson = JSON.stringify(hdrs);
      response.text().then(function(bodyText) {
        if (typeof __exactHttpRespondString === 'function') {
          __exactHttpRespondString(serverId, requestId, status, headersJson, bodyText || '');
        }
      }).catch(function() {
        if (typeof __exactHttpRespondString === 'function') {
          __exactHttpRespondString(serverId, requestId, 500, '{"content-type":"text/plain"}', 'Internal Server Error');
        }
      });
    }

    function handleRequest(json) {
      var data;
      try { data = JSON.parse(json); } catch(e) { return; }
      var requestId = data.id || 0;
      var request;
      try { request = buildRequest(data); } catch(e) {
        sendResponse(requestId, new Response('Bad Request', { status: 400 }));
        return;
      }
      try {
        var result = fetchHandler(request);
        if (result && typeof result.then === 'function') {
          result.then(function(response) {
            sendResponse(requestId, response instanceof Response ? response : new Response(String(response || '')));
          }).catch(function(err) {
            try {
              var errR = errorHandler(err);
              if (errR && typeof errR.then === 'function') {
                errR.then(function(r) { sendResponse(requestId, r instanceof Response ? r : new Response(String(r || ''), { status: 500 })); })
                  .catch(function() { sendResponse(requestId, new Response('Internal Server Error', { status: 500 })); });
              } else {
                sendResponse(requestId, errR instanceof Response ? errR : new Response(String(errR || ''), { status: 500 }));
              }
            } catch(e2) { sendResponse(requestId, new Response('Internal Server Error', { status: 500 })); }
          });
        } else if (result instanceof Response) {
          sendResponse(requestId, result);
        } else {
          sendResponse(requestId, new Response(String(result || '')));
        }
      } catch(err) {
        try {
          var errR2 = errorHandler(err);
          sendResponse(requestId, errR2 instanceof Response ? errR2 : new Response(String(errR2 || ''), { status: 500 }));
        } catch(e2) { sendResponse(requestId, new Response('Internal Server Error', { status: 500 })); }
      }
    }

    function pollLoop() {
      if (closing) return;
      function poll() {
        if (closing) return;
        var json = typeof __exactHttpPoll === 'function' ? __exactHttpPoll(serverId) : null;
        if (json) { handleRequest(json); setTimeout(poll, 0); }
        else if (typeof __exactHttpWait === 'function') {
          __exactHttpWait(serverId, 1000).then(function(wj) { if (wj) handleRequest(wj); setTimeout(poll, 0); })
            .catch(function() { setTimeout(poll, 50); });
        } else { setTimeout(poll, 50); }
      }
      poll();
    }
    pollLoop();

    var h = hostname === '0.0.0.0' ? 'localhost' : hostname;
    return {
      port: actualPort, hostname: h,
      url: 'http://' + h + ':' + actualPort + '/',
      development: options.development !== undefined ? !!options.development : false,
      id: '', pendingRequests: 0,
      stop: function(force) { closing = true; if (typeof __exactHttpClose === 'function') __exactHttpClose(serverId, force ? 1 : 0); },
      reload: function(o) { if (o && typeof o.fetch === 'function') fetchHandler = o.fetch; if (o && typeof o.error === 'function') errorHandler = o.error; },
      ref: function() { if (typeof __exactHttpSetRef === 'function') __exactHttpSetRef(serverId, 1); },
      unref: function() { if (typeof __exactHttpSetRef === 'function') __exactHttpSetRef(serverId, 0); },
      requestIP: function() { return null; }, upgrade: function() { return false; }, publish: function() {},
      fetch: fetchHandler
    };
  };

  // Bun.listen() - TCP server (Bun-compatible API)
  E.listen = function(options) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('Bun.listen() expects an options object');
    }
    var handlers = options.socket;
    if (!handlers || typeof handlers !== 'object') {
      throw new TypeError('Bun.listen() requires a socket handlers object');
    }
    var hostname = options.hostname || '0.0.0.0';
    var port = options.port || 0;

    if (typeof __exactTcpListen !== 'function') {
      throw new Error('TCP server not available in this environment');
    }

    var serverHandle = __exactTcpListen(hostname, port, 128);
    var actualPort = port;
    try {
      var info = JSON.parse(__exactTcpLocalAddr(serverHandle));
      actualPort = info.port;
      if (info.address && info.address !== '0.0.0.0') hostname = info.address;
    } catch(e) {}

    var closing = false;
    var activeSockets = [];

    function BunSocket(handle) {
      this._handle = handle;
      this._destroyed = false;
      this._pollTimer = null;
      this.data = options.data !== undefined ? options.data : undefined;
      this.remoteAddress = '127.0.0.1';
      try {
        var r = JSON.parse(__exactTcpRemoteAddr(handle));
        this.remoteAddress = r.address;
      } catch(e) {}
    }
    BunSocket.prototype.write = function(data) {
      if (this._destroyed) return 0;
      try {
        var str = (typeof data === 'string') ? data :
          (data instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(data))) ?
            (typeof Buffer !== 'undefined' ? Buffer.from(data).toString() : String.fromCharCode.apply(null, data)) : String(data);
        return __exactTcpWrite(this._handle, str);
      } catch(e) { return 0; }
    };
    BunSocket.prototype.end = function(data) {
      if (data !== undefined) this.write(data);
      this._cleanup();
    };
    BunSocket.prototype.flush = function() { return this; };
    BunSocket.prototype.terminate = function() { this._cleanup(); };
    BunSocket.prototype._cleanup = function() {
      if (this._destroyed) return;
      this._destroyed = true;
      if (this._pollTimer != null) { clearTimeout(this._pollTimer); this._pollTimer = null; }
      try { __exactTcpClose(this._handle); } catch(e) {}
      var idx = activeSockets.indexOf(this);
      if (idx !== -1) activeSockets.splice(idx, 1);
      if (handlers.close) { try { handlers.close(this); } catch(e) {} }
    };
    BunSocket.prototype._startPolling = function() {
      var self = this;
      function poll() {
        if (self._destroyed) return;
        try {
          var data = __exactTcpRead(self._handle, 65536);
          if (data === null) {
            self._cleanup();
            return;
          }
          if (data.length > 0 && handlers.data) {
            var buf = (typeof Buffer !== 'undefined') ? Buffer.from(data, 'utf8') : data;
            try { handlers.data(self, buf); } catch(e) {
              if (handlers.error) { try { handlers.error(self, e); } catch(e2) {} }
            }
          }
        } catch(e) {
          if (handlers.error) { try { handlers.error(self, e); } catch(e2) {} }
          self._cleanup();
          return;
        }
        self._pollTimer = setTimeout(poll, 5);
      }
      self._pollTimer = setTimeout(poll, 0);
    };

    var acceptTimer = null;
    function acceptLoop() {
      if (closing) return;
      try {
        var clientHandle = __exactTcpAccept(serverHandle);
        if (clientHandle !== -1) {
          var sock = new BunSocket(clientHandle);
          activeSockets.push(sock);
          if (handlers.open) { try { handlers.open(sock); } catch(e) {
            if (handlers.error) { try { handlers.error(sock, e); } catch(e2) {} }
          }}
          sock._startPolling();
        }
      } catch(e) {}
      acceptTimer = setTimeout(acceptLoop, 10);
    }
    acceptTimer = setTimeout(acceptLoop, 0);

    return {
      port: actualPort,
      hostname: hostname,
      stop: function(closeActive) {
        closing = true;
        if (acceptTimer != null) { clearTimeout(acceptTimer); acceptTimer = null; }
        if (closeActive) {
          var socks = activeSockets.slice();
          for (var i = 0; i < socks.length; i++) { socks[i]._cleanup(); }
        }
        try { __exactTcpClose(serverHandle); } catch(e) {}
      },
      ref: function() { return this; },
      unref: function() { return this; },
      reload: function(newHandlers) {
        if (newHandlers && newHandlers.socket) handlers = newHandlers.socket;
      }
    };
  };

  // Bun.CryptoHasher
  E.CryptoHasher = (function() {
    function CH(algorithm) {
      if (!(this instanceof CH)) return new CH(algorithm);
      if (!algorithm || typeof algorithm !== 'string') throw new TypeError('algorithm must be a string');
      this._algo = algorithm.toLowerCase().replace('-', '');
      this._chunks = [];
    }
    CH.hash = function(algorithm, data, encoding) {
      var h = new CH(algorithm); h.update(data); return h.digest(encoding || 'hex');
    };
    CH.prototype.update = function(data) {
      if (typeof data === 'string') { this._chunks.push(data); }
      else if (data && data.length !== undefined) {
        var str = ''; for (var i = 0; i < data.length; i++) str += String.fromCharCode(data[i]);
        this._chunks.push(str);
      }
      return this;
    };
    CH.prototype.digest = function(encoding) {
      var joined = this._chunks.join('');
      if (typeof g.__exactHashSync === 'function') {
        var hex = g.__exactHashSync(this._algo, joined);
        if (!encoding || encoding === 'hex') return hex;
        if (encoding === 'base64') {
          var bytes = []; for (var i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
          if (typeof btoa === 'function') { var s = ''; for (var j = 0; j < bytes.length; j++) s += String.fromCharCode(bytes[j]); return btoa(s); }
        }
        if (!encoding) {
          var b = new Uint8Array(hex.length / 2);
          for (var k = 0; k < hex.length; k += 2) b[k / 2] = parseInt(hex.substr(k, 2), 16);
          return b;
        }
        return hex;
      }
      throw new Error('Native hash not available');
    };
    CH.prototype.copy = function() { var h = new CH(this._algo); h._chunks = this._chunks.slice(); return h; };
    return CH;
  })();

  // Bun.deepMatch(subset, object)
  E.deepMatch = function deepMatch(subset, object) {
    if (subset === object) return true;
    if (subset == null || object == null) return subset === object;
    if (typeof subset !== 'object' || typeof object !== 'object') return subset === object;
    if (Array.isArray(subset)) {
      if (!Array.isArray(object) || subset.length !== object.length) return false;
      for (var i = 0; i < subset.length; i++) { if (!deepMatch(subset[i], object[i])) return false; }
      return true;
    }
    var keys = Object.keys(subset);
    for (var j = 0; j < keys.length; j++) {
      var k = keys[j];
      if (!Object.prototype.hasOwnProperty.call(object, k) || !deepMatch(subset[k], object[k])) return false;
    }
    return true;
  };

  g.Exact = E;
  g.Bun = E;
})();
)JS";

  try {
    auto buffer = std::make_shared<facebook::jsi::StringBuffer>(exactGlobalJS);
    rt.evaluateJavaScript(buffer, "<exact-global>");
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
  }
}

void runNextTickQueue(ExactHermesRuntime* runtime) {
  if (!runtime) {
    return;
  }
  auto& rt = *runtime->runtime;
  while (!runtime->next_tick.empty()) {
    auto fn = std::move(runtime->next_tick.front());
    runtime->next_tick.pop_front();
    try {
      fn.call(rt);
    } catch (const facebook::jsi::JSError& err) {
      // Try uncaughtException handler first
      bool handled = false;
      try {
        auto handler = rt.global().getProperty(rt, "__exactUncaughtExceptionHandler");
        if (handler.isObject() && handler.asObject(rt).isFunction(rt)) {
          // Create a new Error object from the message (can't copy jsi::Value)
          auto errObj = rt.global()
              .getPropertyAsFunction(rt, "Error")
              .callAsConstructor(rt, facebook::jsi::String::createFromUtf8(rt, err.getMessage()));
          auto result = handler.asObject(rt).asFunction(rt).call(rt, std::move(errObj));
          if (result.isBool() && result.getBool()) handled = true;
        }
      } catch (...) {}
      if (!handled) {
        ex_host_console_log(1, err.getMessage().c_str());
      }
    } catch (const std::exception& err) {
      ex_host_console_log(1, err.what());
    }
  }
}

} // namespace

extern "C" ExactHermesRuntime* ex_hermes_create() {
  auto config = ::hermes::vm::RuntimeConfig::Builder()
                    .withMicrotaskQueue(true)
                    .withEnableEval(true)  // Required for debugger eval
                    .build();
  auto runtime = facebook::hermes::makeHermesRuntime(config);
  if (!runtime) {
    return nullptr;
  }
  auto handle = new ExactHermesRuntime();
  handle->runtime = std::move(runtime);
  handle->runtime_thread = std::this_thread::get_id();
#if defined(HERMES_ENABLE_DEBUGGER)
  try {
    handle->debugger = std::make_unique<facebook::hermes::debugger::AsyncDebuggerAPI>(*handle->runtime);
    handle->debugger_available.store(true);
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
    handle->debugger.reset();
    handle->debugger_available.store(false);
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
    handle->debugger.reset();
    handle->debugger_available.store(false);
  } catch (...) {
    ex_host_console_log(1, "Debugger not available in this Hermes build.");
    handle->debugger.reset();
    handle->debugger_available.store(false);
  }
#else
  handle->debugger.reset();
  handle->debugger_available.store(false);
#endif
  installGlobals(handle);
  return handle;
}

extern "C" void ex_hermes_destroy(ExactHermesRuntime* runtime) {
  if (runtime == nullptr) {
    return;
  }
  delete runtime;
}

extern "C" int ex_hermes_eval(
    ExactHermesRuntime* runtime,
    const uint8_t* data,
    size_t len,
    const char* source_url,
    int is_bytecode,
    char** out_value) {
  if (!runtime || !data || len == 0) {
    return 1;
  }

  std::string source = source_url ? source_url : (is_bytecode ? "<bytecode>" : "<eval>");
  if (!is_bytecode) {
    runtime->sources_by_name[source] = std::string(reinterpret_cast<const char*>(data), len);
  }

  try {
    auto buffer = std::make_shared<MemoryBuffer>(data, len);
    auto result = runtime->runtime->evaluateJavaScript(buffer, source);
    runNextTickQueue(runtime);
    drainMicrotasks(*runtime->runtime);
    if (runtime->debugger_attached.load()) {
      emitNewScripts(runtime);
    }

    // If the result is a thenable/Promise, resolve it before returning.
    // This makes top-level await work in the REPL and eval contexts.
    if (result.isObject()) {
      auto& rt = *runtime->runtime;
      // Stash the result as a temp global so JS can inspect it
      rt.global().setProperty(rt, "__ex_p",
          facebook::jsi::Value(rt, result));
      const char* unwrap_code =
          "(function(){"
          "var p=globalThis.__ex_p;"
          "delete globalThis.__ex_p;"
          "if(!p||typeof p.then!=='function')return null;"
          "var r={v:undefined,ok:true,done:false};"
          "p.then(function(v){r.v=v;r.done=true;},"
          "function(e){r.v=e;r.ok=false;r.done=true;});"
          "return r;"
          "})()";
      auto ubuf = std::make_shared<MemoryBuffer>(
          reinterpret_cast<const uint8_t*>(unwrap_code),
          strlen(unwrap_code));
      auto check = rt.evaluateJavaScript(ubuf, "<promise-unwrap>");
      drainMicrotasks(rt);

      if (!check.isNull() && check.isObject()) {
        auto rObj = check.getObject(rt);
        bool done = false;
        auto doneProp = rObj.getProperty(rt, "done");
        if (doneProp.isBool()) done = doneProp.getBool();

        if (done) {
          auto ok = rObj.getProperty(rt, "ok");
          if (ok.isBool() && ok.getBool()) {
            result = rObj.getProperty(rt, "v");
          } else {
            // Promise rejected — report as error
            auto errVal = rObj.getProperty(rt, "v");
            if (out_value) {
              auto msg = valueToString(rt, errVal);
              auto sz = msg.size();
              char* heap = static_cast<char*>(malloc(sz + 1));
              if (heap) {
                memcpy(heap, msg.data(), sz);
                heap[sz] = '\0';
                *out_value = heap;
              }
            }
            return 1;
          }
        }
        // If !done, the promise hasn't settled yet (truly async).
        // Fall through and return whatever we have — the event loop
        // will drive it later.
      }
    }

    if (out_value) {
      if (result.isUndefined()) {
        *out_value = nullptr;
      } else {
        auto text = valueToString(*runtime->runtime, result);
        auto size = text.size();
        char* heap = static_cast<char*>(malloc(size + 1));
        if (!heap) {
          return 1;
        }
        memcpy(heap, text.data(), size);
        heap[size] = '\0';
        *out_value = heap;
      }
    }

    return 0;
  } catch (const facebook::jsi::JSError& err) {
    // Try to call process uncaughtException handler before reporting error
    auto& rt = *runtime->runtime;
    try {
      auto handler = rt.global().getProperty(rt, "__exactUncaughtExceptionHandler");
      if (handler.isObject() && handler.asObject(rt).isFunction(rt)) {
        // Create a new Error object from the message (can't copy jsi::Value)
        auto errObj = rt.global()
            .getPropertyAsFunction(rt, "Error")
            .callAsConstructor(rt, facebook::jsi::String::createFromUtf8(rt, err.getMessage()));
        auto result = handler.asObject(rt).asFunction(rt).call(rt, std::move(errObj));
        if (result.isBool() && result.getBool()) {
          // Handler returned true — exception was handled, don't crash
          if (out_value) *out_value = nullptr;
          return 0;
        }
      }
    } catch (...) {
      // If the handler itself throws, fall through to normal error reporting
    }

    if (out_value) {
      auto message = err.getMessage();
      auto stack = err.getStack();
      // Include stack trace if available
      std::string full;
      if (!stack.empty()) {
        full = message + "\n" + stack;
      } else {
        full = message;
      }
      auto size = full.size();
      char* heap = static_cast<char*>(malloc(size + 1));
      if (!heap) {
        return 1;
      }
      memcpy(heap, full.data(), size);
      heap[size] = '\0';
      *out_value = heap;
    }
    return 1;
  } catch (const std::exception& err) {
    if (out_value) {
      auto message = std::string(err.what());
      auto size = message.size();
      char* heap = static_cast<char*>(malloc(size + 1));
      if (!heap) {
        return 1;
      }
      memcpy(heap, message.data(), size);
      heap[size] = '\0';
      *out_value = heap;
    }
    return 1;
  }
}

extern "C" void ex_hermes_free_string(char* value) {
  if (value) {
    free(value);
  }
}

extern "C" int ex_hermes_poll(ExactHermesRuntime* runtime, uint64_t now_ms) {
  if (!runtime) {
    return 0;
  }

  int executed = 0;

  // Drain cross-thread callback queue (HTTP server responses, etc.)
  executed += drainCallbackQueue(runtime);

  // Drain pending cross-thread tasks
  {
    std::vector<std::function<void(facebook::jsi::Runtime&)>> tasks;
    {
      std::lock_guard<std::mutex> lock(runtime->task_mutex);
      tasks.swap(runtime->pending_tasks);
    }
    if (!tasks.empty()) {
      auto& rt = *runtime->runtime;
      for (auto& task : tasks) {
        try {
          task(rt);
          executed++;
        } catch (const facebook::jsi::JSError& err) {
          ex_host_console_log(1, err.getMessage().c_str());
        } catch (const std::exception& err) {
          ex_host_console_log(1, err.what());
        }
      }
    }
  }

  runNextTickQueue(runtime);
  drainMicrotasks(*runtime->runtime);

  std::vector<uint64_t> due;
  for (const auto& kv : runtime->timers) {
    if (kv.second.due_ms <= now_ms) {
      due.push_back(kv.first);
    }
  }

  for (auto id : due) {
    auto it = runtime->timers.find(id);
    if (it == runtime->timers.end()) {
      continue;
    }
    try {
      it->second.callback.call(*runtime->runtime);
      executed += 1;
      runNextTickQueue(runtime);
      drainMicrotasks(*runtime->runtime);
    } catch (const facebook::jsi::JSError& err) {
      ex_host_console_log(1, err.getMessage().c_str());
      return -1;
    } catch (const std::exception& err) {
      ex_host_console_log(1, err.what());
      return -1;
    }

    auto after = runtime->timers.find(id);
    if (after != runtime->timers.end()) {
      if (after->second.repeat) {
        after->second.due_ms = now_ms + after->second.interval_ms;
      } else {
        runtime->timers.erase(after);
      }
    }
  }

  return executed;
}

extern "C" int64_t ex_hermes_next_timer(ExactHermesRuntime* runtime) {
  if (!runtime || runtime->timers.empty()) {
    return -1;
  }
  uint64_t next_due = UINT64_MAX;
  for (const auto& kv : runtime->timers) {
    if (kv.second.due_ms < next_due) {
      next_due = kv.second.due_ms;
    }
  }
  if (next_due == UINT64_MAX) {
    return -1;
  }
  return static_cast<int64_t>(next_due);
}

extern "C" int ex_hermes_has_pending_tasks(ExactHermesRuntime* runtime) {
  if (!runtime) {
    return 0;
  }
  if (ex_host_http_has_referenced() || ex_host_http_has_pending_requests()) {
    return 1;
  }
  if (!runtime->next_tick.empty()) {
    return 1;
  }
  {
    std::lock_guard<std::mutex> lock(runtime->callbackMutex);
    if (!runtime->callbackQueue.empty()) return 1;
  }
  return runtime->timers.empty() ? 0 : 1;
}

extern "C" int ex_hermes_debugger_enable(ExactHermesRuntime* runtime) {
#if !defined(HERMES_ENABLE_DEBUGGER)
  (void)runtime;
  return 0;
#else
  if (!runtime || !runtime->debugger || !runtime->debugger_available.load()) {
    return 0;
  }
  if (runtime->debugger_attached.load()) {
    return 1;
  }

  runtime->debugger_attached.store(true);
  auto result = runOnRuntimeThread(runtime, [](ExactHermesRuntime* handle) {
    if (!handle || !handle->runtime || !handle->debugger) {
      return std::string();
    }
    handle->runtime->getDebugger().setIsDebuggerAttached(true);
    handle->debugger->setDebuggerEventCallback_TS(
        [handle](facebook::hermes::HermesRuntime&,
                 facebook::hermes::debugger::AsyncDebuggerAPI&,
                 facebook::hermes::debugger::DebuggerEventType) {
          if (!handle->debugger_attached.load()) {
            return;
          }
          auto event = buildPausedEvent(handle);
          if (!event.empty()) {
            pushDebugEvent(handle, event);
          }
        });
    handle->debugger_callback_set = true;

    emitNewScripts(handle);
    return std::string("1");
  });

  if (result != "1") {
    runtime->debugger_attached.store(false);
    runtime->debugger_available.store(false);
    runtime->debugger.reset();
    return 0;
  }

  return 1;
#endif
}

extern "C" char* ex_hermes_debugger_get_scripts(ExactHermesRuntime* runtime) {
#if !defined(HERMES_ENABLE_DEBUGGER)
  (void)runtime;
  return nullptr;
#else
  auto json = runOnRuntimeThread(runtime, [](ExactHermesRuntime* handle) {
    std::ostringstream out;
    out << "[";
    if (handle && handle->runtime) {
      auto scripts = handle->runtime->getDebugger().getLoadedScripts();
      for (size_t i = 0; i < scripts.size(); ++i) {
        const auto& script = scripts[i];
        if (i > 0) {
          out << ",";
        }
        out << "{";
        out << "\"id\":" << script.fileId << ",";
        out << "\"url\":" << jsonString(script.fileName);
        out << "}";
      }
    }
    out << "]";
    return out.str();
  });

  if (json.empty()) {
    return nullptr;
  }
  char* heap = static_cast<char*>(malloc(json.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, json.data(), json.size());
  heap[json.size()] = '\0';
  return heap;
#endif
}

extern "C" char* ex_hermes_debugger_get_script_source(
    ExactHermesRuntime* runtime,
    uint32_t script_id) {
#if !defined(HERMES_ENABLE_DEBUGGER)
  (void)runtime;
  (void)script_id;
  return nullptr;
#else
  auto source = runOnRuntimeThread(runtime, [=](ExactHermesRuntime* handle) {
    if (!handle || !handle->runtime) {
      return std::string();
    }
    auto it = handle->script_id_to_name.find(script_id);
    if (it == handle->script_id_to_name.end()) {
      auto scripts = handle->runtime->getDebugger().getLoadedScripts();
      for (const auto& script : scripts) {
        handle->script_id_to_name[script.fileId] = script.fileName;
      }
      it = handle->script_id_to_name.find(script_id);
    }
    if (it == handle->script_id_to_name.end()) {
      return std::string();
    }
    auto src_it = handle->sources_by_name.find(it->second);
    if (src_it == handle->sources_by_name.end()) {
      return std::string();
    }
    return src_it->second;
  });

  if (source.empty()) {
    return nullptr;
  }
  char* heap = static_cast<char*>(malloc(source.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, source.data(), source.size());
  heap[source.size()] = '\0';
  return heap;
#endif
}

extern "C" char* ex_hermes_debugger_set_breakpoint(
    ExactHermesRuntime* runtime,
    uint32_t script_id,
    uint32_t line_number,
    uint32_t column_number,
    const char* condition) {
#if !defined(HERMES_ENABLE_DEBUGGER)
  (void)runtime;
  (void)script_id;
  (void)line_number;
  (void)column_number;
  (void)condition;
  return nullptr;
#else
  auto json = runOnRuntimeThread(runtime, [=](ExactHermesRuntime* handle) {
    if (!handle || !handle->runtime) {
      return std::string();
    }
    using facebook::hermes::debugger::kInvalidLocation;
    using facebook::hermes::debugger::SourceLocation;

    SourceLocation loc;
    loc.fileId = script_id;
    loc.line = line_number + 1;
    loc.column = column_number + 1;

    auto& debugger = handle->runtime->getDebugger();
    auto id = debugger.setBreakpoint(loc);
    if (condition && std::strlen(condition) > 0) {
      debugger.setBreakpointCondition(id, condition);
    }
    auto info = debugger.getBreakpointInfo(id);
    auto resolved = info.resolved ? info.resolvedLocation : info.requestedLocation;

    uint32_t out_line =
        resolved.line == kInvalidLocation ? line_number : (resolved.line > 0 ? resolved.line - 1 : 0);
    uint32_t out_column =
        resolved.column == kInvalidLocation ? column_number : (resolved.column > 0 ? resolved.column - 1 : 0);

    std::ostringstream out;
    out << "{";
    out << "\"id\":" << id << ",";
    out << "\"scriptId\":" << resolved.fileId << ",";
    out << "\"line\":" << out_line << ",";
    out << "\"column\":" << out_column;
    out << "}";
    return out.str();
  });

  if (json.empty()) {
    return nullptr;
  }
  char* heap = static_cast<char*>(malloc(json.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, json.data(), json.size());
  heap[json.size()] = '\0';
  return heap;
#endif
}

extern "C" void ex_hermes_debugger_remove_breakpoint(
    ExactHermesRuntime* runtime,
    uint64_t breakpoint_id) {
#if !defined(HERMES_ENABLE_DEBUGGER)
  (void)runtime;
  (void)breakpoint_id;
  return;
#else
  runOnRuntimeThread(runtime, [=](ExactHermesRuntime* handle) {
    if (handle && handle->runtime) {
      handle->runtime->getDebugger().deleteBreakpoint(breakpoint_id);
    }
    return std::string();
  });
#endif
}

extern "C" void ex_hermes_debugger_pause(ExactHermesRuntime* runtime) {
#if !defined(HERMES_ENABLE_DEBUGGER)
  (void)runtime;
  return;
#else
  if (!runtime || !runtime->runtime || !runtime->debugger_available.load()) {
    return;
  }
  runOnRuntimeThread(runtime, [](ExactHermesRuntime* handle) {
    if (!handle || !handle->runtime) {
      return std::string();
    }
    handle->runtime->getDebugger().triggerAsyncPause(
        facebook::hermes::debugger::AsyncPauseKind::Explicit);
    return std::string();
  });
#endif
}

extern "C" void ex_hermes_debugger_resume(ExactHermesRuntime* runtime, int command) {
#if !defined(HERMES_ENABLE_DEBUGGER)
  (void)runtime;
  (void)command;
  return;
#else
  if (!runtime || !runtime->debugger || !runtime->debugger_available.load()) {
    return;
  }
  auto cmd = facebook::hermes::debugger::AsyncDebugCommand::Continue;
  switch (command) {
    case 1:
      cmd = facebook::hermes::debugger::AsyncDebugCommand::StepInto;
      break;
    case 2:
      cmd = facebook::hermes::debugger::AsyncDebugCommand::StepOver;
      break;
    case 3:
      cmd = facebook::hermes::debugger::AsyncDebugCommand::StepOut;
      break;
    default:
      cmd = facebook::hermes::debugger::AsyncDebugCommand::Continue;
      break;
  }

  try {
    runtime->debugger->triggerInterrupt_TS([runtime, cmd](facebook::hermes::HermesRuntime&) {
      if (runtime->debugger && runtime->debugger->resumeFromPaused(cmd)) {
        pushDebugEvent(runtime, "{\"method\":\"Debugger.resumed\",\"params\":{}}");
      }
    });
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
  } catch (...) {
    ex_host_console_log(1, "Unknown native error");
  }
#endif
}

extern "C" char* ex_hermes_debugger_next_event(ExactHermesRuntime* runtime) {
#if !defined(HERMES_ENABLE_DEBUGGER)
  (void)runtime;
  return nullptr;
#else
  if (!runtime) {
    return nullptr;
  }
  std::lock_guard<std::mutex> lock(runtime->debug_mutex);
  if (runtime->debug_events.empty()) {
    return nullptr;
  }
  auto event = std::move(runtime->debug_events.front());
  runtime->debug_events.pop_front();
  if (event.empty()) {
    return nullptr;
  }
  char* heap = static_cast<char*>(malloc(event.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, event.data(), event.size());
  heap[event.size()] = '\0';
  return heap;
#endif
}

extern "C" char* ex_hermes_debugger_eval(
    ExactHermesRuntime* runtime,
    const char* expression,
    uint32_t frame_index) {
#if !defined(HERMES_ENABLE_DEBUGGER)
  (void)runtime;
  (void)expression;
  (void)frame_index;
  return nullptr;
#else
  if (!expression || !runtime || !runtime->debugger) {
    return nullptr;
  }
  auto expr = std::string(expression);

  // evalWhilePaused is asynchronous - the callback is invoked AFTER the
  // interrupt callback returns, when didPause processes the eval command.
  // We use shared state to communicate the result back to the CDP thread.

  auto result_holder = std::make_shared<std::string>();
  auto result_mutex = std::make_shared<std::mutex>();
  auto result_cv = std::make_shared<std::condition_variable>();
  auto result_ready = std::make_shared<bool>(false);

  if (runtime->debugger_attached.load()) {
    // Schedule eval via interrupt - this gets us onto the runtime thread
    runtime->debugger->triggerInterrupt_TS(
        [runtime, expr, frame_index, result_holder, result_mutex, result_cv, result_ready](
            facebook::hermes::HermesRuntime& rt) {
          // Try evalWhilePaused first (for paused debugger state)
          auto ok = runtime->debugger->evalWhilePaused(
              expr,
              frame_index,
              [&rt, result_holder, result_mutex, result_cv, result_ready](
                  facebook::hermes::HermesRuntime&,
                  const facebook::hermes::debugger::EvalResult& result) {
                std::ostringstream out;
                if (result.isException) {
                  out << "{\"exceptionDetails\":{\"text\":"
                      << jsonString(result.exceptionDetails.text) << "}}";
                } else {
                  out << "{\"result\":" << makeRemoteObject(rt, result.value) << "}";
                }
                std::lock_guard<std::mutex> lock(*result_mutex);
                *result_holder = out.str();
                *result_ready = true;
                result_cv->notify_one();
              });

          if (!ok) {
            // evalWhilePaused failed - try regular eval as fallback
            try {
              auto buffer = std::make_shared<facebook::jsi::StringBuffer>(expr);
              auto result = rt.evaluateJavaScript(buffer, "<cdp>");
              std::ostringstream out;
              out << "{\"result\":" << makeRemoteObject(rt, result) << "}";
              std::lock_guard<std::mutex> lock(*result_mutex);
              *result_holder = out.str();
              *result_ready = true;
              result_cv->notify_one();
            } catch (const facebook::jsi::JSError& err) {
              std::ostringstream out;
              out << "{\"exceptionDetails\":{\"text\":" << jsonString(err.getMessage()) << "}}";
              std::lock_guard<std::mutex> lock(*result_mutex);
              *result_holder = out.str();
              *result_ready = true;
              result_cv->notify_one();
            } catch (const std::exception& err) {
              std::ostringstream out;
              out << "{\"exceptionDetails\":{\"text\":" << jsonString(err.what()) << "}}";
              std::lock_guard<std::mutex> lock(*result_mutex);
              *result_holder = out.str();
              *result_ready = true;
              result_cv->notify_one();
            }
          }
        });

    // Wait for result on CDP thread
    std::unique_lock<std::mutex> lock(*result_mutex);
    if (result_cv->wait_for(lock, std::chrono::seconds(10), [&result_ready] { return *result_ready; })) {
      if (!result_holder->empty()) {
        char* heap = static_cast<char*>(malloc(result_holder->size() + 1));
        if (heap) {
          memcpy(heap, result_holder->data(), result_holder->size());
          heap[result_holder->size()] = '\0';
          return heap;
        }
      }
    }
  }

  // Fallback: use runOnRuntimeThread for regular evaluation (not paused)
  auto json = runOnRuntimeThread(runtime, [expr](ExactHermesRuntime* handle) {
    if (!handle || !handle->runtime) {
      return std::string();
    }
    auto& rt = *handle->runtime;
    try {
      auto buffer = std::make_shared<facebook::jsi::StringBuffer>(expr);
      auto result = rt.evaluateJavaScript(buffer, "<cdp>");
      std::ostringstream out;
      out << "{\"result\":" << makeRemoteObject(rt, result) << "}";
      return out.str();
    } catch (const facebook::jsi::JSError& err) {
      std::ostringstream out;
      out << "{\"exceptionDetails\":{\"text\":" << jsonString(err.getMessage()) << "}}";
      return out.str();
    } catch (const std::exception& err) {
      std::ostringstream out;
      out << "{\"exceptionDetails\":{\"text\":" << jsonString(err.what()) << "}}";
      return out.str();
    }
  });

  if (json.empty()) {
    return nullptr;
  }
  char* heap = static_cast<char*>(malloc(json.size() + 1));
  if (!heap) {
    return nullptr;
  }
  memcpy(heap, json.data(), json.size());
  heap[json.size()] = '\0';
  return heap;
#endif
}

// =============================================================================
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
        if (count == 0 || !runtime->ios_dispatch_callback) {
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

extern "C" void ex_hermes_set_module_dispatch_callback(
    ExactHermesRuntime* runtime,
    void (*callback)(const uint8_t* data, size_t length, void* context),
    void* context) {
  if (!runtime) return;
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
        if (count == 0 || !runtime->ios_module_dispatch_callback) {
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
        if (count == 0 || !runtime->ios_module_sync_callback) {
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

        if (status != 0 || !resultData) {
          return facebook::jsi::Value::undefined();
        }

        // Return result as Uint8Array
        auto arrayBuffer = std::make_unique<VectorBuffer>(
            std::vector<uint8_t>(resultData, resultData + resultLength));
        free(resultData);
        auto ab = rt.global()
            .getPropertyAsFunction(rt, "ArrayBuffer")
            .callAsConstructor(rt, static_cast<int>(resultLength))
            .getObject(rt)
            .getArrayBuffer(rt);
        memcpy(ab.data(rt), arrayBuffer->data(), resultLength);
        auto uint8ArrayCtor = rt.global().getPropertyAsFunction(rt, "Uint8Array");
        return uint8ArrayCtor.callAsConstructor(
            rt, rt.global().getProperty(rt, "ArrayBuffer"));
      });

  exactObj.setProperty(rt, "callModuleSync", std::move(fn));
  rt.global().setProperty(rt, "exact", std::move(exactObj));
}

// Emit a module event to JS (for native -> JS events)
extern "C" int ex_hermes_emit_module_event(
    ExactHermesRuntime* runtime,
    const char* module_name,
    const char* event_name,
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
      handler.call(rt, std::move(moduleStr), std::move(eventStr), std::move(payloadArray));
    } else {
      handler.call(rt, std::move(moduleStr), std::move(eventStr));
    }
    return 0;
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
    return -1;
  } catch (...) {
    return -1;
  }
}

// =============================================================================
// GC
// =============================================================================

extern "C" void ex_hermes_gc(ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->runtime) return;
  // GC is automatic in Hermes. The instrumentation().collectGarbage() API
  // requires headers not included in the public Hermes distribution.
  // This is a no-op; Hermes will collect garbage automatically.
  (void)runtime;
}

// =============================================================================
// HTTP server stubs (iOS / standalone builds)
// The CLI provides real implementations via tokio; on iOS these are no-ops.
// =============================================================================

#if defined(EXACT_PLATFORM_IOS)

// Stubs must match the forward declarations exactly (lines 163-210)
extern "C" char* ex_host_http_serve(uint16_t, const char*) { return nullptr; }
extern "C" char* ex_host_http_wait(uint32_t, uint32_t) { return nullptr; }
extern "C" char* ex_host_http_read_body(uint32_t, uint32_t) { return nullptr; }
extern "C" int32_t ex_host_http_respond(uint32_t, uint32_t, uint16_t, const char*, const uint8_t*, uint32_t) { return -1; }
extern "C" int32_t ex_host_http_respond_text(uint32_t, uint32_t, uint16_t, const uint8_t*, uint32_t) { return -1; }
extern "C" int32_t ex_host_http_respond_json(uint32_t, uint32_t, uint16_t, const uint8_t*, uint32_t) { return -1; }
extern "C" int32_t ex_host_http_respond_stream(uint32_t, uint32_t, uint16_t, const char*) { return -1; }
extern "C" int32_t ex_host_http_respond_chunk(uint32_t, uint32_t, const uint8_t*, uint32_t) { return -1; }
extern "C" int32_t ex_host_http_respond_end(uint32_t, uint32_t) { return -1; }
extern "C" int32_t ex_host_http_respond_string(uint32_t, uint32_t, uint16_t, const char*, const uint8_t*, uint32_t) { return -1; }
extern "C" char* ex_host_http_address(uint32_t) { return nullptr; }
extern "C" char* ex_host_http_poll(uint32_t) { return nullptr; }
extern "C" char* ex_host_http_drain(uint32_t, uint32_t) { return nullptr; }
extern "C" int32_t ex_host_http_close(uint32_t, int32_t) { return -1; }
extern "C" int32_t ex_host_http_is_referenced(uint32_t) { return 0; }
extern "C" int32_t ex_host_http_has_referenced(void) { return 0; }
extern "C" int32_t ex_host_http_has_pending_requests(void) { return 0; }
extern "C" void ex_host_http_set_ref(uint32_t, int32_t) {}

#endif // EXACT_PLATFORM_IOS
