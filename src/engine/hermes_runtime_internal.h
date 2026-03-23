#pragma once

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
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

struct TimerEntry {
  uint64_t id;
  uint64_t due_ms;
  uint64_t interval_ms;
  bool repeat;
  bool referenced = true;
  facebook::jsi::Function callback;
  std::vector<facebook::jsi::Value> args;
};

struct NextTickEntry {
  facebook::jsi::Function callback;
  std::vector<facebook::jsi::Value> args;
};

struct FetchCallbackEntry {
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
  std::string url;
  std::chrono::steady_clock::time_point deadline;
};

struct ExactHermesRuntime {
  std::unique_ptr<facebook::hermes::HermesRuntime> runtime;
  std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI> debugger;
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
  std::deque<NextTickEntry> next_tick;
  std::mutex task_mutex;
  std::vector<std::function<void(facebook::jsi::Runtime&)>> pending_tasks;
  std::atomic<int> active_spawn_processes{0};
  std::mutex fetchMutex;
  uint32_t nextFetchId{1};
  std::unordered_map<uint32_t, FetchCallbackEntry> fetchCallbacks;
  std::mutex callbackMutex;
  std::deque<std::function<void(facebook::jsi::Runtime&)>> callbackQueue;

  void (*ios_dispatch_callback)(const uint8_t* data, size_t length, void* context) = nullptr;
  void* ios_dispatch_context = nullptr;
  void (*ios_module_dispatch_callback)(const uint8_t* data, size_t length, void* context) =
      nullptr;
  void* ios_module_dispatch_context = nullptr;
  int (*ios_module_sync_callback)(const uint8_t* data,
                                  size_t length,
                                  uint8_t** result_data,
                                  size_t* result_length,
                                  void* context) = nullptr;
  void* ios_module_sync_context = nullptr;
  void* kernel_handle = nullptr;

  bool stream_enhance_loaded = false;
  bool web_crypto_loaded = false;
  bool web_storage_loaded = false;
  bool form_data_loaded = false;

  bool dns_functions_loaded = false;
  bool fs_functions_loaded = false;
  bool child_process_functions_loaded = false;
  bool net_functions_loaded = false;
  bool sqlite_functions_loaded = false;
  bool http_functions_loaded = false;

  char* (*host_call_fn)(const char* op, const char* args_json) = nullptr;
};

extern "C" int32_t ex_host_is_allow_all(void);
extern "C" int32_t ex_host_check_capability(uint64_t module_id, const char* capability);
extern "C" void ex_host_log_event(const char* event_type,
                                  uint64_t module_id,
                                  const char* capability,
                                  int32_t result);

extern thread_local uint64_t g_active_module_id;

class VectorBuffer : public facebook::jsi::MutableBuffer {
 public:
  explicit VectorBuffer(std::vector<uint8_t> data) : data_(std::move(data)) {}

  size_t size() const override { return data_.size(); }
  uint8_t* data() override { return data_.data(); }

 private:
  std::vector<uint8_t> data_;
};

inline bool isAllowAll() {
  static int cached = -1;
  if (cached < 0) {
    cached = ex_host_is_allow_all();
  }
  return cached != 0;
}

inline bool checkCapability(const std::string& capability) {
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

inline facebook::jsi::Value makeUint8Array(
    facebook::jsi::Runtime& runtime,
    std::vector<uint8_t> data) {
  auto buffer = std::make_shared<VectorBuffer>(std::move(data));
  facebook::jsi::ArrayBuffer arrayBuffer(runtime, buffer);
  auto ctor = runtime.global().getPropertyAsFunction(runtime, "Uint8Array");
  auto typed = ctor.callAsConstructor(runtime, arrayBuffer).getObject(runtime);
  return facebook::jsi::Value(std::move(typed));
}

inline std::vector<uint8_t> extractBytes(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  if (value.isString()) {
    auto string = value.asString(runtime).utf8(runtime);
    return std::vector<uint8_t>(string.begin(), string.end());
  }
  if (!value.isObject()) {
    return {};
  }

  auto object = value.asObject(runtime);
  if (object.isArrayBuffer(runtime)) {
    auto buffer = object.getArrayBuffer(runtime);
    return std::vector<uint8_t>(buffer.data(runtime), buffer.data(runtime) + buffer.size(runtime));
  }

  if (object.hasProperty(runtime, "buffer")) {
    auto bufferValue = object.getProperty(runtime, "buffer");
    if (bufferValue.isObject()) {
      auto bufferObject = bufferValue.asObject(runtime);
      if (bufferObject.isArrayBuffer(runtime)) {
        auto arrayBuffer = bufferObject.getArrayBuffer(runtime);
        size_t offset = 0;
        size_t length = arrayBuffer.size(runtime);
        auto offsetValue = object.getProperty(runtime, "byteOffset");
        if (offsetValue.isNumber()) {
          offset = static_cast<size_t>(offsetValue.asNumber());
        }
        auto lengthValue = object.getProperty(runtime, "byteLength");
        if (lengthValue.isNumber()) {
          length = static_cast<size_t>(lengthValue.asNumber());
        }
        auto* ptr = arrayBuffer.data(runtime) + offset;
        return std::vector<uint8_t>(ptr, ptr + length);
      }
    }
  }

  return {};
}

bool startup_trace_enabled();
bool env_flag_enabled(const char* env_name);

bool eval_bootstrap_script(ExactHermesRuntime* handle,
                           const char* source,
                           const uint8_t* hbc,
                           size_t hbcLen,
                           const char* sourceUrl,
                           bool preferSource,
                           bool allowHbc);

bool installModuleLoader(ExactHermesRuntime* handle);
void ensureStreamEnhance(ExactHermesRuntime* handle);
void ensureWebCrypto(ExactHermesRuntime* handle);
void ensureWebStorage(ExactHermesRuntime* handle);
void ensureFormData(ExactHermesRuntime* handle);
void installLegacyLazyBootstrapGetters(ExactHermesRuntime* handle, bool sharedRuntimeInstalled);
void runLegacyProcessCompatFix(ExactHermesRuntime* handle, bool sharedRuntimeInstalled);
void runLegacyCompatPolyfills(ExactHermesRuntime* handle, bool sharedRuntimeInstalled);
void runLegacyExactGlobal(ExactHermesRuntime* handle, bool sharedRuntimeInstalled);
void runFinalProcessVersionsFix(ExactHermesRuntime* handle);
void installWebStreamsPolyfill(ExactHermesRuntime* handle);
void installDnsHostFunctions(ExactHermesRuntime* handle);
void installCryptoHostFunctions(ExactHermesRuntime* handle);
void installFsHostFunctions(ExactHermesRuntime* handle);
void installChildProcessHostFunctions(ExactHermesRuntime* handle);
void installNetHostFunctions(ExactHermesRuntime* handle);
void installHttpHostFunctions(ExactHermesRuntime* handle);
void installSqliteHostFunctions(ExactHermesRuntime* handle);

extern "C" void ex_host_console_log(int32_t level, const char* message);

std::string escapeJson(const std::string& input);
bool appendEscapedJsonText(std::string& out, const uint8_t* bytes, size_t len);
std::string jsonString(const std::string& value);
std::string makeRemoteObject(facebook::jsi::Runtime& rt, const facebook::jsi::Value& value);
std::string stringifyValue(facebook::jsi::Runtime& runtime, const facebook::jsi::Value& value);
facebook::jsi::Value parseJsonValue(facebook::jsi::Runtime& runtime, const char* json);
void pushDebugEvent(ExactHermesRuntime* runtime, const std::string& event);
std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI> snapshotDebugger(
    ExactHermesRuntime* runtime);
void clearDebugger(ExactHermesRuntime* runtime);
void disableDebugger(ExactHermesRuntime* runtime);
std::string buildPausedEvent(facebook::hermes::debugger::Debugger& debugger);
bool runtimeIsAlive(ExactHermesRuntime* runtime);
void emitNewScripts(ExactHermesRuntime* runtime,
                    facebook::hermes::debugger::Debugger& debugger);

void pushRuntimeCallback(ExactHermesRuntime* runtime,
                         std::function<void(facebook::jsi::Runtime&)> fn);

extern const char* g_streamEnhanceJS;
extern const char* g_webCryptoJS;
extern const char* g_webStorageJS;
extern const char* g_formDataJS;
