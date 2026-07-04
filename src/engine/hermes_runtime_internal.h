#pragma once

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#if defined(__has_include)
#if __has_include(<hermes/AsyncDebuggerAPI.h>)
#define EXACT_HAS_HERMES_ASYNC_DEBUGGER 1
#endif
#endif
#if !defined(EXACT_HAS_HERMES_ASYNC_DEBUGGER)
#define EXACT_HAS_HERMES_ASYNC_DEBUGGER 0
#endif

#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
#include <hermes/AsyncDebuggerAPI.h>
#endif
#include <hermes/hermes.h>
#include <jsi/jsi.h>
#include <jsi/instrumentation.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <cmath>
#include <functional>
#include <initializer_list>
#include <limits>
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
#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
  std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI> debugger;
#endif
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
  void (*ios_dispatch_with_debug_context_callback)(
      const uint8_t* data,
      size_t length,
      const char* debug_context_json,
      void* context) = nullptr;
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

struct NativeWebSocketCallbackContext {
  ExactHermesRuntime* runtime;
  std::shared_ptr<facebook::jsi::Object> ws_instance;
  std::atomic<uint32_t> ref_count{1};
};

extern "C" int32_t ex_host_is_allow_all(void);
extern "C" int32_t ex_host_check_capability(uint64_t module_id, const char* capability);
extern "C" void ex_host_log_event(const char* event_type,
                                  uint64_t module_id,
                                  const char* capability,
                                  int32_t result);

extern thread_local uint64_t g_active_module_id;

extern "C" void ex_host_register_module_package(uint64_t module_id,
                                                const char* package,
                                                const char* locator);
extern "C" int32_t ex_host_check_capability_stack(const uint64_t* module_ids,
                                                  size_t len,
                                                  const char* capability);
extern "C" int32_t ex_host_has_deputy_classes(void);
extern "C" int32_t ex_host_check_import(uint64_t module_id,
                                        const char* specifier);
// @ref LLP 0013#delegation-and-authority-flow — authority-bearing capability handles.
extern "C" uint64_t ex_host_handle_create(const char* capability);
extern "C" uint64_t ex_host_handle_scoped(uint64_t parent, const char* narrower);
extern "C" int32_t ex_host_handle_check(uint64_t id, const char* capability);
extern "C" void ex_host_handle_revoke(uint64_t id);
// @ref LLP 0013 §dynamic permissions — runtime root-grant mutation (tri-state).
extern "C" int32_t ex_host_permission_request(const char* capability);
extern "C" void ex_host_permission_revoke(const char* capability);
extern "C" int32_t ex_host_permission_status(const char* capability);

// @ref LLP 0013#mechanism-3 — frame-derived capability attribution. The bridge
// symbols are exported by the carried Hermes patch stack (patches/hermes/0003)
// and are only referenced when EXACT_HAVE_FRAME_ATTRIBUTION is defined (build.rs
// probes the linked framework for them), so an unpatched engine still links and
// falls back to the thread-local module id below.
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
extern "C" uint32_t ex_hermes_vm_current_package_id(void* vm_runtime);
extern "C" void ex_hermes_vm_set_pending_package_id(void* vm_runtime,
                                                    uint32_t package_id);
extern "C" void ex_hermes_vm_set_default_package_id(void* vm_runtime,
                                                    uint32_t package_id);
extern "C" void ex_hermes_vm_clear_pending_package_id(void* vm_runtime);
extern "C" size_t ex_hermes_vm_collect_package_ids(void* vm_runtime,
                                                   uint32_t* out,
                                                   size_t max);
// @ref LLP 0013#phase-5 (Open-Q3) — arm schedule-time principal capture so a
// deputy op detached across a microtask (`Promise.resolve(x).then(deputy.method)`)
// is attributed to its scheduler, not just the bare deputy frame. Exported by
// patches/hermes/0008; armed at boot iff deputy-class hardening is configured.
extern "C" void ex_hermes_vm_set_job_scheduler_capture(void* vm_runtime,
                                                       int enabled);
// The vm::Runtime pointer (HermesRuntime::getVMRuntimeUnsafe()), cached once at
// runtime creation. Null on unpatched engines and until the runtime is created.
extern void* g_vm_runtime;
// The reserved principal for runtime-internal code (bootstrap, module loader,
// lockdown/compartment installers). Domains stamped with it are transparent to
// frame attribution — the walk skips them so the nearest user frame is charged.
// Kept in sync with kRuntimePackageId in Hermes' CapabilityAttribution.cpp.
constexpr uint32_t kRuntimePrincipalId = 0xFFFFFFFFu;
// Mirror of the Rust NO_USER_PRINCIPAL / engine kNoUserPrincipal: a principal
// with no grants that fails closed. Used as a fail-closed sentinel when the
// deputy-stack collector may have truncated (see checkCapability). (ENG-22643)
constexpr uint32_t kNoUserPrincipalId = 0xFFFFFFFEu;
#endif

// The capability principal for the code currently executing at the host
// boundary. With the carried patch stack this is the package id of the nearest
// JS frame's Domain — engine truth that JS cannot forge (a stored callback or a
// patched prototype method still reports its true author). Without the patch it
// is the legacy thread-local module id set by the loader around evaluation.
// @ref LLP 0013#mechanism-3
inline uint64_t currentPrincipalId() {
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  if (g_vm_runtime != nullptr) {
    return static_cast<uint64_t>(ex_hermes_vm_current_package_id(g_vm_runtime));
  }
#endif
  return g_active_module_id;
}

#if defined(EXACT_HAVE_JSI_MUTABLE_BUFFER)
class VectorBuffer : public facebook::jsi::MutableBuffer {
 public:
  explicit VectorBuffer(std::vector<uint8_t> data) : data_(std::move(data)) {}

  size_t size() const override { return data_.size(); }
  uint8_t* data() override { return data_.data(); }

 private:
  std::vector<uint8_t> data_;
};
#endif

inline bool isAllowAll() {
#ifdef _WIN32
  return ex_host_is_allow_all() != 0;
#else
  static int cached = -1;
  if (cached < 0) {
    cached = ex_host_is_allow_all();
  }
  return cached != 0;
#endif
}

// Whether any deputy capability classes are configured (Phase 5 opt-in). NOT
// cached: a process-lifetime latch of the first observed answer would be a
// footgun if a check ever ran before deputy classes were configured (it would
// pin `false` for the whole process). The check is only reached on the opt-in
// deputy path, and the FFI is two cheap RwLock reads, so query it live. (ENG-22644)
inline bool hasDeputyClasses() {
  return ex_host_has_deputy_classes() != 0;
}

inline bool checkCapability(const std::string& capability) {
  if (isAllowAll()) {
    return true;
  }
  auto principal = currentPrincipalId();
#if defined(EXACT_HAVE_FRAME_ATTRIBUTION)
  // @ref LLP 0013#phase-5 — for deputy-sensitive capability classes (opt-in via
  // policy), effective authority is the AND of every package on the call stack,
  // so a deputy holding e.g. fs:write cannot be driven to act for an ungranted
  // caller. Only collect the stack when deputy classes are actually configured.
  if (g_vm_runtime != nullptr && hasDeputyClasses()) {
    // Collection is innermost-first, so a full buffer drops the OUTERMOST frames
    // — exactly the low-authority callers whose absence would let the AND pass
    // (fail open). Size the buffer generously (the collector collapses
    // consecutive-duplicate principal runs, so this is astronomically deep) and,
    // if it still fills, append the fail-closed sentinel so the deputy-class AND
    // denies rather than trusting a possibly-truncated stack. The non-deputy path
    // keys on ids64[0] (innermost, never dropped) and is unaffected. (ENG-22643)
    constexpr size_t kMaxStack = 256;
    uint32_t ids32[kMaxStack];
    size_t n = ex_hermes_vm_collect_package_ids(g_vm_runtime, ids32, kMaxStack);
    if (n > 0) {
      uint64_t ids64[kMaxStack + 1];
      for (size_t i = 0; i < n; i++) {
        ids64[i] = static_cast<uint64_t>(ids32[i]);
      }
      if (n == kMaxStack) {
        ids64[n++] = static_cast<uint64_t>(kNoUserPrincipalId);
      }
      auto allowed = ex_host_check_capability_stack(ids64, n, capability.c_str());
      ex_host_log_event(
          allowed ? "capability_granted" : "capability_denied",
          ids64[0],
          capability.c_str(),
          allowed);
      return allowed != 0;
    }
  }
#endif
  auto allowed = ex_host_check_capability(principal, capability.c_str());
  ex_host_log_event(
      allowed ? "capability_granted" : "capability_denied",
      principal,
      capability.c_str(),
      allowed);
  return allowed != 0;
}

inline facebook::jsi::Value makeUint8Array(
    facebook::jsi::Runtime& runtime,
    std::vector<uint8_t> data) {
#if defined(EXACT_HAVE_JSI_MUTABLE_BUFFER)
  auto buffer = std::make_shared<VectorBuffer>(std::move(data));
  facebook::jsi::ArrayBuffer arrayBuffer(runtime, buffer);
  auto ctor = runtime.global().getPropertyAsFunction(runtime, "Uint8Array");
  auto typed = ctor.callAsConstructor(runtime, arrayBuffer).getObject(runtime);
#else
  auto ctor = runtime.global().getPropertyAsFunction(runtime, "Uint8Array");
  auto typed =
      ctor.callAsConstructor(runtime, static_cast<int>(data.size())).getObject(runtime);
  for (size_t i = 0; i < data.size(); i++) {
    typed.setProperty(runtime, std::to_string(i).c_str(), static_cast<int>(data[i]));
  }
#endif
  return facebook::jsi::Value(std::move(typed));
}

inline bool exactByteLengthFromValue(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value,
    const char* propertyName,
    size_t defaultValue,
    size_t& out) {
  if (value.isUndefined() || value.isNull()) {
    out = defaultValue;
    return true;
  }
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(runtime, std::string("Invalid ") + propertyName);
  }
  double n = value.asNumber();
  if (!std::isfinite(n) || n < 0 || std::floor(n) != n ||
      n > static_cast<double>(std::numeric_limits<size_t>::max())) {
    throw facebook::jsi::JSError(runtime, std::string("Invalid ") + propertyName);
  }
  out = static_cast<size_t>(n);
  return true;
}

inline bool extractArrayBufferView(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Object& object,
    const uint8_t*& data,
    size_t& length,
    size_t* byteOffsetOut = nullptr) {
  data = nullptr;
  length = 0;
  if (object.isArrayBuffer(runtime)) {
    auto buffer = object.getArrayBuffer(runtime);
    data = buffer.data(runtime);
    length = buffer.size(runtime);
    if (byteOffsetOut) {
      *byteOffsetOut = 0;
    }
    return true;
  }
  if (!object.hasProperty(runtime, "buffer")) {
    return false;
  }
  auto bufferValue = object.getProperty(runtime, "buffer");
  if (!bufferValue.isObject()) {
    return false;
  }
  auto bufferObject = bufferValue.asObject(runtime);
  if (!bufferObject.isArrayBuffer(runtime)) {
    return false;
  }
  auto arrayBuffer = bufferObject.getArrayBuffer(runtime);
  size_t bufferSize = arrayBuffer.size(runtime);
  size_t offset = 0;
  size_t viewLength = bufferSize;
  if (object.hasProperty(runtime, "byteOffset")) {
    exactByteLengthFromValue(
        runtime,
        object.getProperty(runtime, "byteOffset"),
        "byteOffset",
        0,
        offset);
  }
  if (object.hasProperty(runtime, "byteLength")) {
    exactByteLengthFromValue(
        runtime,
        object.getProperty(runtime, "byteLength"),
        "byteLength",
        bufferSize - std::min(offset, bufferSize),
        viewLength);
  } else {
    viewLength = bufferSize - std::min(offset, bufferSize);
  }
  if (offset > bufferSize || viewLength > bufferSize - offset) {
    throw facebook::jsi::JSError(runtime, "ArrayBuffer view out of bounds");
  }
  data = arrayBuffer.data(runtime) + offset;
  length = viewLength;
  if (byteOffsetOut) {
    *byteOffsetOut = offset;
  }
  return true;
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
  const uint8_t* data = nullptr;
  size_t length = 0;
  if (extractArrayBufferView(runtime, object, data, length)) {
    return data ? std::vector<uint8_t>(data, data + length) : std::vector<uint8_t>();
  }

  return {};
}

bool startup_trace_enabled();
bool env_flag_enabled(const char* env_name);
std::string valueToString(facebook::jsi::Runtime& rt, const facebook::jsi::Value& value);
uint64_t nowMs();
double processUptimeSeconds();
facebook::jsi::Function makeHardExitFn(facebook::jsi::Runtime& rt);
void cleanupFetchCallbacks(ExactHermesRuntime* runtime);

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
void installConsoleGlobals(ExactHermesRuntime* handle);
void installTimerGlobals(ExactHermesRuntime* handle);
void installOsInfoGlobals(ExactHermesRuntime* handle);
void installProcessSetup(ExactHermesRuntime* handle);
void installWebSocketGlobals(ExactHermesRuntime* handle);
void installFetchGlobals(ExactHermesRuntime* handle);
void installAndroidHostFunctions(ExactHermesRuntime* handle);
void unregisterAndroidHostFunctions(ExactHermesRuntime* handle);
void installIpcListenerPatch(ExactHermesRuntime* handle);

extern "C" void ex_host_console_log(int32_t level, const char* message);
extern "C" void native_ws_retain_context(void* context);
extern "C" void native_ws_release_context(void* context);

std::string escapeJson(const std::string& input);
bool appendEscapedJsonText(std::string& out, const uint8_t* bytes, size_t len);
std::string jsonString(const std::string& value);
std::string makeRemoteObject(facebook::jsi::Runtime& rt, const facebook::jsi::Value& value);
std::string stringifyValue(facebook::jsi::Runtime& runtime, const facebook::jsi::Value& value);
facebook::jsi::Value parseJsonValue(facebook::jsi::Runtime& runtime, const char* json);
std::unordered_map<std::string, int64_t> captureHeapInfo(
    ExactHermesRuntime* runtime,
    bool includeExpensive);
int64_t lookupHeapInfoValue(
    const std::unordered_map<std::string, int64_t>& heapInfo,
    std::initializer_list<const char*> keys,
    int64_t fallbackValue = 0);
facebook::jsi::Object makeHeapInfoObject(
    facebook::jsi::Runtime& runtime,
    const std::unordered_map<std::string, int64_t>& heapInfo);
std::string stringifyHeapInfo(
    const std::unordered_map<std::string, int64_t>& heapInfo);
char* copyMallocString(const std::string& value);
void pushDebugEvent(ExactHermesRuntime* runtime, const std::string& event);
#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI> snapshotDebugger(
    ExactHermesRuntime* runtime);
#endif
void clearDebugger(ExactHermesRuntime* runtime);
void disableDebugger(ExactHermesRuntime* runtime);
#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
std::string buildPausedEvent(facebook::hermes::debugger::Debugger& debugger);
#endif
bool runtimeIsAlive(ExactHermesRuntime* runtime);
#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
void emitNewScripts(ExactHermesRuntime* runtime,
                    facebook::hermes::debugger::Debugger& debugger);
#endif

void pushRuntimeCallback(ExactHermesRuntime* runtime,
                         std::function<void(facebook::jsi::Runtime&)> fn);

extern const char* g_streamEnhanceJS;
extern const char* g_webCryptoJS;
extern const char* g_webStorageJS;
extern const char* g_formDataJS;
