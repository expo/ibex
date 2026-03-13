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
#include <vector>

struct TimerEntry {
  uint64_t id;
  uint64_t due_ms;
  uint64_t interval_ms;
  bool repeat;
  bool referenced = true;
  facebook::jsi::Function callback;
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
  std::deque<facebook::jsi::Function> next_tick;
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

bool startup_trace_enabled();
bool env_flag_enabled(const char* env_name);

bool eval_bootstrap_script(ExactHermesRuntime* handle,
                           const char* source,
                           const uint8_t* hbc,
                           size_t hbcLen,
                           const char* sourceUrl,
                           bool preferSource,
                           bool allowHbc);

void installModuleLoader(ExactHermesRuntime* handle);
void ensureStreamEnhance(ExactHermesRuntime* handle);
void ensureWebCrypto(ExactHermesRuntime* handle);
void ensureWebStorage(ExactHermesRuntime* handle);
void ensureFormData(ExactHermesRuntime* handle);

extern const char* g_streamEnhanceJS;
extern const char* g_webCryptoJS;
extern const char* g_webStorageJS;
extern const char* g_formDataJS;
