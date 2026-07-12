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
#include <cctype>
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
  uint64_t principal;
  std::vector<uint64_t> principalStack;
  facebook::jsi::Function callback;
  std::vector<facebook::jsi::Value> args;
};

struct NextTickEntry {
  uint64_t principal;
  std::vector<uint64_t> principalStack;
  facebook::jsi::Function callback;
  std::vector<facebook::jsi::Value> args;
};

struct FetchCallbackEntry {
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
  uint64_t principal;
  std::string url;
  std::chrono::steady_clock::time_point deadline;
};

// LLP 0297 W3 (exact repo): pending `__hostCallAsync` promise, resolved from
// any thread via ex_hermes_resolve_host_call → pushRuntimeCallback.
struct HostCallAsyncEntry {
  std::shared_ptr<facebook::jsi::Function> resolve;
  std::shared_ptr<facebook::jsi::Function> reject;
};

struct ExactHermesRuntime {
  std::unique_ptr<facebook::hermes::HermesRuntime> runtime;
  uint64_t host_context_id{0};
  uint64_t runtime_nonce{0};
  // Immutable constructor-selected posture. Bootstrap must never consult
  // process-global environment toggles that other threads can observe/race.
  bool armed{false};
  bool structural_lockdown{false};
  std::string snapshot_endowments;
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  // The frame-attribution VM owned by this handle. The active pointer is
  // selected at each engine entry point; a thread may drive nested runtimes.
  void* attribution_runtime{nullptr};
#endif
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
  // In-flight async DNS resolutions dispatched to the DNS worker pool. Counted
  // as referenced work so a pending lookup keeps the event loop alive (matching
  // Node's ref'd getaddrinfo requests) without a polling timer. (ENG-22995)
  std::atomic<int> pending_dns_lookups{0};
  // In-flight async fs operations dispatched to the fs worker pool (readFile/
  // writeFile/read/write/stat). Same keepalive discipline as DNS: a pending op
  // counts as referenced work so the loop survives until the worker delivers
  // its completion via pushRuntimeCallback. (ENG-23497)
  std::atomic<int> pending_fs_ops{0};
  // Pins held by native workers that may dereference this handle outside the
  // runtime thread. Destroy unregisters first, then waits for this count to
  // reach zero before cleanup/delete.
  std::atomic<uint32_t> native_worker_pins{0};
  std::mutex native_worker_mutex;
  std::condition_variable native_worker_cv;
  std::mutex fetchMutex;
  std::unordered_map<uint32_t, FetchCallbackEntry> fetchCallbacks;
  std::mutex hostCallAsyncMutex;
  uint64_t nextHostCallAsyncId{1};
  std::unordered_map<uint64_t, HostCallAsyncEntry> hostCallAsyncCallbacks;
  std::mutex callbackMutex;
  std::deque<std::function<void(facebook::jsi::Runtime&)>> callbackQueue;
  // Fail-loud marker for async callbacks (process.nextTick, cross-thread
  // tasks/callbacks) that threw with no uncaughtException handler consuming
  // the error: the poll that observes it returns -1 so the host loop surfaces
  // the failure instead of letting the run complete with exit code 0. One-shot
  // (consumed by that poll), mirroring the throwing-timer path's transient -1
  // so a REPL survives it the same way it survives a throwing timer. Only
  // touched on the runtime thread.
  // @ref LLP 0003#the-event-loop — async failures are fatal (ENG-23130)
  bool fatal_async_error = false;
  bool typed_authority_generations_initialized = false;
  uint64_t typed_negative_generation = 0;
  uint64_t typed_dynamic_generation = 0;
  uint64_t typed_handle_generation = 0;
  // Host policy for JS errors escaping drained async callbacks (timers,
  // microtasks, nextTick, cross-thread tasks). CLI default (false): the
  // fatal_async_error / poll -1 contract above. Embedded app hosts opt in
  // via ex_hermes_set_keep_alive_on_async_error(): the error still reports
  // through the __exactUncaughtExceptionHandler consult + raw console path,
  // but the runtime keeps pumping — one bad app callback must not crash or
  // zombify the host (ENG-23731; graceful degradation). Set by hosts during
  // engine construction before the loop starts; read on the runtime thread.
  bool keep_alive_on_async_error = false;

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

  // LLP 0297 §4.3 (exact repo): true for restricted UI worklet runtimes
  // created by ex_worklet_create(). Restricted runtimes refuse the app
  // runtime's host wiring (dispatch/module/kernel/host-call setters are
  // guarded no-ops) — worklets influence the tree only through SharedValues
  // and their synchronous verdicts.
  bool restricted = false;

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
  void (*host_call_async_fn)(ExactHermesRuntime* runtime,
                             uint64_t call_id,
                             const char* op,
                             const char* args_json) = nullptr;
};

struct NativeWebSocketCallbackContext {
  ExactHermesRuntime* runtime;
  std::shared_ptr<facebook::jsi::Object> ws_instance;
  uint64_t runtime_nonce;
  uint64_t principal;
  std::string capability;
  std::atomic<uint32_t> ref_count{1};
  // Guarded by g_websocket_mutex in hermes_runtime_websocket.cc. Keeping the
  // pre-registration terminal state on the exact per-runtime callback
  // context avoids process-global missing-ID tombstones.
  bool websocket_registered{false};
  bool websocket_terminal{false};
};

extern "C" int32_t ex_host_is_allow_all(void);
extern "C" int32_t ex_host_is_armed(void);
extern "C" uint64_t ex_hermes_current_runtime_nonce(void);
extern "C" int32_t ex_hermes_engine_mapped_object(uint64_t* out_device,
                                                   uint64_t* out_inode);
extern "C" int32_t ex_host_check_capability(uint64_t module_id, const char* capability);
extern "C" int32_t ex_host_check_capability_no_follow_final(uint64_t module_id,
                                                            const char* capability);
extern "C" int32_t ex_host_check_handle_mint(uint64_t module_id,
                                             const char* capability);
extern "C" void ex_host_log_event(const char* event_type,
                                  uint64_t module_id,
                                  const char* capability,
                                  int32_t result);

extern thread_local uint64_t g_active_module_id;
constexpr uint64_t kNoNativePrincipalOverride = std::numeric_limits<uint64_t>::max();
extern thread_local uint64_t g_native_callback_principal_id;
extern thread_local uint64_t g_active_runtime_nonce;

extern "C" uint64_t ex_host_enter_context(uint64_t context_id);
extern "C" void ex_host_restore_context(uint64_t previous);

inline uint64_t exactCurrentRuntimeNonce() {
  return g_active_runtime_nonce;
}

class ScopedRuntimeSecurityContext {
 public:
  explicit ScopedRuntimeSecurityContext(const ExactHermesRuntime* runtime)
      : previousRuntime_(g_active_runtime_nonce), previousHost_(UINT64_MAX) {
    if (runtime != nullptr) {
      g_active_runtime_nonce = runtime->runtime_nonce;
      previousHost_ = ex_host_enter_context(runtime->host_context_id);
    }
  }
  ~ScopedRuntimeSecurityContext() {
    if (previousHost_ != UINT64_MAX) ex_host_restore_context(previousHost_);
    g_active_runtime_nonce = previousRuntime_;
  }
  ScopedRuntimeSecurityContext(const ScopedRuntimeSecurityContext&) = delete;
  ScopedRuntimeSecurityContext& operator=(const ScopedRuntimeSecurityContext&) = delete;

 private:
  uint64_t previousRuntime_;
  uint64_t previousHost_;
};

extern "C" void ex_host_register_module_package(uint64_t module_id,
                                                const char* package,
                                                const char* locator,
                                                const char* integrity);
extern "C" int32_t ex_host_check_capability_stack(const uint64_t* module_ids,
                                                  size_t len,
                                                  const char* capability);
extern "C" int32_t ex_host_check_capability_stack_no_follow_final(const uint64_t* module_ids,
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
// @ref LLP 0013 — §dynamic permissions — runtime root-grant mutation (tri-state).
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
// @ref LLP 0013#phase-5 — (Open-Q3) — arm schedule-time principal capture so a
// deputy op detached across a microtask (`Promise.resolve(x).then(deputy.method)`)
// is attributed to its scheduler, not just the bare deputy frame. Exported by
// patches/hermes/0008; armed at boot iff deputy-class hardening is configured.
extern "C" void ex_hermes_vm_set_job_scheduler_capture(void* vm_runtime,
                                                       int enabled);
// The vm::Runtime pointer (HermesRuntime::getVMRuntimeUnsafe()), cached at
// runtime creation. Null on unpatched engines and until the runtime is created.
// THREAD-LOCAL: names the runtime the current thread created and drives, so
// concurrent runtimes on other threads (unit-test harness, worklets) can't
// clobber or free the pointer this thread's attribution walk reads. (ENG-23011)
extern thread_local void* g_vm_runtime;
// The reserved principal for runtime-internal code (bootstrap, module loader,
// lockdown/compartment installers). Domains stamped with it are transparent to
// frame attribution — the walk skips them so the nearest user frame is charged.
// Kept in sync with kRuntimePackageId in Hermes' CapabilityAttribution.cpp.
constexpr uint32_t kRuntimePrincipalId = 0xFFFFFFFFu;
// Mirror of the Rust NO_USER_PRINCIPAL / engine kNoUserPrincipal: a principal
// with no grants that fails closed. Used as a fail-closed sentinel when the
// deputy-stack collector may have truncated (see checkCapability). (ENG-22643)
constexpr uint32_t kNoUserPrincipalId = 0xFFFFFFFEu;

// A thread may drive more than one Hermes runtime, including re-entrantly when
// an embedder host call evaluates a nested runtime. Capability attribution must
// follow the runtime currently being driven, then restore the outer runtime on
// unwind. @ref LLP 0013#mechanism-3
class ScopedActiveAttributionRuntime {
 public:
  explicit ScopedActiveAttributionRuntime(void* runtime)
      : previous_(g_vm_runtime) {
    g_vm_runtime = runtime;
  }

  ScopedActiveAttributionRuntime(const ScopedActiveAttributionRuntime&) = delete;
  ScopedActiveAttributionRuntime& operator=(const ScopedActiveAttributionRuntime&) = delete;

  ~ScopedActiveAttributionRuntime() {
    g_vm_runtime = previous_;
  }

 private:
  void* previous_;
};
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
    auto principal =
        static_cast<uint64_t>(ex_hermes_vm_current_package_id(g_vm_runtime));
    if (principal == static_cast<uint64_t>(kNoUserPrincipalId) &&
        g_native_callback_principal_id != kNoNativePrincipalOverride) {
      return g_native_callback_principal_id;
    }
    return principal;
  }
#endif
  if (g_native_callback_principal_id != kNoNativePrincipalOverride) {
    return g_native_callback_principal_id;
  }
  return g_active_module_id;
}

// @ref LLP 0013#phase-5 — native-host callbacks can re-enter JS with no live
// user frame. Carry the scheduling/owning principal only for that no-user
// boundary; frame attribution remains authoritative when Hermes reports one.
class ScopedNativePrincipal {
 public:
  explicit ScopedNativePrincipal(uint64_t principal)
      : previous_(g_native_callback_principal_id) {
    g_native_callback_principal_id = principal;
  }

  ScopedNativePrincipal(const ScopedNativePrincipal&) = delete;
  ScopedNativePrincipal& operator=(const ScopedNativePrincipal&) = delete;

  ~ScopedNativePrincipal() {
    g_native_callback_principal_id = previous_;
  }

 private:
  uint64_t previous_;
};

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
  return ex_host_is_allow_all() != 0;
}

// Whether any deputy capability classes are configured (Phase 5 opt-in). NOT
// cached: a process-lifetime latch of the first observed answer would be a
// footgun if a check ever ran before deputy classes were configured (it would
// pin `false` for the whole process). The check is only reached on the opt-in
// deputy path, and the FFI is two cheap RwLock reads, so query it live. (ENG-22644)
inline bool hasDeputyClasses() {
  return ex_host_has_deputy_classes() != 0;
}

inline bool checkCapabilityWithFsMode(const std::string& capability, bool noFollowFinal) {
  if (isAllowAll()) {
    return true;
  }
  auto principal = currentPrincipalId();
#if defined(EXACT_HAVE_FRAME_ATTRIBUTION)
  // @ref LLP 0013#phase-5 — for deputy-sensitive capability classes (opt-in via
  // policy), effective authority is the AND of every package on the call stack,
  // so a deputy holding e.g. fs:write cannot be driven to act for an ungranted
  // caller. Also collect when the live frame walk found no user principal: the
  // scheduler capture can recover the package/root that caused a native-resolved
  // continuation, avoiding a false deny while still denying ungranted schedulers.
  bool deputyClasses = hasDeputyClasses();
  bool useStack =
      g_vm_runtime != nullptr &&
      (deputyClasses || principal == kNoUserPrincipalId);
  if (useStack) {
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
      // @ref LLP 0013#phase-5 — (Open-Q3), ENG-22759 — fold in the HOST-queue
      // scheduling principal for a deputy op detached across a timer /
      // process.nextTick / setImmediate / the non-JSI queueMicrotask fallback.
      // ENG-22761 captures that principal into g_native_callback_principal_id
      // (ScopedNativePrincipal around the detached drain), but currentPrincipalId
      // consults it only as a fallback for a *no-user* frame walk. A detached
      // deputy METHOD (`setTimeout(deputy.readFor, 0, SECRET)`) runs with its own
      // frame live, so the walk returns the deputy and the scheduler is otherwise
      // dropped — leaving [deputy] (len 1), the deputy-class AND skipped, and the
      // read laundered for the ungranted scheduler. Append it here, exactly as
      // Hermes' collectStackPackageIds appends the Promise-queue scheduler for
      // `Promise.resolve(x).then(deputy.method)` (that queue lives in the VM; the
      // timer/nextTick queues live in the embedder, so the append is done here).
      // An ungranted scheduler makes the AND deny; a granted package's own timer
      // continuation (scheduler == the innermost frame) collapses and is not
      // false-denied. Skip the runtime/no-user sentinels — a native completion with
      // no attributable scheduler is not evidence of laundering (matches ENG-22761
      // for the Promise queue). Deputy-class path only, with room after the
      // truncation sentinel.
      if (deputyClasses && n <= kMaxStack &&
          g_native_callback_principal_id != kNoNativePrincipalOverride) {
        uint64_t scheduler = g_native_callback_principal_id;
        if (scheduler != static_cast<uint64_t>(kRuntimePrincipalId) &&
            scheduler != static_cast<uint64_t>(kNoUserPrincipalId) &&
            scheduler != ids64[n - 1]) {
          ids64[n++] = scheduler;
        }
      }
      auto allowed = noFollowFinal
          ? ex_host_check_capability_stack_no_follow_final(ids64, n, capability.c_str())
          : ex_host_check_capability_stack(ids64, n, capability.c_str());
      ex_host_log_event(
          allowed ? "capability_granted" : "capability_denied",
          ids64[0],
          capability.c_str(),
          allowed);
      return allowed != 0;
    }
  }
#endif
  auto allowed = noFollowFinal
      ? ex_host_check_capability_no_follow_final(principal, capability.c_str())
      : ex_host_check_capability(principal, capability.c_str());
  ex_host_log_event(
      allowed ? "capability_granted" : "capability_denied",
      principal,
      capability.c_str(),
      allowed);
  return allowed != 0;
}

inline bool checkCapability(const std::string& capability) {
  return checkCapabilityWithFsMode(capability, false);
}

inline bool checkCapabilityNoFollowFinal(const std::string& capability) {
  return checkCapabilityWithFsMode(capability, true);
}

// POSIX SCM_RIGHTS crosses subsystem boundaries: network/process code may need
// to transfer a raw fd, while fs.cc owns the registry that keeps raw integers
// from becoming ambient authority. These helpers are implemented in
// hermes_runtime_fs.cc and intentionally expose only narrow checked operations.
// Windows compiles hermes_runtime_fs_windows.cc instead. Both implementations
// provide exactCollectTypedPrincipalStack for common typed adapters; the raw-fd
// transfer helpers remain POSIX-only except for the Windows IPC-registration
// no-op.
void exactRegisterTransferableFd(int fd, uint64_t owner);
void exactRegisterProcessIpcFd(int fd);
void exactRegisterReceivedFdForCurrentPrincipal(int fd);
bool exactConsumeTransferableFdForCurrentPrincipal(int fd);
std::vector<uint64_t> exactCollectTypedPrincipalStack();

// Closed tags shared with ex_host_authorize_typed_system_info_stack.  Never
// accept a coverage edge or selector name from JavaScript as free-form text.
enum class ExactSystemInfoSurface : uint32_t {
  CpuCount = 0,
  FreeMemory = 1,
  Hostname = 2,
  LoadAverage = 3,
  NetworkInterfaces = 4,
  TotalMemory = 5,
  Uptime = 6,
  UserInfo = 7,
  CachedValue = 8,
  ProcessRss = 9,
  Cwd = 10,
};

enum class ExactSystemInfoName : uint32_t {
  Architecture = 0,
  CameraMetadata = 1,
  Cpus = 2,
  Cwd = 3,
  Hostname = 4,
  Language = 5,
  LoadAverage = 6,
  Locale = 7,
  Memory = 8,
  NetworkInterfaces = 9,
  OsRelease = 10,
  Platform = 11,
  Screen = 12,
  StoragePaths = 13,
  Uptime = 14,
  User = 15,
};

extern "C" int32_t ex_host_authorize_typed_system_info_stack(
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    uint32_t surface,
    uint32_t info_name,
    uint32_t stage);

inline void exactRequireTypedSystemInfo(
    facebook::jsi::Runtime& runtime,
    ExactSystemInfoSurface surface,
    ExactSystemInfoName name) {
  if (ex_host_is_armed() != 1) return;
  auto principals = exactCollectTypedPrincipalStack();
  auto actor = currentPrincipalId();
  // sys:read declares Requested and Commit.  Both decisions happen before
  // the native reader crosses the information-disclosure barrier.
  for (uint32_t stage = 0; stage <= 1; ++stage) {
    if (ex_host_authorize_typed_system_info_stack(
            actor,
            principals.data(),
            principals.size(),
            static_cast<uint32_t>(surface),
            static_cast<uint32_t>(name),
            stage) != 1) {
      throw facebook::jsi::JSError(runtime, "Permission denied: system information");
    }
  }
}

void exactCleanupRuntimeFileDescriptors(uint64_t runtimeNonce);
void exactCleanupRuntimeSockets(uint64_t runtimeNonce);
void exactCleanupRuntimeSqlite(uint64_t runtimeNonce);
void exactCleanupRuntimeHttpServers(uint64_t runtimeNonce);
bool disposeAsyncCallbackError(
    ExactHermesRuntime* runtime,
    const facebook::jsi::JSError& err);
bool exactPinRuntimeNativeWorker(ExactHermesRuntime* runtime);
void exactUnpinRuntimeNativeWorker(ExactHermesRuntime* runtime);

class ScopedTypedPrincipalStack {
 public:
  explicit ScopedTypedPrincipalStack(const std::vector<uint64_t>& principals);
  ~ScopedTypedPrincipalStack();
  ScopedTypedPrincipalStack(const ScopedTypedPrincipalStack&) = delete;
 ScopedTypedPrincipalStack& operator=(const ScopedTypedPrincipalStack&) = delete;

 private:
  std::vector<uint64_t> principals_;
  const std::vector<uint64_t>* previous_;
};
void exactRequireOwnedIpcFd(facebook::jsi::Runtime& runtime, int fd, const char* syscall);
void exactRequireTransferableFd(facebook::jsi::Runtime& runtime, int fd, const char* syscall);

struct ParsedNetworkUrl {
  std::string scheme;
  std::string host;
  int port;
};

inline std::string asciiLower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

inline void requireNetworkResolveCapability(
    facebook::jsi::Runtime& runtime,
    const std::string& target,
    const char* syscall) {
  auto capability = "network:resolve:" + asciiLower(target);
  if (!checkCapability(capability)) {
    throw facebook::jsi::JSError(
        runtime,
        std::string("Permission denied: ") + syscall + " requires " + capability);
  }
}

inline int defaultPortForNetworkScheme(const std::string& scheme) {
  if (scheme == "http" || scheme == "ws") {
    return 80;
  }
  if (scheme == "https" || scheme == "wss") {
    return 443;
  }
  return -1;
}

inline bool parseNetworkPort(const std::string& value, int& port) {
  if (value.empty()) {
    return false;
  }
  int parsed = 0;
  for (unsigned char c : value) {
    if (std::isdigit(c) == 0) {
      return false;
    }
    int digit = static_cast<int>(c - '0');
    if (parsed > (65535 - digit) / 10) {
      return false;
    }
    parsed = parsed * 10 + digit;
  }
  port = parsed;
  return true;
}

inline std::string formatNetworkEndpoint(const std::string& host, int port) {
  // Capability resources must use URI-style brackets for IPv6. Without them,
  // `::1:443` is ambiguous and policy parsing can reinterpret the final
  // address component as a port.
  if (host.find(':') != std::string::npos &&
      !(host.size() >= 2 && host.front() == '[' && host.back() == ']')) {
    return "[" + host + "]:" + std::to_string(port);
  }
  return host + ":" + std::to_string(port);
}

inline bool parseNetworkUrl(
    const std::string& url,
    ParsedNetworkUrl& parsed,
    const char** failureReason = nullptr) {
  const auto fail = [failureReason](const char* reason) {
    if (failureReason != nullptr) {
      *failureReason = reason;
    }
    return false;
  };
  for (unsigned char byte : url) {
    if (byte <= 0x20 || byte == 0x7f) {
      return fail("ASCII control or space");
    }
  }
  auto scheme_end = url.find("://");
  if (scheme_end == std::string::npos || scheme_end == 0) {
    return fail("missing scheme");
  }
  parsed.scheme = asciiLower(url.substr(0, scheme_end));
  size_t authority_start = scheme_end + 3;
  size_t authority_end = url.find_first_of("/?#", authority_start);
  std::string authority = url.substr(
      authority_start,
      authority_end == std::string::npos ? std::string::npos : authority_end - authority_start);
  auto at = authority.rfind('@');
  if (at != std::string::npos) {
    authority = authority.substr(at + 1);
  }
  if (authority.empty()) {
    return fail("missing authority");
  }

  parsed.port = defaultPortForNetworkScheme(parsed.scheme);
  std::string host;
  if (authority[0] == '[') {
    auto close = authority.find(']');
    if (close == std::string::npos) {
      return fail("unterminated IPv6 host");
    }
    host = authority.substr(1, close - 1);
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':') {
        return fail("invalid IPv6 authority suffix");
      }
      auto port_str = authority.substr(close + 2);
      if (!parseNetworkPort(port_str, parsed.port)) {
        return fail("invalid port");
      }
    }
  } else {
    auto first_colon = authority.find(':');
    auto colon = authority.rfind(':');
    if (first_colon != std::string::npos && first_colon != colon) {
      return fail("unbracketed IPv6 host");
    }
    if (colon != std::string::npos) {
      host = authority.substr(0, colon);
      auto port_str = authority.substr(colon + 1);
      if (!parseNetworkPort(port_str, parsed.port)) {
        return fail("invalid port");
      }
    } else {
      host = authority;
    }
  }

  if (host.empty() || parsed.port < 0 || parsed.port > 65535) {
    return fail("invalid host or port");
  }
  parsed.host = asciiLower(host);
  return true;
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

inline uint32_t exactUint32FromSize(
    facebook::jsi::Runtime& runtime,
    size_t length,
    const char* propertyName) {
  if (length > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
    throw facebook::jsi::JSError(runtime, std::string(propertyName) + " exceeds uint32 range");
  }
  return static_cast<uint32_t>(length);
}

inline uint32_t exactUint32FromValue(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value,
    const char* propertyName,
    uint32_t defaultValue) {
  size_t parsed = defaultValue;
  exactByteLengthFromValue(runtime, value, propertyName, defaultValue, parsed);
  return exactUint32FromSize(runtime, parsed, propertyName);
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
// Native TLS bridge host functions (ENG-23492/ENG-23526); installed from
// installNetHostFunctions and driven by the platform TCP host functions.
void installTlsHostFunctions(ExactHermesRuntime* handle);
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

// Process-global registries retain resources by runtime nonce and must be
// drained before the owning Hermes handle is deleted.
extern "C" void exactCleanupRuntimeSpawnedProcesses(uint64_t runtimeNonce);
extern "C" void exactCleanupRuntimeWebSockets(uint64_t runtimeNonce);
extern "C" void ibex_tls_cleanup_runtime(uint64_t runtimeNonce);

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

// ENG-22925/ENG-23028: run `body` with the runtime pinned alive. Holds
// g_runtimeRegistryMutex across a membership test AND the synchronous execution
// of `body`, so a caller on any thread can safely dereference runtime-owned
// state (per-runtime mutexes/maps) that would otherwise race a concurrent
// ex_hermes_destroy — which holds the same mutex across its `delete`. Returns
// true iff the runtime was alive and `body` ran. `body` MUST be short and MUST
// NOT re-enter the runtime registry (no ex_hermes_destroy / pushRuntimeCallback /
// runtimeIsAlive). If it takes a per-runtime lock, that lock must follow the
// registry in the global lock order; destroy-side cleanup that needs the same
// lock must also happen under the registry. This is the cross-translation-unit
// form of the resolve_host_call pin so sibling completion paths (fetch,
// debugger, etc.) can close the same check-then-lock TOCTOU without exposing the
// registry internals.
bool withRuntimePinned(ExactHermesRuntime* runtime,
                       const std::function<void()>& body);

#if EXACT_HAS_HERMES_ASYNC_DEBUGGER
void emitNewScripts(ExactHermesRuntime* runtime,
                    facebook::hermes::debugger::Debugger& debugger);
#endif

void pushRuntimeCallback(ExactHermesRuntime* runtime,
                         std::function<void(facebook::jsi::Runtime&)> fn,
                         bool* accepted = nullptr);

void exactRequireFdReadable(facebook::jsi::Runtime& runtime, int fd, const char* syscall);
void exactRequireFdWritable(facebook::jsi::Runtime& runtime, int fd, const char* syscall);

extern const char* g_streamEnhanceJS;
extern const char* g_webCryptoJS;
extern const char* g_webStorageJS;
extern const char* g_formDataJS;
